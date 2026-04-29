# -*- encoding: utf-8 -*-
"""Ephemeral W3C VC-JWT projection workflow for KERIA.

KERIA coordinates this workflow but does not sign as a Signify-managed AID.
The managed edge controller signs short-lived request bytes and submits the
signatures back to KERIA. KERIA then assembles a VC-JWT, submits it to an
allowlisted verifier, stores only a compact result summary, and purges all
signature/token material when the session TTL expires.

SSE is only a live nudge. The durable recovery path is
``/identifiers/{name}/w3c/signing-requests``.
"""

from __future__ import annotations

import copy
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import falcon
from hio.base import doing
from keri.core import coring
from vc_isomer.data_integrity import (
    create_proof_configuration,
    create_verify_data,
    encode_multibase_base58btc,
)
from vc_isomer.jwt import (
    b64url_decode,
    b64url_encode,
    build_vc_jwt_payload,
    canonical_json_bytes,
)
from vc_isomer.profile import VRD_SCHEMA, transpose_acdc_to_w3c_vc

from .. import log_name, ogler
from ..db.basing import W3CProjectionRecord, W3CSigningRequestRecord
from . import didwebing, streaming

logger = ogler.getLogger(log_name)

W3C_SIG_ROUTE = "/w3c/signing/request"
W3C_DONE_ROUTE = "/w3c/projection/complete"
W3C_SIG_EVENT = "w3c.signing-request"
W3C_DONE_EVENT = "w3c.projection.complete"

W3C_KIND_PROOF = "data_integrity_proof"
W3C_KIND_JWT = "vc_jwt"

SUPPORTED_VERIFIER_KINDS = {
    "isomer-python-vc-jwt",
    "isomer-node-vc-jwt",
    "isomer-go-vc-jwt",
}

W3C_REQ_PENDING = "pending"
W3C_REQ_COMPLETE = "complete"
W3C_REQ_FAILED = "failed"

W3C_STATE_PROOF = "pending_proof_signature"
W3C_STATE_JWT = "pending_jwt_signature"
W3C_STATE_SUBMIT = "submitting_verifier"
W3C_STATE_COMPLETE = "complete"
W3C_STATE_FAILED = "failed"
W3C_STATE_EXPIRED = "expired"

DEFAULT_TTL_SECONDS = 600
DEFAULT_SIGNAL_INTERVAL = 30.0


class W3CProjectionError(ValueError):
    """Raised when a W3C projection session cannot advance safely."""


@dataclass
class W3CVerifierConfig:
    """Allowlisted verifier target for Phase 4 VC-JWT submissions."""

    id: str
    label: str
    kind: str
    verifyUrl: str
    healthUrl: str | None = None


@dataclass
class W3CProjectionConfig:
    """Runtime configuration for ephemeral W3C projection sessions."""

    enabled: bool = False
    session_ttl_seconds: int = DEFAULT_TTL_SECONDS
    verifiers: list[W3CVerifierConfig] | None = None
    status_base_url: str | None = None


def loadAdminEnds(app, config: W3CProjectionConfig):
    """Register W3C projection routes when the workflow is enabled."""
    if not config.enabled:
        return

    app.add_route("/w3c/verifiers", W3CVerifierCollectionEnd(config))
    projectionEnd = W3CProjectionCollectionEnd(config)
    app.add_route("/identifiers/{name}/w3c/projections", projectionEnd)
    app.add_route(
        "/identifiers/{name}/w3c/projections/{sessionId}",
        W3CProjectionResourceEnd(config),
    )
    requestEnd = W3CSigningRequestCollectionEnd(config)
    app.add_route("/identifiers/{name}/w3c/signing-requests", requestEnd)
    app.add_route(
        "/identifiers/{name}/w3c/signing-requests/{requestId}/signatures",
        W3CSigningRequestSignatureEnd(config),
    )


def configFromSources(config: Any, cf=None) -> W3CProjectionConfig:
    """Merge W3C projection config from config file data, explicit config, and env."""
    merged = {}
    if cf is not None:
        data = cf.get() or {}
        if isinstance(data.get("w3c_projection"), dict):
            merged.update(data["w3c_projection"])

    if isinstance(config, W3CProjectionConfig):
        merged.update(asdict(config))
    elif isinstance(config, dict):
        merged.update(config)

    merged.update(configFromEnvironment())

    verifiers = []
    for verifier in merged.get("verifiers") or []:
        if isinstance(verifier, W3CVerifierConfig):
            verifiers.append(verifier)
        elif isinstance(verifier, dict):
            verifiers.append(W3CVerifierConfig(**verifier))

    return W3CProjectionConfig(
        enabled=parseBool(merged.get("enabled", False)),
        session_ttl_seconds=int(
            merged.get("session_ttl_seconds", DEFAULT_TTL_SECONDS)
            or DEFAULT_TTL_SECONDS
        ),
        verifiers=verifiers,
        status_base_url=emptyToNone(merged.get("status_base_url")),
    )


def configFromEnvironment() -> dict[str, Any]:
    """Return W3C projection settings explicitly present in the environment."""
    config = {}
    if os.getenv("KERIA_W3C_PROJECTION_ENABLED") is not None:
        config["enabled"] = os.getenv("KERIA_W3C_PROJECTION_ENABLED")
    if os.getenv("KERIA_W3C_PROJECTION_SESSION_TTL_SECONDS") is not None:
        config["session_ttl_seconds"] = os.getenv(
            "KERIA_W3C_PROJECTION_SESSION_TTL_SECONDS"
        )
    if os.getenv("KERIA_W3C_PROJECTION_STATUS_BASE_URL") is not None:
        config["status_base_url"] = os.getenv("KERIA_W3C_PROJECTION_STATUS_BASE_URL")
    if os.getenv("KERIA_W3C_PROJECTION_VERIFIERS") is not None:
        config["verifiers"] = json.loads(os.getenv("KERIA_W3C_PROJECTION_VERIFIERS"))
    return config


def parseBool(value: Any) -> bool:
    """Parse flexible bool-ish config values."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).lower() in ("true", "1", "yes", "on")


def emptyToNone(value: Any) -> str | None:
    """Normalize empty string config values to None."""
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def utcTimestamp() -> str:
    """Return RFC3339 UTC timestamp without fractional seconds."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def expiresAt(ttl: int) -> str:
    """Return an RFC3339 expiry timestamp ttl seconds from now."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .__add__(timedelta(seconds=ttl))
        .isoformat()
        .replace("+00:00", "Z")
    )


def parseTimestamp(value: str) -> datetime:
    """Parse an RFC3339 timestamp into an aware datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class W3CProjectionDoer(doing.Doer):
    """Advance short-lived W3C projection sessions and expire old material."""

    SignalInterval = DEFAULT_SIGNAL_INTERVAL

    def __init__(self, agent, config: W3CProjectionConfig, signalCues, tock=1.0):
        self.agent = agent
        self.config = config
        if signalCues is None:
            raise ValueError("signalCues is required")
        self.signalCues = signalCues
        self.adb = agent.adb
        self.lastSignalTymes = {}
        super().__init__(tock=tock)

    def recur(self, tyme=None, tock=0.0, **opts):
        if not self.config.enabled:
            return False

        try:
            self.cleanupExpired()
            self.advanceActiveSessions()
            self.signalPendingRequests(0.0 if tyme is None else tyme)
        except Exception:  # pragma: no cover - defensive runtime logging
            logger.exception("failed W3C projection processing")

        return False

    def advanceActiveSessions(self):
        """Advance sessions that have newly submitted edge signatures."""
        for _keys, session in list(self.adb.w3cproj.getItemIter()):
            if session.state in {W3C_STATE_COMPLETE, W3C_STATE_FAILED, W3C_STATE_EXPIRED}:
                continue
            try:
                self.advanceSession(session)
            except Exception as ex:  # pragma: no cover - per-session recovery
                session.state = W3C_STATE_FAILED
                session.error = str(ex)
                session.updated = utcTimestamp()
                self.adb.w3cproj.pin(keys=(session.d,), val=session)
                logger.exception("failed W3C projection session %s", session.d)

    def advanceSession(self, session: W3CProjectionRecord):
        """Move one session through proof, JWT, and verifier submission states."""
        if session.state == W3C_STATE_PROOF:
            request = self.adb.w3creq.get(keys=(session.proofRequest,))
            if request is None or request.signature is None:
                return
            self.applyProofSignature(session, request)

        if session.state == W3C_STATE_JWT:
            request = self.adb.w3creq.get(keys=(session.jwtRequest,))
            if request is None or request.signature is None:
                return
            self.applyJwtSignature(session, request)

        if session.state == W3C_STATE_SUBMIT:
            self.submitVerifier(session)

    def applyProofSignature(
        self, session: W3CProjectionRecord, request: W3CSigningRequestRecord
    ):
        """Verify the Data Integrity proof signature and create the JWT request."""
        signature = signatureRaw(request.signature)
        verify_data = b64url_decode(request.signingInputB64)
        if not verferFromMethod(session.verificationMethod).verify(signature, verify_data):
            request.state = W3C_REQ_FAILED
            request.error = "invalid data integrity proof signature"
            request.updated = utcTimestamp()
            self.adb.w3creq.pin(keys=(request.d,), val=request)
            raise W3CProjectionError(request.error)

        proof = copy.deepcopy(session.proofConfig)
        proof["proofValue"] = encode_multibase_base58btc(signature)
        secured = copy.deepcopy(session.unsignedVc)
        secured["proof"] = proof

        header = {"alg": "EdDSA", "kid": session.verificationMethod, "typ": "JWT"}
        payload = build_vc_jwt_payload(secured)
        signing_input = jwtSigningInput(header, payload)
        jwt_request = ensureSigningRequest(
            agent=self.agent,
            session=session,
            kind=W3C_KIND_JWT,
            signing_input=signing_input,
        )

        request.state = W3C_REQ_COMPLETE
        request.updated = utcTimestamp()
        self.adb.w3creq.pin(keys=(request.d,), val=request)

        session.proofSignature = request.signature
        session.securedVc = secured
        session.jwtHeader = header
        session.jwtPayload = payload
        session.jwtRequest = jwt_request.d
        session.state = W3C_STATE_JWT
        session.updated = utcTimestamp()
        self.adb.w3cproj.pin(keys=(session.d,), val=session)

    def applyJwtSignature(
        self, session: W3CProjectionRecord, request: W3CSigningRequestRecord
    ):
        """Verify the compact JWT signature and assemble the VC-JWT token."""
        signature = signatureRaw(request.signature)
        signing_input = b64url_decode(request.signingInputB64)
        if not verferFromMethod(session.verificationMethod).verify(signature, signing_input):
            request.state = W3C_REQ_FAILED
            request.error = "invalid VC-JWT signature"
            request.updated = utcTimestamp()
            self.adb.w3creq.pin(keys=(request.d,), val=request)
            raise W3CProjectionError(request.error)

        token = f"{signing_input.decode('utf-8')}.{b64url_encode(signature)}"
        request.state = W3C_REQ_COMPLETE
        request.updated = utcTimestamp()
        self.adb.w3creq.pin(keys=(request.d,), val=request)

        session.jwtSignature = request.signature
        session.token = token
        session.state = W3C_STATE_SUBMIT
        session.updated = utcTimestamp()
        self.adb.w3cproj.pin(keys=(session.d,), val=session)

    def submitVerifier(self, session: W3CProjectionRecord):
        """POST the assembled VC-JWT to the selected verifier."""
        body = json.dumps({"token": session.token}).encode("utf-8")
        req = urllib.request.Request(
            session.verifierUrl,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as ex:
            raw = ex.read()
            session.verifierStatus = ex.code
            session.verifierResponse = decodeResponseBody(raw)
            session.state = W3C_STATE_FAILED
            session.error = f"verifier returned HTTP {ex.code}"
            session.updated = utcTimestamp()
            self.adb.w3cproj.pin(keys=(session.d,), val=session)
            return
        except Exception as ex:
            session.state = W3C_STATE_FAILED
            session.error = f"verifier submission failed: {ex}"
            session.updated = utcTimestamp()
            self.adb.w3cproj.pin(keys=(session.d,), val=session)
            return

        session.verifierStatus = status
        session.verifierResponse = decodeResponseBody(raw)
        session.state = W3C_STATE_COMPLETE if 200 <= status < 300 else W3C_STATE_FAILED
        if session.state == W3C_STATE_FAILED:
            session.error = f"verifier returned HTTP {status}"
        session.updated = utcTimestamp()
        self.adb.w3cproj.pin(keys=(session.d,), val=session)

        if session.state == W3C_STATE_COMPLETE:
            streaming.enqueueSignedReplyCue(
                self.signalCues,
                event=W3C_DONE_EVENT,
                route=W3C_DONE_ROUTE,
                payload=sessionResponse(session),
                event_id=session.d,
            )

    def signalPendingRequests(self, tyme: float):
        """Queue bounded live nudges for pending edge-signature requests."""
        for _keys, request in self.adb.w3creq.getItemIter():
            if request.state != W3C_REQ_PENDING:
                continue
            last = self.lastSignalTymes.get(request.d)
            if last is not None and tyme - last < self.SignalInterval:
                continue
            streaming.enqueueSignedReplyCue(
                self.signalCues,
                event=W3C_SIG_EVENT,
                route=W3C_SIG_ROUTE,
                payload=requestPayload(request),
                event_id=request.d,
            )
            self.lastSignalTymes[request.d] = tyme
            request.lastSignaled = utcTimestamp()
            self.adb.w3creq.pin(keys=(request.d,), val=request)

    def cleanupExpired(self):
        """Purge expired sessions and their signing requests."""
        now = datetime.now(timezone.utc)
        expired_sessions = set()
        for _keys, session in list(self.adb.w3cproj.getItemIter()):
            if parseTimestamp(session.expires) <= now:
                expired_sessions.add(session.d)
                self.adb.w3cproj.rem(keys=(session.d,))

        for _keys, request in list(self.adb.w3creq.getItemIter()):
            if request.session in expired_sessions or parseTimestamp(request.expires) <= now:
                self.adb.w3creq.rem(keys=(request.d,))
                self.lastSignalTymes.pop(request.d, None)


def createProjectionSession(
    agent, config: W3CProjectionConfig, name: str, credentialSaid: str, verifierId: str
) -> W3CProjectionRecord:
    """Create one short-lived projection session and its first signing request."""
    if not config.enabled:
        raise falcon.HTTPNotFound(description="W3C projection is disabled")

    verifier = verifierById(config, verifierId)
    if verifier.kind not in SUPPORTED_VERIFIER_KINDS:
        raise falcon.HTTPBadRequest(description=f"unsupported verifier kind {verifier.kind}")

    hab = agent.hby.habByName(name)
    if hab is None or hab.pre == agent.agentHab.pre:
        raise falcon.HTTPNotFound(description=f"managed identifier {name} not found")

    issuer_did = didwebing.publishedDws(agent, hab.pre)
    if issuer_did is None:
        raise falcon.HTTPBadRequest(description=f"identifier {name} has no ready did:webs DID")

    creder, *_ = cloneCredential(agent, credentialSaid)
    acdc = copy.deepcopy(creder.sad)
    validateProjectionCredential(agent, hab.pre, creder)

    now = utcTimestamp()
    expires = expiresAt(config.session_ttl_seconds)
    verification_method = f"{issuer_did}#{hab.kever.verfers[0].qb64}"
    status_base_url = config.status_base_url or verifierBaseUrl(verifier.verifyUrl)
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did=issuer_did,
        status_base_url=status_base_url,
    )
    proof_config = create_proof_configuration(
        verification_method=verification_method,
        created=now,
    )
    proof_bytes = create_verify_data(vc, proof_config)
    payload = {
        "d": "",
        "aid": hab.pre,
        "name": name,
        "credentialSaid": credentialSaid,
        "issuerDid": issuer_did,
        "verifierId": verifier.id,
        "verifierUrl": verifier.verifyUrl,
        "statusBaseUrl": status_base_url,
        "state": W3C_STATE_PROOF,
        "created": now,
        "updated": now,
        "expires": expires,
        "verificationMethod": verification_method,
        "unsignedVc": vc,
        "proofConfig": proof_config,
    }
    _saider, payload = coring.Saider.saidify(payload)
    session = W3CProjectionRecord(**payload)
    request = ensureSigningRequest(
        agent=agent,
        session=session,
        kind=W3C_KIND_PROOF,
        signing_input=proof_bytes,
    )
    session.proofRequest = request.d
    agent.adb.w3cproj.put(keys=(session.d,), val=session)
    return session


def ensureSigningRequest(
    *, agent, session: W3CProjectionRecord, kind: str, signing_input: bytes
) -> W3CSigningRequestRecord:
    """Create or reuse one short-lived W3C edge-signature request."""
    for _keys, request in agent.adb.w3creq.getItemIter():
        if request.session == session.d and request.kind == kind:
            return request

    now = utcTimestamp()
    payload = {
        "d": "",
        "session": session.d,
        "type": W3C_SIG_EVENT,
        "kind": kind,
        "agent": agent.agentHab.pre,
        "aid": session.aid,
        "name": session.name,
        "credentialSaid": session.credentialSaid,
        "signingInputB64": b64url_encode(signing_input),
        "encoding": "base64url",
        "verificationMethod": session.verificationMethod,
        "state": W3C_REQ_PENDING,
        "created": now,
        "updated": now,
        "expires": session.expires,
    }
    _saider, payload = coring.Saider.saidify(payload)
    request = W3CSigningRequestRecord(**payload)
    agent.adb.w3creq.put(keys=(request.d,), val=request)
    return request


def cloneCredential(agent, said: str):
    """Clone one locally saved credential or raise a 404."""
    if agent.rgy.reger.saved.get(keys=(said,)) is None:
        raise falcon.HTTPNotFound(description=f"credential {said} not found")
    return agent.rgy.reger.cloneCred(said=said)


def validateProjectionCredential(agent, aid: str, creder):
    """Require an active VRD ACDC owned by the issuer or holder presenter."""
    subject = creder.sad.get("a", {}) if isinstance(creder.sad, dict) else {}
    holder = subject.get("i") if isinstance(subject, dict) else None
    if creder.issuer != aid and holder != aid:
        raise falcon.HTTPBadRequest(
            description="W3C projection requires the selected identifier to be the credential issuer or holder"
        )
    if creder.schema != VRD_SCHEMA:
        raise falcon.HTTPBadRequest(
            description=f"unsupported W3C projection schema SAID {creder.schema}"
        )

    tever = agent.rgy.tevers.get(creder.regi)
    state = tever.vcState(creder.said) if tever is not None else None
    ilk = getattr(state, "et", getattr(state, "ilk", None)) if state is not None else None
    if ilk not in ("iss", "bis"):
        raise falcon.HTTPBadRequest(description=f"credential {creder.said} is not active")


def verifierById(config: W3CProjectionConfig, verifier_id: str) -> W3CVerifierConfig:
    """Return one configured verifier by id."""
    for verifier in config.verifiers or []:
        if verifier.id == verifier_id:
            return verifier
    raise falcon.HTTPBadRequest(description=f"unknown W3C verifier {verifier_id}")


def verifierBaseUrl(verify_url: str) -> str:
    """Derive a status base URL from the verifier origin when none is configured."""
    parsed = urllib.parse.urlparse(verify_url)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def iterRequests(agent, name: str | None = None, includeComplete=False):
    """Iterate W3C signing requests, optionally filtered by identifier alias."""
    terminal = {W3C_REQ_COMPLETE, W3C_REQ_FAILED}
    for _keys, request in agent.adb.w3creq.getItemIter():
        if name is not None and request.name != name:
            continue
        if not includeComplete and request.state in terminal:
            continue
        yield request


def requestPayload(request: W3CSigningRequestRecord) -> dict[str, Any]:
    """Return the signed client-facing payload for a W3C signing request."""
    return {
        "d": request.d,
        "session": request.session,
        "type": request.type,
        "kind": request.kind,
        "agent": request.agent,
        "aid": request.aid,
        "name": request.name,
        "credentialSaid": request.credentialSaid,
        "signingInputB64": request.signingInputB64,
        "encoding": request.encoding,
        "verificationMethod": request.verificationMethod,
        "created": request.created,
        "expires": request.expires,
    }


def requestResponse(agent, request: W3CSigningRequestRecord) -> dict[str, Any]:
    """Return one request with state and a current signed envelope."""
    return {
        **requestPayload(request),
        "state": request.state,
        "lastSignaled": request.lastSignaled,
        "error": request.error,
        "envelope": streaming.signedReplyEnvelope(
            agent, W3C_SIG_ROUTE, requestPayload(request)
        ),
    }


def sessionResponse(session: W3CProjectionRecord) -> dict[str, Any]:
    """Return safe projection session status without raw token/signature material."""
    return {
        "d": session.d,
        "aid": session.aid,
        "name": session.name,
        "credentialSaid": session.credentialSaid,
        "issuerDid": session.issuerDid,
        "verifierId": session.verifierId,
        "state": session.state,
        "created": session.created,
        "updated": session.updated,
        "expires": session.expires,
        "proofRequest": session.proofRequest,
        "jwtRequest": session.jwtRequest,
        "verifierStatus": session.verifierStatus,
        "verifierResponse": session.verifierResponse,
        "error": session.error,
    }


def submitSignature(agent, name: str, request_id: str, signature: str):
    """Store one edge signature for later Doer processing."""
    request = agent.adb.w3creq.get(keys=(request_id,))
    if request is None or request.name != name:
        raise falcon.HTTPNotFound(description=f"W3C signing request {request_id} not found")
    if request.state != W3C_REQ_PENDING:
        return request
    signatureRaw(signature)
    request.signature = signature
    request.updated = utcTimestamp()
    agent.adb.w3creq.pin(keys=(request.d,), val=request)
    return request


def jwtSigningInput(header: dict[str, Any], payload: dict[str, Any]) -> bytes:
    """Return compact-JWT signing input bytes."""
    return f"{b64url_encode(canonical_json_bytes(header))}.{b64url_encode(canonical_json_bytes(payload))}".encode("utf-8")


def signatureRaw(signature: str) -> bytes:
    """Decode an unindexed CESR Cigar signature and return raw Ed25519 bytes."""
    try:
        return coring.Cigar(qb64=signature).raw
    except Exception as exc:
        raise falcon.HTTPBadRequest(description="invalid unindexed signature") from exc


def verferFromMethod(method: str):
    """Build a verifier from the verification method fragment."""
    fragment = method.split("#", 1)[1] if "#" in method else method
    return coring.Verfer(qb64=fragment)


def decodeResponseBody(raw: bytes) -> dict[str, Any] | str:
    """Decode a verifier response as JSON when possible."""
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return raw.decode("utf-8", errors="replace")


class W3CVerifierCollectionEnd:
    """Configured W3C verifier allowlist."""

    def __init__(self, config: W3CProjectionConfig):
        self.config = config

    def on_get(self, req, rep):
        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(
            {"verifiers": [asdict(verifier) for verifier in self.config.verifiers or []]}
        ).encode("utf-8")


class W3CProjectionCollectionEnd:
    """Create projection sessions for managed AID credentials."""

    def __init__(self, config: W3CProjectionConfig):
        self.config = config

    def on_post(self, req, rep, name):
        agent = req.context.agent
        body = req.get_media()
        credential_said = body.get("credentialSaid")
        verifier_id = body.get("verifierId")
        if not credential_said or not verifier_id:
            raise falcon.HTTPBadRequest(description="credentialSaid and verifierId are required")

        session = createProjectionSession(
            agent,
            self.config,
            name=name,
            credentialSaid=credential_said,
            verifierId=verifier_id,
        )
        rep.status = falcon.HTTP_202
        rep.content_type = "application/json"
        rep.data = json.dumps(sessionResponse(session)).encode("utf-8")


class W3CProjectionResourceEnd:
    """Projection session status."""

    def __init__(self, config: W3CProjectionConfig):
        self.config = config

    def on_get(self, req, rep, name, sessionId):
        agent = req.context.agent
        session = agent.adb.w3cproj.get(keys=(sessionId,))
        if session is None or session.name != name:
            raise falcon.HTTPNotFound(description=f"W3C projection {sessionId} not found")
        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(sessionResponse(session)).encode("utf-8")


class W3CSigningRequestCollectionEnd:
    """Polling fallback for W3C edge-signature requests."""

    def __init__(self, config: W3CProjectionConfig):
        self.config = config

    def on_get(self, req, rep, name):
        agent = req.context.agent
        include_complete = req.get_param_as_bool("includeComplete") or False
        requests = [
            requestResponse(agent, request)
            for request in iterRequests(agent, name=name, includeComplete=include_complete)
        ]
        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps({"requests": requests}).encode("utf-8")


class W3CSigningRequestSignatureEnd:
    """Accept one edge signature for a pending W3C request."""

    def __init__(self, config: W3CProjectionConfig):
        self.config = config

    def on_post(self, req, rep, name, requestId):
        agent = req.context.agent
        body = req.get_media()
        signature = body.get("signature")
        if not signature:
            raise falcon.HTTPBadRequest(description="signature is required")
        request = submitSignature(agent, name, requestId, signature)
        rep.status = falcon.HTTP_202
        rep.content_type = "application/json"
        rep.data = json.dumps(requestResponse(agent, request)).encode("utf-8")
