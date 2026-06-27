# -*- encoding: utf-8 -*-
"""Edge-owned W3C credential workflow boundary for KERIA.

Signify edge clients assemble and sign VC-JWT and VP-JWT artifacts. KERIA
validates those artifacts against local KERI/ACDC/TEL state, records workflow
state, and forwards issuer grants or verifier presentations.
"""

from __future__ import annotations

import copy
import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import falcon
from hio.base import doing
from keri import core, kering
from keri.app import forwarding
from keri.core import coring, eventing, serdering
from vc_isomer.common import canonicalize_did_url, canonicalize_did_webs
from vc_isomer.constants import EDDSA, STATUS_TYPE, VC_JWT_TYP, VP_JWT_TYP
from vc_isomer.data_integrity import (
    ED25519_MULTIKEY_PREFIX,
    encode_multibase_base58btc,
    verify_proof,
)
from vc_isomer.jwt import decode_jwt
from vc_isomer.profile import VRD_SCHEMA, transpose_acdc_to_w3c_vc

from .. import log_name, ogler
from ..db.basing import (
    W3CHeldCredentialRecord,
    W3CIssuanceRecord,
    W3CPresentTxRecord,
    W3CStatusProjectionRecord,
    W3CVerifierContactRecord,
)
from . import didwebing

logger = ogler.getLogger(log_name)

W3C_GRANT_ROUTE = "/w3c/vc/grant"
W3C_STATUS_ROUTE_PREFIX = "/w3c/vc/status"

W3C_ISS_READY = "ready_for_vc_jwt"
W3C_ISS_ISSUED = "issued"
W3C_ISS_DELIVERY_PENDING = "delivery_pending"
W3C_ISS_GRANT_SENT = "grant_sent"
W3C_ISS_FAILED = "failed"

W3C_HELD_ADMITTED = "admitted"
W3C_HELD_FAILED = "failed"

W3C_PRES_SUBMITTED = "submitted"
W3C_PRES_VERIFIED = "verified"
W3C_PRES_FAILED = "failed"

DEFAULT_TTL_SECONDS = 600
DEFAULT_SIGNAL_INTERVAL = 30.0
DEFAULT_PROFILE = "gleif-vrd-isomer-v1"
ACTIVE_TEL_ILKS = {coring.Ilks.iss, coring.Ilks.bis}
REVOKED_TEL_ILKS = {coring.Ilks.rev, coring.Ilks.brv}


class W3CError(ValueError):
    """Raised when a W3C workflow cannot advance safely."""


@dataclass
class W3CConfig:
    """Runtime configuration for KERIA W3C holder-presentation workflows."""

    enabled: bool = False
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    signal_interval_seconds: float = DEFAULT_SIGNAL_INTERVAL
    status_base_url: str | None = None


def loadAdminEnds(app, config: W3CConfig):
    """Register authenticated KERIA W3C workflow routes."""
    if not config.enabled:
        return

    issuances = W3CIssuanceCollectionEnd(config)
    app.add_route("/identifiers/{name}/w3c/issuances", issuances)
    app.add_route(
        "/identifiers/{name}/w3c/issuances/{issuanceId}", W3CIssuanceResourceEnd(config)
    )
    app.add_route(
        "/identifiers/{name}/w3c/issuances/{issuanceId}/vc-jwt",
        W3CIssuanceVcJwtEnd(config),
    )
    app.add_route(
        "/identifiers/{name}/w3c/issuances/{issuanceId}/grant",
        W3CIssuanceGrantEnd(config),
    )

    app.add_route(
        "/identifiers/{name}/w3c/credentials", W3CHeldCredentialCollectionEnd(config)
    )
    app.add_route(
        "/identifiers/{name}/w3c/credentials/{credentialId}",
        W3CHeldCredentialResourceEnd(config),
    )

    contacts = W3CVerifierContactCollectionEnd(config)
    app.add_route("/identifiers/{name}/w3c/verifier-contacts", contacts)
    app.add_route(
        "/identifiers/{name}/w3c/verifier-contacts/{contactId}",
        W3CVerifierContactResourceEnd(config),
    )

    presentations = W3CPresentationCollectionEnd(config)
    app.add_route("/identifiers/{name}/w3c/presentations", presentations)
    app.add_route(
        "/identifiers/{name}/w3c/presentations/{presentationId}",
        W3CPresentationResourceEnd(config),
    )


def loadPublicEnds(app, agency, config: W3CConfig):
    """Register public W3C status routes."""
    if not config.enabled:
        return

    app.add_route(
        f"{W3C_STATUS_ROUTE_PREFIX}/{{credSaid}}", W3CStatusResourceEnd(agency=agency)
    )


def loadHandlers(agent, exc, config: W3CConfig):
    """Register peer EXN handlers for issuer-to-holder W3C delivery."""
    if not config.enabled:
        return
    exc.addHandler(W3CVcGrantHandler(agent=agent, config=config))


def configFromSources(config: Any, cf=None) -> W3CConfig:
    """Merge W3C config from config file data, explicit config, and env."""
    merged: dict[str, Any] = {}
    if cf is not None:
        data = cf.get() or {}
        if isinstance(data.get("w3c"), dict):
            merged.update(data["w3c"])

    if isinstance(config, W3CConfig):
        merged.update(asdict(config))
    elif isinstance(config, dict):
        merged.update(config)

    merged.update(configFromEnvironment())
    return W3CConfig(
        enabled=parseBool(merged.get("enabled", False)),
        ttl_seconds=int(
            merged.get("ttl_seconds", DEFAULT_TTL_SECONDS) or DEFAULT_TTL_SECONDS
        ),
        signal_interval_seconds=float(
            merged.get("signal_interval_seconds", DEFAULT_SIGNAL_INTERVAL)
            or DEFAULT_SIGNAL_INTERVAL
        ),
        status_base_url=emptyToNone(merged.get("status_base_url")),
    )


def configFromEnvironment() -> dict[str, Any]:
    """Return W3C holder workflow settings explicitly present in the environment."""
    config = {}
    if os.getenv("KERIA_W3C_ENABLED") is not None:
        config["enabled"] = os.getenv("KERIA_W3C_ENABLED")
    if os.getenv("KERIA_W3C_TTL_SECONDS") is not None:
        config["ttl_seconds"] = os.getenv("KERIA_W3C_TTL_SECONDS")
    if os.getenv("KERIA_W3C_SIGNAL_INTERVAL_SECONDS") is not None:
        config["signal_interval_seconds"] = os.getenv(
            "KERIA_W3C_SIGNAL_INTERVAL_SECONDS"
        )
    if os.getenv("KERIA_W3C_STATUS_BASE_URL") is not None:
        config["status_base_url"] = os.getenv("KERIA_W3C_STATUS_BASE_URL")
    return config


def parseBool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).lower() in ("true", "1", "yes", "on")


def emptyToNone(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def utcTimestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def expiresAt(ttl: int) -> str:
    return (
        (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=ttl))
        .isoformat()
        .replace("+00:00", "Z")
    )


class W3CDoer(doing.Doer):
    """Reconcile already-received W3C grants into holder W3C credential records."""

    def __init__(self, agent, config: W3CConfig, signalCues=None, tock=1.0):
        self.agent = agent
        self.config = config
        self.lastGrantReconcileTyme: float | None = None
        self.grantReconcileInterval = max(1.0, min(config.signal_interval_seconds, 5.0))
        super().__init__(tock=tock)

    def recur(self, tyme=None, tock=0.0, **opts):
        if not self.config.enabled:
            return False
        try:
            current = 0.0 if tyme is None else tyme
            if (
                self.lastGrantReconcileTyme is None
                or current - self.lastGrantReconcileTyme >= self.grantReconcileInterval
            ):
                self.lastGrantReconcileTyme = current
                reconcileReceivedGrantExns(self.agent, self.config)
        except Exception:  # pragma: no cover - defensive runtime logging
            logger.exception("failed W3C workflow processing")
        return False


def startIssuance(
    agent, config: W3CConfig, issuerName: str, sourceCredentialSaid: str
) -> W3CIssuanceRecord:
    """Create or resume issuer-side W3C issuance context for edge VC-JWT creation."""
    requireEnabled(config)
    for _keys, record in agent.adb.w3cissu.getItemIter():
        if (
            record.issuerName == issuerName
            and record.sourceCredentialSaid == sourceCredentialSaid
        ):
            return record

    hab = requireHab(agent, issuerName)
    issuer_did = requirePublishedDws(agent, issuerName, hab.pre)
    creder, *_ = cloneCredential(agent, sourceCredentialSaid)
    acdc = copy.deepcopy(creder.sad)
    validateIssuanceSource(agent, hab.pre, creder)
    holder_aid = holderAidFromAcdc(acdc)
    holder_did = holderDidFromAcdc(acdc)
    validateHolderDidChain(acdc, holder_aid, holder_did)

    now = utcTimestamp()
    status_base_url = requireStatusBaseUrl(config)
    pinStatusProjection(
        agent=agent,
        name=issuerName,
        aid=hab.pre,
        credential_said=sourceCredentialSaid,
        issuer_did=issuer_did,
        status_base_url=status_base_url,
        now=now,
    )
    payload = {
        "d": "",
        "issuerName": issuerName,
        "issuerAid": hab.pre,
        "holderAid": holder_aid,
        "sourceCredentialSaid": sourceCredentialSaid,
        "schemaSaid": creder.schema,
        "issuerDid": canonicalize_did_webs(issuer_did),
        "holderDid": canonicalize_did_webs(holder_did),
        "profile": DEFAULT_PROFILE,
        "state": W3C_ISS_READY,
        "created": now,
        "updated": now,
        "statusUrl": statusResourceUrl(status_base_url, sourceCredentialSaid),
        "statusBaseUrl": statusReferenceBaseUrl(status_base_url),
        "sourceCredential": acdc,
    }
    _saider, payload = coring.Saider.saidify(payload)
    record = W3CIssuanceRecord(**payload)
    agent.adb.w3cissu.pin(keys=(record.d,), val=record)
    return record


def submitIssuanceVcJwt(
    agent, config: W3CConfig, issuerName: str, issuanceId: str, body: dict[str, Any]
):
    """Validate and store an issuer edge-built VC-JWT."""
    requireEnabled(config)
    record = requireIssuance(agent, issuanceId)
    hab = requireHab(agent, issuerName)
    if record.issuerName != issuerName or record.issuerAid != hab.pre:
        raise falcon.HTTPNotFound(description=f"W3C issuance {issuanceId} not found")
    vc_jwt = requireString(body, "vcJwt")
    decoded_vc = validateVcJwtForIssuance(agent, record, vc_jwt)
    record.vcJwt = vc_jwt
    record.decodedVc = decoded_vc
    record.state = W3C_ISS_DELIVERY_PENDING
    record.error = None
    record.updated = utcTimestamp()
    agent.adb.w3cissu.pin(keys=(record.d,), val=record)
    return record


def grantPayloadFromIssuance(record: W3CIssuanceRecord) -> dict[str, str]:
    """Return the issuer-signed EXN payload for delivering one finalized VC-JWT."""
    if not record.vcJwt:
        raise falcon.HTTPBadRequest(
            description="W3C issuance has no finalized VC-JWT to grant"
        )
    return {
        "holderAid": record.holderAid,
        "holderDid": canonicalize_did_webs(record.holderDid),
        "issuerAid": record.issuerAid,
        "issuerDid": canonicalize_did_webs(record.issuerDid),
        "sourceCredentialSaid": record.sourceCredentialSaid,
        "schemaSaid": record.schemaSaid,
        "issuanceId": record.d,
        "vcJwt": record.vcJwt,
        "statusUrl": record.statusUrl,
        "profile": record.profile or DEFAULT_PROFILE,
    }


def submitIssuanceGrant(
    agent, config: W3CConfig, issuerName: str, issuanceId: str, body: dict[str, Any]
):
    """Accept a locally edge-signed issuer grant EXN and queue it for holder delivery."""
    requireEnabled(config)
    hab = requireHab(agent, issuerName)
    record = requireIssuance(agent, issuanceId)
    if record.issuerName != issuerName or record.issuerAid != hab.pre:
        raise falcon.HTTPNotFound(description=f"W3C issuance {issuanceId} not found")
    if record.vcJwt is None:
        raise falcon.HTTPBadRequest(
            description="W3C issuance has no finalized VC-JWT to grant"
        )

    serder, sigers, atc, rec = signedGrantExchangeBody(body)
    validateIssuanceGrantExn(record, serder, rec)
    for recp in rec:
        if recp not in agent.hby.kevers:
            raise falcon.HTTPBadRequest(
                description=f"attempt to send W3C grant to unknown AID={recp}"
            )

    if record.state == W3C_ISS_GRANT_SENT and record.grantSaid == serder.said:
        return record

    seal = eventing.SealEvent(
        i=hab.pre, s="{:x}".format(hab.kever.lastEst.s), d=hab.kever.lastEst.d
    )
    ims = eventing.messagize(serder=serder, sigers=sigers, seal=seal)
    ims.extend(atc.encode("utf-8"))
    agent.hby.psr.parseOne(ims=bytearray(ims), exc=agent.exc)
    queueIssuanceGrantDelivery(agent, hab, serder, ims[serder.size :], rec)

    record.grantSaid = serder.said
    record.state = W3C_ISS_GRANT_SENT
    record.error = None
    record.updated = utcTimestamp()
    agent.adb.w3cissu.pin(keys=(record.d,), val=record)
    return record


def queueIssuanceGrantDelivery(
    agent, hab, serder, grant_atc: bytes | bytearray, rec: list[str]
):
    """Send issuer KEL context and the signed W3C grant EXN to recipients."""
    for recp in rec:
        postman = forwarding.StreamPoster(
            hby=agent.hby,
            hab=agent.agentHab,
            recp=recp,
            topic="credential",
        )
        try:
            for context_serder, context_atc in grantDeliveryContextMessages(
                agent, hab.pre
            ):
                postman.send(serder=context_serder, attachment=context_atc)
            postman.send(serder=serder, attachment=grant_atc)
        except kering.ValidationError:
            logger.info(
                "unable to send W3C grant %s to recipient=%s", serder.said, recp
            )
            continue

        agent.extend([doing.DoDoer(doers=postman.deliver())])


def grantDeliveryContextMessages(agent, issuer_aid: str):
    """Yield KERI messages needed to verify an issuer-signed W3C grant EXN."""
    kever = agent.hby.db.kevers.get(issuer_aid)
    if kever is not None:
        for msg in agent.hby.db.cloneDelegation(kever):
            serder = serdering.SerderKERI(raw=msg)
            yield serder, msg[serder.size :]

    for msg in agent.hby.db.clonePreIter(pre=issuer_aid):
        serder = serdering.SerderKERI(raw=msg)
        yield serder, msg[serder.size :]


def signedGrantExchangeBody(body: dict[str, Any]):
    """Parse the Signify-created EXN submission body for issuer grant delivery."""
    ked = requireDict(body, "exn")
    sigs = requireStringList(body, "sigs")
    atc = body.get("atc", "")
    if not isinstance(atc, str):
        raise falcon.HTTPBadRequest(description="atc is required")
    rec = requireStringList(body, "rec")
    serder = serdering.SerderKERI(sad=ked)
    sigers = [core.Siger(qb64=sig) for sig in sigs]
    return serder, sigers, atc, rec


def validateIssuanceGrantExn(record: W3CIssuanceRecord, serder, rec: list[str]):
    if rec != [record.holderAid]:
        raise falcon.HTTPBadRequest(
            description="W3C grant recipients must contain only the issuance holder AID"
        )
    payload = validateGrantExnShape(serder)
    expected = grantPayloadFromIssuance(record)
    for field, expected_value in expected.items():
        actual = payload.get(field)
        if field in {"issuerDid", "holderDid"} and isinstance(actual, str):
            actual = canonicalize_did_webs(actual)
        if actual != expected_value:
            raise falcon.HTTPBadRequest(
                description=f"W3C grant EXN field {field} does not match issuance"
            )


def validateGrantExnShape(serder) -> dict[str, Any]:
    if serder.ked.get("r") != W3C_GRANT_ROUTE:
        raise falcon.HTTPBadRequest(
            description=f"W3C grant EXN route must be {W3C_GRANT_ROUTE}"
        )
    payload = serder.ked.get("a")
    if not isinstance(payload, dict):
        raise falcon.HTTPBadRequest(
            description="W3C grant EXN payload must be an object"
        )
    holder_aid = requireString(payload, "holderAid")
    issuer_aid = requireString(payload, "issuerAid")
    if serder.pre != issuer_aid:
        raise falcon.HTTPBadRequest(
            description="W3C grant EXN sender must match issuerAid"
        )
    if serder.ked.get("rp") != holder_aid:
        raise falcon.HTTPBadRequest(
            description="W3C grant EXN recipient must match holderAid"
        )
    if payload.get("i") not in {None, holder_aid}:
        raise falcon.HTTPBadRequest(
            description="W3C grant EXN payload recipient must match holderAid"
        )
    if "grantSaid" in payload:
        raise falcon.HTTPBadRequest(
            description="W3C grantSaid is derived from the EXN SAID"
        )
    for field in (
        "holderDid",
        "issuerDid",
        "sourceCredentialSaid",
        "schemaSaid",
        "issuanceId",
        "vcJwt",
        "statusUrl",
    ):
        requireString(payload, field)
    return payload


def reconcileReceivedGrantExns(agent, config: W3CConfig) -> dict[str, int]:
    """Materialize holder credentials for verified, already-stored W3C grant EXNs."""
    summary = {"scanned": 0, "created": 0, "resumed": 0, "skipped": 0, "failed": 0}
    if not config.enabled:
        return summary

    for _keys, serder in agent.hby.db.exns.getItemIter():
        if serder.ked.get("r") != W3C_GRANT_ROUTE:
            continue
        summary["scanned"] += 1
        try:
            result = reconcileReceivedGrantExn(agent, config, serder)
        except Exception:
            summary["failed"] += 1
            logger.exception(
                "failed to reconcile received W3C grant EXN %s",
                getattr(serder, "said", ""),
            )
            continue
        summary[result] += 1

    return summary


def reconcileReceivedGrantExn(agent, config: W3CConfig, serder) -> str:
    payload = validateGrantExnShape(serder)
    holder_name = localNameForAid(agent, payload["holderAid"])
    if holder_name is None:
        return "skipped"
    existing = heldCredentialByGrant(
        agent, serder.said
    ) or heldCredentialByLogicalPayload(agent, payload)
    if existing is not None:
        return "resumed"
    materializeHeldCredentialFromGrant(agent, config, holder_name, payload, serder.said)
    return "created"


def materializeHeldCredentialFromGrant(
    agent,
    config: W3CConfig,
    holderName: str,
    payload: dict[str, Any],
    grant_said: str | None,
) -> W3CHeldCredentialRecord:
    """Validate an inbound VC-JWT and materialize holder state directly."""
    requireEnabled(config)
    hab = requireHab(agent, holderName)
    holder_did = requirePublishedDws(agent, holderName, hab.pre)
    if payload["holderAid"] != hab.pre:
        raise falcon.HTTPBadRequest(
            description="W3C grant holder AID does not match local holder"
        )
    if canonicalize_did_webs(payload["holderDid"]) != canonicalize_did_webs(holder_did):
        raise falcon.HTTPBadRequest(
            description="W3C grant holder DID does not match local did:webs DID"
        )

    decoded_vc = validateVcJwtForGrant(agent, payload)
    existing = heldCredentialByGrant(agent, grant_said) if grant_said else None
    existing = existing or heldCredentialByLogicalPayload(agent, payload)
    if existing is not None:
        return existing

    now = utcTimestamp()
    held_payload = {
        "d": "",
        "holderName": holderName,
        "holderAid": hab.pre,
        "holderDid": canonicalize_did_webs(holder_did),
        "issuerAid": payload["issuerAid"],
        "issuerDid": canonicalize_did_webs(payload["issuerDid"]),
        "sourceCredentialSaid": payload["sourceCredentialSaid"],
        "schemaSaid": payload["schemaSaid"],
        "profile": payload.get("profile") or DEFAULT_PROFILE,
        "vcJwt": payload["vcJwt"],
        "decodedVc": decoded_vc,
        "statusUrl": payload["statusUrl"],
        "deliverySource": "exn_grant",
        "grantSaid": grant_said,
        "state": W3C_HELD_ADMITTED,
        "imported": now,
        "updated": now,
        "lastValidation": now,
        "validationState": "valid",
    }
    _saider, held_payload = coring.Saider.saidify(held_payload)
    held = W3CHeldCredentialRecord(**held_payload)
    agent.adb.w3cheld.pin(keys=(held.d,), val=held)
    return held


def submitPresentation(
    agent, config: W3CConfig, holderName: str, body: dict[str, Any]
) -> W3CPresentTxRecord:
    """Validate an edge-built VP-JWT, submit it to the verifier, and record result state."""
    requireEnabled(config)
    hab = requireHab(agent, holderName)
    holder_did = requirePublishedDws(agent, holderName, hab.pre)
    vp_jwt = requireString(body, "vpJwt")
    contact = createVerifierContact(agent, holderName, body)
    selected = selectPresentationCredential(agent, holderName, body)
    verifier = verifierRequestBindings(body)
    validateVpJwtForPresentation(
        agent, holderName, canonicalize_did_webs(holder_did), selected, body, vp_jwt
    )

    now = utcTimestamp()
    response = None
    submission_state = "not_submitted"
    state = W3C_PRES_SUBMITTED
    error = None
    if verifier["responseUri"]:
        response = postVerifierPresentation(
            verifier["responseUri"], vp_jwt, verifier["aud"], verifier["nonce"]
        )
        submission_state = "submitted"
        if isinstance(response, dict) and response.get("verified") is True:
            state = W3C_PRES_VERIFIED
        if isinstance(response, dict) and response.get("status", 200) >= 400:
            state = W3C_PRES_FAILED
            error = json.dumps(response)

    payload = {
        "d": "",
        "holderName": holderName,
        "holderAid": hab.pre,
        "holderDid": canonicalize_did_webs(holder_did),
        "contactId": contact.d,
        "requestDescriptor": withoutVpJwt(body),
        "state": state,
        "nonce": verifier["nonce"],
        "aud": verifier["aud"],
        "requestUri": body.get("request_uri"),
        "responseUri": verifier["responseUri"],
        "matchedCredentialIds": [selected.d],
        "selectedCredentialId": selected.d,
        "vpJwt": vp_jwt,
        "submissionEndpoint": verifier["responseUri"],
        "submissionState": submission_state,
        "verifierResponse": response,
        "created": now,
        "updated": now,
        "expires": expiresAt(config.ttl_seconds),
        "error": error,
    }
    _saider, payload = coring.Saider.saidify(payload)
    tx = W3CPresentTxRecord(**payload)
    agent.adb.w3cptx.pin(keys=(tx.d,), val=tx)
    return tx


def createVerifierContact(
    agent, holderName: str, descriptor: dict[str, Any]
) -> W3CVerifierContactRecord:
    hab = requireHab(agent, holderName)
    origin = verifierOrigin(descriptor)
    for _keys, contact in agent.adb.w3cvcnt.getItemIter():
        if contact.holderName == holderName and contact.origin == origin:
            contact.updated = utcTimestamp()
            agent.adb.w3cvcnt.pin(keys=(contact.d,), val=contact)
            return contact

    now = utcTimestamp()
    payload = {
        "d": "",
        "holderName": holderName,
        "holderAid": hab.pre,
        "origin": origin,
        "label": descriptor.get("verifierLabel") or descriptor.get("label"),
        "formats": descriptorFormats(descriptor),
        "created": now,
        "updated": now,
        "metadata": {"requestDescriptor": withoutVpJwt(descriptor)},
    }
    _saider, payload = coring.Saider.saidify(payload)
    contact = W3CVerifierContactRecord(**payload)
    agent.adb.w3cvcnt.pin(keys=(contact.d,), val=contact)
    return contact


def listIssuances(agent, issuerName: str) -> list[W3CIssuanceRecord]:
    return [
        record
        for _keys, record in agent.adb.w3cissu.getItemIter()
        if record.issuerName == issuerName
    ]


def listHeldCredentials(agent, holderName: str) -> list[W3CHeldCredentialRecord]:
    return [
        record
        for _keys, record in agent.adb.w3cheld.getItemIter()
        if record.holderName == holderName
    ]


def listVerifierContacts(agent, holderName: str) -> list[W3CVerifierContactRecord]:
    return [
        record
        for _keys, record in agent.adb.w3cvcnt.getItemIter()
        if record.holderName == holderName
    ]


def listPresentations(agent, holderName: str) -> list[W3CPresentTxRecord]:
    return [
        record
        for _keys, record in agent.adb.w3cptx.getItemIter()
        if record.holderName == holderName
    ]


def validateVcJwtForIssuance(
    agent, record: W3CIssuanceRecord, vc_jwt: str
) -> dict[str, Any]:
    decoded = decodeJwtOr400(vc_jwt, "VC-JWT")
    source = record.sourceCredential
    if not isinstance(source, dict):
        creder, *_ = cloneCredential(agent, record.sourceCredentialSaid)
        source = copy.deepcopy(creder.sad)
    expected_status_base = record.statusBaseUrl or statusReferenceBaseUrl(
        requireStatusBaseUrl(W3CConfig(enabled=True))
    )
    return validateVcJwt(
        agent=agent,
        token=vc_jwt,
        decoded=decoded,
        issuer_aid=record.issuerAid,
        issuer_did=record.issuerDid,
        holder_aid=record.holderAid,
        holder_did=record.holderDid,
        source_credential_said=record.sourceCredentialSaid,
        schema_said=record.schemaSaid,
        status_url=record.statusUrl,
        status_base_url=expected_status_base,
        source=source,
    )


def validateVcJwtForGrant(agent, payload: dict[str, Any]) -> dict[str, Any]:
    creder, *_ = cloneCredential(agent, payload["sourceCredentialSaid"])
    source = copy.deepcopy(creder.sad)
    validateIssuanceSource(agent, payload["issuerAid"], creder)
    validateHolderDidChain(source, payload["holderAid"], payload["holderDid"])
    return validateVcJwt(
        agent=agent,
        token=payload["vcJwt"],
        decoded=decodeJwtOr400(payload["vcJwt"], "VC-JWT"),
        issuer_aid=payload["issuerAid"],
        issuer_did=payload["issuerDid"],
        holder_aid=payload["holderAid"],
        holder_did=payload["holderDid"],
        source_credential_said=payload["sourceCredentialSaid"],
        schema_said=payload["schemaSaid"],
        status_url=payload["statusUrl"],
        status_base_url=statusReferenceBaseFromStatusUrl(
            payload["statusUrl"], payload["sourceCredentialSaid"]
        ),
        source=source,
    )


def validateVcJwt(
    *,
    agent,
    token: str,
    decoded,
    issuer_aid: str,
    issuer_did: str,
    holder_aid: str,
    holder_did: str,
    source_credential_said: str,
    schema_said: str,
    status_url: str,
    status_base_url: str,
    source: dict[str, Any],
) -> dict[str, Any]:
    if decoded.header.get("alg") != EDDSA or decoded.header.get("typ") != VC_JWT_TYP:
        raise falcon.HTTPBadRequest(description="VC-JWT must use EdDSA JWT header")
    vc = decoded.payload.get("vc")
    if not isinstance(vc, dict):
        raise falcon.HTTPBadRequest(description="VC-JWT is missing vc claim")

    verfer = currentVerfer(agent, issuer_aid)
    expected_kid = canonicalizeVerificationMethod(f"{issuer_did}#{verfer.qb64}")
    if (
        canonicalizeVerificationMethod(str(decoded.header.get("kid", "")))
        != expected_kid
    ):
        raise falcon.HTTPBadRequest(
            description="VC-JWT kid does not match issuer did:webs key"
        )
    if not verfer.verify(decoded.signature, decoded.signing_input):
        raise falcon.HTTPBadRequest(description="VC-JWT signature does not verify")

    if decoded.payload.get("iss") != canonicalize_did_webs(issuer_did):
        raise falcon.HTTPBadRequest(description="VC-JWT iss does not match issuer DID")
    if decoded.payload.get("jti") != f"urn:said:{source_credential_said}":
        raise falcon.HTTPBadRequest(
            description="VC-JWT jti does not match source credential SAID"
        )

    expected_vc = transpose_acdc_to_w3c_vc(
        source,
        issuer_did=issuer_did,
        status_base_url=status_base_url,
    )
    comparable_vc = copy.deepcopy(vc)
    comparable_vc.pop("proof", None)
    if comparable_vc != expected_vc:
        raise falcon.HTTPBadRequest(
            description="VC-JWT embedded VC does not match source ACDC projection"
        )
    subject = vc.get("credentialSubject", {})
    if not isinstance(subject, dict):
        raise falcon.HTTPBadRequest(
            description="VC-JWT credentialSubject must be an object"
        )
    if subject.get("id") != canonicalize_did_webs(holder_did):
        raise falcon.HTTPBadRequest(
            description="VC-JWT subject DID does not match holder"
        )
    if subject.get("AID") != holder_aid:
        raise falcon.HTTPBadRequest(
            description="VC-JWT subject AID does not match holder"
        )
    isomer = vc.get("isomer", {})
    if (
        not isinstance(isomer, dict)
        or isomer.get("sourceCredentialSaid") != source_credential_said
    ):
        raise falcon.HTTPBadRequest(
            description="VC-JWT source credential SAID binding is invalid"
        )
    if isomer.get("sourceSchemaSaid") != schema_said or schema_said != source.get("s"):
        raise falcon.HTTPBadRequest(description="VC-JWT schema binding is invalid")
    if vc.get("credentialStatus", {}).get("id") != status_url:
        raise falcon.HTTPBadRequest(
            description="VC-JWT status URL does not match KERIA state"
        )
    if not verify_proof(vc, didMethodForVerfer(expected_kid, verfer)):
        raise falcon.HTTPBadRequest(
            description="VC-JWT embedded Data Integrity proof does not verify"
        )
    return vc


def validateVpJwtForPresentation(
    agent,
    holderName: str,
    holder_did: str,
    selected: W3CHeldCredentialRecord,
    descriptor: dict[str, Any],
    vp_jwt: str,
):
    decoded = decodeJwtOr400(vp_jwt, "VP-JWT")
    if decoded.header.get("alg") != EDDSA or decoded.header.get("typ") != VP_JWT_TYP:
        raise falcon.HTTPBadRequest(description="VP-JWT must use EdDSA JWT header")
    hab = requireHab(agent, holderName)
    verfer = currentVerfer(agent, hab.pre)
    expected_kid = canonicalizeVerificationMethod(f"{holder_did}#{verfer.qb64}")
    if (
        canonicalizeVerificationMethod(str(decoded.header.get("kid", "")))
        != expected_kid
    ):
        raise falcon.HTTPBadRequest(
            description="VP-JWT kid does not match holder did:webs key"
        )
    if not verfer.verify(decoded.signature, decoded.signing_input):
        raise falcon.HTTPBadRequest(description="VP-JWT signature does not verify")

    vp = decoded.payload.get("vp")
    if not isinstance(vp, dict):
        raise falcon.HTTPBadRequest(description="VP-JWT is missing vp claim")
    if decoded.payload.get("iss") != holder_did or vp.get("holder") != holder_did:
        raise falcon.HTTPBadRequest(description="VP-JWT holder binding is invalid")
    bindings = verifierRequestBindings(descriptor)
    if bindings["aud"] and decoded.payload.get("aud") != bindings["aud"]:
        raise falcon.HTTPBadRequest(
            description="VP-JWT aud does not match verifier request"
        )
    if bindings["nonce"] and decoded.payload.get("nonce") != bindings["nonce"]:
        raise falcon.HTTPBadRequest(
            description="VP-JWT nonce does not match verifier request"
        )
    credentials = vp.get("verifiableCredential")
    if not isinstance(credentials, list) or credentials != [selected.vcJwt]:
        raise falcon.HTTPBadRequest(
            description="VP-JWT embedded VC-JWT does not match selected held credential"
        )
    descriptor_said = descriptor.get("credentialSaid") or descriptor.get(
        "sourceCredentialSaid"
    )
    if descriptor_said and descriptor_said != selected.sourceCredentialSaid:
        raise falcon.HTTPBadRequest(
            description="VP-JWT selected credential does not match requested source credential"
        )
    validateHeldCredentialFresh(agent, selected)


def selectPresentationCredential(
    agent, holderName: str, descriptor: dict[str, Any]
) -> W3CHeldCredentialRecord:
    credential_id = descriptor.get("credentialId")
    if isinstance(credential_id, str) and credential_id:
        return requireHeldCredential(agent, holderName, credential_id)

    source_said = descriptor.get("credentialSaid") or descriptor.get(
        "sourceCredentialSaid"
    )
    candidates = [
        record
        for record in uniquePresentationEligibleCredentials(
            listHeldCredentials(agent, holderName)
        )
        if not source_said or record.sourceCredentialSaid == source_said
    ]
    if len(candidates) != 1:
        raise falcon.HTTPBadRequest(
            description="presentation requires exactly one eligible held credential"
        )
    return candidates[0]


def validateHeldCredentialFresh(agent, record: W3CHeldCredentialRecord):
    creder, *_ = cloneCredential(agent, record.sourceCredentialSaid)
    validateIssuanceSource(agent, record.issuerAid, creder)


def currentVerfer(agent, aid: str):
    kever = agent.hby.kevers.get(aid)
    verfers = getattr(kever, "verfers", None)
    if verfers:
        return verfers[0]
    hab = localHabForAid(agent, aid)
    if hab is not None and getattr(hab.kever, "verfers", None):
        return hab.kever.verfers[0]
    raise falcon.HTTPBadRequest(description=f"missing current key state for AID={aid}")


def didMethodForVerfer(method_id: str, verfer) -> dict[str, Any]:
    return {
        "id": method_id,
        "publicKeyMultibase": encode_multibase_base58btc(
            ED25519_MULTIKEY_PREFIX + verfer.raw
        ),
    }


def decodeJwtOr400(token: str, label: str):
    try:
        return decode_jwt(token)
    except Exception as exc:
        raise falcon.HTTPBadRequest(description=f"malformed {label}: {exc}") from exc


def requireEnabled(config: W3CConfig):
    if not config.enabled:
        raise falcon.HTTPNotFound(description="W3C workflows are disabled")


def requireHab(agent, name: str):
    hab = agent.hby.habByName(name)
    if hab is None or hab.pre == agent.agentHab.pre:
        raise falcon.HTTPNotFound(description=f"managed identifier {name} not found")
    return hab


def requirePublishedDws(agent, name: str, aid: str) -> str:
    did = didwebing.publishedDws(agent, aid)
    if did is None:
        raise falcon.HTTPBadRequest(
            description=f"identifier {name} has no ready did:webs DID"
        )
    return canonicalize_did_webs(did)


def requireStatusBaseUrl(config: W3CConfig) -> str:
    if config.status_base_url is None:
        raise falcon.HTTPBadRequest(description="w3c.status_base_url is required")
    return config.status_base_url


def statusReferenceBaseUrl(base_url: str) -> str:
    return f"{base_url.rstrip()}/w3c/vc"


def statusResourceUrl(base_url: str, credential_said: str) -> str:
    return f"{base_url.rstrip()}{W3C_STATUS_ROUTE_PREFIX}/{credential_said}"


def statusReferenceBaseFromStatusUrl(status_url: str, credential_said: str) -> str:
    suffix = f"/status/{credential_said}"
    if not status_url.endswith(suffix):
        raise falcon.HTTPBadRequest(
            description="W3C credential status URL is not bound to source credential SAID"
        )
    return status_url[: -len(suffix)]


def pinStatusProjection(
    *,
    agent,
    name: str,
    aid: str,
    credential_said: str,
    issuer_did: str,
    status_base_url: str,
    now: str,
) -> W3CStatusProjectionRecord:
    existing = agent.adb.w3cstat.get(keys=(credential_said,))
    record = W3CStatusProjectionRecord(
        credentialSaid=credential_said,
        aid=aid,
        name=name,
        issuerDid=canonicalize_did_webs(issuer_did),
        statusBaseUrl=status_base_url,
        created=existing.created if existing is not None else now,
        updated=now,
    )
    agent.adb.w3cstat.pin(keys=(credential_said,), val=record)
    return record


def projectCredentialStatus(agent, record: W3CStatusProjectionRecord) -> dict[str, Any]:
    try:
        creder, *_ = cloneCredential(agent, record.credentialSaid)
    except falcon.HTTPError as exc:
        raise W3CError(
            f"credential {record.credentialSaid} is no longer available"
        ) from exc

    acdc = creder.sad
    registry_said = getattr(creder, "regi", "") or acdc.get("ri")
    if not registry_said:
        raise W3CError(
            f"credential {record.credentialSaid} does not reference a registry"
        )

    tever = registryTever(agent, registry_said)
    if tever is None:
        raise W3CError(
            f"missing TEL registry state for credential {record.credentialSaid}: {registry_said}"
        )

    state = tever.vcState(record.credentialSaid)
    if state is None:
        raise W3CError(
            f"missing accepted TEL state for credential {record.credentialSaid}"
        )

    ilk = telIlk(state)
    if ilk not in ACTIVE_TEL_ILKS | REVOKED_TEL_ILKS:
        raise W3CError(
            f"unsupported TEL state {ilk!r} for credential {record.credentialSaid}"
        )

    return {
        "id": statusResourceUrl(record.statusBaseUrl, record.credentialSaid),
        "type": STATUS_TYPE,
        "credSaid": record.credentialSaid,
        "registry": registry_said,
        "statusRegistryId": registry_said,
        "schemaSaid": acdc.get("s", ""),
        "issuerAid": acdc.get("i", getattr(creder, "issuer", "")),
        "issuer": canonicalize_did_webs(record.issuerDid),
        "revoked": ilk in REVOKED_TEL_ILKS,
        "status": ilk,
        "statusSaid": getattr(state, "d", getattr(state, "said", "")),
        "statusSequence": anchorSequence(state, record.credentialSaid),
        "statusDate": getattr(state, "dt", getattr(state, "date", "")),
        "updatedAt": utcTimestamp(),
    }


def validateIssuanceSource(agent, issuer_aid: str, creder):
    if creder.issuer != issuer_aid:
        raise falcon.HTTPBadRequest(
            description="W3C issuance requires the selected identifier to be the source issuer"
        )
    if creder.schema != VRD_SCHEMA:
        raise falcon.HTTPBadRequest(
            description=f"unsupported W3C issuance schema SAID {creder.schema}"
        )
    state = credentialTelState(agent, creder)
    ilk = telIlk(state) if state is not None else None
    if ilk not in ACTIVE_TEL_ILKS:
        raise falcon.HTTPBadRequest(
            description=f"credential {creder.said} is not active"
        )


def validateHolderDidChain(acdc: dict[str, Any], holder_aid: str, holder_did: str):
    if not holder_aid:
        raise falcon.HTTPBadRequest(
            description="source VRD credential is missing holder AID"
        )
    if not holder_did:
        raise falcon.HTTPBadRequest(
            description="source VRD credential is missing holder did:webs DID"
        )
    if not str(holder_did).startswith("did:webs:"):
        raise falcon.HTTPBadRequest(
            description="source VRD holder DID must be did:webs"
        )
    subject = acdc.get("a", {}) if isinstance(acdc, dict) else {}
    if (
        isinstance(subject, dict)
        and subject.get("i")
        and subject.get("i") != holder_aid
    ):
        raise falcon.HTTPBadRequest(description="source VRD holder AID is incoherent")


def cloneCredential(agent, said: str):
    if agent.rgy.reger.saved.get(keys=(said,)) is None:
        raise falcon.HTTPNotFound(description=f"credential {said} not found")
    return agent.rgy.reger.cloneCred(said=said)


def credentialTelState(agent, creder):
    tever = registryTever(agent, creder.regi)
    return tever.vcState(creder.said) if tever is not None else None


def registryTever(agent, registry_said: str):
    tevers = getattr(agent.rgy, "tevers", None)
    tever = teverFromRegistryCache(tevers, registry_said)
    if tever is not None:
        return tever
    reger = getattr(agent.rgy, "reger", None)
    reger_tevers = getattr(reger, "tevers", None)
    return teverFromRegistryCache(reger_tevers, registry_said)


def teverFromRegistryCache(tevers, registry_said: str):
    if tevers is None:
        return None
    try:
        if registry_said in tevers:
            return tevers[registry_said]
    except KeyError:
        return None
    if hasattr(tevers, "get"):
        return tevers.get(registry_said)
    return None


def telIlk(state) -> str | None:
    return getattr(state, "et", getattr(state, "ilk", None))


def anchorSequence(state, credential_said: str) -> int:
    anchor = getattr(state, "a", None)
    if isinstance(anchor, dict) and "s" in anchor:
        return stateSequenceInt(anchor["s"])
    sequence = getattr(state, "sequence", None)
    if sequence is not None:
        return stateSequenceInt(sequence)
    raise W3CError(f"missing KEL anchor sequence for credential {credential_said}")


def stateSequenceInt(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16)
    return int(value)


def holderAidFromAcdc(acdc: dict[str, Any]) -> str:
    subject = acdc.get("a", {}) if isinstance(acdc, dict) else {}
    return subject.get("i", "") if isinstance(subject, dict) else ""


def holderDidFromAcdc(acdc: dict[str, Any]) -> str:
    subject = acdc.get("a", {}) if isinstance(acdc, dict) else {}
    return subject.get("DID", "") if isinstance(subject, dict) else ""


def heldCredentialByGrant(
    agent, grant_said: str | None
) -> W3CHeldCredentialRecord | None:
    if grant_said is None:
        return None
    for _keys, record in agent.adb.w3cheld.getItemIter():
        if record.grantSaid == grant_said:
            return record
    return None


def heldCredentialByLogicalPayload(
    agent, payload: dict[str, Any]
) -> W3CHeldCredentialRecord | None:
    for _keys, record in agent.adb.w3cheld.getItemIter():
        if (
            record.holderAid == payload["holderAid"]
            and record.issuerAid == payload["issuerAid"]
            and record.sourceCredentialSaid == payload["sourceCredentialSaid"]
            and record.schemaSaid == payload["schemaSaid"]
            and record.vcJwt == payload["vcJwt"]
        ):
            return record
    return None


def uniquePresentationEligibleCredentials(
    records: list[W3CHeldCredentialRecord],
) -> list[W3CHeldCredentialRecord]:
    selected: dict[tuple[str, str, str, str, str], W3CHeldCredentialRecord] = {}
    for record in records:
        if record.state != W3C_HELD_ADMITTED:
            continue
        key = (
            record.holderAid,
            record.issuerAid,
            record.sourceCredentialSaid,
            record.schemaSaid,
            record.vcJwt,
        )
        current = selected.get(key)
        if current is None or (record.updated, record.d) > (current.updated, current.d):
            selected[key] = record
    return list(selected.values())


def verifierOrigin(descriptor: dict[str, Any]) -> str:
    for key in (
        "verifierOrigin",
        "origin",
        "response_uri",
        "submissionEndpoint",
        "client_id",
        "aud",
    ):
        value = descriptor.get(key)
        if isinstance(value, str) and value:
            return value
    raise falcon.HTTPBadRequest(
        description="verifier request descriptor is missing verifier origin"
    )


def verifierRequestBindings(descriptor: dict[str, Any]) -> dict[str, str | None]:
    return {
        "aud": stringValue(descriptor.get("aud"))
        or stringValue(descriptor.get("client_id")),
        "nonce": stringValue(descriptor.get("nonce")),
        "responseUri": stringValue(descriptor.get("response_uri"))
        or stringValue(descriptor.get("submissionEndpoint")),
    }


def descriptorFormats(descriptor: dict[str, Any]) -> list[str]:
    value = descriptor.get("formats") or descriptor.get("requestedFormats")
    if isinstance(value, list):
        return [str(item) for item in value]
    value = descriptor.get("format") or descriptor.get("requestedFormat")
    return [str(value)] if value else []


def postVerifierPresentation(
    endpoint: str, vp_jwt: str, audience: str | None, nonce: str | None
) -> dict[str, Any] | str:
    body = {"token": vp_jwt}
    if audience:
        body["audience"] = audience
    if nonce:
        body["nonce"] = nonce
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as ex:
        raw = ex.read()
        return {"status": ex.code, "body": decodeResponseBody(raw)}
    return decodeResponseBody(raw)


def canonicalizeVerificationMethod(method: str) -> str:
    return canonicalize_did_url(method)


def decodeResponseBody(raw: bytes) -> dict[str, Any] | str:
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return raw.decode("utf-8", errors="replace")


def requireString(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value.strip():
        raise falcon.HTTPBadRequest(description=f"{field} is required")
    return value.strip()


def requireDict(body: dict[str, Any], field: str) -> dict[str, Any]:
    value = body.get(field)
    if not isinstance(value, dict):
        raise falcon.HTTPBadRequest(description=f"{field} is required")
    return value


def requireStringList(body: dict[str, Any], field: str) -> list[str]:
    value = body.get(field)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise falcon.HTTPBadRequest(description=f"{field} is required")
    return [item.strip() for item in value]


def mediaBody(req) -> dict[str, Any]:
    body = req.get_media() or {}
    if not isinstance(body, dict):
        raise falcon.HTTPBadRequest(description="request body must be a JSON object")
    return body


def stringValue(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def withoutVpJwt(body: dict[str, Any]) -> dict[str, Any]:
    copy_body = dict(body)
    copy_body.pop("vpJwt", None)
    return copy_body


def localNameForAid(agent, aid: str) -> str | None:
    hab = localHabForAid(agent, aid)
    return getattr(hab, "name", None) if hab is not None else None


def localHabForAid(agent, aid: str):
    habs = getattr(agent.hby, "habs", {})
    return habs.get(aid) if hasattr(habs, "get") else None


def requireIssuance(agent, issuanceId: str) -> W3CIssuanceRecord:
    record = agent.adb.w3cissu.get(keys=(issuanceId,))
    if record is None:
        raise falcon.HTTPNotFound(description=f"W3C issuance {issuanceId} not found")
    return record


def requireHeldCredential(
    agent, holderName: str, credentialId: str
) -> W3CHeldCredentialRecord:
    record = agent.adb.w3cheld.get(keys=(credentialId,))
    if record is None or record.holderName != holderName:
        raise falcon.HTTPNotFound(
            description=f"W3C credential {credentialId} not found"
        )
    return record


def requireVerifierContact(
    agent, holderName: str, contactId: str
) -> W3CVerifierContactRecord:
    record = agent.adb.w3cvcnt.get(keys=(contactId,))
    if record is None or record.holderName != holderName:
        raise falcon.HTTPNotFound(
            description=f"W3C verifier contact {contactId} not found"
        )
    return record


def requirePresentation(
    agent, holderName: str, presentationId: str
) -> W3CPresentTxRecord:
    record = agent.adb.w3cptx.get(keys=(presentationId,))
    if record is None or record.holderName != holderName:
        raise falcon.HTTPNotFound(
            description=f"W3C presentation {presentationId} not found"
        )
    return record


def issuanceResponse(record: W3CIssuanceRecord) -> dict[str, Any]:
    return {
        "issuanceId": record.d,
        "issuerName": record.issuerName,
        "issuerAid": record.issuerAid,
        "holderAid": record.holderAid,
        "sourceCredentialSaid": record.sourceCredentialSaid,
        "schemaSaid": record.schemaSaid,
        "issuerDid": record.issuerDid,
        "holderDid": record.holderDid,
        "profile": record.profile,
        "state": record.state,
        "created": record.created,
        "updated": record.updated,
        "statusUrl": record.statusUrl,
        "statusBaseUrl": record.statusBaseUrl,
        "sourceCredential": record.sourceCredential,
        "vcJwt": record.vcJwt,
        "decodedVc": record.decodedVc,
        "grantSaid": record.grantSaid,
        "error": record.error,
    }


def heldCredentialResponse(
    record: W3CHeldCredentialRecord, *, detail=False
) -> dict[str, Any]:
    body = {
        "credentialId": record.d,
        "holderName": record.holderName,
        "holderAid": record.holderAid,
        "holderDid": record.holderDid,
        "issuerAid": record.issuerAid,
        "issuerDid": record.issuerDid,
        "sourceCredentialSaid": record.sourceCredentialSaid,
        "schemaSaid": record.schemaSaid,
        "profile": record.profile,
        "statusUrl": record.statusUrl,
        "deliverySource": record.deliverySource,
        "grantSaid": record.grantSaid,
        "state": record.state,
        "imported": record.imported,
        "updated": record.updated,
        "lastValidation": record.lastValidation,
        "validationState": record.validationState,
        "error": record.error,
    }
    if detail:
        body["vcJwt"] = record.vcJwt
        body["decodedVc"] = record.decodedVc
    return body


def verifierContactResponse(record: W3CVerifierContactRecord) -> dict[str, Any]:
    return {
        "contactId": record.d,
        "holderName": record.holderName,
        "holderAid": record.holderAid,
        "origin": record.origin,
        "label": record.label,
        "formats": record.formats,
        "firstSeen": record.created,
        "lastSeen": record.updated,
        "metadata": record.metadata,
    }


def presentationResponse(record: W3CPresentTxRecord) -> dict[str, Any]:
    return {
        "presentationId": record.d,
        "holderName": record.holderName,
        "holderAid": record.holderAid,
        "holderDid": record.holderDid,
        "contactId": record.contactId,
        "requestDescriptor": record.requestDescriptor,
        "state": record.state,
        "nonce": record.nonce,
        "aud": record.aud,
        "requestUri": record.requestUri,
        "responseUri": record.responseUri,
        "matchedCredentialIds": record.matchedCredentialIds,
        "selectedCredentialId": record.selectedCredentialId,
        "vpJwt": record.vpJwt,
        "submissionEndpoint": record.submissionEndpoint,
        "submissionState": record.submissionState,
        "verifierResponse": record.verifierResponse,
        "created": record.created,
        "updated": record.updated,
        "expires": record.expires,
        "error": record.error,
    }


def jsonResponse(rep, status: str, body: dict[str, Any] | list[Any]):
    rep.status = status
    rep.content_type = "application/json"
    rep.data = json.dumps(body).encode("utf-8")


class W3CVcGrantHandler:
    """Peer EXN handler for issuer-signed W3C VC-JWT delivery grants."""

    resource = W3C_GRANT_ROUTE

    def __init__(self, agent, config: W3CConfig):
        self.agent = agent
        self.config = config

    def verify(self, serder, **kwa):
        try:
            validateGrantExnShape(serder)
        except Exception:
            logger.exception("invalid W3C grant EXN %s", getattr(serder, "said", ""))
            return False
        return True

    def handle(self, serder, attachments=None, **kwa):
        payload = validateGrantExnShape(serder)
        holder_name = localNameForAid(self.agent, payload["holderAid"])
        if holder_name is None:
            logger.info(
                "ignoring W3C grant %s for non-local holder %s",
                serder.said,
                payload["holderAid"],
            )
            return
        record = materializeHeldCredentialFromGrant(
            self.agent, self.config, holder_name, payload, serder.said
        )
        notifier = getattr(self.agent, "notifier", None)
        if notifier is not None:
            notifier.add(
                attrs=dict(
                    src=serder.pre,
                    r=self.resource,
                    d=serder.said,
                    issuerAid=payload["issuerAid"],
                    holderAid=payload["holderAid"],
                    sourceCredentialSaid=payload["sourceCredentialSaid"],
                    credentialId=record.d,
                )
            )


class W3CIssuanceCollectionEnd:
    def __init__(self, config: W3CConfig):
        self.config = config

    def on_get(self, req, rep, name):
        records = [
            issuanceResponse(record)
            for record in listIssuances(req.context.agent, name)
        ]
        jsonResponse(rep, falcon.HTTP_200, {"issuances": records})

    def on_post(self, req, rep, name):
        source_said = requireString(mediaBody(req), "sourceCredentialSaid")
        record = startIssuance(req.context.agent, self.config, name, source_said)
        jsonResponse(rep, falcon.HTTP_201, issuanceResponse(record))


class W3CIssuanceResourceEnd:
    def __init__(self, config: W3CConfig):
        self.config = config

    def on_get(self, req, rep, name, issuanceId):
        record = requireIssuance(req.context.agent, issuanceId)
        if record.issuerName != name:
            raise falcon.HTTPNotFound(
                description=f"W3C issuance {issuanceId} not found"
            )
        jsonResponse(rep, falcon.HTTP_200, issuanceResponse(record))


class W3CIssuanceVcJwtEnd:
    def __init__(self, config: W3CConfig):
        self.config = config

    def on_post(self, req, rep, name, issuanceId):
        record = submitIssuanceVcJwt(
            req.context.agent, self.config, name, issuanceId, mediaBody(req)
        )
        jsonResponse(rep, falcon.HTTP_202, issuanceResponse(record))


class W3CIssuanceGrantEnd:
    def __init__(self, config: W3CConfig):
        self.config = config

    def on_post(self, req, rep, name, issuanceId):
        record = submitIssuanceGrant(
            req.context.agent, self.config, name, issuanceId, mediaBody(req)
        )
        jsonResponse(rep, falcon.HTTP_202, issuanceResponse(record))


class W3CHeldCredentialCollectionEnd:
    def __init__(self, config: W3CConfig):
        self.config = config

    def on_get(self, req, rep, name):
        records = [
            heldCredentialResponse(record)
            for record in listHeldCredentials(req.context.agent, name)
        ]
        jsonResponse(rep, falcon.HTTP_200, {"credentials": records})


class W3CHeldCredentialResourceEnd:
    def __init__(self, config: W3CConfig):
        self.config = config

    def on_get(self, req, rep, name, credentialId):
        record = requireHeldCredential(req.context.agent, name, credentialId)
        jsonResponse(rep, falcon.HTTP_200, heldCredentialResponse(record, detail=True))


class W3CVerifierContactCollectionEnd:
    def __init__(self, config: W3CConfig):
        self.config = config

    def on_get(self, req, rep, name):
        contacts = [
            verifierContactResponse(record)
            for record in listVerifierContacts(req.context.agent, name)
        ]
        jsonResponse(rep, falcon.HTTP_200, {"contacts": contacts})

    def on_post(self, req, rep, name):
        record = createVerifierContact(req.context.agent, name, mediaBody(req))
        jsonResponse(rep, falcon.HTTP_201, verifierContactResponse(record))


class W3CVerifierContactResourceEnd:
    def __init__(self, config: W3CConfig):
        self.config = config

    def on_get(self, req, rep, name, contactId):
        record = requireVerifierContact(req.context.agent, name, contactId)
        jsonResponse(rep, falcon.HTTP_200, verifierContactResponse(record))


class W3CPresentationCollectionEnd:
    def __init__(self, config: W3CConfig):
        self.config = config

    def on_get(self, req, rep, name):
        txs = [
            presentationResponse(record)
            for record in listPresentations(req.context.agent, name)
        ]
        jsonResponse(rep, falcon.HTTP_200, {"presentations": txs})

    def on_post(self, req, rep, name):
        tx = submitPresentation(req.context.agent, self.config, name, mediaBody(req))
        jsonResponse(rep, falcon.HTTP_202, presentationResponse(tx))


class W3CPresentationResourceEnd:
    def __init__(self, config: W3CConfig):
        self.config = config

    def on_get(self, req, rep, name, presentationId):
        tx = requirePresentation(req.context.agent, name, presentationId)
        jsonResponse(rep, falcon.HTTP_200, presentationResponse(tx))


class W3CStatusResourceEnd:
    """Public W3C credential status resource backed by live KERIA TEL state."""

    def __init__(self, agency):
        self.agency = agency

    def on_get(self, req, rep, credSaid):
        record = self.agency.adb.w3cstat.get(keys=(credSaid,))
        if record is None:
            raise falcon.HTTPNotFound(
                description=f"W3C credential status {credSaid} not found"
            )
        agent = self.agency.lookup(record.aid)
        if agent is None:
            raise falcon.HTTPConflict(
                description=f"W3C credential status owner {record.aid} is not available"
            )
        try:
            body = projectCredentialStatus(agent, record)
        except W3CError as exc:
            raise falcon.HTTPConflict(description=str(exc)) from exc
        jsonResponse(rep, falcon.HTTP_200, body)
