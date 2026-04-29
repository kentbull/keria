# -*- encoding: utf-8 -*-
"""
KERIA did:webs dynamic asset endpoints.

This module adapts the did:webs artifact-generation behavior used by
``did-webs-resolver`` into KERIA without making KERIA depend on that package at
runtime.

did:webs publication uses the generic agent signaling layer in
``keria.app.streaming`` for live notifications. This module deliberately keeps
only did:webs-specific state: asset generation, durable edge-signing requests,
polling endpoints, and approval payload shape. The ``/didwebs/{aid}`` status
route is a debug-only informational helper; it is not a Signify client workflow
contract and may be removed.
"""

import copy
import json
import math
import os
import urllib.parse
from base64 import urlsafe_b64encode
from dataclasses import asdict, dataclass
from importlib import resources
from typing import Any

import falcon
from hio.base import doing
from hio.help import decking
from keri import kering
from keri.app import habbing, signing
from keri.core import coring, eventing, scheming, serdering
from keri.db import dbing
from keri.help import helping
from keri.vc import proving
from keri.vdr import credentialing, eventing as vdr_eventing, viring

from .. import log_name, ogler
from . import streaming
from ..db.basing import DidWebsPubRecord, DidWebsSetupRecord

logger = ogler.getLogger(log_name)

RESOURCE_PACKAGE = "keria.resources"

DID_JSON = "did.json"
KERI_CESR = "keri.cesr"
CESR_MIME = "application/cesr"

DES_ALIASES_SCHEMA = "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5"
DES_ALIASES_RULES_FILE = "designated-aliases-rules.json"
DES_ALIASES_PUBLIC_SCHEMA_FILE = "designated-aliases-public-schema.json"
DEFAULT_PATH = "dws"
DEFAULT_REGISTRY_PREFIX = "did:webs_designated_aliases"

# states for the did:webs publication of designated aliases self-attestation ACDC
DWS_PUB_RDY = "ready"
DWS_PUB_DELWAIT = "waiting_delegation"
DWS_PUB_REGWAIT = "waiting_registry"
DWS_PUB_ISS = "issuing"
DWS_PUB_SIGREQ = "client_signature_required"
DWS_PUB_DIS = "disabled"
DWS_PUB_ERR = "error"

# states for orchestrating managed AID did:webs designated alias ACDC and backing registry auto-creation
DWS_SIG_ROUTE = "/didwebs/signing/request"
DWS_RDY_ROUTE = "/didwebs/ready"
DWS_REG_CREATE = "didwebs.registry.create"
DWS_DA_ISSUE = "didwebs.designated-alias.issue"
DWS_ACT_CRT_REG = "create_registry"
DWS_ACT_ISS_DA = "issue_designated_alias"
DWS_RDY_EVT = "didwebs.ready"

# did:webs workflow states
DWS_REQ_PND = "pending"
DWS_REQ_CPT = "complete"
DWS_REQ_FLD = "failed"


def _loadJsonResource(filename: str) -> dict[str, Any]:
    with resources.files(RESOURCE_PACKAGE).joinpath(filename).open(
        encoding="utf-8"
    ) as resource:
        return json.load(resource)


DES_ALIASES_RULES = _loadJsonResource(DES_ALIASES_RULES_FILE)
DES_ALIASES_PUBLIC_SCHEMA = _loadJsonResource(DES_ALIASES_PUBLIC_SCHEMA_FILE)


class ArtifactUnavailable(ValueError):
    """Raised when did:webs artifacts are not available for an AID."""


@dataclass
class DidWebsConfig:
    """Runtime configuration for KERIA did:webs asset hosting."""

    enabled: bool = False
    public_base_url: str | None = None
    domain: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None
    meta: bool = False
    registry_name_prefix: str = DEFAULT_REGISTRY_PREFIX
    auto_issue: bool = True


def loadPublicEnds(app, agency, config: DidWebsConfig):
    """Register public did:webs asset routes when did:webs hosting is enabled."""
    if not config.enabled:
        return

    did_path = route_path(config)
    prefix = f"/{did_path}" if did_path else ""
    app.add_route(f"{prefix}/{{aid}}/{DID_JSON}", DIDWebsResourceEnd(agency, config))
    app.add_route(f"{prefix}/{{aid}}/{KERI_CESR}", KeriCesrResourceEnd(agency, config))


def loadAdminEnds(app, config: DidWebsConfig):
    """Register signed admin helper routes for did:webs publication material."""
    if not config.enabled:
        return

    requestsEnd = DIDWebsSigningRequestCollectionEnd(config)
    app.add_route("/didwebs/signing/requests", requestsEnd)
    requestEnd = DIDWebsSigningRequestResourceEnd(config)
    app.add_route("/didwebs/signing/requests/{requestId}", requestEnd)
    statusEnd = DIDWebsStatusEnd(config)
    app.add_route("/didwebs/{aid}", statusEnd)


def configFromSources(
    config: Any, cf=None, httpPort: int | None = None
) -> DidWebsConfig:
    """Merge did:webs config from config file data, explicit config, and env."""
    merged = {}
    if cf is not None:
        data = cf.get() or {}
        if isinstance(data.get("did_webs"), dict):
            merged.update(data["did_webs"])

    if isinstance(config, DidWebsConfig):
        merged.update(asdict(config))
    elif isinstance(config, dict):
        merged.update(config)

    merged.update(configFromEnvironment())
    didwebs = DidWebsConfig(
        enabled=parseBool(merged.get("enabled", False)),
        public_base_url=emptyToNone(merged.get("public_base_url")),
        domain=emptyToNone(merged.get("domain")),
        host=emptyToNone(merged.get("host")),
        port=parseOptionalInt(merged.get("port")),
        path=emptyToNone(merged.get("path")),
        meta=parseBool(merged.get("meta", False)),
        registry_name_prefix=merged.get("registry_name_prefix")
        or DEFAULT_REGISTRY_PREFIX,
        auto_issue=parseBool(merged.get("auto_issue", True)),
    )

    if didwebs.public_base_url is not None:
        parsed = urllib.parse.urlparse(didwebs.public_base_url)
        if didwebs.domain is None:
            didwebs.domain = parsed.hostname
        if didwebs.host is None:
            didwebs.host = parsed.hostname
        if didwebs.port is None:
            didwebs.port = parsed.port
        if didwebs.path is None:
            didwebs.path = parsed.path.strip("/") or None

    if didwebs.host is None:
        didwebs.host = didwebs.domain
    if didwebs.domain is None:
        didwebs.domain = didwebs.host
    if didwebs.port is None and didwebs.public_base_url is None and didwebs.enabled:
        didwebs.port = httpPort
    if didwebs.path is None:
        didwebs.path = DEFAULT_PATH

    return didwebs


def configFromEnvironment() -> dict[str, Any]:
    """Return did:webs settings explicitly present in the environment."""
    env_map = {
        "enabled": "KERIA_DID_WEBS_ENABLED",
        "public_base_url": "KERIA_DID_WEBS_PUBLIC_BASE_URL",
        "domain": "KERIA_DID_WEBS_DOMAIN",
        "host": "KERIA_DID_WEBS_HOST",
        "port": "KERIA_DID_WEBS_PORT",
        "path": "KERIA_DID_WEBS_PATH",
        "meta": "KERIA_DID_WEBS_META",
        "registry_name_prefix": "KERIA_DID_WEBS_REGISTRY_NAME_PREFIX",
        "auto_issue": "KERIA_DID_WEBS_AUTO_ISSUE",
    }
    return {
        key: os.getenv(env)
        for key, env in env_map.items()
        if os.getenv(env) is not None
    }


def parseBool(value: Any) -> bool:
    """Parse flexible bool-ish config values."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).lower() in ("true", "1", "yes", "on")


def parseOptionalInt(value: Any) -> int | None:
    """Parse optional integer config values."""
    if value in (None, ""):
        return None
    return int(value)


def emptyToNone(value: Any) -> str | None:
    """Normalize empty string config values to None."""
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def route_path(config: DidWebsConfig) -> str:
    """Return the URL path prefix used by the public asset routes."""
    return (config.path or "").strip("/")


def registryName(config: DidWebsConfig, aid: str) -> str:
    """Return the dedicated designated-alias registry name for one AID."""
    return f"{config.registry_name_prefix}:{aid}"


def didForAid(config: DidWebsConfig, aid: str) -> str:
    """Build the canonical did:webs DID for one configured AID."""
    domain = config.domain or config.host
    if not domain:
        raise ArtifactUnavailable("did:webs domain or host is not configured")

    did = f"did:webs:{domain}"
    if config.port is not None:
        did += f"%3A{config.port}"

    if route := route_path(config):
        did += ":" + route.replace("/", ":")

    return f"{did}:{aid}"


def assetBaseUrl(config: DidWebsConfig, aid: str) -> str:
    """Build the HTTP base URL for one AID's did:webs assets."""
    if config.public_base_url:
        return f"{config.public_base_url.rstrip('/')}/{aid}"

    host = config.host or config.domain
    if not host:
        raise ArtifactUnavailable("did:webs host or domain is not configured")

    port = f":{config.port}" if config.port is not None else ""
    path = f"/{route_path(config)}" if route_path(config) else ""
    return f"http://{host}{port}{path}/{aid}"


def assetUrls(config: DidWebsConfig, aid: str) -> dict[str, str]:
    """Build did.json and keri.cesr URLs for one AID."""
    base = assetBaseUrl(config, aid)
    return {
        "didJsonUrl": f"{base}/{DID_JSON}",
        "keriCesrUrl": f"{base}/{KERI_CESR}",
    }


def aliasCredentialData(config: DidWebsConfig, aid: str) -> dict:
    """Return suggested designated-alias ACDC subject data for Signify clients."""
    did_webs = didForAid(config, aid)
    return {
        "d": "",
        "dt": helping.nowIso8601(),
        "ids": [
            did_webs.replace("did:webs", "did:web", 1),
            did_webs,
        ],
    }


class DidWebsAgentPublisher(doing.Doer):
    """Self-issue KERIA-owned did:webs designated-alias credentials."""

    def __init__(self, agent, config: DidWebsConfig, tock=1.0):
        self.agent = agent
        self.config = config
        self.state = DWS_PUB_DIS
        self.error = None
        super().__init__(tock=tock)

    def recur(self, tyme, tock=0.0, **opts):
        if not self.config.enabled or not self.config.auto_issue:
            self.state = DWS_PUB_DIS
            return False

        try:
            self.state = ensureAgentDesignatedAlias(self.agent, self.config)
            self.error = None
        except Exception as ex:  # pragma: no cover - defensive runtime logging
            self.state = DWS_PUB_ERR
            self.error = str(ex)
            logger.exception("failed did:webs designated-alias publication")
            return False

        return self.state == DWS_PUB_RDY


class DidWebsAidPublisher(doing.DoDoer):
    """Coordinate edge-signed did:webs publication for Signify-managed AIDs.

    This Doer is intentionally a coordinator, not a signer. KERIA does not own
    Signify-managed AID keys, so it cannot create the registry or issue the
    designated-alias ACDC itself. Instead, it advances durable publication work
    until it reaches a step that needs the edge controller, then creates or
    reuses a durable setup request and queues a transient SSE signal.

    Mental model for maintainers:

    * ``adb.dwspub`` is durable work tracking, keyed by managed AID. It answers
      "which AIDs should this publisher keep advancing?"
    * ``adb.dwsreq`` is durable client work, keyed by request SAID. It answers
      "which edge-signed action should SignifyPy/SignifyTS perform?"
    * ``workCues`` is an in-memory wakeup path. AID creation enqueues the AID so
      a newly created record is processed promptly, but restart recovery comes
      from ``adb.dwspub``.
    * ``signalCues`` is the generic SSE handoff to ``SseBroadcasterDoer``. This
      publisher enqueues intent only; the streaming Doer signs and broadcasts.
    * SSE is only a nudge. Clients must dedupe by request SAID and polling
      ``/didwebs/signing/requests`` remains the durable recovery path.
    """

    SignalInterval = 30.0
    WorkBatchSize = 16

    def __init__(
        self, agent, config: DidWebsConfig, adb=None, signalCues=None, tock=1.0
    ):
        self.agent = agent
        self.config = config
        self.adb = adb if adb is not None else agent.adb
        if signalCues is None:
            raise ValueError("signalCues is required")
        self.signalCues = signalCues
        self.states = {}
        self.errors = {}
        # In-memory throttle keyed by setup request SAID. Active publication
        # work is retried every Doer recurrence, but live SSE should be
        # re-queued only occasionally while the durable request remains pending.
        self.lastSignalTymes = {}
        # Wakeup cues are distinct from durable work. Losing this deck on
        # restart is fine because rehydratePublicationWork reloads adb.dwspub.
        self.workCues = decking.Deck()
        # Active non-ready work keyed by managed AID, with the local alias as
        # the value needed for Signify client request payloads.
        self.active = {}
        # Ready events are transient and should be emitted once per process for
        # each transition observed by this publisher.
        self.readySignaled = set()
        self.rehydratePublicationWork()
        super().__init__(doers=[], tock=tock)

    def recur(self, tyme, deeds=None):
        if not self.config.enabled or not self.config.auto_issue:
            return False

        try:
            self.processWorkCues()
            self.processActive(tyme)
        except Exception as ex:  # pragma: no cover - defensive runtime logging
            self.errors["*"] = str(ex)
            logger.exception("failed managed did:webs publication processing")

        super().recur(tyme=tyme, deeds=deeds)
        return False

    def rehydratePublicationWork(self):
        """Load durable non-ready publication work into the active set.

        This is the restart path. Normal processing should not scan Habery
        aliases every tick; ``adb.dwspub`` is the source of truth for managed
        AIDs that were accepted by KERIA and need did:webs publication work.
        """
        if not self.config.enabled or not self.config.auto_issue:
            return

        for _keys, record in self.adb.dwspub.getItemIter():
            self.states[record.aid] = record.state
            if record.error is not None:
                self.errors[record.aid] = record.error
            if record.state != DWS_PUB_RDY:
                self.active[record.aid] = record.name

    def enqueue(self, name: str, aid: str):
        """Queue one managed AID for prompt publication processing.

        The durable record must already exist in ``adb.dwspub``. This method is
        only a wakeup path used after AID creation; it is not the source of
        truth for publication work.
        """
        self.workCues.append(dict(name=name, aid=aid))

    def processWorkCues(self):
        """Move newly queued durable work into the active repair set."""
        while self.workCues:
            cue = self.workCues.popleft()
            aid = cue["aid"]
            record = self.adb.dwspub.get(keys=(aid,))
            # A stale in-memory cue can outlive a deleted or never-pinned
            # durable record. In that case there is no publication contract to
            # advance.
            if record is None:
                continue
            if record.state == DWS_PUB_RDY:
                self.states[aid] = DWS_PUB_RDY
                self.active.pop(aid, None)
                continue

            name = cue.get("name") or record.name
            self.active[aid] = name

    def processActive(self, tyme):
        """Advance active non-ready publication work in bounded batches.

        ``tyme`` is the hio Doer scheduler time. It is used only for in-process
        SSE re-signal throttling, not for durable protocol state.
        """
        now = 0.0 if tyme is None else tyme
        processed = 0
        for aid, name in list(self.active.items()):
            if processed >= self.WorkBatchSize:
                break

            processed += 1
            self.processPublicationWork(tyme=now, name=name, aid=aid)

    def processPublicationWork(self, tyme, name: str, aid: str):
        """Advance one durable publication record.

        ``ensureManagedDesignatedAlias`` decides the next protocol milestone:
        ready, waiting for registry completion, or client signature required.
        This method persists that projection back into ``adb.dwspub`` and emits
        transient signals when a durable setup request or ready transition is
        observed.
        """
        store = self.adb.dwspub
        record = store.get(keys=(aid,))
        if record is None:
            self.active.pop(aid, None)
            return

        previous = self.states.get(aid)
        try:
            state, request = ensureManagedDesignatedAlias(
                self.agent, self.config, name, aid
            )
            record.name = name
            record.did = didForAid(self.config, aid)
            record.registryName = registryName(self.config, aid)
            record.state = state
            record.updated = helping.nowIso8601()
            record.error = None
            store.pin(keys=(aid,), val=record)
            self.states[aid] = state
            self.errors.pop(aid, None)

            if request is not None:
                # The setup request is durable in adb.dwsreq. This call only
                # decides whether to queue a live SSE nudge for connected
                # clients.
                self.signalRequest(tyme, request)

            if state == DWS_PUB_RDY:
                self.active.pop(aid, None)
                if previous != DWS_PUB_RDY and aid not in self.readySignaled:
                    self.enqueueReady(aid)
                    self.readySignaled.add(aid)
            else:
                self.active[aid] = name
        except Exception as ex:  # pragma: no cover - defensive per-AID recovery
            record.state = DWS_PUB_ERR
            record.updated = helping.nowIso8601()
            record.error = str(ex)
            store.pin(keys=(aid,), val=record)
            self.states[aid] = DWS_PUB_ERR
            self.errors[aid] = str(ex)
            self.active[aid] = name
            logger.exception("failed managed did:webs publication for %s", aid)

    def signalRequest(self, tyme, request: DidWebsSetupRecord):
        """Queue a live setup-request signal immediately, then at a bounded cadence.

        The same durable request may remain pending across many Doer recurrences
        while the edge client is offline, slow, or still submitting signed
        events. Re-signal throttling prevents an active AID from flooding the
        transient SSE channel with the same request every tick. This state is
        deliberately not durable; after restart KERIA may signal again, and the
        client-side dedupe store suppresses duplicate approvals by request SAID.
        """
        last = self.lastSignalTymes.get(request.d)
        if last is not None and tyme - last < self.SignalInterval:
            return

        self.enqueueSigningRequest(request)
        self.lastSignalTymes[request.d] = tyme
        request.lastSignaled = helping.nowIso8601()
        self.adb.dwsreq.pin(keys=(request.d,), val=request)

    def enqueueSigningRequest(self, request: DidWebsSetupRecord):
        """Queue one managed-AID setup request for live SSE clients.

        The queue entry is generic streaming intent. ``SseBroadcasterDoer`` will
        add the agent-signed ``rpy`` envelope before fan-out.
        """
        streaming.enqueueSignedReplyCue(
            self.signalCues,
            event=request.type,
            route=DWS_SIG_ROUTE,
            payload=requestPayload(request),
            event_id=request.d,
        )

    def enqueueReady(self, aid: str):
        """Queue that did:webs artifacts are now publication-complete.

        This is a convenience signal for connected clients. The durable truth is
        still the observable designated-alias ACDC and the ``adb.dwspub`` ready
        state.
        """
        streaming.enqueueSignedReplyCue(
            self.signalCues,
            event=DWS_RDY_EVT,
            route=DWS_RDY_ROUTE,
            payload={
                "aid": aid,
                "did": didForAid(self.config, aid),
                **assetUrls(self.config, aid),
                "timestamp": helping.nowIso8601(),
            },
            event_id=aid,
        )


def trackManagedAidPublication(
    agent, name: str, aid: str, config: DidWebsConfig | None = None
) -> DidWebsPubRecord | None:
    """Idempotently create durable did:webs publication work for one managed AID."""
    config = config if config is not None else getattr(agent, "didWebsConfig", None)
    if config is None or not config.enabled or not config.auto_issue:
        return None
    if aid == agent.agentHab.pre:
        return None

    store = agent.adb.dwspub
    now = helping.nowIso8601()
    record = store.get(keys=(aid,))
    try:
        did = didForAid(config, aid)
        regname = registryName(config, aid)
    except ArtifactUnavailable:
        logger.exception("unable to track did:webs publication work for %s", aid)
        return None

    if record is None:
        record = DidWebsPubRecord(
            aid=aid,
            name=name,
            agent=agent.agentHab.pre,
            did=did,
            registryName=regname,
            state=DWS_PUB_SIGREQ,
            created=now,
            updated=now,
        )
    else:
        record.name = name
        record.agent = agent.agentHab.pre
        record.did = did
        record.registryName = regname
        record.updated = now

    store.pin(keys=(aid,), val=record)

    publisher = getattr(agent, "didWebsManagedPublisher", None)
    if publisher is not None:
        publisher.enqueue(name=name, aid=aid)

    return record


def ensureManagedDesignatedAlias(
    agent, config: DidWebsConfig, name: str, aid: str
) -> tuple[str, DidWebsSetupRecord | None]:
    """Advance edge-signing coordination for one Signify-managed AID."""
    did = didForAid(config, aid)
    if matchingDesignatedAliases(agent.hby, agent.rgy, aid, did):
        completeSigningRequests(agent, aid)
        return DWS_PUB_RDY, None

    pinDesignatedAliasesSchema(agent.hby)
    processPublicationEscrows(agent)

    registry = agent.rgy.registryByName(registryName(config, aid))
    if registry is None:
        request = ensureSigningRequest(
            agent=agent,
            config=config,
            name=name,
            aid=aid,
            request_type=DWS_REG_CREATE,
            action=DWS_ACT_CRT_REG,
        )
        return DWS_PUB_SIGREQ, request

    if not registryComplete(agent, registry):
        processPublicationEscrows(agent)
        return DWS_PUB_REGWAIT, None

    completeSigningRequests(agent, aid, action=DWS_ACT_CRT_REG)

    if findDesignatedAliasCredential(agent, config, aid, registry) is not None:
        processPublicationEscrows(agent)
        if matchingDesignatedAliases(agent.hby, agent.rgy, aid, did):
            completeSigningRequests(agent, aid)
            return DWS_PUB_RDY, None
        return DWS_PUB_ISS, None

    request = ensureSigningRequest(
        agent=agent,
        config=config,
        name=name,
        aid=aid,
        request_type=DWS_DA_ISSUE,
        action=DWS_ACT_ISS_DA,
        registry_id=registry.regk,
    )
    return DWS_PUB_SIGREQ, request


def ensureSigningRequest(
    *,
    agent,
    config: DidWebsConfig,
    name: str,
    aid: str,
    request_type: str,
    action: str,
    registry_id: str | None = None,
) -> DidWebsSetupRecord:
    """Create or reuse one durable managed-AID signing request."""
    existing = findSigningRequest(
        agent, aid=aid, action=action, states={DWS_REQ_PND, DWS_REQ_FLD}
    )
    if existing is not None:
        return existing

    did = didForAid(config, aid)
    payload = {
        "d": "",
        "type": request_type,
        "action": action,
        "agent": agent.agentHab.pre,
        "aid": aid,
        "name": name,
        "did": did,
        "registryName": registryName(config, aid),
        "schema": DES_ALIASES_SCHEMA,
        "credentialData": aliasCredentialData(config, aid),
        "rules": copy.deepcopy(DES_ALIASES_RULES),
        **assetUrls(config, aid),
        "dt": helping.nowIso8601(),
    }
    if registry_id is not None:
        payload["registryId"] = registry_id
    _saider, payload = coring.Saider.saidify(payload)
    record = DidWebsSetupRecord(**payload)
    agent.adb.dwsreq.put(keys=(record.d,), val=record)
    return record


def iterSigningRequests(agent, aid: str | None = None, states: set[str] | None = None):
    """Iterate durable managed-AID signing requests, optionally filtered."""
    store = agent.adb.dwsreq
    for _keys, request in store.getItemIter():
        if aid is not None and request.aid != aid:
            continue
        if states is not None and request.state not in states:
            continue
        yield request


def findSigningRequest(
    agent, aid: str, action: str | None = None, states: set[str] | None = None
):
    """Return the first matching durable signing request for an AID."""
    for request in iterSigningRequests(agent, aid=aid, states=states):
        if action is None or request.action == action:
            return request
    return None


def completeSigningRequests(agent, aid: str, action: str | None = None):
    """Mark pending signing requests complete once the requested state appears."""
    store = agent.adb.dwsreq
    for request in iterSigningRequests(agent, aid=aid, states={DWS_REQ_PND}):
        if action is not None and request.action != action:
            continue
        request.state = DWS_REQ_CPT
        store.pin(keys=(request.d,), val=request)


def requestPayload(request: DidWebsSetupRecord) -> dict:
    """Return the immutable signed payload from a durable request record."""
    payload = {
        "d": request.d,
        "type": request.type,
        "action": request.action,
        "agent": request.agent,
        "aid": request.aid,
        "name": request.name,
        "did": request.did,
        "registryName": request.registryName,
        "schema": request.schema,
        "credentialData": copy.deepcopy(request.credentialData),
        "rules": copy.deepcopy(request.rules),
        "didJsonUrl": request.didJsonUrl,
        "keriCesrUrl": request.keriCesrUrl,
        "dt": request.dt,
    }
    if request.registryId is not None:
        payload["registryId"] = request.registryId
    return payload


def signingRequestEnvelope(agent, request: DidWebsSetupRecord) -> dict:
    """Create a KERI rpy envelope signed by the KERIA agent AID."""
    return streaming.signedReplyEnvelope(
        agent, DWS_SIG_ROUTE, requestPayload(request)
    )


def signingRequestResponse(agent, request: DidWebsSetupRecord) -> dict:
    """Return one durable request with its current signed envelope."""
    return {
        **requestPayload(request),
        "state": request.state,
        "lastSignaled": request.lastSignaled,
        "error": request.error,
        "envelope": signingRequestEnvelope(agent, request),
    }


def signingRequestSummary(agent, aid: str) -> dict | None:
    """Return compact status data for the first active signing request."""
    request = findSigningRequest(agent, aid=aid, states={DWS_REQ_PND, DWS_REQ_FLD})
    if request is None:
        return None
    return {
        "id": request.d,
        "type": request.type,
        "action": request.action,
        "state": request.state,
        "lastSignaled": request.lastSignaled,
        "error": request.error,
    }


def ensureAgentDesignatedAlias(agent, config: DidWebsConfig) -> str:
    """Advance automatic designated-alias issuance for the KERIA agent AID."""
    aid = agent.agentHab.pre
    did = didForAid(config, aid)
    if matchingDesignatedAliases(agent.hby, agent.rgy, aid, did):
        return DWS_PUB_RDY

    if not hasDelegationSourceSeal(agent.hby, agent.agentHab):
        return DWS_PUB_DELWAIT

    pinDesignatedAliasesSchema(agent.hby)
    processPublicationEscrows(agent)

    registry = agent.rgy.registryByName(registryName(config, aid))
    if registry is None:
        registry = createDesignatedAliasesRegistry(agent, config, aid)
        processPublicationEscrows(agent)
        if not registryComplete(agent, registry):
            return DWS_PUB_REGWAIT

    if not registryComplete(agent, registry):
        processPublicationEscrows(agent)
        return DWS_PUB_REGWAIT

    if findDesignatedAliasCredential(agent, config, aid, registry) is not None:
        processPublicationEscrows(agent)
        if matchingDesignatedAliases(agent.hby, agent.rgy, aid, did):
            return DWS_PUB_RDY
        return DWS_PUB_ISS

    issueDACred(agent, config, aid, registry)
    processPublicationEscrows(agent)
    if matchingDesignatedAliases(agent.hby, agent.rgy, aid, did):
        return DWS_PUB_RDY

    return DWS_PUB_ISS


def pinDesignatedAliasesSchema(hby: habbing.Habery):
    """Pin the embedded public designated-alias schema into an agent Habery."""
    schemer = hby.db.schema.get(keys=(DES_ALIASES_SCHEMA,))
    if schemer is not None:
        return schemer

    schemer = scheming.Schemer(sed=copy.deepcopy(DES_ALIASES_PUBLIC_SCHEMA))
    if schemer.said != DES_ALIASES_SCHEMA:
        raise kering.ConfigurationError(
            f"embedded designated-alias schema SAID mismatch: {schemer.said}"
        )

    hby.db.schema.pin(schemer.said, schemer)
    return schemer


def hasDelegationSourceSeal(hby: habbing.Habery, hab: habbing.Hab) -> bool:
    """Return True when a delegated AID has its source seal available."""
    if getattr(hab, "delpre", None) is None:
        return True

    prefixer = coring.Prefixer(qb64=hab.pre)
    dig = hby.db.getKeLast(key=dbing.snKey(pre=prefixer.qb64b, sn=0))
    if dig is None:
        return False

    dgkey = dbing.dgKey(pre=prefixer.qb64b, dig=bytes(dig))
    return hby.db.getAes(dgkey) is not None


def createDesignatedAliasesRegistry(agent, config: DidWebsConfig, aid: str):
    """Create and anchor the dedicated designated-alias registry for an AID."""
    registry = agent.rgy.makeRegistry(
        name=registryName(config, aid), prefix=aid, noBackers=True
    )
    seal = eventing.SealEvent(registry.regk, "0", registry.regd)._asdict()
    agent.agentHab.interact(data=[seal])
    agent.registrar.incept(agent.agentHab, registry)
    return registry


def registryComplete(agent, registry) -> bool:
    """Return True when the registry inception TEL event is complete."""
    return agent.registrar.complete(pre=registry.regk, sn=0)


def findDesignatedAliasCredential(agent, config: DidWebsConfig, aid: str, registry):
    """Find any stored or in-progress matching designated-alias credential."""
    did = didForAid(config, aid)
    wanted = {did, did.replace("did:webs", "did:web", 1)}

    for (_said,), creder in agent.rgy.reger.creds.getItemIter():
        if creder.issuer != aid:
            continue
        if creder.schema != DES_ALIASES_SCHEMA:
            continue
        if creder.regi != registry.regk:
            continue
        aliases = set(creder.sad.get("a", {}).get("ids", []))
        if wanted.issubset(aliases):
            return creder

    return None


def issueDACred(agent, config: DidWebsConfig, aid: str, registry):
    """Issue and anchor one self-issued designated-alias ACDC."""
    data = aliasCredentialData(config, aid)
    creder = proving.credential(
        issuer=aid,
        schema=DES_ALIASES_SCHEMA,
        data=data,
        status=registry.regk,
        rules=DES_ALIASES_RULES,
    )
    agent.credentialer.validate(creder)

    if registry.noBackers:
        iserder = vdr_eventing.issue(
            vcdig=creder.said, regk=registry.regk, dt=data["dt"]
        )
    else:
        iserder = vdr_eventing.backerIssue(
            vcdig=creder.said,
            regk=registry.regk,
            regsn=registry.regi,
            regd=registry.regser.said,
            dt=data["dt"],
        )

    rseq = coring.Seqner(snh=iserder.ked["s"])
    seal = eventing.SealEvent(iserder.pre, rseq.snh, iserder.said)._asdict()
    anc = agent.agentHab.interact(data=[seal])
    aserder = serdering.SerderKERI(raw=bytes(anc))

    agent.registrar.issue(registry.regk, iserder, aserder)
    agent.credentialer.issue(creder=creder, serder=iserder)


def processPublicationEscrows(agent):
    """Run the existing registry and credential escrows needed by publication."""
    agent.rgy.processEscrows()
    agent.registrar.processEscrows()
    agent.credentialer.processEscrows()
    agent.verifier.processEscrows()


def publicationState(agent, config: DidWebsConfig, aid: str) -> str:
    """Return a debug-only projection of did:webs publication state.

    WARNING: Can be removed at any time and will be removed soon. Do not rely on this.
    """
    if not config.enabled:
        return DWS_PUB_DIS

    did = didForAid(config, aid)
    if matchingDesignatedAliases(agent.hby, agent.rgy, aid, did):
        return DWS_PUB_RDY

    if aid == agent.agentHab.pre:
        publisher = getattr(agent, "didWebsAgentPublisher", None)
        if not config.auto_issue:
            return DWS_PUB_DIS
        if publisher is not None:
            return publisher.state
        return DWS_PUB_ISS

    managedPublisher = getattr(agent, "didWebsManagedPublisher", None)
    if managedPublisher is not None and aid in managedPublisher.errors:
        return DWS_PUB_ERR
    if not config.auto_issue:
        return DWS_PUB_DIS

    record = agent.adb.dwspub.get(keys=(aid,))
    if record is not None:
        if record.error is not None:
            return DWS_PUB_ERR
        return record.state

    if signingRequestSummary(agent, aid) is not None:
        return DWS_PUB_SIGREQ

    return DWS_PUB_DIS


def statusForAid(agent, config: DidWebsConfig, aid: str) -> dict:
    """Return debug-only publication material and availability for one local AID.

    This is an informational maintainer endpoint. Signify clients should use
    the durable signing-request endpoints and generic signal stream for
    did:webs orchestration.
    """
    if not isLocalAid(agent, aid):
        raise falcon.HTTPNotFound(description=f"{aid} is not a local KERIA identifier")

    did = didForAid(config, aid)
    alias_available = bool(matchingDesignatedAliases(agent.hby, agent.rgy, aid, did))
    optional_missing = [] if alias_available else ["designated_alias_acdc"]

    urls = assetUrls(config, aid)
    return {
        "debug": True,
        "informational": True,
        "notice": (
            "Debug-only informational endpoint; not a Signify client workflow "
            "contract and may be removed."
        ),
        "aid": aid,
        "did": did,
        **urls,
        "available": True,
        "missing": [],
        "designatedAliasAvailable": alias_available,
        "optionalMissing": optional_missing,
        "publicationState": publicationState(agent, config, aid),
        "registryName": registryName(config, aid),
        "schema": DES_ALIASES_SCHEMA,
        "credentialData": aliasCredentialData(config, aid),
        "rules": copy.deepcopy(DES_ALIASES_RULES),
        "signingRequest": signingRequestSummary(agent, aid),
    }


def isLocalAid(agent, aid: str) -> bool:
    """Return True when an AID is locally represented in this KERIA agent."""
    return aid in agent.hby.habs and aid in agent.hby.kevers


def requireAvailable(agent, config: DidWebsConfig, aid: str):
    """Return the DID when did:webs assets are available, otherwise raise."""
    if not isLocalAid(agent, aid):
        raise ArtifactUnavailable(f"{aid} is not a local KERIA identifier")

    return didForAid(config, aid)


def matchingDesignatedAliases(
    hby: habbing.Habery, rgy: credentialing.Regery, aid: str, did: str
) -> list[str]:
    """Return designated aliases that match the configured DID."""
    wanted = {did, did.replace("did:webs", "did:web", 1)}
    aliases = genDesignatedAliases(hby, rgy, aid)
    return [alias for alias in aliases if alias in wanted]


def genDesignatedAliases(
    hby: habbing.Habery, rgy: credentialing.Regery, aid: str
) -> list[str]:
    """Return non-revoked self-issued designated aliases for one AID."""
    reger = rgy.reger
    issued = reger.issus.get(keys=aid) or []
    by_schema = reger.schms.get(keys=DES_ALIASES_SCHEMA.encode("utf-8")) or []
    schema_saids = {saider.qb64 for saider in by_schema}
    saids = [saider for saider in issued if saider.qb64 in schema_saids]
    if not saids:
        return []

    aliases = []
    for said in saids:
        try:
            creder, *_ = reger.cloneCred(said=said.qb64)
        except kering.MissingEntryError:
            continue

        tever = rgy.tevers.get(creder.regi)
        state = tever.vcState(creder.said) if tever is not None else None
        if state is None or state.et not in ("iss", "bis"):
            continue

        aliases.extend(creder.sad.get("a", {}).get("ids", []))

    return aliases


def didJson(agent, config: DidWebsConfig, aid: str) -> dict:
    """Generate one did.json body for an available local AID."""
    did = requireAvailable(agent, config, aid)
    diddoc = generateDidDoc(agent.hby, agent.rgy, did=did, aid=aid, meta=config.meta)
    return toDidWeb(diddoc, meta=config.meta)


def keriCesr(agent, config: DidWebsConfig, aid: str) -> bytearray:
    """Generate one keri.cesr body for an available local AID."""
    requireAvailable(agent, config, aid)
    hab = agent.hby.habs[aid]
    return genKeriCesr(hab, agent.rgy.reger, aid)


def generateDidDoc(
    hby: habbing.Habery,
    rgy: credentialing.Regery,
    did: str,
    aid: str,
    meta: bool = False,
) -> dict:
    """Generate a did:webs DID document from local KERI state."""
    parsed_aid = parseDidWebs(did)["aid"]
    if parsed_aid != aid:
        raise ValueError(f"{did} does not contain AID {aid}")

    if aid not in hby.kevers:
        raise ArtifactUnavailable(f"unknown AID {aid}")

    hab = hby.habs.get(aid)
    kever = hby.kevers[aid]
    verification_methods = generateVerificationMethods(
        kever.verfers, kever.tholder.thold, did, aid
    )
    service_endpoints = genServiceEndpoints(hby, hab, kever, aid)
    equivalent_ids, aka_ids = getEquivalentAndAkaIds(did, aid, hby, rgy)
    did_doc = {
        "id": did,
        "verificationMethod": verification_methods,
        "service": service_endpoints,
        "alsoKnownAs": aka_ids,
    }

    if not meta:
        return did_doc

    return {
        "didDocument": did_doc,
        "didResolutionMetadata": {
            "contentType": "application/did+json",
            "retrieved": helping.nowUTC().strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "didDocumentMetadata": {
            "witnesses": getWitnessList(hby.db, kever),
            "versionId": f"{kever.sner.num}",
            "equivalentId": equivalent_ids,
        },
    }


def parseDidWebs(did: str) -> dict[str, str | None]:
    """Parse the subset of did:webs DIDs KERIA generates."""
    if not did.startswith("did:webs:"):
        raise ValueError(f"{did} is not a did:webs DID")

    body = did[len("did:webs:") :]
    query = None
    if "?" in body:
        body, query = body.split("?", 1)
        query = f"?{query}"

    segments = body.split(":")
    if len(segments) < 2:
        raise ValueError(f"{did} is missing an AID")

    domain_port = segments[0]
    path_segments = segments[1:-1]
    aid = segments[-1]
    domain, port = (
        (domain_port.split("%3A", 1) + [None])[:2]
        if "%3A" in domain_port
        else (domain_port.split("%3a", 1) + [None])[:2]
        if "%3a" in domain_port
        else (domain_port, None)
    )
    coring.Prefixer(qb64=aid)
    return {
        "domain": domain,
        "port": port,
        "path": ":".join(path_segments) or None,
        "aid": aid,
        "query": query,
    }


def generateVerificationMethods(verfers, thold, did: str, aid: str) -> list[dict]:
    """Generate JWK verification methods from the latest key state."""
    vms = []
    for verfer in verfers:
        kid = verfer.qb64
        x = urlsafe_b64encode(verfer.raw).rstrip(b"=").decode("utf-8")
        vms.append(
            {
                "id": f"#{kid}",
                "type": "JsonWebKey",
                "controller": stripQuery(did),
                "publicKeyJwk": {"kid": kid, "kty": "OKP", "crv": "Ed25519", "x": x},
            }
        )

    if isinstance(thold, int) and thold > 1:
        vms.append(
            {
                "id": f"#{aid}",
                "type": "ConditionalProof2022",
                "controller": stripQuery(did),
                "threshold": thold,
                "conditionThreshold": [vm["id"] for vm in vms],
            }
        )
    elif isinstance(thold, list):
        vms.append(generateWeightedThresholdProof(thold, verfers, vms, did, aid))

    return vms


def generateWeightedThresholdProof(thold, verfers, vms, did: str, aid: str) -> dict:
    """Generate a ConditionalProof2022 method for weighted threshold key states."""
    lcd = int(math.lcm(*[fr.denominator for fr in thold[0]]))
    threshold = float(lcd / 2)
    numerators = [int(fr.numerator * lcd / fr.denominator) for fr in thold[0]]
    conditions = []
    for idx, _verfer in enumerate(verfers):
        conditions.append({"condition": vms[idx]["id"], "weight": numerators[idx]})

    return {
        "id": f"#{aid}",
        "type": "ConditionalProof2022",
        "controller": stripQuery(did),
        "threshold": threshold,
        "conditionWeightedThreshold": conditions,
    }


def stripQuery(did: str) -> str:
    """Remove DID URL query parameters for controller fields."""
    return did.split("?", 1)[0]


def genServiceEndpoints(
    hby: habbing.Habery, hab: habbing.Hab | None, kever, aid: str
) -> list[dict]:
    """Generate DID service endpoints from endpoint-role and loc-scheme state."""
    serv_ends = []
    serv_ends.extend(genWitnessServiceEndpoints(hby, kever))

    if hab is not None and getattr(hab, "delpre", None) is not None:
        serv_ends.extend(genDelegationService(hby=hby, pre=hab.pre, delpre=hab.delpre))

    return serv_ends


def genWitnessServiceEndpoints(hby: habbing.Habery, kever) -> list[dict]:
    """Generate resolver-reconstructable witness service endpoints."""
    serv_ends = []
    for eid in kever.wits:
        urls = {}
        for (_, scheme), loc in hby.db.locs.getItemIter(keys=(eid,)):
            if loc.url:
                urls[scheme] = loc.url
        if urls:
            serv_ends.append(
                {
                    "id": f"#{eid}/{kering.Roles.witness}",
                    "type": kering.Roles.witness,
                    "serviceEndpoint": urls,
                }
            )
    return serv_ends


def genDelegationService(hby: habbing.Habery, pre: str, delpre: str) -> list[dict]:
    """Return delegation service material when the delegator OOBI is known."""
    seal = {"i": pre, "s": "0", "d": pre}
    dserder = hby.db.fetchLastSealingEventByEventSeal(pre=delpre, seal=seal)
    if dserder is None:
        return []

    del_oobi = getResolvedOobi(hby=hby, pre=delpre)
    if del_oobi is None:
        return []

    return [
        {
            "id": dserder.sad["a"][0]["d"],
            "type": "DelegatorOOBI",
            "serviceEndpoint": del_oobi,
        }
    ]


def getResolvedOobi(hby: habbing.Habery, pre: str) -> str | None:
    """Return a previously resolved OOBI for an AID, if any."""
    for (oobi,), obr in hby.db.roobi.getItemIter():
        if obr.cid == pre:
            return oobi
    return None


def getEquivalentAndAkaIds(
    did: str, aid: str, hby: habbing.Habery, rgy: credentialing.Regery
) -> tuple[list[str], list[str]]:
    """Return equivalentId and alsoKnownAs values for a DID document."""
    equivalent_ids = []
    aka_ids = []
    for alias in genDesignatedAliases(hby, rgy, aid):
        if alias.startswith("did:webs"):
            equivalent_ids.append(alias)
        aka_ids.append(alias)
    return equivalent_ids, aka_ids


def getWitnessList(baser, kever) -> list[dict]:
    """Return witness metadata for DID resolution results."""
    witness_list = []
    for idx, eid in enumerate(kever.wits):
        for (_, scheme), loc in baser.locs.getItemIter(keys=(eid,)):
            witness_list.append({"idx": str(idx), "scheme": scheme, "url": loc.url})
    return witness_list


def toDidWeb(diddoc: dict, meta: bool = False) -> dict:
    """Convert did:webs method identifiers to did:web for did.json."""
    diddoc = copy.deepcopy(diddoc)
    if meta:
        diddoc["didDocument"] = diddocToDidWeb(diddoc["didDocument"])
        return diddoc
    return diddocToDidWeb(diddoc)


def diddocToDidWeb(diddoc: dict) -> dict:
    """Convert method identifiers in one DID document to did:web."""
    diddoc["id"] = diddoc["id"].replace("did:webs", "did:web", 1)
    for verification_method in diddoc["verificationMethod"]:
        verification_method["controller"] = verification_method["controller"].replace(
            "did:webs", "did:web", 1
        )
    return diddoc


def genKeriCesr(hab: habbing.Hab, reger: viring.Reger, aid: str) -> bytearray:
    """Load KEL, loc-scheme, TEL, and ACDC CESR bytes for one AID."""
    keri_cesr = bytearray()
    keri_cesr.extend(hab.replay(pre=aid))
    keri_cesr.extend(genLocSchemesCesr(hab, aid))
    keri_cesr.extend(genDesignatedAliasesCesr(hab, reger, aid))
    return keri_cesr


def genLocSchemesCesr(
    hab: habbing.Hab, aid: str, role: str | None = None, scheme: str = ""
) -> bytearray:
    """Return location scheme and endpoint role reply CESR bytes for one AID."""
    kever = hab.kevers[aid]
    msgs = bytearray()
    if not role or role == kering.Roles.witness:
        for eid in kever.wits:
            msgs.extend(hab.loadLocScheme(eid=eid, scheme=scheme) or bytearray())
            msgs.extend(
                hab.loadEndRole(cid=eid, eid=eid, role=kering.Roles.controller)
                or bytearray()
            )
    if not role or role == kering.Roles.agent:
        for (_, erole, eid), _ in hab.db.ends.getItemIter(
            keys=(aid, kering.Roles.agent)
        ):
            msgs.extend(hab.loadLocScheme(eid=eid, scheme=scheme) or bytearray())
            msgs.extend(hab.loadEndRole(cid=aid, eid=eid, role=erole) or bytearray())
    if not role or role == kering.Roles.mailbox:
        for (_, erole, eid), _ in hab.db.ends.getItemIter(
            keys=(aid, kering.Roles.mailbox)
        ):
            msgs.extend(hab.loadLocScheme(eid=eid) or bytearray())
            msgs.extend(hab.loadEndRole(cid=aid, eid=eid, role=erole) or bytearray())
    return msgs


def genDesignatedAliasesCesr(
    hab: habbing.Hab, reger: viring.Reger, aid: str
) -> bytearray:
    """Return TEL and ACDC bytes for self-issued designated-alias credentials."""
    local_creds = getSelfIssuedAcdcs(aid, reger)
    cesr_bytes = bytearray()
    for cred in local_creds:
        creder, *_ = reger.cloneCred(said=cred.qb64)
        cesr_bytes.extend(addCredCesrBytes(creder, hab, reger))
    return cesr_bytes


def getSelfIssuedAcdcs(aid: str, reger: viring.Reger) -> list[coring.Saider]:
    """Get self-issued ACDCs filtered to the designated-alias schema."""
    creds_issued = reger.issus.get(keys=aid) or []
    creds_by_schema = reger.schms.get(keys=DES_ALIASES_SCHEMA.encode("utf-8")) or []
    schema_saids = {cred_by_schm.qb64 for cred_by_schm in creds_by_schema}
    return [
        cred_issued for cred_issued in creds_issued if cred_issued.qb64 in schema_saids
    ]


def addCredCesrBytes(
    creder: serdering.SerderACDC, hab: habbing.Hab, reger: viring.Reger
) -> bytearray:
    """Add one ACDC credential and its TEL bytes to the CESR stream."""
    creder_bytes = bytearray()
    creder_bytes.extend(genTelCesr(reger, creder.regi))
    creder_bytes.extend(genTelCesr(reger, creder.said))
    creder_bytes.extend(genAcdcCesr(hab, reger, creder))
    return creder_bytes


def genTelCesr(reger: viring.Reger, evt_pre: str) -> bytearray:
    """Return TEL event CESR bytes for one registry or credential prefix."""
    msgs = bytearray()
    for msg in reger.clonePreIter(pre=evt_pre):
        msgs.extend(msg)
    return msgs


def genAcdcCesr(
    hab: habbing.Hab, reger: viring.Reger, creder: serdering.SerderACDC
) -> bytearray:
    """Return one ACDC with signatures and anchor attachments as CESR bytes."""
    prefixer, seqner, saider = reger.cancs.get(keys=(creder.said,))
    return bytearray(signing.serialize(creder, prefixer, seqner, saider))


class DIDWebsResourceEnd:
    """Public did.json endpoint for locally managed KERIA AIDs."""

    def __init__(self, agency, config: DidWebsConfig):
        self.agency = agency
        self.config = config

    def on_get(self, req, rep, aid):
        agent = self.agency.lookup(aid)
        if agent is None:
            raise falcon.HTTPNotFound(description=f"unknown destination AID {aid}")

        try:
            rep.status = falcon.HTTP_200
            rep.content_type = "application/json"
            rep.data = json.dumps(didJson(agent, self.config, aid), indent=2).encode(
                "utf-8"
            )
        except ArtifactUnavailable as ex:
            raise falcon.HTTPNotFound(description=str(ex))


class KeriCesrResourceEnd:
    """Public keri.cesr endpoint for locally managed KERIA AIDs."""

    def __init__(self, agency, config: DidWebsConfig):
        self.agency = agency
        self.config = config

    def on_get(self, req, rep, aid):
        agent = self.agency.lookup(aid)
        if agent is None:
            raise falcon.HTTPNotFound(description=f"unknown destination AID {aid}")

        try:
            rep.status = falcon.HTTP_200
            rep.content_type = CESR_MIME
            rep.data = bytes(keriCesr(agent, self.config, aid))
        except ArtifactUnavailable as ex:
            raise falcon.HTTPNotFound(description=str(ex))


class DIDWebsStatusEnd:
    """Debug-only signed admin helper for did:webs publication material.

    This route is informational maintainer surface, not a Signify client
    workflow contract. It may be removed once end-to-end VC-JWT presentation to
    a W3C verifier no longer needs local inspection.
    """

    def __init__(self, config: DidWebsConfig):
        self.config = config

    def on_get(self, req, rep, aid):
        agent = req.context.agent
        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(statusForAid(agent, self.config, aid)).encode("utf-8")


class DIDWebsSigningRequestCollectionEnd:
    """Signed admin polling endpoint for did:webs edge-signing requests."""

    def __init__(self, config: DidWebsConfig):
        self.config = config

    def on_get(self, req, rep):
        agent = req.context.agent
        aid = req.get_param("aid")
        include_complete = parseBool(req.get_param("includeComplete", False))
        states = None if include_complete else {DWS_REQ_PND, DWS_REQ_FLD}
        requests = [
            signingRequestResponse(agent, request)
            for request in iterSigningRequests(agent, aid=aid, states=states)
        ]
        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps({"requests": requests}).encode("utf-8")


class DIDWebsSigningRequestResourceEnd:
    """Signed admin polling endpoint for one did:webs edge-signing request."""

    def __init__(self, config: DidWebsConfig):
        self.config = config

    def on_get(self, req, rep, requestId):
        agent = req.context.agent
        request = agent.adb.dwsreq.get(keys=(requestId,))
        if request is None:
            raise falcon.HTTPNotFound(description=f"unknown did:webs request {requestId}")

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(signingRequestResponse(agent, request)).encode("utf-8")
