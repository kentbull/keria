# -*- encoding: utf-8 -*-
"""
KERIA did:webs dynamic asset endpoints.

This module adapts the did:webs artifact-generation behavior used by
``did-webs-resolver`` into KERIA without making KERIA depend on that package at
runtime.
"""

import copy
import json
import math
import os
import urllib.parse
from base64 import urlsafe_b64encode
from dataclasses import asdict, dataclass
from typing import Any

import falcon
from keri import kering
from keri.app import habbing, signing
from keri.core import coring, serdering
from keri.help import helping
from keri.vdr import credentialing, viring

from .. import log_name, ogler

logger = ogler.getLogger(log_name)

DID_JSON = "did.json"
KERI_CESR = "keri.cesr"
CESR_MIME = "application/cesr"

DES_ALIASES_SCHEMA = "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5"
DEFAULT_PATH = "dws"
DEFAULT_REGISTRY_PREFIX = "did:webs_designated_aliases"

DES_ALIASES_RULES = {
    "d": "EEVTx0jLLZDQq8a5bXrXgVP0JDP7j8iDym9Avfo8luLw",
    "aliasDesignation": {
        "l": "The issuer of this ACDC designates the identifiers in the ids field as the only allowed namespaced aliases of the issuer's AID."
    },
    "usageDisclaimer": {
        "l": "This attestation only asserts designated aliases of the controller of the AID, that the AID controlled namespaced alias has been designated by the controller. It does not assert that the controller of this AID has control over the infrastructure or anything else related to the namespace other than the included AID."
    },
    "issuanceDisclaimer": {
        "l": "All information in a valid and non-revoked alias designation assertion is accurate as of the date specified."
    },
    "termsOfUse": {
        "l": "Designated aliases of the AID must only be used in a manner consistent with the expressed intent of the AID controller."
    },
}


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


def statusForAid(agent, config: DidWebsConfig, aid: str) -> dict:
    """Return publication material and availability status for one local AID."""
    if not isLocalAid(agent, aid):
        raise falcon.HTTPNotFound(description=f"{aid} is not a local KERIA identifier")

    did = didForAid(config, aid)
    alias_available = bool(matchingDesignatedAliases(agent.hby, agent.rgy, aid, did))
    optional_missing = [] if alias_available else ["designated_alias_acdc"]

    urls = assetUrls(config, aid)
    return {
        "aid": aid,
        "did": did,
        **urls,
        "available": True,
        "missing": [],
        "designatedAliasAvailable": alias_available,
        "optionalMissing": optional_missing,
        "registryName": registryName(config, aid),
        "schema": DES_ALIASES_SCHEMA,
        "credentialData": aliasCredentialData(config, aid),
        "rules": copy.deepcopy(DES_ALIASES_RULES),
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
    """Signed admin helper endpoint for did:webs publication material."""

    def __init__(self, config: DidWebsConfig):
        self.config = config

    def on_get(self, req, rep, aid):
        agent = req.context.agent
        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(statusForAid(agent, self.config, aid)).encode("utf-8")
