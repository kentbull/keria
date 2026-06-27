# -*- encoding: utf-8 -*-
"""KERIA edge-owned W3C workflow boundary tests."""

from types import SimpleNamespace

import pytest
from keri.app import configing
from keri.core import signing as core_signing
from keri.peer import exchanging
from vc_isomer.jwt import issue_vc_jwt, issue_vp_jwt
from vc_isomer.profile import transpose_acdc_to_w3c_vc
from vc_isomer.signing import HabSigner

from keria.app import w3cing
from keria.db import basing


def w3c_config():
    return w3cing.W3CConfig(
        enabled=True,
        ttl_seconds=600,
        signal_interval_seconds=30.0,
        status_base_url="http://127.0.0.1:8787",
    )


def edge_signer(seed=b"0123456789abcdef"):
    return core_signing.Salter(raw=seed).signer()


class SigningHab:
    def __init__(self, aid, signer, name=None):
        self.name = name or aid
        self.pre = aid
        self.kever = SimpleNamespace(
            verfers=[signer.verfer], lastEst=SimpleNamespace(s=0, d=aid)
        )
        self._signer = signer

    def sign(self, ser, **kwa):
        return [self._signer.sign(ser, index=None)]


class ReadThroughTevers(dict):
    """Test double for KERIpy rbdict membership-triggered read-through."""

    def __contains__(self, key):
        return key == "registry-said"

    def __getitem__(self, key):
        if key != "registry-said":
            raise KeyError(key)
        return "loaded-tever"

    def get(self, key, default=None):
        return default


def valid_acdc(
    *, issuer="Eissuer", holder="Eholder", holder_did="did:webs:example.com:dws:Eholder"
):
    return {
        "d": "credential-said",
        "i": issuer,
        "ri": "registry-said",
        "s": w3cing.VRD_SCHEMA,
        "a": {
            "i": holder,
            "AID": holder,
            "DID": holder_did,
            "LegalName": "Example Holder",
            "HeadquartersAddress": "1 Main St, Suite 2, Denver, CO 80202, US",
            "dt": "2026-06-01T00:00:00Z",
        },
        "e": {"le": {"n": "legal-entity-said", "s": "legal-entity-schema"}},
        "r": {
            "usageDisclaimer": {"l": "usage"},
            "issuanceDisclaimer": {"l": "issuance"},
            "privacyDisclaimer": {"l": "privacy"},
        },
    }


def fake_creder(acdc):
    return SimpleNamespace(
        sad=acdc,
        issuer=acdc["i"],
        schema=acdc["s"],
        regi=acdc["ri"],
        said=acdc["d"],
    )


def issue_valid_vc_jwt(acdc, issuer_did, status_base_url, issuer_hab):
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did=issuer_did,
        status_base_url=status_base_url,
    )
    return issue_vc_jwt(
        vc,
        signer=HabSigner(issuer_hab),
        verification_method=f"{issuer_did}#{issuer_hab.kever.verfers[0].qb64}",
        proof_created="2026-06-01T00:00:00Z",
    )


def test_agency_baser_exposes_edge_owned_w3c_record_stores(helpers):
    with helpers.openKeria() as (agency, _agent, _app, _client):
        now = "2026-06-01T00:00:00Z"
        issuance = basing.W3CIssuanceRecord(
            d="issuance-id",
            issuerName="qvi",
            issuerAid="Eqvi",
            holderAid="Ele",
            sourceCredentialSaid="credential-said",
            schemaSaid=w3cing.VRD_SCHEMA,
            issuerDid="did:webs:example.com:dws:Eqvi",
            holderDid="did:webs:example.com:dws:Ele",
            profile=w3cing.DEFAULT_PROFILE,
            state=w3cing.W3C_ISS_READY,
            created=now,
            updated=now,
            statusUrl="http://status.example/w3c/vc/status/credential-said",
            statusBaseUrl="http://status.example/w3c/vc",
            sourceCredential={},
        )
        held = basing.W3CHeldCredentialRecord(
            d="held-id",
            holderName="le",
            holderAid="Ele",
            holderDid="did:webs:example.com:dws:Ele",
            issuerAid="Eqvi",
            issuerDid="did:webs:example.com:dws:Eqvi",
            sourceCredentialSaid="credential-said",
            schemaSaid=w3cing.VRD_SCHEMA,
            profile=w3cing.DEFAULT_PROFILE,
            vcJwt="vc.jwt.token",
            decodedVc={},
            statusUrl="http://status.example/w3c/vc/status/credential-said",
            deliverySource="exn_grant",
            grantSaid="grant-said",
            state=w3cing.W3C_HELD_ADMITTED,
            imported=now,
            updated=now,
            lastValidation=now,
            validationState="valid",
        )
        contact = basing.W3CVerifierContactRecord(
            d="contact-id",
            holderName="le",
            holderAid="Ele",
            origin="https://verifier.example",
            label="Verifier",
            formats=["vp+jwt"],
            created=now,
            updated=now,
            metadata={},
        )
        tx = basing.W3CPresentTxRecord(
            d="presentation-id",
            holderName="le",
            holderAid="Ele",
            holderDid="did:webs:example.com:dws:Ele",
            contactId=contact.d,
            requestDescriptor={},
            state=w3cing.W3C_PRES_SUBMITTED,
            nonce="nonce",
            aud="https://verifier.example",
            requestUri=None,
            responseUri="https://verifier.example/verify",
            matchedCredentialIds=[held.d],
            selectedCredentialId=held.d,
            vpJwt="vp.jwt.token",
            submissionEndpoint="https://verifier.example/verify",
            submissionState="submitted",
            verifierResponse={},
            created=now,
            updated=now,
            expires="2026-06-01T00:10:00Z",
        )

        agency.adb.w3cissu.pin(keys=(issuance.d,), val=issuance)
        agency.adb.w3cheld.pin(keys=(held.d,), val=held)
        agency.adb.w3cvcnt.pin(keys=(contact.d,), val=contact)
        agency.adb.w3cptx.pin(keys=(tx.d,), val=tx)

        assert agency.adb.w3cissu.get(keys=(issuance.d,)) == issuance
        assert agency.adb.w3cheld.get(keys=(held.d,)) == held
        assert agency.adb.w3cvcnt.get(keys=(contact.d,)) == contact
        assert agency.adb.w3cptx.get(keys=(tx.d,)) == tx
        assert not hasattr(agency.adb, "w3creq")
        assert not hasattr(agency.adb, "w3cimp")


def test_config_from_sources_uses_w3c_key_and_environment(monkeypatch):
    monkeypatch.setenv("KERIA_W3C_ENABLED", "true")
    cf = configing.Configer(name="keria", temp=True, reopen=True, clear=True)
    cf.put(
        {
            "w3c": {
                "enabled": False,
                "ttl_seconds": 60,
                "signal_interval_seconds": 5,
                "status_base_url": "http://status.example",
            }
        }
    )

    config = w3cing.configFromSources({}, cf=cf)

    assert config.enabled is True
    assert config.ttl_seconds == 60
    assert config.signal_interval_seconds == 5
    assert config.status_base_url == "http://status.example"


def test_load_admin_ends_registers_edge_owned_w3c_routes(helpers):
    with helpers.openKeria() as (_agency, _agent, app, client):
        w3cing.loadAdminEnds(app, w3c_config())

        assert client.simulate_get("/identifiers/qvi/w3c/issuances").json == {
            "issuances": []
        }
        assert client.simulate_get("/identifiers/le/w3c/credentials").json == {
            "credentials": []
        }
        assert client.simulate_get("/identifiers/le/w3c/verifier-contacts").json == {
            "contacts": []
        }
        assert client.simulate_get("/identifiers/le/w3c/presentations").json == {
            "presentations": [],
        }
        assert (
            client.simulate_get("/identifiers/le/w3c/signing-requests").status
            == "404 Not Found"
        )
        assert (
            client.simulate_get("/identifiers/le/w3c/present-txs").status
            == "404 Not Found"
        )


def test_start_issuance_creates_edge_artifact_context_without_signing_request(
    helpers, monkeypatch
):
    issuer_aid = "E" + ("Q" * 43)
    holder_aid = "E" + ("H" * 43)
    holder_did = f"did:webs:example.com:dws:{holder_aid}"
    signer = edge_signer()
    issuer_hab = SigningHab(issuer_aid, signer, "qvi")
    acdc = valid_acdc(issuer=issuer_aid, holder=holder_aid, holder_did=holder_did)
    creder = fake_creder(acdc)

    with helpers.openKeria() as (_agency, agent, _app, _client):
        monkeypatch.setattr(agent.hby, "habByName", lambda name: issuer_hab)
        monkeypatch.setattr(
            w3cing.didwebing,
            "publishedDws",
            lambda _agent, aid: f"did:webs:example.com:dws:{aid}",
        )
        monkeypatch.setattr(w3cing, "cloneCredential", lambda _agent, _said: (creder,))
        monkeypatch.setattr(w3cing, "validateIssuanceSource", lambda *_args: None)

        record = w3cing.startIssuance(agent, w3c_config(), "qvi", "credential-said")

        assert record.state == w3cing.W3C_ISS_READY
        assert record.issuerAid == issuer_aid
        assert record.holderAid == holder_aid
        assert record.sourceCredential == acdc
        assert record.statusBaseUrl == "http://127.0.0.1:8787/w3c/vc"
        assert not hasattr(record, "signingRequestId")


def test_submit_edge_built_vc_jwt_validates_and_stores_delivery_ready(
    helpers, monkeypatch
):
    issuer_aid = "E" + ("Q" * 43)
    holder_aid = "E" + ("H" * 43)
    issuer_did = f"did:webs:example.com:dws:{issuer_aid}"
    holder_did = f"did:webs:example.com:dws:{holder_aid}"
    issuer_hab = SigningHab(issuer_aid, edge_signer(), "qvi")
    acdc = valid_acdc(issuer=issuer_aid, holder=holder_aid, holder_did=holder_did)
    creder = fake_creder(acdc)

    with helpers.openKeria() as (_agency, agent, _app, _client):
        agent.hby.kevers[issuer_aid] = issuer_hab.kever
        monkeypatch.setattr(agent.hby, "habByName", lambda name: issuer_hab)
        monkeypatch.setattr(
            w3cing.didwebing, "publishedDws", lambda _agent, aid: issuer_did
        )
        monkeypatch.setattr(w3cing, "cloneCredential", lambda _agent, _said: (creder,))
        monkeypatch.setattr(w3cing, "validateIssuanceSource", lambda *_args: None)
        record = w3cing.startIssuance(agent, w3c_config(), "qvi", "credential-said")
        vc_jwt, secured_vc = issue_valid_vc_jwt(
            acdc, issuer_did, record.statusBaseUrl, issuer_hab
        )

        updated = w3cing.submitIssuanceVcJwt(
            agent, w3c_config(), "qvi", record.d, {"vcJwt": vc_jwt}
        )

        assert updated.state == w3cing.W3C_ISS_DELIVERY_PENDING
        assert updated.vcJwt == vc_jwt
        assert updated.decodedVc == secured_vc


def test_submit_vc_jwt_rejects_wrong_issuer_signature(helpers, monkeypatch):
    issuer_aid = "E" + ("Q" * 43)
    holder_aid = "E" + ("H" * 43)
    issuer_did = f"did:webs:example.com:dws:{issuer_aid}"
    holder_did = f"did:webs:example.com:dws:{holder_aid}"
    issuer_hab = SigningHab(issuer_aid, edge_signer(), "qvi")
    wrong_hab = SigningHab("E" + ("W" * 43), edge_signer(b"abcdef0123456789"), "wrong")
    acdc = valid_acdc(issuer=issuer_aid, holder=holder_aid, holder_did=holder_did)
    creder = fake_creder(acdc)

    with helpers.openKeria() as (_agency, agent, _app, _client):
        agent.hby.kevers[issuer_aid] = issuer_hab.kever
        monkeypatch.setattr(agent.hby, "habByName", lambda name: issuer_hab)
        monkeypatch.setattr(
            w3cing.didwebing, "publishedDws", lambda _agent, aid: issuer_did
        )
        monkeypatch.setattr(w3cing, "cloneCredential", lambda _agent, _said: (creder,))
        monkeypatch.setattr(w3cing, "validateIssuanceSource", lambda *_args: None)
        record = w3cing.startIssuance(agent, w3c_config(), "qvi", "credential-said")
        vc_jwt, _vc = issue_valid_vc_jwt(
            acdc, issuer_did, record.statusBaseUrl, wrong_hab
        )

        with pytest.raises(Exception) as excinfo:
            w3cing.submitIssuanceVcJwt(
                agent, w3c_config(), "qvi", record.d, {"vcJwt": vc_jwt}
            )

        assert "kid does not match" in excinfo.value.description


def test_w3c_grant_exn_handler_materializes_held_credential_directly(
    helpers, monkeypatch
):
    issuer_aid = "E" + ("Q" * 43)
    holder_aid = "E" + ("H" * 43)
    issuer_did = f"did:webs:example.com:dws:{issuer_aid}"
    holder_did = f"did:webs:example.com:dws:{holder_aid}"
    issuer_hab = SigningHab(issuer_aid, edge_signer(), "qvi")
    holder_hab = SigningHab(holder_aid, edge_signer(b"1234567890abcdef"), "le")
    acdc = valid_acdc(issuer=issuer_aid, holder=holder_aid, holder_did=holder_did)
    vc_jwt, _secured = issue_valid_vc_jwt(
        acdc, issuer_did, "http://status.example/w3c/vc", issuer_hab
    )

    with helpers.openKeria() as (_agency, agent, _app, _client):
        agent.hby.habs[holder_aid] = holder_hab
        agent.hby.kevers[issuer_aid] = issuer_hab.kever
        agent.hby.kevers[holder_aid] = holder_hab.kever
        monkeypatch.setattr(
            agent.hby, "habByName", lambda name: holder_hab if name == "le" else None
        )
        monkeypatch.setattr(
            w3cing.didwebing, "publishedDws", lambda _agent, aid: holder_did
        )
        monkeypatch.setattr(
            w3cing, "cloneCredential", lambda _agent, _said: (fake_creder(acdc),)
        )
        monkeypatch.setattr(w3cing, "validateIssuanceSource", lambda *_args: None)
        exn, _atc = exchanging.exchange(
            route=w3cing.W3C_GRANT_ROUTE,
            sender=issuer_aid,
            recipient=holder_aid,
            payload={
                "holderAid": holder_aid,
                "holderDid": holder_did,
                "issuerAid": issuer_aid,
                "issuerDid": issuer_did,
                "sourceCredentialSaid": "credential-said",
                "schemaSaid": w3cing.VRD_SCHEMA,
                "issuanceId": "issuance-id",
                "vcJwt": vc_jwt,
                "statusUrl": "http://status.example/w3c/vc/status/credential-said",
                "profile": w3cing.DEFAULT_PROFILE,
            },
        )

        handler = w3cing.W3CVcGrantHandler(agent=agent, config=w3c_config())
        assert handler.verify(exn) is True
        handler.handle(exn)

        held = [record for _keys, record in agent.adb.w3cheld.getItemIter()]
        assert len(held) == 1
        assert held[0].state == w3cing.W3C_HELD_ADMITTED
        assert held[0].vcJwt == vc_jwt
        assert held[0].grantSaid == exn.said
        assert not hasattr(agent.adb, "w3cimp")


def test_presentation_accepts_edge_built_vp_jwt_without_signing_request(
    helpers, monkeypatch
):
    issuer_aid = "E" + ("Q" * 43)
    holder_aid = "E" + ("H" * 43)
    holder_did = f"did:webs:example.com:dws:{holder_aid}"
    holder_hab = SigningHab(holder_aid, edge_signer(b"1234567890abcdef"), "le")
    held = basing.W3CHeldCredentialRecord(
        d="held-id",
        holderName="le",
        holderAid=holder_aid,
        holderDid=holder_did,
        issuerAid=issuer_aid,
        issuerDid=f"did:webs:example.com:dws:{issuer_aid}",
        sourceCredentialSaid="credential-said",
        schemaSaid=w3cing.VRD_SCHEMA,
        profile=w3cing.DEFAULT_PROFILE,
        vcJwt="vc.jwt.token",
        decodedVc={},
        statusUrl="http://status.example/w3c/vc/status/credential-said",
        deliverySource="exn_grant",
        grantSaid="grant-said",
        state=w3cing.W3C_HELD_ADMITTED,
        imported="2026-06-01T00:00:00Z",
        updated="2026-06-01T00:00:00Z",
        lastValidation="2026-06-01T00:00:00Z",
        validationState="valid",
    )
    vp_jwt, _vp = issue_vp_jwt(
        [held.vcJwt],
        holder_did=holder_did,
        signer=HabSigner(holder_hab),
        audience="https://verifier.example",
        nonce="nonce-1",
    )

    with helpers.openKeria() as (_agency, agent, _app, _client):
        agent.hby.habs[holder_aid] = holder_hab
        agent.hby.kevers[holder_aid] = holder_hab.kever
        monkeypatch.setattr(
            agent.hby, "habByName", lambda name: holder_hab if name == "le" else None
        )
        monkeypatch.setattr(
            w3cing.didwebing, "publishedDws", lambda _agent, aid: holder_did
        )
        monkeypatch.setattr(
            w3cing,
            "cloneCredential",
            lambda _agent, _said: (
                fake_creder(
                    valid_acdc(
                        issuer=issuer_aid, holder=holder_aid, holder_did=holder_did
                    )
                ),
            ),
        )
        monkeypatch.setattr(w3cing, "validateIssuanceSource", lambda *_args: None)
        monkeypatch.setattr(
            w3cing,
            "postVerifierPresentation",
            lambda endpoint, token, audience, nonce: {"accepted": True},
        )
        agent.adb.w3cheld.pin(keys=(held.d,), val=held)

        tx = w3cing.submitPresentation(
            agent,
            w3c_config(),
            "le",
            {
                "credentialId": held.d,
                "credentialSaid": held.sourceCredentialSaid,
                "aud": "https://verifier.example",
                "nonce": "nonce-1",
                "response_uri": "https://verifier.example/verify",
                "vpJwt": vp_jwt,
            },
        )

        assert tx.state == w3cing.W3C_PRES_SUBMITTED
        assert tx.selectedCredentialId == held.d
        assert tx.vpJwt == vp_jwt
        assert tx.submissionState == "submitted"
        assert not hasattr(tx, "signingRequestId")


def test_presentation_rejects_vp_signed_by_wrong_holder(helpers, monkeypatch):
    holder_aid = "E" + ("H" * 43)
    holder_did = f"did:webs:example.com:dws:{holder_aid}"
    holder_hab = SigningHab(holder_aid, edge_signer(b"1234567890abcdef"), "le")
    wrong_hab = SigningHab("E" + ("W" * 43), edge_signer(b"abcdef0123456789"), "wrong")
    held = basing.W3CHeldCredentialRecord(
        d="held-id",
        holderName="le",
        holderAid=holder_aid,
        holderDid=holder_did,
        issuerAid="Eqvi",
        issuerDid="did:webs:example.com:dws:Eqvi",
        sourceCredentialSaid="credential-said",
        schemaSaid=w3cing.VRD_SCHEMA,
        profile=w3cing.DEFAULT_PROFILE,
        vcJwt="vc.jwt.token",
        decodedVc={},
        statusUrl="http://status.example/w3c/vc/status/credential-said",
        deliverySource="exn_grant",
        grantSaid="grant-said",
        state=w3cing.W3C_HELD_ADMITTED,
        imported="2026-06-01T00:00:00Z",
        updated="2026-06-01T00:00:00Z",
        lastValidation="2026-06-01T00:00:00Z",
        validationState="valid",
    )
    vp_jwt, _vp = issue_vp_jwt(
        [held.vcJwt],
        holder_did=holder_did,
        signer=HabSigner(wrong_hab),
        audience="https://verifier.example",
        nonce="nonce-1",
    )

    with helpers.openKeria() as (_agency, agent, _app, _client):
        agent.hby.habs[holder_aid] = holder_hab
        agent.hby.kevers[holder_aid] = holder_hab.kever
        monkeypatch.setattr(
            agent.hby, "habByName", lambda name: holder_hab if name == "le" else None
        )
        monkeypatch.setattr(
            w3cing.didwebing, "publishedDws", lambda _agent, aid: holder_did
        )
        agent.adb.w3cheld.pin(keys=(held.d,), val=held)

        with pytest.raises(Exception) as excinfo:
            w3cing.submitPresentation(
                agent,
                w3c_config(),
                "le",
                {
                    "credentialId": held.d,
                    "aud": "https://verifier.example",
                    "nonce": "nonce-1",
                    "response_uri": "https://verifier.example/verify",
                    "vpJwt": vp_jwt,
                },
            )

        assert "kid does not match" in excinfo.value.description


def test_registry_tever_uses_read_through_cache_membership():
    agent = SimpleNamespace(rgy=SimpleNamespace(tevers=ReadThroughTevers(), reger=None))

    assert w3cing.registryTever(agent, "registry-said") == "loaded-tever"
