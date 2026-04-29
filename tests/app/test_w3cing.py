# -*- encoding: utf-8 -*-
"""KERIA ephemeral W3C projection workflow tests."""

import json
from types import SimpleNamespace

import falcon
import pytest
from keri.app import configing

from keria.app import w3cing
from keria.db import basing


def verifier_config(kind="isomer-python-vc-jwt"):
    return w3cing.W3CProjectionConfig(
        enabled=True,
        session_ttl_seconds=600,
        verifiers=[
            w3cing.W3CVerifierConfig(
                id="isomer-local",
                label="Local Isomer",
                kind=kind,
                verifyUrl="http://127.0.0.1:9723/verify/vc",
            )
        ],
        status_base_url="http://127.0.0.1:8787",
    )


def patch_projection_inputs(monkeypatch, agent, aid=None, creder=None):
    aid = aid or "E" + ("A" * 43)
    fake_hab = SimpleNamespace(pre=aid, kever=agent.agentHab.kever)
    fake_creder = creder or SimpleNamespace(
        sad={
            "d": "credential-said",
            "i": aid,
            "s": w3cing.VRD_SCHEMA,
            "a": {"i": aid},
        },
        issuer=aid,
        schema=w3cing.VRD_SCHEMA,
        regi="registry-said",
        said="credential-said",
    )

    monkeypatch.setattr(agent.hby, "habByName", lambda name: fake_hab)
    monkeypatch.setattr(
        w3cing.didwebing,
        "publishedDws",
        lambda _agent, _aid: f"did:webs:example.com:dws:{aid}",
    )
    monkeypatch.setattr(w3cing, "cloneCredential", lambda _agent, _said: (fake_creder,))
    monkeypatch.setattr(w3cing, "validateProjectionCredential", lambda *_args: None)
    monkeypatch.setattr(
        w3cing,
        "transpose_acdc_to_w3c_vc",
        lambda acdc, issuer_did, status_base_url: {
            "id": f"urn:said:{acdc['d']}",
            "issuer": issuer_did,
            "issuanceDate": "2025-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:subject"},
            "credentialStatus": {
                "id": f"{status_base_url}/status/{acdc['d']}",
                "type": "KERICredentialStatus",
            },
        },
    )
    monkeypatch.setattr(w3cing, "create_verify_data", lambda *_args: b"proof-bytes")
    return aid


def projection_creder(
    *,
    issuer="Eissuer",
    holder="Eholder",
    schema=w3cing.VRD_SCHEMA,
    said="credential-said",
):
    return SimpleNamespace(
        sad={"d": said, "i": issuer, "s": schema, "a": {"i": holder}},
        issuer=issuer,
        schema=schema,
        regi="registry-said",
        said=said,
    )


def validation_agent(*, ilk="iss"):
    tever = SimpleNamespace(vcState=lambda _said: SimpleNamespace(et=ilk))
    return SimpleNamespace(rgy=SimpleNamespace(tevers={"registry-said": tever}))


def test_agency_baser_exposes_w3c_projection_stores(helpers):
    with helpers.openKeria() as (agency, _agent, _app, _client):
        session = basing.W3CProjectionRecord(
            d="session-said",
            aid="managed-aid",
            name="aid1",
            credentialSaid="credential-said",
            issuerDid="did:webs:example.com:dws:managed-aid",
            verifierId="isomer-local",
            verifierUrl="http://127.0.0.1:9723/verify/vc",
            statusBaseUrl="http://127.0.0.1:8787",
            state=w3cing.W3C_STATE_PROOF,
            created="2025-01-01T00:00:00Z",
            updated="2025-01-01T00:00:00Z",
            expires="2025-01-01T00:10:00Z",
            verificationMethod="did:webs:example.com:dws:managed-aid#key",
            unsignedVc={},
            proofConfig={},
        )
        request = basing.W3CSigningRequestRecord(
            d="request-said",
            session=session.d,
            type=w3cing.W3C_SIG_EVENT,
            kind=w3cing.W3C_KIND_PROOF,
            agent="agent-aid",
            aid=session.aid,
            name=session.name,
            credentialSaid=session.credentialSaid,
            signingInputB64="cHJvb2Y",
            encoding="base64url",
            verificationMethod=session.verificationMethod,
            state=w3cing.W3C_REQ_PENDING,
            created=session.created,
            updated=session.updated,
            expires=session.expires,
        )

        agency.adb.w3cproj.pin(keys=(session.d,), val=session)
        agency.adb.w3creq.pin(keys=(request.d,), val=request)

        assert agency.adb.w3cproj.get(keys=(session.d,)) == session
        assert agency.adb.w3creq.get(keys=(request.d,)) == request


def test_config_from_sources_reads_config_file_and_env(helpers, monkeypatch):
    monkeypatch.setenv("KERIA_W3C_PROJECTION_ENABLED", "true")
    cf = configing.Configer(name="keria", temp=True, reopen=True, clear=True)
    cf.put(
        {
            "w3c_projection": {
                "enabled": False,
                "session_ttl_seconds": 60,
                "status_base_url": "http://status.example",
                "verifiers": [
                    {
                        "id": "isomer-local",
                        "label": "Local Isomer",
                        "kind": "isomer-python-vc-jwt",
                        "verifyUrl": "http://127.0.0.1:9723/verify/vc",
                    }
                ],
            }
        }
    )

    config = w3cing.configFromSources({}, cf=cf)

    assert config.enabled is True
    assert config.session_ttl_seconds == 60
    assert config.status_base_url == "http://status.example"
    assert config.verifiers[0].id == "isomer-local"


def test_create_projection_session_stores_session_and_first_request(
    helpers, monkeypatch
):
    with helpers.openKeria() as (_agency, agent, _app, _client):
        aid = patch_projection_inputs(monkeypatch, agent)

        session = w3cing.createProjectionSession(
            agent,
            verifier_config(),
            name="aid1",
            credentialSaid="credential-said",
            verifierId="isomer-local",
        )
        request = agent.adb.w3creq.get(keys=(session.proofRequest,))

        assert agent.adb.w3cproj.get(keys=(session.d,)) == session
        assert session.aid == aid
        assert session.state == w3cing.W3C_STATE_PROOF
        assert session.issuerDid == f"did:webs:example.com:dws:{aid}"
        assert session.unsignedVc["id"] == "urn:said:credential-said"
        assert request.kind == w3cing.W3C_KIND_PROOF
        assert request.signingInputB64 == "cHJvb2YtYnl0ZXM"


def test_create_projection_session_can_use_holder_did_as_temporary_presenter(
    helpers, monkeypatch
):
    issuer = "E" + ("I" * 43)
    holder = "E" + ("H" * 43)
    creder = projection_creder(issuer=issuer, holder=holder)
    with helpers.openKeria() as (_agency, agent, _app, _client):
        patch_projection_inputs(monkeypatch, agent, aid=holder, creder=creder)

        session = w3cing.createProjectionSession(
            agent,
            verifier_config(),
            name="holder",
            credentialSaid="credential-said",
            verifierId="isomer-local",
        )

        assert session.aid == holder
        assert session.issuerDid == f"did:webs:example.com:dws:{holder}"
        assert session.verificationMethod.startswith(
            f"did:webs:example.com:dws:{holder}#"
        )


def test_validate_projection_credential_accepts_issuer_or_holder():
    creder = projection_creder()
    agent = validation_agent()

    w3cing.validateProjectionCredential(agent, "Eissuer", creder)
    w3cing.validateProjectionCredential(agent, "Eholder", creder)


def test_validate_projection_credential_rejects_unrelated_presenter():
    creder = projection_creder()
    agent = validation_agent()

    with pytest.raises(falcon.HTTPBadRequest) as ex:
        w3cing.validateProjectionCredential(agent, "Eother", creder)

    assert "issuer or holder" in ex.value.description


def test_validate_projection_credential_rejects_unsupported_schema():
    creder = projection_creder(schema="Eunsupported")
    agent = validation_agent()

    with pytest.raises(falcon.HTTPBadRequest) as ex:
        w3cing.validateProjectionCredential(agent, "Eissuer", creder)

    assert "unsupported W3C projection schema" in ex.value.description


def test_validate_projection_credential_rejects_inactive_credential():
    creder = projection_creder()
    agent = validation_agent(ilk="rev")

    with pytest.raises(falcon.HTTPBadRequest) as ex:
        w3cing.validateProjectionCredential(agent, "Eholder", creder)

    assert "is not active" in ex.value.description


def test_create_projection_session_accepts_supported_verifier_kinds(
    helpers, monkeypatch
):
    for kind in sorted(w3cing.SUPPORTED_VERIFIER_KINDS):
        with helpers.openKeria() as (_agency, agent, _app, _client):
            patch_projection_inputs(monkeypatch, agent)

            session = w3cing.createProjectionSession(
                agent,
                verifier_config(kind=kind),
                name="aid1",
                credentialSaid="credential-said",
                verifierId="isomer-local",
            )

            assert session.verifierId == "isomer-local"


def test_projection_doer_advances_signatures_and_posts_verifier(
    helpers, monkeypatch
):
    with helpers.openKeria() as (_agency, agent, _app, _client):
        patch_projection_inputs(monkeypatch, agent)
        session = w3cing.createProjectionSession(
            agent,
            verifier_config(),
            name="aid1",
            credentialSaid="credential-said",
            verifierId="isomer-local",
        )
        doer = w3cing.W3CProjectionDoer(
            agent=agent,
            config=verifier_config(),
            signalCues=agent.signalCues,
        )
        proof_request = agent.adb.w3creq.get(keys=(session.proofRequest,))
        proof_sig = agent.agentHab.sign(ser=b"proof-bytes", indexed=False)[0].qb64
        w3cing.submitSignature(agent, "aid1", proof_request.d, proof_sig)

        doer.advanceSession(session)
        session = agent.adb.w3cproj.get(keys=(session.d,))
        jwt_request = agent.adb.w3creq.get(keys=(session.jwtRequest,))

        assert agent.adb.w3creq.get(keys=(proof_request.d,)).state == w3cing.W3C_REQ_COMPLETE
        assert session.state == w3cing.W3C_STATE_JWT
        assert jwt_request.kind == w3cing.W3C_KIND_JWT

        signing_input = w3cing.b64url_decode(jwt_request.signingInputB64)
        jwt_sig = agent.agentHab.sign(ser=signing_input, indexed=False)[0].qb64
        w3cing.submitSignature(agent, "aid1", jwt_request.d, jwt_sig)

        posted = {}

        class FakeResponse:
            status = 202

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps({"done": True}).encode("utf-8")

        def fake_urlopen(request, timeout):
            posted["url"] = request.full_url
            posted["body"] = json.loads(request.data.decode("utf-8"))
            posted["timeout"] = timeout
            return FakeResponse()

        monkeypatch.setattr(w3cing.urllib.request, "urlopen", fake_urlopen)
        doer.advanceSession(session)
        session = agent.adb.w3cproj.get(keys=(session.d,))

        assert session.state == w3cing.W3C_STATE_COMPLETE
        assert session.verifierStatus == 202
        assert session.verifierResponse == {"done": True}
        assert posted["url"] == "http://127.0.0.1:9723/verify/vc"
        assert posted["body"]["token"] == session.token
        assert posted["timeout"] == 10


def test_projection_doer_rejects_invalid_signature(helpers, monkeypatch):
    with helpers.openKeria() as (_agency, agent, _app, _client):
        patch_projection_inputs(monkeypatch, agent)
        session = w3cing.createProjectionSession(
            agent,
            verifier_config(),
            name="aid1",
            credentialSaid="credential-said",
            verifierId="isomer-local",
        )
        doer = w3cing.W3CProjectionDoer(
            agent=agent,
            config=verifier_config(),
            signalCues=agent.signalCues,
        )
        proof_request = agent.adb.w3creq.get(keys=(session.proofRequest,))
        bad_sig = agent.agentHab.sign(ser=b"wrong-bytes", indexed=False)[0].qb64
        w3cing.submitSignature(agent, "aid1", proof_request.d, bad_sig)

        doer.advanceActiveSessions()
        session = agent.adb.w3cproj.get(keys=(session.d,))
        request = agent.adb.w3creq.get(keys=(proof_request.d,))

        assert session.state == w3cing.W3C_STATE_FAILED
        assert "invalid data integrity proof signature" in session.error
        assert request.state == w3cing.W3C_REQ_FAILED


def test_projection_doer_cleans_expired_sessions_and_requests(helpers):
    with helpers.openKeria() as (_agency, agent, _app, _client):
        session = basing.W3CProjectionRecord(
            d="session-said",
            aid="managed-aid",
            name="aid1",
            credentialSaid="credential-said",
            issuerDid="did:webs:example.com:dws:managed-aid",
            verifierId="isomer-local",
            verifierUrl="http://127.0.0.1:9723/verify/vc",
            statusBaseUrl="http://127.0.0.1:8787",
            state=w3cing.W3C_STATE_COMPLETE,
            created="2025-01-01T00:00:00Z",
            updated="2025-01-01T00:00:00Z",
            expires="2025-01-01T00:10:00Z",
            verificationMethod="did:webs:example.com:dws:managed-aid#key",
            unsignedVc={},
            proofConfig={},
            proofSignature="secret",
            token="secret-token",
        )
        request = basing.W3CSigningRequestRecord(
            d="request-said",
            session=session.d,
            type=w3cing.W3C_SIG_EVENT,
            kind=w3cing.W3C_KIND_JWT,
            agent=agent.agentHab.pre,
            aid=session.aid,
            name=session.name,
            credentialSaid=session.credentialSaid,
            signingInputB64="abc",
            encoding="base64url",
            verificationMethod=session.verificationMethod,
            state=w3cing.W3C_REQ_COMPLETE,
            created=session.created,
            updated=session.updated,
            expires=session.expires,
            signature="secret",
        )
        agent.adb.w3cproj.pin(keys=(session.d,), val=session)
        agent.adb.w3creq.pin(keys=(request.d,), val=request)

        doer = w3cing.W3CProjectionDoer(
            agent=agent,
            config=verifier_config(),
            signalCues=agent.signalCues,
        )
        doer.cleanupExpired()

        assert agent.adb.w3cproj.get(keys=(session.d,)) is None
        assert agent.adb.w3creq.get(keys=(request.d,)) is None


def test_verifier_route_returns_configured_allowlist():
    config = verifier_config()
    req = SimpleNamespace()
    rep = SimpleNamespace(status=None, content_type=None, data=None)

    w3cing.W3CVerifierCollectionEnd(config).on_get(req, rep)

    assert rep.status == falcon.HTTP_200
    assert rep.content_type == "application/json"
    assert json.loads(rep.data)["verifiers"][0]["id"] == "isomer-local"
