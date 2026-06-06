# -*- encoding: utf-8 -*-
"""
KERIA did:webs dynamic asset endpoint tests.
"""

import json
from dataclasses import dataclass

import falcon
from keri.app import configing

from keria.app import aiding, didwebing


@dataclass
class FakeCredential:
    said: str
    sad: dict


def enabled_config():
    return didwebing.DidWebsConfig(
        enabled=True,
        domain="127.0.0.1",
        host="127.0.0.1",
        port=3902,
        path="dws",
    )


def test_config_from_sources_prefers_env(monkeypatch):
    monkeypatch.setenv("KERIA_DID_WEBS_ENABLED", "true")
    monkeypatch.setenv(
        "KERIA_DID_WEBS_PUBLIC_BASE_URL", "http://example.com:3902/custom"
    )
    monkeypatch.setenv("KERIA_DID_WEBS_META", "1")

    config = didwebing.configFromSources(
        {"enabled": False, "path": "ignored"}, httpPort=3902
    )

    assert config.enabled is True
    assert config.public_base_url == "http://example.com:3902/custom"
    assert config.domain == "example.com"
    assert config.host == "example.com"
    assert config.port == 3902
    assert config.path == "ignored"
    assert config.meta is True


def test_config_from_sources_reads_config_file(helpers):
    cf = configing.Configer(name="keria", temp=True, reopen=True, clear=True)
    cf.put(
        {
            "did_webs": {
                "enabled": True,
                "domain": "example.com",
                "port": 443,
                "path": "dws",
                "registry_name_prefix": "aliases",
            }
        }
    )

    config = didwebing.configFromSources({}, cf=cf)

    assert config.enabled is True
    assert config.domain == "example.com"
    assert config.host == "example.com"
    assert config.port == 443
    assert config.path == "dws"
    assert config.registry_name_prefix == "aliases"


def test_embedded_designated_alias_schema_pins_with_expected_said(helpers):
    with helpers.openKeria() as (_agency, agent, _app, _client):
        schemer = didwebing.pinDesignatedAliasesSchema(agent.hby)

        assert schemer.said == didwebing.DES_ALIASES_SCHEMA
        assert agent.hby.db.schema.get(keys=(didwebing.DES_ALIASES_SCHEMA,)) is not None


def test_setup_descriptor_reports_missing_registry(helpers):
    config = enabled_config()
    with helpers.openKeria() as (agency, agent, app, client):
        agent.didWebsConfig = config
        aiding.loadEnds(app=app, agency=agency, authn=None)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]

        result = client.simulate_get("/identifiers/aid1/dws/setup")

        assert result.status == falcon.HTTP_200
        assert result.json["name"] == "aid1"
        assert result.json["aid"] == aid
        assert result.json["did"] == f"did:webs:127.0.0.1%3A3902:dws:{aid}"
        assert result.json["dws"] is None
        assert result.json["ready"] is False
        assert result.json["didJsonUrl"] == (
            f"http://127.0.0.1:3902/dws/{aid}/did.json"
        )
        assert result.json["keriCesrUrl"] == (
            f"http://127.0.0.1:3902/dws/{aid}/keri.cesr"
        )
        assert result.json["registry"] == {
            "name": didwebing.registryName(config, aid),
            "registryId": None,
            "ready": False,
            "createArgs": {
                "name": "aid1",
                "registryName": didwebing.registryName(config, aid),
            },
        }
        assert result.json["designatedAlias"]["schema"] == didwebing.DES_ALIASES_SCHEMA
        assert result.json["designatedAlias"]["credentialSaid"] is None
        assert result.json["designatedAlias"]["ready"] is False
        assert result.json["designatedAlias"]["issueArgs"] is None


def test_setup_descriptor_reports_registry_pending(helpers, monkeypatch):
    config = enabled_config()
    with helpers.openKeria() as (agency, agent, app, client):
        agent.didWebsConfig = config
        aiding.loadEnds(app=app, agency=agency, authn=None)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]
        registry = agent.rgy.makeRegistry(
            name=didwebing.registryName(config, aid), prefix=aid, noBackers=True
        )
        monkeypatch.setattr(didwebing, "registryComplete", lambda _agent, _reg: False)

        result = client.simulate_get("/identifiers/aid1/dws/setup")

        assert result.status == falcon.HTTP_200
        assert result.json["ready"] is False
        assert result.json["registry"]["registryId"] == registry.regk
        assert result.json["registry"]["ready"] is False
        assert result.json["designatedAlias"]["issueArgs"]["ri"] == registry.regk


def test_setup_descriptor_reports_registry_ready_without_designated_alias(
    helpers, monkeypatch
):
    config = enabled_config()
    with helpers.openKeria() as (agency, agent, app, client):
        agent.didWebsConfig = config
        aiding.loadEnds(app=app, agency=agency, authn=None)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]
        registry = agent.rgy.makeRegistry(
            name=didwebing.registryName(config, aid), prefix=aid, noBackers=True
        )
        monkeypatch.setattr(didwebing, "registryComplete", lambda _agent, _reg: True)

        result = client.simulate_get("/identifiers/aid1/dws/setup")

        assert result.status == falcon.HTTP_200
        assert result.json["ready"] is False
        assert result.json["registry"]["ready"] is True
        assert result.json["designatedAlias"]["credentialSaid"] is None
        issue_args = result.json["designatedAlias"]["issueArgs"]
        assert issue_args["ri"] == registry.regk
        assert issue_args["s"] == didwebing.DES_ALIASES_SCHEMA
        assert issue_args["r"] == didwebing.DES_ALIASES_RULES
        assert issue_args["a"]["d"] == ""
        assert set(issue_args["a"]["ids"]) == {
            f"did:web:127.0.0.1%3A3902:dws:{aid}",
            f"did:webs:127.0.0.1%3A3902:dws:{aid}",
        }
        assert "dt" in issue_args["a"]


def test_setup_descriptor_reports_designated_alias_issued_but_not_ready(
    helpers, monkeypatch
):
    config = enabled_config()
    with helpers.openKeria() as (agency, agent, app, client):
        agent.didWebsConfig = config
        aiding.loadEnds(app=app, agency=agency, authn=None)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]
        registry = agent.rgy.makeRegistry(
            name=didwebing.registryName(config, aid), prefix=aid, noBackers=True
        )
        credential = FakeCredential(
            said="credential-said",
            sad={"d": "credential-said"},
        )
        monkeypatch.setattr(didwebing, "registryComplete", lambda _agent, _reg: True)
        monkeypatch.setattr(
            didwebing,
            "findDesignatedAliasCredential",
            lambda _agent, _config, _aid, _registry: credential,
        )

        result = client.simulate_get("/identifiers/aid1/dws/setup")

        assert result.status == falcon.HTTP_200
        assert result.json["ready"] is False
        assert result.json["registry"]["registryId"] == registry.regk
        assert result.json["designatedAlias"]["credentialSaid"] == "credential-said"
        assert result.json["designatedAlias"]["ready"] is False


def test_setup_descriptor_reports_ready(helpers, monkeypatch):
    config = enabled_config()
    with helpers.openKeria() as (agency, agent, app, client):
        agent.didWebsConfig = config
        aiding.loadEnds(app=app, agency=agency, authn=None)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]
        did = didwebing.didForAid(config, aid)
        monkeypatch.setattr(
            didwebing,
            "matchingDesignatedAliases",
            lambda _hby, _rgy, candidate_aid, candidate: [candidate]
            if candidate_aid == aid and candidate == did
            else [],
        )

        result = client.simulate_get("/identifiers/aid1/dws/setup")

        assert result.status == falcon.HTTP_200
        assert result.json["ready"] is True
        assert result.json["dws"] == did
        assert result.json["designatedAlias"]["ready"] is True


def test_setup_descriptor_rejects_unpublishable_aid(helpers):
    config = enabled_config()
    with helpers.openKeria() as (agency, agent, app, client):
        agent.didWebsConfig = config
        aiding.loadEnds(app=app, agency=agency, authn=None)

        result = client.simulate_get(f"/identifiers/{agent.agentHab.pre}/dws/setup")

        assert result.status == falcon.HTTP_404


def test_old_signing_request_endpoints_are_gone(helpers):
    with helpers.openKeria() as (agency, _agent, app, client):
        aiding.loadEnds(app=app, agency=agency, authn=None)

        assert client.simulate_get("/didwebs/signing/requests").status == falcon.HTTP_404
        assert client.simulate_get("/didwebs/signing/requests/bad").status == (
            falcon.HTTP_404
        )
        assert client.simulate_get("/didwebs/Eaid").status == falcon.HTTP_404


def test_asset_routes_return_generated_material_without_alias_acdc(helpers):
    config = enabled_config()

    with helpers.openKeria() as (agency, _agent, app, client):
        aiding.loadEnds(app=app, agency=agency, authn=None)
        didwebing.loadPublicEnds(app=app, agency=agency, config=config)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]

        did_result = client.simulate_get(f"/dws/{aid}/did.json")
        cesr_result = client.simulate_get(f"/dws/{aid}/keri.cesr")

        assert did_result.status == falcon.HTTP_200
        assert did_result.json["id"] == f"did:web:127.0.0.1%3A3902:dws:{aid}"
        assert did_result.json["alsoKnownAs"] == []
        assert cesr_result.status == falcon.HTTP_200
        assert aid.encode("utf-8") in cesr_result.content


def test_asset_routes_reject_unknown_aid(helpers):
    config = enabled_config()

    with helpers.openKeria() as (agency, _agent, app, client):
        didwebing.loadPublicEnds(app=app, agency=agency, config=config)

        result = client.simulate_get(
            "/dws/EJZ5K7I_TwPOtqK5pLaYk-sSMgdFU_CfGZp_Pr7G9KkM/did.json"
        )

        assert result.status == falcon.HTTP_404
        assert "unknown destination AID" in result.text


def test_asset_routes_are_disabled_by_default(helpers):
    config = didwebing.DidWebsConfig(
        enabled=False, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (agency, _agent, app, client):
        didwebing.loadPublicEnds(app=app, agency=agency, config=config)

        result = client.simulate_get(
            "/dws/EJZ5K7I_TwPOtqK5pLaYk-sSMgdFU_CfGZp_Pr7G9KkM/did.json"
        )

        assert result.status == falcon.HTTP_404


def test_asset_routes_return_generated_material_when_available(helpers, monkeypatch):
    config = enabled_config()

    with helpers.openKeria() as (agency, _agent, app, client):
        aiding.loadEnds(app=app, agency=agency, authn=None)
        didwebing.loadPublicEnds(app=app, agency=agency, config=config)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]
        did = didwebing.didForAid(config, aid)

        monkeypatch.setattr(
            didwebing,
            "matchingDesignatedAliases",
            lambda _hby, _rgy, candidate_aid, candidate: [candidate]
            if candidate_aid == aid and candidate == did
            else [],
        )
        monkeypatch.setattr(
            didwebing,
            "genDesignatedAliases",
            lambda _hby, _rgy, _aid: [did],
        )
        monkeypatch.setattr(
            didwebing,
            "genDesignatedAliasesCesr",
            lambda _hab, _reger, _aid: bytearray(b"alias-cesr"),
        )

        did_result = client.simulate_get(f"/dws/{aid}/did.json")
        cesr_result = client.simulate_get(f"/dws/{aid}/keri.cesr")

        assert did_result.status == falcon.HTTP_200
        did_doc = json.loads(did_result.text)
        assert did_doc["id"] == f"did:web:127.0.0.1%3A3902:dws:{aid}"
        assert did_doc["alsoKnownAs"] == [did]
        assert cesr_result.status == falcon.HTTP_200
        assert cesr_result.content.endswith(b"alias-cesr")
