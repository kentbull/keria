# -*- encoding: utf-8 -*-
"""
KERIA did:webs dynamic asset endpoint tests.
"""

import json

import falcon
from hio.base import doing
from keri.app import configing
from keri.core import coring, eventing, parsing
from keri.core.eventing import SealEvent
from keri.vc import proving

from keria.app import aiding, didwebing


def add_agent_delegation_source_seal(agent, helpers):
    controller, signers = helpers.incept(
        bran=b"0123456789abcdefghijk",
        stem="signify:controller",
        pidx=0,
    )
    assert controller.pre == agent.caid
    seal = {"i": agent.agentHab.pre, "s": "0", "d": agent.agentHab.kever.serder.said}
    ixn = eventing.interact(
        pre=agent.caid,
        sn="1",
        dig=agent.hby.kevers[agent.caid].serder.said,
        data=[seal],
    )
    sigers = [signers[0].sign(ser=ixn.raw, index=0)]
    ims = eventing.messagize(ixn, sigers=sigers)
    parsing.Parser(kvy=agent.hby.kvy).parseOne(ims=ims)
    aiding.AgentResourceEnd.anchorSeals(agent, ixn)


def test_config_from_sources_prefers_env(monkeypatch):
    monkeypatch.setenv("KERIA_DID_WEBS_ENABLED", "true")
    monkeypatch.setenv(
        "KERIA_DID_WEBS_PUBLIC_BASE_URL", "http://example.com:3902/custom"
    )
    monkeypatch.setenv("KERIA_DID_WEBS_META", "1")
    monkeypatch.setenv("KERIA_DID_WEBS_AUTO_ISSUE", "false")

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
    assert config.auto_issue is False


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
    assert config.auto_issue is True


def test_embedded_designated_alias_schema_pins_with_expected_said(helpers):
    with helpers.openKeria() as (_agency, agent, _app, _client):
        schemer = didwebing.pinDesignatedAliasesSchema(agent.hby)

        assert schemer.said == didwebing.DES_ALIASES_SCHEMA
        assert agent.hby.db.schema.get(keys=(didwebing.DES_ALIASES_SCHEMA,)) is not None


def test_agent_adds_publisher_doer_when_did_webs_auto_issue_enabled(helpers):
    cf = configing.Configer(name="keria", temp=True, reopen=True, clear=True)
    cf.put(
        {
            "did_webs": {
                "enabled": True,
                "domain": "127.0.0.1",
                "host": "127.0.0.1",
                "port": 3902,
                "path": "dws",
            }
        }
    )

    with helpers.openKeria(cf=cf) as (_agency, agent, _app, _client):
        assert agent.didWebsConfig.enabled is True
        assert agent.didWebsConfig.auto_issue is True
        assert isinstance(agent.didWebsPublisher, didwebing.DidWebsPublisherDoer)
        assert agent.didWebsPublisher in agent.doers


def test_status_route_reports_optional_missing_alias_acdc(
    helpers, mockHelpingNowIso8601
):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (agency, agent, app, client):
        aiding.loadEnds(app=app, agency=agency, authn=None)
        didwebing.loadAdminEnds(app=app, config=config)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]

        result = client.simulate_get(f"/didwebs/{aid}")

        assert result.status == falcon.HTTP_200
        assert result.json["available"] is True
        assert result.json["missing"] == []
        assert result.json["designatedAliasAvailable"] is False
        assert result.json["optionalMissing"] == ["designated_alias_acdc"]
        assert result.json["publicationState"] == didwebing.PUBLICATION_DISABLED
        assert result.json["did"] == f"did:webs:127.0.0.1%3A3902:dws:{aid}"
        assert result.json["didJsonUrl"] == f"http://127.0.0.1:3902/dws/{aid}/did.json"
        assert (
            result.json["keriCesrUrl"] == f"http://127.0.0.1:3902/dws/{aid}/keri.cesr"
        )
        assert (
            result.json["registryName"] == f"{didwebing.DEFAULT_REGISTRY_PREFIX}:{aid}"
        )
        assert result.json["schema"] == didwebing.DES_ALIASES_SCHEMA
        assert result.json["credentialData"] == {
            "d": "",
            "dt": "2021-06-27T21:26:21.233257+00:00",
            "ids": [
                f"did:web:127.0.0.1%3A3902:dws:{aid}",
                f"did:webs:127.0.0.1%3A3902:dws:{aid}",
            ],
        }


def test_status_route_reports_managed_aid_ready_for_client_after_endrole(
    helpers, mockHelpingNowIso8601
):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (_agency, agent, app, client):
        aiding.loadEnds(app=app, agency=_agency, authn=None)
        didwebing.loadAdminEnds(app=app, config=config)

        salt = b"0123456789abcdef"
        op = helpers.createAid(client, "aid1", salt)
        aid = op["response"]["i"]

        result = client.simulate_get(f"/didwebs/{aid}")
        assert result.status == falcon.HTTP_200
        assert result.json["publicationState"] == didwebing.PUBLICATION_DISABLED

        rpy = helpers.endrole(aid, agent.agentHab.pre)
        sigs = helpers.sign(salt, 0, 0, rpy.raw)
        body = dict(rpy=rpy.ked, sigs=sigs)
        res = client.simulate_post(path="/identifiers/aid1/endroles", json=body)
        assert res.status == falcon.HTTP_202

        result = client.simulate_get(f"/didwebs/{aid}")
        assert result.status == falcon.HTTP_200
        assert (
            result.json["publicationState"]
            == didwebing.PUBLICATION_CLIENT_SIGNATURE_REQUIRED
        )


def test_publisher_waits_for_agent_delegation_source_seal(helpers):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (_agency, agent, _app, _client):
        publisher = didwebing.DidWebsPublisherDoer(agent=agent, config=config)

        publisher.recur(0)

        assert publisher.state == didwebing.PUBLICATION_WAITING_DELEGATION
        assert (
            agent.rgy.registryByName(
                didwebing.registryName(config, agent.agentHab.pre)
            )
            is None
        )


def test_publisher_self_issues_agent_designated_alias_acdc(helpers):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (_agency, agent, _app, _client):
        add_agent_delegation_source_seal(agent, helpers)
        publisher = didwebing.DidWebsPublisherDoer(agent=agent, config=config)

        done = False
        for _ in range(10):
            done = publisher.recur(0)
            if done:
                break

        aid = agent.agentHab.pre
        status = didwebing.statusForAid(agent, config, aid)
        registry = agent.rgy.registryByName(didwebing.registryName(config, aid))
        credentials = didwebing.getSelfIssuedAcdcs(aid, agent.rgy.reger)

        assert publisher.state == didwebing.PUBLICATION_READY
        assert done is True
        assert status["publicationState"] == didwebing.PUBLICATION_READY
        assert status["designatedAliasAvailable"] is True
        assert registry is not None
        assert len(credentials) == 1
        assert didwebing.didJson(agent, config, aid)["alsoKnownAs"] == status[
            "credentialData"
        ]["ids"]
        assert credentials[0].qb64.encode("utf-8") in didwebing.keriCesr(
            agent, config, aid
        )

        registry_count = len(list(agent.rgy.reger.regs.getItemIter()))
        credential_count = len(didwebing.getSelfIssuedAcdcs(aid, agent.rgy.reger))

        for _ in range(3):
            publisher.recur(0)

        assert len(list(agent.rgy.reger.regs.getItemIter())) == registry_count
        assert (
            len(didwebing.getSelfIssuedAcdcs(aid, agent.rgy.reger))
            == credential_count
        )


def test_agent_removes_did_webs_publisher_after_success(helpers, monkeypatch):
    cf = configing.Configer(name="keria", temp=True, reopen=True, clear=True)
    cf.put(
        {
            "did_webs": {
                "enabled": True,
                "domain": "127.0.0.1",
                "host": "127.0.0.1",
                "port": 3902,
                "path": "dws",
            }
        }
    )
    calls = []

    def publish_ready(_agent, _config):
        calls.append((_agent, _config))
        return didwebing.PUBLICATION_READY

    monkeypatch.setattr(didwebing, "ensureAgentDesignatedAlias", publish_ready)

    with helpers.openKeria(cf=cf) as (_agency, agent, _app, _client):
        publisher = agent.didWebsPublisher
        assert isinstance(publisher, didwebing.DidWebsPublisherDoer)
        assert publisher in agent.doers

        doist = doing.Doist(tock=0.03125)
        deeds = doist.enter(doers=[agent])
        try:
            for _ in range(3):
                doist.recur(deeds=deeds)

            assert publisher.done is True
            assert publisher not in agent.doers
            assert agent.didWebsPublisher is None
            assert all(deed[2] is not publisher for deed in agent.deeds)
            assert len(calls) == 1
        finally:
            doist.exit(deeds=deeds)


def test_asset_routes_return_generated_material_without_alias_acdc(helpers):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (agency, agent, app, client):
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

        identifier = client.simulate_get(f"/identifiers/{aid}")
        assert identifier.status == falcon.HTTP_200


def test_asset_routes_reject_unknown_aid(helpers):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (agency, agent, app, client):
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

    with helpers.openKeria() as (agency, agent, app, client):
        didwebing.loadPublicEnds(app=app, agency=agency, config=config)

        result = client.simulate_get(
            "/dws/EJZ5K7I_TwPOtqK5pLaYk-sSMgdFU_CfGZp_Pr7G9KkM/did.json"
        )

        assert result.status == falcon.HTTP_404


def test_asset_routes_return_generated_material_when_available(helpers, monkeypatch):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (agency, agent, app, client):
        aiding.loadEnds(app=app, agency=agency, authn=None)
        didwebing.loadPublicEnds(app=app, agency=agency, config=config)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]

        monkeypatch.setattr(
            didwebing,
            "matchingDesignatedAliases",
            lambda _hby, _rgy, _aid, _did: [_did],
        )
        monkeypatch.setattr(
            didwebing,
            "genDesignatedAliases",
            lambda _hby, _rgy, _aid: [didwebing.didForAid(config, aid)],
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
        assert did_doc["alsoKnownAs"] == [f"did:webs:127.0.0.1%3A3902:dws:{aid}"]
        assert cesr_result.status == falcon.HTTP_200
        assert cesr_result.content.endswith(b"alias-cesr")


def test_asset_routes_return_material_for_stored_agent_designated_alias_acdc(
    helpers,
):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (agency, agent, app, client):
        aid = agent.agentHab.pre
        agency.adb.ctrl.pin(keys=(aid,), val=coring.Prefixer(qb64=agent.caid))
        didwebing.loadPublicEnds(app=app, agency=agency, config=config)

        controller, signers = helpers.incept(
            bran=b"0123456789abcdefghijk",
            stem="signify:controller",
            pidx=0,
        )
        assert controller.pre == agent.caid
        seal = {"i": aid, "s": "0", "d": agent.agentHab.kever.serder.said}
        ixn = eventing.interact(
            pre=agent.caid,
            sn="1",
            dig=agent.hby.kevers[agent.caid].serder.said,
            data=[seal],
        )
        sigers = [signers[0].sign(ser=ixn.raw, index=0)]
        ims = eventing.messagize(ixn, sigers=sigers)
        parsing.Parser(kvy=agent.hby.kvy).parseOne(ims=ims)
        aiding.AgentResourceEnd.anchorSeals(agent, ixn)

        registry = agent.rgy.makeRegistry(
            name=didwebing.registryName(config, aid), prefix=aid, noBackers=True
        )
        seal = SealEvent(registry.regk, "0", registry.regd)._asdict()
        agent.agentHab.interact(data=[seal])
        seqner = coring.Seqner(sn=agent.agentHab.kever.sn)
        saider = coring.Saider(qb64=agent.agentHab.kever.serder.said)
        registry.anchorMsg(
            pre=registry.regk, regd=registry.regd, seqner=seqner, saider=saider
        )
        agent.rgy.processEscrows()

        data = didwebing.aliasCredentialData(config, aid)
        creder = proving.credential(
            issuer=aid,
            schema=didwebing.DES_ALIASES_SCHEMA,
            data=data,
            status=registry.regk,
            rules=didwebing.DES_ALIASES_RULES,
        )
        issuer = registry.issue(said=creder.said)
        seal = SealEvent(issuer.pre, "0", issuer.said)._asdict()
        agent.agentHab.interact(data=[seal])
        seqner = coring.Seqner(sn=agent.agentHab.kever.sn)
        saider = coring.Saider(qb64=agent.agentHab.kever.serder.said)
        registry.anchorMsg(
            pre=issuer.pre, regd=issuer.said, seqner=seqner, saider=saider
        )
        agent.rgy.processEscrows()

        agent.rgy.reger.logCred(creder, agent.agentHab.kever.prefixer, seqner, saider)
        credential_said = coring.Saider(qb64=creder.said)
        agent.rgy.reger.saved.pin(keys=credential_said.qb64b, val=credential_said)
        agent.rgy.reger.issus.add(keys=aid, val=credential_said)
        agent.rgy.reger.schms.add(
            keys=didwebing.DES_ALIASES_SCHEMA.encode("utf-8"), val=credential_said
        )

        did_result = client.simulate_get(f"/dws/{aid}/did.json")
        cesr_result = client.simulate_get(f"/dws/{aid}/keri.cesr")

        assert did_result.status == falcon.HTTP_200
        assert did_result.json["id"] == f"did:web:127.0.0.1%3A3902:dws:{aid}"
        assert did_result.json["alsoKnownAs"] == data["ids"]
        assert cesr_result.status == falcon.HTTP_200
        assert creder.said.encode("utf-8") in cesr_result.content


def test_asset_routes_can_serve_agent_aid_when_available(helpers, monkeypatch):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (agency, agent, app, client):
        agency.adb.ctrl.pin(
            keys=(agent.agentHab.pre,), val=coring.Prefixer(qb64=agent.caid)
        )
        didwebing.loadPublicEnds(app=app, agency=agency, config=config)

        monkeypatch.setattr(
            didwebing,
            "matchingDesignatedAliases",
            lambda _hby, _rgy, _aid, _did: [_did],
        )
        monkeypatch.setattr(
            didwebing,
            "genDesignatedAliases",
            lambda _hby, _rgy, _aid: [didwebing.didForAid(config, agent.agentHab.pre)],
        )
        monkeypatch.setattr(
            didwebing,
            "genDesignatedAliasesCesr",
            lambda _hab, _reger, _aid: bytearray(b"agent-alias-cesr"),
        )

        did_result = client.simulate_get(f"/dws/{agent.agentHab.pre}/did.json")
        cesr_result = client.simulate_get(f"/dws/{agent.agentHab.pre}/keri.cesr")

        assert did_result.status == falcon.HTTP_200
        assert (
            did_result.json["id"]
            == f"did:web:127.0.0.1%3A3902:dws:{agent.agentHab.pre}"
        )
        assert cesr_result.status == falcon.HTTP_200
        assert cesr_result.content.endswith(b"agent-alias-cesr")
