# -*- encoding: utf-8 -*-
"""
KERIA did:webs dynamic asset endpoint tests.
"""

import json

import falcon
import pytest
from hio.base import doing
from keri.app import configing
from keri.core import coring, eventing, indexing, parsing, serdering
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


def assert_agent_signed_envelope(agent, envelope, request):
    rserder = serdering.SerderKERI(sad=envelope["rpy"])
    siger = indexing.Siger(qb64=envelope["sigs"][0])
    assert rserder.ked["r"] == didwebing.DWS_SIG_ROUTE
    assert rserder.ked["a"]["d"] == request.d
    assert rserder.ked["a"]["aid"] == request.aid
    assert agent.agentHab.kever.verfers[0].verify(sig=siger.raw, ser=rserder.raw)


def test_agent_adds_publisher_doers_when_did_webs_auto_issue_enabled(helpers):
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
        assert isinstance(
            agent.didWebsAgentPublisher, didwebing.DidWebsAgentPublisher
        )
        assert isinstance(
            agent.didWebsManagedPublisher, didwebing.DidWebsAidPublisher
        )
        assert agent.didWebsAgentPublisher in agent.doers
        assert agent.didWebsManagedPublisher in agent.doers
        assert agent.didWebsManagedPublisher.signalCues is agent.signalCues


def test_agent_owns_agency_db_publication_work_store(helpers):
    with helpers.openKeria() as (agency, agent, _app, _client):
        assert agent.adb is agency.adb
        assert agent.adb.dwspub is agency.adb.dwspub
        assert agent.adb.dwsreq is agency.adb.dwsreq

        record = didwebing.DidWebsSetupRecord(
            d="request-said",
            type=didwebing.DWS_REG_CREATE,
            action=didwebing.DWS_ACT_CRT_REG,
            agent=agent.agentHab.pre,
            aid="managed-aid",
            name="aid1",
            did="did:webs:example.com:dws:managed-aid",
            registryName="registry",
            schema=didwebing.DES_ALIASES_SCHEMA,
            credentialData={},
            rules={},
            didJsonUrl="https://example.com/dws/managed-aid/did.json",
            keriCesrUrl="https://example.com/dws/managed-aid/keri.cesr",
            dt="2025-01-01T00:00:00.000000+00:00",
        )
        agent.adb.dwsreq.pin(keys=(record.d,), val=record)

        assert agency.adb.dwsreq.get(keys=(record.d,)) == record


def test_managed_publisher_requires_signal_cues(helpers):
    config = didwebing.DidWebsConfig(enabled=True, domain="127.0.0.1")

    with helpers.openKeria() as (_agency, agent, _app, _client):
        with pytest.raises(ValueError, match="signalCues is required"):
            didwebing.DidWebsAidPublisher(agent=agent, config=config)


def test_aid_creation_tracks_managed_publication_work(helpers):
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

    with helpers.openKeria(cf=cf) as (_agency, agent, app, client):
        aiding.loadEnds(app=app, agency=_agency, authn=None)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]
        record = agent.adb.dwspub.get(keys=(aid,))

        assert record is not None
        assert record.aid == aid
        assert record.name == "aid1"
        assert record.agent == agent.agentHab.pre
        assert record.did == f"did:webs:127.0.0.1%3A3902:dws:{aid}"
        assert record.registryName == didwebing.registryName(agent.didWebsConfig, aid)
        assert record.state == didwebing.DWS_PUB_SIGREQ
        assert list(agent.didWebsManagedPublisher.workCues) == [
            {"name": "aid1", "aid": aid}
        ]

        didwebing.trackManagedAidPublication(agent, "aid1", aid)
        records = list(agent.adb.dwspub.getItemIter())
        assert len(records) == 1


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
        didwebing.trackManagedAidPublication(agent, "aid1", aid, config=config)

        result = client.simulate_get(f"/didwebs/{aid}")

        assert result.status == falcon.HTTP_200
        assert result.json["debug"] is True
        assert result.json["informational"] is True
        assert "may be removed" in result.json["notice"]
        assert result.json["available"] is True
        assert result.json["missing"] == []
        assert result.json["designatedAliasAvailable"] is False
        assert result.json["optionalMissing"] == ["designated_alias_acdc"]
        assert (
            result.json["publicationState"]
            == didwebing.DWS_PUB_SIGREQ
        )
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


def test_status_route_reports_managed_aid_ready_for_client_before_endrole(
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
        didwebing.trackManagedAidPublication(agent, "aid1", aid, config=config)

        result = client.simulate_get(f"/didwebs/{aid}")
        assert result.status == falcon.HTTP_200
        assert (
            result.json["publicationState"]
            == didwebing.DWS_PUB_SIGREQ
        )

        rpy = helpers.endrole(aid, agent.agentHab.pre)
        sigs = helpers.sign(salt, 0, 0, rpy.raw)
        body = dict(rpy=rpy.ked, sigs=sigs)
        res = client.simulate_post(path="/identifiers/aid1/endroles", json=body)
        assert res.status == falcon.HTTP_202

        result = client.simulate_get(f"/didwebs/{aid}")
        assert result.status == falcon.HTTP_200
        assert (
            result.json["publicationState"]
            == didwebing.DWS_PUB_SIGREQ
        )


def test_status_route_projects_durable_publication_state_without_registry_scan(
    helpers, monkeypatch
):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (_agency, agent, app, client):
        aiding.loadEnds(app=app, agency=_agency, authn=None)
        didwebing.loadAdminEnds(app=app, config=config)

        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]
        didwebing.trackManagedAidPublication(agent, "aid1", aid, config=config)
        record = agent.adb.dwspub.get(keys=(aid,))
        record.state = didwebing.DWS_PUB_REGWAIT
        agent.adb.dwspub.pin(keys=(aid,), val=record)

        def fail_registry_scan(_name):
            raise AssertionError("debug status should not inspect registry state")

        monkeypatch.setattr(agent.rgy, "registryByName", fail_registry_scan)

        result = client.simulate_get(f"/didwebs/{aid}")

        assert result.status == falcon.HTTP_200
        assert result.json["publicationState"] == didwebing.DWS_PUB_REGWAIT


def test_publisher_waits_for_agent_delegation_source_seal(helpers):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (_agency, agent, _app, _client):
        publisher = didwebing.DidWebsAgentPublisher(agent=agent, config=config)

        publisher.recur(0)

        assert publisher.state == didwebing.DWS_PUB_DELWAIT
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
        publisher = didwebing.DidWebsAgentPublisher(agent=agent, config=config)

        done = False
        for _ in range(10):
            done = publisher.recur(0)
            if done:
                break

        aid = agent.agentHab.pre
        status = didwebing.statusForAid(agent, config, aid)
        registry = agent.rgy.registryByName(didwebing.registryName(config, aid))
        credentials = didwebing.getSelfIssuedAcdcs(aid, agent.rgy.reger)

        assert publisher.state == didwebing.DWS_PUB_RDY
        assert done is True
        assert status["publicationState"] == didwebing.DWS_PUB_RDY
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
        return didwebing.DWS_PUB_RDY

    monkeypatch.setattr(didwebing, "ensureAgentDesignatedAlias", publish_ready)

    with helpers.openKeria(cf=cf) as (_agency, agent, _app, _client):
        publisher = agent.didWebsAgentPublisher
        assert isinstance(publisher, didwebing.DidWebsAgentPublisher)
        assert publisher in agent.doers

        doist = doing.Doist(tock=0.03125)
        deeds = doist.enter(doers=[agent])
        try:
            for _ in range(3):
                doist.recur(deeds=deeds)

            assert publisher.done is True
            assert publisher not in agent.doers
            assert agent.didWebsAgentPublisher is None
            assert agent.didWebsManagedPublisher in agent.doers
            assert all(deed[2] is not publisher for deed in agent.deeds)
            assert len(calls) == 1
        finally:
            doist.exit(deeds=deeds)


def test_managed_publisher_creates_registry_signing_request_without_endrole(
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
        didwebing.trackManagedAidPublication(agent, "aid1", aid, config=config)

        stream = iter(agent.sseBroadcasterDoer.broadcaster.subscribe())
        assert next(stream) == b"retry: 5000\n\n"

        publisher = didwebing.DidWebsAidPublisher(
            agent=agent, config=config, signalCues=agent.signalCues
        )
        publisher.recur(0)
        assert publisher.signalCues is agent.signalCues
        assert len(agent.signalCues) == 1
        signal = list(agent.signalCues)[0]
        assert signal["event"] == didwebing.DWS_REG_CREATE
        assert signal["route"] == didwebing.DWS_SIG_ROUTE
        assert next(stream) == b""

        agent.sseBroadcasterDoer.recur(0)
        frame = next(stream).decode("utf-8")

        requests = list(didwebing.iterSigningRequests(agent, aid=aid))
        assert len(requests) == 1
        request = requests[0]
        assert agent.adb.dwsreq.get(keys=(request.d,)) == request
        assert not hasattr(agent, "didWebsSigningRequests")
        assert f"id: {request.d}" in frame
        assert f"event: {didwebing.DWS_REG_CREATE}" in frame
        sse_payload = json.loads(frame.split("data: ", 1)[1].split("\n\n", 1)[0])
        assert_agent_signed_envelope(agent, sse_payload, request)
        assert request.type == didwebing.DWS_REG_CREATE
        assert request.action == didwebing.DWS_ACT_CRT_REG
        assert request.agent == agent.agentHab.pre
        assert request.aid == aid
        assert request.name == "aid1"
        assert request.did == f"did:webs:127.0.0.1%3A3902:dws:{aid}"
        assert request.registryName == didwebing.registryName(config, aid)
        assert request.schema == didwebing.DES_ALIASES_SCHEMA
        assert request.credentialData["ids"] == [
            f"did:web:127.0.0.1%3A3902:dws:{aid}",
            f"did:webs:127.0.0.1%3A3902:dws:{aid}",
        ]
        assert agent.rgy.registryByName(didwebing.registryName(config, aid)) is None
        assert publisher.states[aid] == didwebing.DWS_PUB_SIGREQ

        envelope = didwebing.signingRequestEnvelope(agent, request)
        assert_agent_signed_envelope(agent, envelope, request)

        status = client.simulate_get(f"/didwebs/{aid}")
        assert status.status == falcon.HTTP_200
        assert status.json["signingRequest"]["id"] == request.d
        assert status.json["signingRequest"]["action"] == request.action

        pending = client.simulate_get("/didwebs/signing/requests")
        assert pending.status == falcon.HTTP_200
        assert len(pending.json["requests"]) == 1
        assert pending.json["requests"][0]["d"] == request.d
        assert_agent_signed_envelope(
            agent, pending.json["requests"][0]["envelope"], request
        )

        fetched = client.simulate_get(f"/didwebs/signing/requests/{request.d}")
        assert fetched.status == falcon.HTTP_200
        assert fetched.json["d"] == request.d


def test_managed_publisher_enqueues_ready_signal(helpers, monkeypatch):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (_agency, agent, app, client):
        aiding.loadEnds(app=app, agency=_agency, authn=None)
        op = helpers.createAid(client, "aid1", b"0123456789abcdef")
        aid = op["response"]["i"]
        didwebing.trackManagedAidPublication(agent, "aid1", aid, config=config)
        monkeypatch.setattr(
            didwebing,
            "ensureManagedDesignatedAlias",
            lambda _agent, _config, _name, _aid: (didwebing.DWS_PUB_RDY, None),
        )

        stream = iter(agent.sseBroadcasterDoer.broadcaster.subscribe())
        assert next(stream) == b"retry: 5000\n\n"

        publisher = didwebing.DidWebsAidPublisher(
            agent=agent, config=config, signalCues=agent.signalCues
        )
        publisher.recur(0)
        assert publisher.signalCues is agent.signalCues
        assert len(agent.signalCues) == 1
        signal = list(agent.signalCues)[0]
        assert signal["event"] == didwebing.DWS_RDY_EVT
        assert signal["route"] == didwebing.DWS_RDY_ROUTE
        assert signal["event_id"] == aid
        record = agent.adb.dwspub.get(keys=(aid,))
        assert record.state == didwebing.DWS_PUB_RDY
        assert aid not in publisher.active
        assert next(stream) == b""

        agent.sseBroadcasterDoer.recur(0)
        frame = next(stream).decode("utf-8")
        assert f"id: {aid}" in frame
        assert f"event: {didwebing.DWS_RDY_EVT}" in frame

        envelope = json.loads(frame.split("data: ", 1)[1].split("\n\n", 1)[0])
        rserder = serdering.SerderKERI(sad=envelope["rpy"])
        siger = indexing.Siger(qb64=envelope["sigs"][0])
        assert rserder.ked["r"] == didwebing.DWS_RDY_ROUTE
        assert rserder.ked["a"]["agent"] == agent.agentHab.pre
        assert rserder.ked["a"]["aid"] == aid
        assert agent.agentHab.kever.verfers[0].verify(sig=siger.raw, ser=rserder.raw)
        assert len(agent.signalCues) == 0

        publisher.recur(10)
        assert len(agent.signalCues) == 0


def test_managed_publisher_reuses_existing_registry_request(helpers):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (_agency, agent, app, client):
        aiding.loadEnds(app=app, agency=_agency, authn=None)
        salt = b"0123456789abcdef"
        op = helpers.createAid(client, "aid1", salt)
        aid = op["response"]["i"]
        didwebing.trackManagedAidPublication(agent, "aid1", aid, config=config)

        publisher = didwebing.DidWebsAidPublisher(
            agent=agent, config=config, signalCues=agent.signalCues
        )
        publisher.recur(0)
        publisher.recur(1)

        restarted = didwebing.DidWebsAidPublisher(
            agent=agent, config=config, signalCues=agent.signalCues
        )
        assert restarted.active == {aid: "aid1"}
        restarted.recur(0)

        requests = list(didwebing.iterSigningRequests(agent, aid=aid))
        assert len(requests) == 1
        assert requests[0].action == didwebing.DWS_ACT_CRT_REG


def test_managed_publisher_creates_da_request_after_registry_complete(
    helpers, monkeypatch
):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (_agency, agent, app, client):
        aiding.loadEnds(app=app, agency=_agency, authn=None)
        salt = b"0123456789abcdef"
        op = helpers.createAid(client, "aid1", salt)
        aid = op["response"]["i"]
        didwebing.trackManagedAidPublication(agent, "aid1", aid, config=config)

        registry = agent.rgy.makeRegistry(
            name=didwebing.registryName(config, aid), prefix=aid, noBackers=True
        )
        monkeypatch.setattr(didwebing, "registryComplete", lambda _agent, _reg: True)

        publisher = didwebing.DidWebsAidPublisher(
            agent=agent, config=config, signalCues=agent.signalCues
        )
        publisher.recur(0)

        requests = list(didwebing.iterSigningRequests(agent, aid=aid))
        assert len(requests) == 1
        request = requests[0]
        assert registry is not None
        assert request.type == didwebing.DWS_DA_ISSUE
        assert request.action == didwebing.DWS_ACT_ISS_DA
        assert request.registryName == didwebing.registryName(config, aid)
        assert request.registryId == registry.regk
        assert publisher.states[aid] == didwebing.DWS_PUB_SIGREQ


def test_managed_publisher_waits_when_registry_incomplete(helpers, monkeypatch):
    config = didwebing.DidWebsConfig(
        enabled=True, domain="127.0.0.1", host="127.0.0.1", port=3902, path="dws"
    )

    with helpers.openKeria() as (_agency, agent, app, client):
        aiding.loadEnds(app=app, agency=_agency, authn=None)
        salt = b"0123456789abcdef"
        op = helpers.createAid(client, "aid1", salt)
        aid = op["response"]["i"]
        didwebing.trackManagedAidPublication(agent, "aid1", aid, config=config)

        agent.rgy.makeRegistry(
            name=didwebing.registryName(config, aid), prefix=aid, noBackers=True
        )
        monkeypatch.setattr(didwebing, "registryComplete", lambda _agent, _reg: False)

        publisher = didwebing.DidWebsAidPublisher(
            agent=agent, config=config, signalCues=agent.signalCues
        )
        publisher.recur(0)

        assert publisher.states[aid] == didwebing.DWS_PUB_REGWAIT
        assert list(didwebing.iterSigningRequests(agent, aid=aid)) == []


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
