import base64
import json
from types import SimpleNamespace

import falcon
import pytest
from hio.help import decking

from keri import core
from keri.core import coring, eventing
from keri.kering import ValidationError
from keri.peer import exchanging

from keria.app import syncing
from keria.core import longrunning


def test_multisig_add_adapter(helpers, monkeypatch):
    with helpers.openKeria() as (_, live_agent, _, _):
        assert live_agent.exc.routes["/multisig/add"] is live_agent.syncHandler
        assert isinstance(
            live_agent.syncHandler, syncing.SignifyMultisigAddHandler
        )
        assert live_agent.syncer in live_agent.doers

    signer = core.Signer(raw=b"\x00" * 32)
    next_signer = core.Signer(raw=b"\x01" * 32)
    icp = eventing.incept(
        keys=[signer.verfer.qb64],
        ndigs=[coring.Diger(ser=next_signer.verfer.qb64b).qb64],
    )
    rot = eventing.rotate(
        pre=icp.pre,
        keys=[next_signer.verfer.qb64],
        dig=icp.said,
        ndigs=[coring.Diger(ser=signer.verfer.qb64b).qb64],
    )

    class FakeGroupHab:
        pre = icp.pre
        smids = ["old-a", "old-b"]
        rmids = ["old-a", "old-b", "new-c"]

    monkeypatch.setattr(syncing.habbing, "SignifyGroupHab", FakeGroupHab)
    hab = FakeGroupHab()
    submitted = []
    prepared = []

    class Catalog:
        said = "EManifest"
        raw = b'{"d":"EManifest"}'
        manifest = {
            "d": said,
            "smids": ["old-a", "old-b", "new-c"],
            "rmids": ["old-a", "old-b", "new-c"],
        }

    def prepare(ghab, reger, **kwa):
        prepared.append((ghab, reger, kwa))
        return Catalog()

    monkeypatch.setattr(syncing.syncing, "prepare", prepare)
    monitor = SimpleNamespace(
        submit=lambda oid, typ, metadata: submitted.append((oid, typ, metadata))
    )
    agent = SimpleNamespace(
        hby=SimpleNamespace(
            habs={"group": hab},
            habByName=lambda name: None,
        ),
        rgy=SimpleNamespace(reger=object()),
        monitor=monitor,
    )
    body = dict(
        rot=rot.ked,
        target="new-c",
        smids=["old-a", "old-b", "new-c"],
        rmids=["old-a", "old-b", "new-c"],
        registry="ERegistry",
        credential="ECredential",
        schema="ESchema",
        endpoint={"cid": icp.pre, "role": "agent", "eid": "EAgent"},
        location={"eid": "EAgent", "scheme": "http"},
    )
    req = SimpleNamespace(
        context=SimpleNamespace(agent=agent), get_media=lambda: body
    )
    rep = falcon.Response()

    syncing.MultisigAddCollectionEnd.on_post(req, rep, "group")

    assert rep.status == falcon.HTTP_202
    assert json.loads(rep.data) == {
        "manifest": Catalog.manifest,
        "signable": base64.urlsafe_b64encode(Catalog.raw)
        .rstrip(b"=")
        .decode("utf-8"),
        "operation": "multisig.add.EManifest",
    }
    assert prepared[0][2]["member_pres"] == ["old-a", "old-b", "new-c"]
    assert prepared[0][2]["smids"] == body["smids"]
    assert prepared[0][2]["rmids"] == body["rmids"]
    assert prepared[0][2]["endpoint"] == (icp.pre, "agent", "EAgent")
    assert prepared[0][2]["location"] == ("EAgent", "http")
    assert submitted == [
        (
            "EManifest",
            longrunning.OpTypes.multisig_add,
            {
                "gid": icp.pre,
                "target": "new-c",
                "rotation": rot.said,
                "manifest": "EManifest",
                "role": "source",
            },
        )
    ]

    msgs = decking.Deck()
    agent.hby.habByPre = lambda pre: hab if pre == "new-c" else None
    handler = syncing.SignifyMultisigAddHandler(agent=agent, msgs=msgs)
    exc = exchanging.Exchanger(
        hby=SimpleNamespace(db=SimpleNamespace(kevers={})), handlers=[]
    )
    exc.addHandler(handler)
    assert exc.routes["/multisig/add"] is handler
    with pytest.raises(ValidationError):
        exc.addHandler(syncing.SignifyMultisigAddHandler(agent=agent, msgs=msgs))

    status_monitor = object.__new__(longrunning.Monitor)
    status_monitor.syncer = SimpleNamespace(
        status=lambda manifest: {
            "status": "core-converged",
            "said": "EDelivery",
        }
    )
    status = status_monitor.status(
        longrunning.Op(
            oid="EManifest",
            type=longrunning.OpTypes.multisig_add,
            start="",
            metadata=submitted[0][2],
        )
    )
    assert status.done is False
    assert status.metadata["status"] == "core-converged"
