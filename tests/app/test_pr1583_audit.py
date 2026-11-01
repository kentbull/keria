"""Signify edge artifacts, real Habery reopen, and KERIA member response."""
import json
from types import SimpleNamespace
import falcon
import pytest
from keri.app import habbing, configing
from keri.core import eventing, coring
from keria.app import aiding


def open_persistent(root):
    return habbing.Habery(name="signify-rmids-audit", temp=False, headDirPath=str(root),
                         cf=configing.Configer(name="signify-rmids-audit", temp=True))


def response_roster(hby, pre):
    req = SimpleNamespace(context=SimpleNamespace(agent=SimpleNamespace(hby=hby)))
    rep = falcon.Response()
    aiding.GroupMemberCollectionEnd().on_get(req, rep, pre)
    return [m["aid"] for m in json.loads(rep.data)["rotation"]]


@pytest.mark.parametrize("empty", [False, True])
def test_signify_roster(tmp_path, empty):
    hby = open_persistent(tmp_path)
    try:
        with habbing.openHby(name="edge-rmids-audit") as edge:
            members = [edge.makeHab(name=f"m{i}") for i in range(3)]
            for m in members:
                hby.makeSignifyHab(name=m.name, serder=m.kever.serder,
                                  sigers=m.sign(ser=m.kever.serder.raw))
            smids = [members[0].pre]
            rmids = [] if empty else [m.pre for m in members]
            serder = eventing.incept(keys=[members[0].kever.verfers[0].qb64],
                ndigs=[] if empty else [m.kever.ndigers[0].qb64 for m in members],
                isith="1", nsith="0" if empty else "2", code=coring.MtrDex.Blake3_256)
            group = hby.makeSignifyGroupHab(name="group", mhab=hby.habs[smids[0]],
                smids=smids, rmids=rmids, serder=serder, sigers=members[0].sign(ser=serder.raw))
            pre = group.pre
            assert len(group.kever.ndigers) == len(rmids)
            assert response_roster(hby, pre) == rmids, "API must respect explicit empty roster"
    finally:
        hby.close()
    hby = open_persistent(tmp_path)
    try:
        assert isinstance(hby.habs[pre], habbing.SignifyGroupHab)
        assert response_roster(hby, pre) == rmids
        assert len(hby.habs[pre].kever.ndigers) == len(rmids)
        assert hby.habs[pre].rmids == rmids, "reload must preserve stored rotation roster"
    finally:
        hby.close()
