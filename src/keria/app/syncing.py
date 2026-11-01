# -*- encoding: utf-8 -*-
"""
KERIA adapter for the experimental multisig add state synchronization flow.
"""

import base64
import json

import falcon

from keri import syncing
from keri.app import habbing
from keri.core import serdering
from keri.kering import ValidationError

from keria.core import httping, longrunning


MULTISIG_ADD_ROUTE = "/identifiers/{name}/multisig/add"


def loadEnds(app):
    app.add_route(MULTISIG_ADD_ROUTE, MultisigAddCollectionEnd())


class SignifyMultisigAddHandler(syncing.MultisigAddHandler):
    """Bind the KERIpy handler to one already authenticated KERIA Agent."""

    def __init__(self, agent, msgs=None):
        self.agent = agent
        super().__init__(msgs=msgs)

    def _bound_work(self, serder, attachments=None, essr=None):
        work = self._work(serder=serder, attachments=attachments, essr=essr)
        if self.agent.hby.habByPre(work["target"]) is None:
            raise syncing.SyncError(
                f"target {work['target']} is not managed by this Agent"
            )
        return work

    def verify(self, serder, attachments=None, essr=None):
        self._bound_work(serder=serder, attachments=attachments, essr=essr)
        return True

    def handle(self, serder, attachments=None, essr=None):
        work = self._bound_work(
            serder=serder, attachments=attachments, essr=essr
        )

        if work["op"] == "deliver":
            catalog = work["catalog"]
            self.agent.monitor.submit(
                catalog.said,
                longrunning.OpTypes.multisig_add,
                metadata=dict(
                    gid=catalog.gid,
                    target=catalog.target,
                    rotation=catalog.rotation["said"],
                    manifest=catalog.said,
                    role="target",
                ),
            )
        self.msgs.append(work)


class MultisigAddCollectionEnd:
    """Prepare one bounded multisig add catalog before rotating the group."""

    @staticmethod
    def on_post(req, rep, name):
        agent = req.context.agent
        hab = (
            agent.hby.habs[name]
            if name in agent.hby.habs
            else agent.hby.habByName(name)
        )
        if hab is None:
            raise falcon.HTTPNotFound(
                description=f"alias or prefix {name} is not a valid identifier"
            )
        if not isinstance(hab, habbing.SignifyGroupHab):
            raise falcon.HTTPBadRequest(
                description=f"hab for alias or prefix {name} is not a multisig group"
            )

        body = req.get_media()
        rot = httping.getRequiredParam(body, "rot")
        target = httping.getRequiredParam(body, "target")
        smids = httping.getRequiredParam(body, "smids")
        rmids = httping.getRequiredParam(body, "rmids")
        registry = httping.getRequiredParam(body, "registry")
        credential = httping.getRequiredParam(body, "credential")
        schema = httping.getRequiredParam(body, "schema")
        endpoint = httping.getRequiredParam(body, "endpoint")
        location = httping.getRequiredParam(body, "location")

        try:
            endpoint = _coordinates(endpoint, ("cid", "role", "eid"), "endpoint")
            location = _coordinates(location, ("eid", "scheme"), "location")
            rotation = serdering.SerderKERI(sad=rot)
            if rotation.pre != hab.pre:
                raise ValidationError(
                    f"rotation prefix {rotation.pre} does not match group {hab.pre}"
                )

            _validate_added_member(hab.smids, smids, target)
            prior_rmids = hab.smids if hab.rmids is None else hab.rmids
            if target not in prior_rmids:
                raise ValidationError(
                    "target must already be a precommitted rotation member"
                )
            if rmids != list(prior_rmids):
                raise ValidationError(
                    "rmids must preserve the precommitted rotation members"
                )

            catalog = syncing.prepare(
                hab,
                agent.rgy.reger,
                target=target,
                rotation=rotation,
                registry=registry,
                credential=credential,
                schema=schema,
                member_pres=list(dict.fromkeys(smids + rmids)),
                smids=smids,
                rmids=rmids,
                endpoint=endpoint,
                location=location,
            )
        except (TypeError, ValueError, ValidationError) as ex:
            raise falcon.HTTPBadRequest(description=str(ex))

        metadata = dict(
            gid=hab.pre,
            target=target,
            rotation=rotation.said,
            manifest=catalog.said,
            role="source",
        )
        agent.monitor.submit(
            catalog.said, longrunning.OpTypes.multisig_add, metadata=metadata
        )

        signable = base64.urlsafe_b64encode(catalog.raw).rstrip(b"=").decode("utf-8")
        rep.status = falcon.HTTP_202
        rep.content_type = falcon.MEDIA_JSON
        rep.data = json.dumps(
            dict(
                manifest=catalog.manifest,
                signable=signable,
                operation=f"{longrunning.OpTypes.multisig_add}.{catalog.said}",
            )
        ).encode("utf-8")


def _validate_added_member(prior, proposed, target):
    if not isinstance(proposed, list):
        raise ValidationError("smids must be an ordered list")
    if proposed.count(target) != 1 or len(proposed) != len(prior) + 1:
        raise ValidationError("smids must add target exactly once")
    if [pre for pre in proposed if pre != target] != list(prior):
        raise ValidationError("smids must preserve the prior member order")


def _coordinates(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValidationError(f"{name} must contain exactly {list(fields)}")
    if not all(isinstance(value[field], str) and value[field] for field in fields):
        raise ValidationError(f"{name} coordinates must be non-empty strings")
    return tuple(value[field] for field in fields)
