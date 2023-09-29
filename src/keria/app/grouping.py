# -*- encoding: utf-8 -*-
"""
KERIA
keria.app.grouping module

"""
import json

import falcon
from keri.app import habbing
from keri.core import coring, eventing

from keria.core import httping


def loadEnds(app):
    msrCol = MultisigRequestCollectionEnd()
    app.add_route("/identifiers/{name}/multisig/request", msrCol)
    msrRes = MultisigRequestResourceEnd()
    app.add_route("/multisig/request/{said}", msrRes)


class MultisigRequestCollectionEnd:
    """ Collection endpoint class for creating mulisig exn requests from """

    @staticmethod
    def on_post(req, rep, name):
        """ POST method for multisig request collection

        Parameters:
            req (falcon.Request): HTTP request object
            rep (falcon.Response): HTTP response object
            name (str): AID of Hab to load credentials for

        """
        agent = req.context.agent

        body = req.get_media()

        # Get the hab
        hab = agent.hby.habByName(name)
        if hab is None:
            raise falcon.HTTPNotFound(description=f"alias={name} is not a valid reference to an identfier")

        # ...and make sure we're a Group
        if not isinstance(hab, habbing.SignifyGroupHab):
            raise falcon.HTTPBadRequest(description=f"hab for alias {name} is not a multisig")

        # grab all of the required parameters
        ked = httping.getRequiredParam(body, "exn")
        serder = coring.Serder(ked=ked)
        sigs = httping.getRequiredParam(body, "sigs")
        atc = httping.getRequiredParam(body, "atc")

        # create sigers from the edge signatures so we can messagize the whole thing
        sigers = [coring.Siger(qb64=sig) for sig in sigs]

        # create seal for the proper location to find the signatures
        kever = hab.mhab.kever
        seal = eventing.SealEvent(i=hab.mhab.pre, s=hex(kever.lastEst.s), d=kever.lastEst.d)

        ims = eventing.messagize(serder=serder, sigers=sigers, seal=seal)
        ims.extend(atc.encode("utf-8"))  # add the pathed attachments
        # make a copy and parse
        agent.hby.psr.parseOne(ims=bytearray(ims))
        # now get rid of the event so we can pass it as atc to send
        del ims[:serder.size]

        smids = hab.db.signingMembers(pre=hab.pre)
        smids.remove(hab.mhab.pre)

        for recp in smids:  # this goes to other participants
            agent.postman.send(hab=agent.agentHab,
                               dest=recp,
                               topic="multisig",
                               serder=serder,
                               attachment=ims)

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(serder.ked).encode("utf-8")


class MultisigRequestResourceEnd:
    """ Resource endpoint class for getting full data for a mulisig exn request from a notification """

    @staticmethod
    def on_get(req, rep, said):
        """ GET method for multisig resources

        Parameters:
            req (falcon.Request): HTTP request object
            rep (falcon.Response): HTTP response object
            said (str): qb64 SAID of EXN multisig message.

        """
        agent = req.context.agent
        exn = agent.hby.db.exns.get(keys=(said,))
        if exn is None:
            raise falcon.HTTPNotFound(description=f"no multisig request with said={said} found")

        route = exn.ked['r']
        if not route.startswith("/multisig"):
            raise falcon.HTTPBadRequest(f"invalid mutlsig conversation with said={said}")

        payload = exn.ked['a']
        match route.split("/"):
            case ["", "multisig", "icp"]:
                pass
            case ["", "multisig", *_]:
                gid = payload["gid"]
                if gid not in agent.hby.habs:
                    raise falcon.HTTPBadRequest(f"multisig request for non-local group pre={gid}")

        esaid = exn.ked['e']['d']
        exns = agent.mux.get(esaid=esaid)

        for d in exns:
            exn = d['exn']
            serder = coring.Serder(ked=exn)

            route = serder.ked['r']
            payload = serder.ked['a']
            match route.split("/"):
                case ["", "multisig", "icp"]:
                    pass
                case ["", "multisig", "vcp"]:
                    gid = payload["gid"]
                    ghab = agent.hby.habs[gid]
                    d['groupName'] = ghab.name
                    d['memberName'] = ghab.mhab.name

                    sender = serder.ked['i']
                    if (c := agent.org.get(sender)) is not None:
                        d['sender'] = c['alias']
                case ["", "multisig", "iss"]:
                    gid = payload["gid"]
                    ghab = agent.hby.habs[gid]
                    d['groupName'] = ghab.name
                    d['memberName'] = ghab.mhab.name

                    sender = serder.ked['i']
                    if (c := agent.org.get(sender)) is not None:
                        d['sender'] = c['alias']

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(exns).encode("utf-8")