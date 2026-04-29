# -*- encoding: utf-8 -*-
"""Generic signed agent event streaming helpers for KERIA.

This module owns the reusable transport contract between one KERIA agent and
its connected edge clients. Topic modules such as ``didwebing`` may publish
events here, but topic modules must not own SSE framing, subscriber fan-out, or
KERI ``rpy`` envelope signing.

Maintainer invariants:

* ``/signals/stream`` is an authenticated admin endpoint registered
  independently of ``did_webs.enabled``.
* SSE delivery is transient. Every topic that needs reliability must maintain a
  durable polling fallback. For did:webs publication, that fallback is
  ``/didwebs/signing/requests``.
* Each published payload is wrapped in a KERI ``rpy`` envelope signed by
  ``agent.agentHab``. Clients verify this envelope against the connected KERIA
  agent AID before approving or auto-approving any edge-signed work.
* Subscriber queues are independent. A slow or abandoned stream must not drain
  events from another active client.
* The ``Agent`` owns one stable ``SseBroadcaster``. Topic modules enqueue signal
  cues. ``SseBroadcasterDoer`` is the only active publisher that drains those
  cues and fans them out to the Agent-owned broadcaster.
"""

import json
import time
from collections import deque

import falcon
from hio.base import doing
from keri.core import eventing

from .. import log_name, ogler

logger = ogler.getLogger(log_name)


class SseBroadcaster:
    """In-memory per-agent SSE broadcaster with independent subscriber queues.

    The broadcaster intentionally stores no durable state and has no Doer
    lifecycle of its own. It is passive fan-out only, owned by ``Agent``;
    ``SseBroadcasterDoer`` owns cue draining, signing, and publishing.
    """

    def __init__(self):
        self.subscribers = {}
        self._index = 0

    def subscribe(self):
        self._index += 1
        sid = str(self._index)
        queue = deque()
        self.subscribers[sid] = queue
        return SseEventIterable(self, sid, queue)

    def unsubscribe(self, sid: str):
        self.subscribers.pop(sid, None)

    def publish(self, event: str, data: dict, event_id: str):
        payload = json.dumps(data).encode("utf-8")
        frame = {
            "id": event_id,
            "event": event,
            "data": payload,
        }
        for queue in list(self.subscribers.values()):
            queue.append(frame)


class SseEventIterable:
    """SSE iterable modeled after KERIpy signaling without shared draining.

    Falcon consumes this object as ``rep.stream``. The first yielded frame is
    only the SSE retry prelude, which lets clients learn the reconnect cadence
    before any topic event exists. Later frames drain this subscriber's private
    queue.

    ``TimeoutSSE`` is measured from iterator activation in ``__iter__``, not
    from the last event sent. ``time.perf_counter`` is used for that elapsed-time
    check because it is monotonic and therefore not affected by wall-clock
    updates.
    """

    TimeoutSSE = 300  # seconds

    def __init__(self, broadcaster: SseBroadcaster, sid: str, queue, retry=5000):
        self.broadcaster = broadcaster
        self.sid = sid
        self.queue = queue
        self.retry = retry
        self.start = None
        self.end = None

    def __iter__(self):
        # Equal start/end values are intentional. __next__ uses this as the
        # "first pull has not happened yet" sentinel before normal queue
        # draining begins.
        self.start = self.end = time.perf_counter()
        return self

    def __next__(self):
        if self.end - self.start >= self.TimeoutSSE:
            self.broadcaster.unsubscribe(self.sid)
            raise StopIteration

        # Expected exactly on the first pull after iter(stream). Send the retry
        # prelude immediately, then advance end so later pulls drain event
        # frames. perf_counter is monotonic, making it appropriate for this
        # elapsed-time timeout check.
        if self.start == self.end:
            self.end = time.perf_counter()
            return bytes(f"retry: {self.retry}\n\n".encode("utf-8"))

        data = bytearray()
        while self.queue:
            event = self.queue.popleft()
            data.extend(
                bytearray(
                    "id: {}\nretry: {}\nevent: {}\ndata: ".format(
                        event["id"], self.retry, event["event"]
                    ).encode("utf-8")
                )
            )
            data.extend(event["data"])
            data.extend(b"\n\n")

        self.end = time.perf_counter()
        return bytes(data)


class SseBroadcasterDoer(doing.Doer):
    """Doer that drains generic agent signal cues into the Agent broadcaster.

    ``Agent`` is the composition root: it owns the cue deck and the broadcaster
    and passes both here explicitly. Topic modules should receive the same cue
    deck by dependency injection and append cue dictionaries with
    ``enqueueSignedReplyCue``. They should not reach through ``Agent`` to find
    this Doer or call ``SseBroadcaster.publish`` directly.

    The Doer is deliberately lossy. If a cue is malformed, it is logged and
    dropped because SSE is only a live notification layer. Durable workflows
    must be recoverable through their own topic-specific polling endpoint.
    """

    def __init__(self, agent, cues=None, broadcaster=None, tock=0.0):
        self.agent = agent
        if cues is None:
            raise ValueError("cues is required")
        if broadcaster is None:
            raise ValueError("broadcaster is required")
        self.cues = cues
        self.broadcaster = broadcaster
        super().__init__(tock=tock)

    def recur(self, tyme=None, tock=0.0, **opts):
        while self.cues:
            cue = self.cues.popleft()
            try:
                # Signing happens at the generic transport boundary so topic
                # modules never need to construct KERI rpy envelopes or know
                # how subscriber fan-out is implemented.
                self.broadcaster.publish(
                    event=cue["event"],
                    data=signedReplyEnvelope(
                        self.agent,
                        route=cue["route"],
                        payload=cue["payload"],
                    ),
                    event_id=cue["event_id"],
                )
            except Exception:  # pragma: no cover - defensive transient logging
                logger.exception("failed to publish SSE signal cue %s", cue)

        return False


def enqueueSignedReplyCue(cues, event: str, route: str, payload: dict, event_id: str):
    """Queue one agent-signed reply for live SSE publication.

    The queued payload is unsigned intent. ``SseBroadcasterDoer`` converts it
    into a signed reply envelope when it drains the cue. ``event_id`` should be
    stable for the topic-level work item so clients can dedupe repeated live
    nudges; did:webs uses the setup request SAID.
    """
    cues.append(
        {
            "event": event,
            "route": route,
            "payload": payload,
            "event_id": event_id,
        }
    )


def signedReplyEnvelope(agent, route: str, payload: dict) -> dict:
    """Create a KERI ``rpy`` envelope signed by the KERIA agent AID.

    The ``agent`` payload field is inserted when omitted. Clients rely on this
    field, plus signature verification against the connected KERIA agent AID, to
    distinguish legitimate server-originated requests from replayed or
    cross-agent messages.
    """
    data = dict(payload)
    data.setdefault("agent", agent.agentHab.pre)
    rserder = eventing.reply(route=route, data=data)
    sigs = agent.agentHab.sign(ser=rserder.raw)
    return {"rpy": rserder.ked, "sigs": [siger.qb64 for siger in sigs]}


def loadEnds(app):
    """Register generic signed agent event streaming routes."""
    app.add_route("/signals/stream", SignalsStreamEnd())


class SignalsStreamEnd:
    """Signed admin SSE endpoint for agent-to-edge-controller events.

    This endpoint only subscribes the caller to the current agent's stable
    broadcaster. It does not sign, persist, replay, or filter topic messages.
    Those responsibilities belong to ``SseBroadcasterDoer`` and the topic
    modules that own their durable recovery paths.
    """

    def on_get(self, req, rep):
        agent = req.context.agent
        rep.status = falcon.HTTP_200
        rep.content_type = "text/event-stream"
        rep.set_header("Cache-Control", "no-cache")
        rep.set_header("connection", "close")
        rep.stream = agent.sseBroadcaster.subscribe()
