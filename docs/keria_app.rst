KERIA App API
=============

keria.app.agenting
------------------

.. automodule:: keria.app.agenting
    :members:

Agency and Agent Configuration
==============================

A KERIA Agency can be configured with either environment variables or a configuration file.
The configuration file is a JSON file. Both alternatives are shown here.

Environment Variables
---------------------

.. code-block:: bash

    # Service Endpoint Location URLs creating Endpoint Role Authorizations and Location Scheme records on startup
    export KERIA_CURLS="https://url1,https://url2"
    # Introduction URLs resolved on startup (OOBIs)
    export KERIA_IURLS="https://url3,https://url4"
    # Data OOBI URLs resolved on startup
    export KERIA_DURLS="https://url5,https://url6"
    # how long before an agent can be idle before shutting down; defaults to 1 day
    export KERIA_RELEASER_TIMEOUT=86400

JSON Configuration File
-----------------------

To use the JSON configuration file option make sure to mount the JSON file to the directory you specify with the
`--config-dir` option and name the JSON file the name specified by the `--config-dir` option to the `keria start` command like so.

With the absolute path version the `--config-dir` argument does not have an affect since the
`--config-file` argument specifies the absolute path to the JSON file.

.. code-block:: bash

    # Relative path version, interpreted relative to directory executing keria binary from.
    # This means the file "keria.json" must exist in the "scripts/keri/cf" folder
    keria start \
        --config-dir scripts \
        --config-file keria

    # Absolute path version
    keria start \
        --config-dir /path/to/config-dir/keria.json \
        --config-file /path/to/config-dir/keria.json

The JSON file must have an object with the same name that you sent to the `keria start` command via the `--name` argument.
The default is "keria" which is why the JSON file below shows a sub-object named "keria".
Make sure to include the "dt" date timestamp field or the configuration will not be loaded.

You can configure the cycle time, or tocks, of the escrower as well as the agent initializer.

You can also configure the CURLs, IURLs, and DURLs of the agent.
CURLs are Service Endpoint Location URLs creating Endpoint Role Authorizations and Location Scheme records on startup.
IURLS are Introduction URLs resolved on startup (OOBIs).
DURLS are Data OOBI URLs resolved on startup usually of things like ACDC credential schemas or ACDC credential CESR streams.

.. code-block:: json

    {
      "dt": "2025-01-13T16:08:30.123456+00:00",
      "keria": {
        "dt": "2025-01-13T16:08:30.123457+00:00",
        "curls": ["http://127.0.0.1:3902/"]
      },
      "iurls": [
        "http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller?name=Wan&tag=witness",
        "http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller?name=Wil&tag=witness",
        "http://127.0.0.1:5644/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller?name=Wes&tag=witness"
      ],
      "tocks": {
        "initer": 0.0,
        "escrower": 1.0
      }
    }

keria.app.aiding
----------------

.. automodule:: keria.app.aiding
    :members:

keria.app.streaming
-------------------

``keria.app.streaming`` is the generic KERIA agent-to-edge signaling layer. It
registers the authenticated admin ``GET /signals/stream`` endpoint and provides
the reusable cueing helpers that topic modules use to request signed SSE events.

The important ownership boundary is this:

- ``SseBroadcaster`` is passive per-agent fan-out to currently connected
  subscribers.
- ``Agent`` owns the stable ``SseBroadcaster`` and the shared signal cue deck.
- ``SseBroadcasterDoer`` is the active cue-draining publisher. It signs queued
  payloads with ``agent.agentHab`` and broadcasts the resulting KERI ``rpy``
  envelope to the Agent-owned broadcaster.
- Topic modules own durable state, polling fallbacks, event names, reply routes,
  payload semantics, and enqueueing decisions.

The stream is intentionally transient. A disconnected client can miss events,
so every topic that requires reliability must expose a durable read path. For
did:webs publication that read path is ``/didwebs/signing/requests``.
Repeated SSE messages are allowed; clients must dedupe using the topic's stable
event identifier. For did:webs, that identifier is the setup request SAID
(``request.d``).

SSE event data is a signed reply envelope:

.. code-block:: json

    {
      "rpy": {
        "v": "...",
        "t": "rpy",
        "d": "...",
        "dt": "...",
        "r": "/topic/reply/route",
        "a": {
          "agent": "KERIA agent AID",
          "topic": "payload fields"
        }
      },
      "sigs": ["agent signature"]
    }

Clients should verify the signature against the connected KERIA agent AID and,
when the caller expects one topic, check the ``r`` route before interpreting the
payload.

.. automodule:: keria.app.streaming
    :members:

keria.app.didwebing
-------------------

``keria.app.didwebing`` uses the generic signaling layer; it does not own SSE
transport. Its durable contract is did:webs-specific:

- dynamic public ``did.json`` and ``keri.cesr`` asset generation;
- durable managed-AID signing requests under ``/didwebs/signing/requests``;
- did:webs approval payloads for registry creation and designated-alias ACDC
  issuance.

The signed admin status route under ``/didwebs/{aid}`` is debug-only,
informational maintainer surface. It is not a Signify client workflow contract
and may be removed once end-to-end VC-JWT presentation to a W3C verifier no
longer needs that local inspection hook.

KERIA may self-issue for its own agent AID because it owns ``agent.agentHab``.
For Signify-managed AIDs, KERIA coordinates publication but must not sign as the
managed AID. It emits a signed generic signal and keeps a durable polling record
so SignifyPy or SignifyTS can verify the agent request, sign at the edge, submit
the resulting events through normal KERIA APIs, and recover from missed SSE
events.

The managed-AID publisher has three separate state channels:

- ``AgencyBaser.dwspub`` is durable publication work keyed by managed AID. It is
  the source of truth for which AIDs should be advanced toward did:webs
  publication readiness.
- ``AgencyBaser.dwsreq`` is durable edge-client setup work keyed by request
  SAID. It is the source of truth for polling and for client-side dedupe.
- The generic signal cue deck is transient live notification intent. The
  publisher queues a cue when it wants connected clients to notice a durable
  setup request or ready transition; ``SseBroadcasterDoer`` signs and broadcasts
  it later.

``DidWebsAidPublisher`` may see the same pending request on every recurrence
while waiting for the edge client to create a registry or issue the
designated-alias ACDC. It therefore throttles repeated SSE nudges in memory.
That throttle is not durable: after restart, KERIA may signal pending requests
again, and Signify clients are expected to suppress duplicate approvals by
request SAID.

.. automodule:: keria.app.didwebing
    :members:

keria.app.credentialing
-----------------------

.. automodule:: keria.app.credentialing
    :members:

keria.app.indirecting
---------------------

.. automodule:: keria.app.indirecting
    :members:

keria.app.notifying
-------------------

.. automodule:: keria.app.notifying
    :members:

keria.app.presenting
--------------------

.. automodule:: keria.app.presenting
    :members:

keria.app.specing
-----------------

.. automodule:: keria.app.specing
    :members:
