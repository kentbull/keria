KERIA App API
=============

keria.app.agenting
------------------

.. automodule:: keria.app.agenting
    :members:

Agency and Agent Configuration
===================

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

Scheduler Configuration
-----------------------

Configure KERIpy scheduler cadences directly under ``tocks`` and KERIA
cadences under ``tocks.signify``. Values must be finite, non-negative numbers.
Explicit ``0.0`` values are retained. Invalid or unknown settings stop Agency
startup before any Agent is opened.

Active message, queue, HTTP, and coordination paths default to ``0.0`` so they
resume on the next scheduler cycle. The full Agent escrow scan defaults to one
second and the idle-Agent release scan defaults to 60 seconds. The finite
``GrantDoer`` inherits the configured ``granter`` cadence. KERIA's delegation
Anchorer uses KERIpy's ``anchorerEscrow`` cadence, and the one-shot ``sig-fix``
CLI is intentionally not process-configurable.

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
        "witnessMsg": 0.0,
        "signify": {
          "initer": 0.0,
          "escrower": 1.0
        }
      }
    }

KERIA settings have corresponding ``KERIA_*_TOCK`` environment variables:
``agency``, ``agent``, ``gracefulShutdown``, ``bootServer``, ``adminServer``,
``httpServer``, ``releaser``, ``initer``, ``querier``, ``escrower``, ``parser``,
``witnesser``, ``delegator``, ``exchangeSender``, ``granter``, ``admitter``,
``groupRequester``, ``seeker``, ``exchangecue``, and ``submitter``. For example,
``KERIA_ESCROWER_TOCK=0.5`` overrides ``tocks.signify.escrower``.

Flat KERIA keys directly under ``tocks`` remain accepted for migration from
KERIA 0.4.1 and emit one warning per process. Nested ``tocks.signify`` values
win when both forms are present. Resolved process settings are not copied into
per-Agent configuration files.

keria.app.aiding
----------------

.. automodule:: keria.app.aiding
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
