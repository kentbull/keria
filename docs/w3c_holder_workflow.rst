W3C Holder Workflow
===================

KERIA's W3C workflow routes validate holder-centered VRD projection and
presentation artifacts. KERIA owns durable state, validation, status
projection, grant forwarding, and verifier submission. It does not own W3C
artifact construction or edge signing.

Signing Boundary
----------------

KERIA never signs or assembles VC-JWT or VP-JWT token material in this
workflow. The edge builds the projected VC, adds the Data Integrity proof, wraps
it as VC-JWT, and later builds the request-bound VP-JWT. KERIA validates the
completed artifacts against local KERI, ACDC, TEL, and did:webs state.

SignifyTS, SignifyPy, or another edge wallet must use the W3C helper packages
to decide policy and sign the final W3C artifacts.

Configuration
-------------

W3C routes require W3C support to be enabled and a public status base URL:

- ``KERIA_W3C_ENABLED=true``
- ``KERIA_W3C_STATUS_BASE_URL=<public KERIA base URL>``
- ``KERIA_W3C_TTL_SECONDS`` for workflow expiry metadata, optional
- ``KERIA_W3C_SIGNAL_INTERVAL_SECONDS`` for grant reconciliation cadence,
  optional

Issuer and holder identifiers also need ready did:webs DIDs before W3C issuance
or presentation can complete.

Issuance Lifecycle
------------------

``POST /identifiers/{name}/w3c/issuances`` starts QVI-side W3C issuance from
one native issuer-side VRD ACDC. KERIA validates the source credential, holder
AID/DID chain, TEL state, did:webs readiness, and status projection config.

The issuance enters ``ready_for_vc_jwt`` and returns context for edge VC-JWT
creation. The edge builds and signs the final VC-JWT, then submits it with:

``POST /identifiers/{name}/w3c/issuances/{issuanceId}/vc-jwt``

After KERIA validates the VC-JWT, the issuance moves to ``delivery_pending`` and
can be delivered to the holder through an issuer-signed W3C grant:

``POST /identifiers/{name}/w3c/issuances/{issuanceId}/grant``

Holder Credential State
-----------------------

``/w3c/vc/grant`` is the issuer-to-holder EXN route for delivering one
finalized VC-JWT. KERIA validates the issuer-signed EXN and materializes a held
W3C credential only when the matching native VRD ACDC exists locally. The
portable W3C artifact never replaces the KERI-native source of truth.

Holder clients inspect admitted W3C credentials with:

- ``GET /identifiers/{name}/w3c/credentials``
- ``GET /identifiers/{name}/w3c/credentials/{credentialId}``

Presentation Lifecycle
----------------------

``POST /identifiers/{name}/w3c/presentations`` submits a holder presentation
from a runtime verifier descriptor and an edge-built VP-JWT. KERIA selects a
credential only when exactly one eligible held W3C credential exists.

If zero or multiple credentials match, KERIA fails the transaction with
``presentation requires exactly one eligible held credential``. This is a
wallet-state correctness failure: issue and receive the W3C VRD first, or
remove duplicate eligible held credentials before presenting.

When exactly one credential matches, KERIA validates holder DID, issuer DID,
selected credential, audience, nonce, response URI, status, and proof binding
before posting the VP-JWT to the verifier response URI.

Troubleshooting
---------------

``ready_for_vc_jwt``
    The edge has not submitted the finalized VC-JWT. Check edge W3C package
    configuration, did:webs readiness, and signing policy.

``identifier ... has no ready did:webs DID``
    Publish and wait for did:webs readiness before W3C issuance or
    presentation.

``w3c.status_base_url is required``
    Configure ``KERIA_W3C_STATUS_BASE_URL`` so generated VC-JWTs can include a
    dereferenceable W3C status resource.

``presentation requires exactly one eligible held credential``
    The holder has zero or more than one eligible held W3C credential. KERIA
    fails closed instead of guessing which credential to disclose.
