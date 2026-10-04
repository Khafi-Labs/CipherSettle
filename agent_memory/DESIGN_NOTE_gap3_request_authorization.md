# Design note: Gap 3, authorization of derive requests

STATUS: **Step 1 IMPLEMENTED and tested. Step 2 is a DESIGN ONLY: `NEEDS_HUMAN_CRYPTO_REVIEW`, not implemented.**
Per the project rules, a protocol-level change (who may authorize a key derivation, and how nodes check it) stops here for a cryptographer's approval. Nothing below is claimed secure.

## Problem (from the Gap List, confirmed by reading the code)
Derive requests are authenticated by one HMAC key shared by `quorum_service` and every node
(`quorum_core::sign_derive_auth`). Whoever holds it can ask any node for any invoice's key share and
seal it to a transport key of their choosing. That defeats "no single operator can read invoices".

## Step 1 (IMPLEMENTED, EXECUTED): distinct key per node
* The service keeps a MASTER secret; node `i` is configured only with `derive_node_auth_key(master, i)`
  = HKDF-SHA256 (RFC 5869; salt `ciphersettle/derive-auth/v1`, info `node-auth-key || i as u64 BE`).
  HKDF is verified against RFC 5869 test case 1 (`hkdf_sha256_matches_rfc5869_test_case_1`).
* The client builds one request per node under that node's key. The node-side verification is unchanged.
* The service refuses to start with a master shorter than 32 bytes.
* Provisioning: `quorum_node derive-auth-key <master_b64> <node_id>` prints the key for that node.
* Evidence: failing first, adversarial group S (an attacker with node 0's REAL key) = all 5 nodes served the
  forged request (`evidence/test_s_before_fix_session12.log`); after: only node 0 serves, 1 < t+1 = 3.
* Rotation = generate a new master, re-derive and re-provision every node, restart (no online rotation or key
  versioning yet: that is a limitation, not a feature).
* WHAT THIS DOES NOT SOLVE: the service holds the master, so a fully compromised `quorum_service` can still
  authorize any derivation (this is exactly Step 2's job). It also does not help if an attacker steals `t+1` node keys.

## Step 2 (DESIGN, needs cryptographer approval): signed per-request authorization
Goal: a compromised service (holding the master and every API key) but WITHOUT an authorizer's signing key
cannot obtain any invoice key.

### Construction (established primitives only: Ed25519 per RFC 8032, already in the tree via ed25519-dalek)
An **authorization** is an Ed25519 signature by an *authorizer* over a canonical, length-prefixed byte string:
`"ciphersettle/derive-authz/v1" || identity || grantee_transport_public_key || expires_at_ms (u64 BE) || nonce[16] || node_set_id`.
* The grantee's transport public key and the invoice identity are inside the signed bytes, so the service
  cannot redirect an authorization to a different key or invoice.
* Each node verifies the signature itself against a locally pinned authorizer public key, checks expiry
  (the existing short window and restart guard stay), and consumes the nonce (the existing single-use set).
  The per-node HMAC of step 1 remains as the transport-level service-to-node check (defence in depth).
* Who is an authorizer: the invoice **issuer** (signs for access to its own invoice) and, for regulator
  access, the **admin/regulator authority**. Registering an authorizer public key per invoice happens at
  invoice registration (the issuer's key is bound into the invoice commitment record that the nodes can check).

### Decisions that are NOT mine to make (need owner/cryptographer)
1. Is the authorizer the issuer's own key held by the issuer (strongest, requires client-side signing tooling),
   or an organisation key in an HSM? Who may sign for a bank or regulator?
2. How authorizer keys are registered and revoked, and how nodes learn them (pinned at registration vs a
   signed registry): a registry is a new trust root and must be designed and reviewed.
3. Whether the transcript must also bind the node id (to stop cross-node replay of a single signature) and
   the audit-log tip (to bind the authorization to an audited event).
4. Domain separation tag, canonical encoding and versioning (needs a reviewer's sign-off).
5. Behavior when an authorizer key is lost (invoice becomes un-derivable; recovery policy).

### Alternatives considered
* Threshold-signed authorization by the quorum itself: circular (the quorum is what we are protecting).
* JWT/OAuth bearer tokens from the service: the service is the compromised party, so it can mint them.
* Per-caller mTLS to the nodes: authenticates a connection, not a request; no binding to the transport key.

### Tests to write first when approved
1. "Fully compromised service" (holds master + API keys, no authorizer key) requests a key for any invoice: every node refuses.
2. A valid authorization replayed (same nonce), expired, for another invoice/transport key/node: refused.
3. Tampering with every field of the signed bytes: refused (property-style sweep).
4. Revoked/unknown authorizer: refused.

## Gating
Gap 3 stays OPEN until Step 2 is approved, implemented and its adversarial test passes. The pilot gate lists Gap 3.
