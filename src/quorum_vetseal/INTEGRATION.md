# `quorum_vetseal` — sealing design and integration record

> **Status: implemented and integrated.** This crate is a `blstrs`-only
> workspace member. Its ElGamal sealing and NIZK proofs are wired into
> `DerivePartial` in `quorum_node`, and its types appear in `quorum_core`'s
> `Message` enum, `quorum_client`, and `quorum_service`. This document is a
> record of the design and of how it was plumbed in — not a list of
> outstanding work.

## What it provides

ElGamal sealing of BLS shares/signatures under a caller-generated transport
public key, so that no node, broker, or backend process — including
`quorum_service` itself — ever holds a plaintext derived key or an unsealed
partial share meant for someone else. Homomorphic Lagrange combine happens on
the ciphertexts, without decrypting anywhere except at the true end caller.

The design rationale, the specific tradeoffs, and the security properties
relied upon are recorded as CRYPTO-005 and CRYPTO-008 in
`docs/cryptography/CRYPTO_DECISIONS.md`. Read that before relying on any of
this.

## 1. Workspace placement

```
src/quorum_vetseal/          <- this crate
src/quorum_core/Cargo.toml   <- add: quorum_vetseal = { path = "../quorum_vetseal" }
src/quorum_node/Cargo.toml   <- same
src/quorum_client/Cargo.toml <- same
```

`quorum_vetseal` is a workspace member in the top-level `Cargo.toml`. Note that
it sits *underneath* `quorum_core` rather than being bolted on afterwards: that
direction is required because sealing is wired into the real `DeriveRequest`
flow, not layered over it afterwards.

## 2. Wire protocol changes (`quorum_core`'s `Message` enum)

```rust
// before
Message::DeriveRequest { identity: String },
Message::DerivePartial { node_id: usize, share: SignatureShare },

// after
Message::DeriveRequest {
    identity: String,
    transport_public_key: quorum_vetseal::TransportPublicKey,
},
Message::DerivePartial {
    node_id: usize,
    sealed_share: quorum_vetseal::SealedShare,
    proof: quorum_vetseal::ShareProof,   // added with the NIZK (CRYPTO-004)
},
```

`TransportPublicKey` and `SealedShare` both already derive
`Serialize`/`Deserialize`, so this is a type swap in the enum, not new
serialization code.

## 3. `quorum_node`'s `handle_message` (around the `Message::DeriveRequest`
   arm, in `src/quorum_node/src/main.rs` — search for
   `Message::DeriveRequest`)

```rust
Message::DeriveRequest { identity, transport_public_key } => {
    let share = shared.secret_key_share.sign(identity.as_bytes());
    // existing per-share verification stays exactly as-is
    if !shared.public_key_set.public_key_share(shared.node_id).verify(&share, identity.as_bytes()) {
        return Some(Message::DeriveReject { .. });
    }
    let sealed = quorum_vetseal::encrypt_share(&share, &transport_public_key, &mut rand::thread_rng())
        .expect("encrypting our own genuine, already-verified share cannot fail");
    let proof = quorum_core::seal_partial_with_proof(
        &shared.secret_key_share, &shared.public_key_set.public_key_share(shared.node_id),
        identity, &transport_public_key, &sealed, &mut rand::thread_rng(),
    ).expect("proving our own genuine, already-verified share cannot fail");
    Some(Message::DerivePartial { node_id: shared.node_id, sealed_share: sealed, proof })
}
```

Nothing about DKG, share verification, or the audit log changes -- this
only touches the last step of an already-verified partial, right before
it leaves the node.

## 4. `quorum_client::derive_from_quorum` -- the important split

Today this one function both **collects** shares and **has** the
plaintext result. It needs to become two functions with two different
trust requirements:

```rust
/// Safe to run anywhere, including inside quorum_service. Never touches
/// a plaintext key.
pub async fn collect_sealed_derived_key(
    nodes: &[NodeHandle],
    identity: &str,
    transport_public_key: &TransportPublicKey,
    group_pks: &PublicKeySet,
    proof_policy: ProofPolicy,
) -> Result<SealedDerivedKey> {
    let sealed_shares = /* same fan-out/collect logic as today, but each
                            response's proof is verified against group_pks
                            for the node index it claims to come from --
                            see the note below */;
    quorum_vetseal::combine_sealed_shares(&sealed_shares)
}

/// MUST run wherever `transport_secret_key` lives -- i.e. never inside
/// quorum_service. This is the function a browser/CLI calls locally.
pub fn open_sealed_derived_key(
    sealed: &SealedDerivedKey,
    transport_secret_key: &TransportSecretKey,
    public_key_set: &PublicKeySet,
    identity: &str,
) -> Result<Signature> {
    let sig = transport_secret_key.decrypt_combined(sealed)?;
    if !public_key_set.public_key().verify(&sig, identity.as_bytes()) {
        return Err(/* bad node in the subset -- caller should retry
                       collect_sealed_derived_key with a different subset,
                       same recovery path as today's k-of-n liveness */);
    }
    Ok(sig)
}
```

**Note on per-share verification:** `collect_sealed_derived_key` takes a
`ProofPolicy`. Under `ProofPolicy::Require` — what every production caller
uses — each node's NIZK is verified against the group's own Feldman
commitment for the claimed `node_id` *before* combining, via
`quorum_core::verify_sealed_partial`. That is the deferred item named in
the crate's original design notes, and it is now built and live; see
`src/quorum_vetseal/src/nizk.rs` and CRYPTO-004 in
`docs/cryptography/CRYPTO_DECISIONS.md`. The final `public_key.verify()`
in `open_sealed_derived_key` is *not* redundant with it and is still
required: the NIZK proves each ciphertext encrypts *that node's genuine
share of the requested identity*, while the post-decrypt check proves the
*combined* result is the right key — and it is what triggers the
retry-with-a-different-subset path. `ProofPolicy::Skip` exists only so the
adversarial suite can drive that retry path (finding A12) with an
adversary a sound proof would otherwise exclude; it is never a default.
The one behavior change to call out explicitly in review: when a node's
proof fails it is excluded at collection time rather than being caught one
step later, after combine+decrypt — same outcome (reject, retry a
different subset), detected earlier.

## 5. `quorum_service` (`DeriveInvoiceKeyReq`'s
   `transport_public_key_b64` field in `src/quorum_service/src/main.rs`)

This is the field that makes the whole change land. `quorum_service`'s
`derive_invoice_key` handler calls `collect_sealed_derived_key` and
returns the `SealedDerivedKey` (base64-encoded) over HTTP -- **never**
calls `open_sealed_derived_key`, and never accepts or holds a
`TransportSecretKey`. The decrypt step happens client-side (browser/CLI),
using the transport secret key that was generated there and never sent
to `quorum_service` at all. This is verified in source: `quorum_service`
contains no `TransportSecretKey` construction.

## 6. Tests to add at the integration level (unit-level coverage already
   lives in this crate)

These were written as follow-ups when this record was first drafted; two
of the three now exist, and the third is noted as still open.

- ~~`quorum_node` integration test: a `DeriveRequest` round-trip over real
  mTLS returns a `SealedShare`, never a raw `SignatureShare`.~~ **Done** —
  adversarial group M drives a live 5-node quorum over real mTLS and
  checks the collection result, plus `quorum_poc`'s own round trip.
- ~~`quorum_adversarial` new test group: a process playing
  `quorum_service`'s role, with the transport secret key withheld from its
  config/environment, structurally cannot produce a usable key from what it
  relays.~~ **Done** — group M substitutes a strong adversary that returns
  a valid proof for the *wrong* scalar and asserts (M1) the gate excludes it
  before the combine while (M2) the identical adversary, gate off, does
  poison the combine and fail post-decrypt verification.
- **Still open:** no test greps the raw wire bytes for the retired
  plaintext `SignatureShare` variant as a regression guard. `Message::DerivePartial`
  now carries only `sealed_share` + `proof`, so the type system enforces it;
  an explicit byte-level assertion would be belt-and-braces on top of that.
