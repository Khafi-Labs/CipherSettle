# quorum_poc

Phase 0 exit-criteria PoC for the **"Option B: Off-Chain Threshold
BLS/IBE"** track of the project's original phased roadmap (that roadmap
document is not part of this repository) — a throwaway, single-process
simulation of a 3-of-5 threshold DKG plus one identity-based
derive-and-decrypt round trip, built *before* any of Phase 1's real
infrastructure (separate node binaries, mTLS, HSMs) exists, per the
roadmap's own sequencing advice.

## Run it

```bash
cargo run -p quorum_poc
```

No `dfx`, no IC replica, no network access needed — this crate is pure
`blstrs` + std, needs none of the Internet Computer SDK, and builds on the
same rustc this whole workspace is pinned to (see `rust-toolchain.toml`).

## What it proves (Phase 0 exit criteria: "working DKG+derive PoC")

1. **DKG** — 5 simulated nodes each deal a random polynomial
   (Feldman VSS), verify each other's point-to-point shares against public
   commitments, and end up holding a share of the *sum* polynomial. No
   party — not even this PoC's own `main()` — ever computes the group
   secret in one place.
2. **Derive** — 3-of-5 nodes jointly compute a partial BLS signature over
   an identity string (`invoice_id`), which a coordinator combines into
   the identity's private key. This is the actual Boneh-Franklin IBE
   construction (`sk_id = s · H(id)`), so it matches vetKD's
   derive-don't-decrypt model, not a "quorum decrypts centrally" model.
3. **k-of-n liveness** — the same identity is derived twice from two
   *different* 3-node subsets and shown to produce byte-identical keys.
4. **Round trip** — the derived key is hashed into a symmetric key and
   used to decrypt a ciphertext that was "registered" client-side ahead
   of time, mirroring `register_invoice` → `derive_invoice_key` →
   client-side decrypt.
5. **One adversarial check** — a garbage signature share is rejected by
   per-share verification before it would reach a combiner.

## What it deliberately does NOT prove

See the module doc comment at the top of `src/main.rs` for the full list.
In short: this is not a hardened DKG (no complaint/dispute protocol for a
cheating dealer), not real network transport (no mTLS, no separate
processes), not full IBE encryption (a KDF/XOR stand-in, not a real
pairing-based `Encrypt`), and not resharing/rotation. All four of those
are named, in exactly that order of urgency, in the roadmap's Phase 1.

## Next steps toward the roadmap's Phase 1

- Split `Node` into an actual standalone binary (or async task) so DKG and
  derive go over a real channel instead of in-process function calls, then
  add mTLS per the roadmap's node-to-node channel requirement.
- Add a complaint/dispute round to the DKG loop in `main()` instead of the
  current `assert!`/panic on a bad share.
- Replace the XOR/KDF round-trip stand-in with a real IBE
  `Encrypt(mpk, id, msg)` (or keep this KEM/DEM shape deliberately — vetKD
  itself delivers a transport-key-wrapped derived key rather than doing
  IBE encryption on-chain, so this shortcut may be the right long-term
  shape, not just a PoC one; make that decision explicitly rather than by
  default).
- Wire `ciphersettle_core::resolve_access` / `audit_action_for` in ahead of
  the actual `derive_for_identity` call, exactly as Phase 3 describes,
  once there's a service layer around this crypto core.
