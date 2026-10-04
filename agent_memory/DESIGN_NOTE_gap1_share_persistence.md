# Design note: Gap 1, durable key-share persistence

STATUS: **DECIDED (engineering decisions under the owner's delegation) and IMPLEMENTED for the pilot tier.**
Labeled `NEEDS_HUMAN_CRYPTO_REVIEW`. The decisions below are engineering calls, not cryptographer or
legal sign-off. Nothing here makes the project "production-ready" (see "What this does not solve").

## Problem (EXECUTED: `evidence/test_p_before_fix_session07.log`, 1 of 8 checks pass)
The share lived only in `NodeState::Ready` in memory and every start re-ran DKG. After stopping and
restarting all nodes the group public key changed (P2 FAIL) and a pre-restart invoice key could no
longer be derived (P3 FAIL). Nodes with no usable share just started a fresh DKG and kept running
(P4-P7 FAIL).

## Decisions

| # | Question | Decision | Rejected alternatives (why) |
|---|----------|----------|-----------------------------|
| D1 | Where does the share live? | One encrypted file per node, `share.v1.json`, in a directory the node owns (0700, file 0600). | Plaintext file protected only by permissions (any read of the disk or a backup exposes the share). Postgres (nodes are deliberately independent of the service DB). |
| D2 | How is it encrypted? | Envelope encryption: a fresh random 256-bit data key (DEK) per file encrypts the 32-byte share with AES-256-GCM; the DEK is wrapped by a key-encryption key (KEK) through a `KekProvider` trait. AEAD library: `ring` (already in the tree through rustls, so no new crate; `Cargo.lock` gains two dependency edges and no new package). | A bespoke scheme (forbidden). Passphrase-derived KEK (needs a KDF policy and human entry at boot; not decided). One KEK shared by all nodes (a single stolen KEK would open every share). |
| D3 | What is bound to the ciphertext? | AEAD associated data on BOTH operations: format version, node id, `n`, `t`, crypto epoch string, SHA-256 fingerprint of the group public key. | Unbound ciphertext (a share file could be moved into another node's slot or another group). |
| D4 | Pilot KEK source | `FileKek`: 32 raw bytes in a file, owner-only (the node refuses 0644), located outside the share directory, one distinct KEK per node. | Environment variable (leaks to child processes and `/proc`). |
| D5 | Real-data KEK source | A KMS/HSM implementation of `KekProvider` (wrap/unwrap with the AAD as encryption context). **Interface only; no cloud backend is implemented or claimed.** Needs a cloud/HSM account and a human decision. | Claiming the file KEK is sufficient for real data. It is not: a root attacker on the host reads both files. |
| D6 | Lifecycle | Three explicit boot modes. (a) share file exists and `init_ceremony=false`: load, verify, resume, never run DKG. (b) no share file and `init_ceremony=true`: run DKG, persist the share BEFORE reporting ready (a persist failure exits the process). (c) every other combination is a fatal startup error: share exists + `init_ceremony=true` (never overwrite), no share + `init_ceremony=false` (never silently run DKG), corrupt/wrong-KEK/wrong-node/wrong-group/pin-mismatch file. | Auto-run DKG when the file is missing (this is the bug). |
| D7 | Legacy ephemeral mode | Kept ONLY for throwaway test quorums and made fail-closed: a config with no `persistence` section is a startup error unless `allow_ephemeral_share=true` is set explicitly. | Leaving ephemeral as the silent default (a forgotten config field would destroy the group key at the next restart). |
| D8 | Overwrite protection | The share file is created with temp file, `fsync`, hard-link into place (fails if the target exists), `fsync` of the directory. A crash leaves either no share file or a complete one. | `rename` (silently replaces an existing share). |
| D9 | Operator pin | After the ceremony each node logs `sha256` of the group public key; operators record it and set `expected_group_pubkey_sha256_hex`. A share for any other group is refused. | Trusting whatever group key the file contains (acceptable only for tests). |
| D10 | Backup | Copy the (already encrypted) `share.v1.json` to offline storage; custody the KEK separately (different person/system). A unit test covers copy plus same KEK on an empty directory. **Not rehearsed with real operators.** KEK splitting (for example Shamir) is NOT decided: it would be a new key-management procedure and is left to the owner and the cryptographer. | Backing up share and KEK together (defeats the encryption). |

## Verified behaviour (all EXECUTED)
* 17 new unit tests in `quorum_node::share_store`: round trip; plaintext never in the file; wrong KEK;
  every single-byte flip of the file; truncation, empty and oversize files; missing file; move into
  another node's slot; edited `node_id` header; other group (pin and substitution); wrong `n`/`t`;
  never overwrite; refuse to write a share that does not match the group; stale temp file; file modes
  0600/0700; KEK file mode and size; backup/restore; error text free of key material.
* Mutation checks: removing the node id and fingerprint from the AAD fails `editing_the_node_id_field_...`;
  disabling the commitment check in `restore_verified` fails `create_new_refuses_a_share_that_does_not_match_the_group`.
* Adversarial group P (real processes): P1 ceremony persists and derives; P2 group key identical on
  all 5 nodes after stopping and restarting all of them; P3 the pre-restart derived key is
  byte-identical and verifies against the original group key; P4 corrupted file, P5 missing file,
  P6 wrong KEK, P7 ceremony over an existing share, P9 missing config all exit non-zero with the
  intended error and write no ready/pubkey output; P8 weak log-marker check (see limits).

## What this does NOT solve (do not claim otherwise)
1. **Gap 2, resharing / replacement.** A node that loses its disk AND its backup is gone for good.
   Losing more than `n-(t+1)` nodes loses every key. There is still no way to refresh shares or replace a node.
2. **Host compromise.** The decrypted share is in process memory while running (zeroized on drop,
   best effort, no `mlock`). A root attacker on a node reads the KEK file and the share file. Gap 10 in
   the project's own table (HSM) remains open.
3. **Partial ceremony.** If the ceremony fails on some nodes after others persisted, the persisted
   nodes refuse `init_ceremony=true`. Recovery is to delete every node's share directory and rerun the
   ceremony on all nodes together. This is a pilot-stage procedure, not a membership protocol.
4. **Gap 3** (single shared HMAC key as the authorization layer) is untouched.
5. **R-2 / pending audit vote is still memory-only** and lost on restart; the audit log files
   (`audit_log_file`, `pubkey_file`, `ready_file`) are still written with a non-atomic `let _ =
   std::fs::write` (F-01, Gap 13). Only the share file got the atomic path.
6. **Not tested:** power-loss / `kill -9` at random points during `create_new` (the design makes it
   safe and the stale-temp case is unit tested, but there is no crash-injection harness yet, which is
   Gap 13's test); a real KMS/HSM; multi-host operation; the orchestrator does not yet generate
   persistent configs (only the adversarial harness exercises them).

## Gating (restating the earlier decision)
* Pilot on non-real data: Gaps 1 (this), 3, 6, 10 closed with evidence.
* Real data: additionally Gap 4(c), independent cryptographic review, external audit, counsel's
  opinion (Gap 15), a KMS/HSM `KekProvider`, and a rehearsed backup/restore.

## Questions for the owner / cryptographer
1. Is `FileKek` acceptable for the pilot, or is a KMS required even for non-real data?
2. Which cloud/HSM will back `KekProvider` for real data?
3. KEK escrow: single custodian, or a threshold split of the KEK (needs a reviewed procedure)?
4. Should a failed ceremony be recoverable without wiping all nodes (that is membership-change work, Gap 2)?
5. Cryptographer: confirm AES-256-GCM with random 96-bit nonces under a single-use DEK, and the AAD contents.
