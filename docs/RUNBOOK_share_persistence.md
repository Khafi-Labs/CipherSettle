# Runbook: node key-share persistence (pilot tier, non-real data only)
STATUS: NEEDS_HUMAN_CRYPTO_REVIEW. Procedure written from the implemented behaviour; NOT rehearsed with real operators.

## One-time ceremony (all 5 nodes together)
1. Per node, generate a distinct 32-byte KEK file OUTSIDE the share dir, mode 0600 (e.g. `head -c32 /dev/urandom > node0.kek; chmod 600 node0.kek`). The node refuses any other mode or size.
2. Configure `persistence { dir, kek_file, init_ceremony: true }` on every node (no `expected_group_pubkey_sha256_hex` yet). Start all nodes.
3. Each node logs `share persisted ... sha256=<fingerprint>`. Check all 5 fingerprints are identical, record it.
4. Stop nodes. Set `init_ceremony: false` and `expected_group_pubkey_sha256_hex` to the recorded fingerprint. Start.

## Normal start
Share file present + `init_ceremony=false`: the node loads, verifies against the group commitment and the pin, and resumes. It never runs DKG.

## Backup / restore
Copy the already-encrypted `share.v1.json` to offline storage. Keep the KEK with a different custodian. Restore = place both on the replacement host with `init_ceremony=false`. (Unit-tested only.)

## Failure meanings (exit code 2, no ready/pubkey output)
missing file => restore from backup, never run the ceremony on one node; corrupt/wrong KEK => `failed authenticated decryption`; ceremony over an existing share => refused, share untouched; no `persistence` section => set it (`allow_ephemeral_share=true` is for throwaway test quorums ONLY).
Partial ceremony (some nodes persisted): delete every node's share dir and rerun on all nodes. Losing more than n-(t+1) shares+backups loses all keys (Gap 2 open).
