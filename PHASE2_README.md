# Phase 2 — Tamper-Evident Audit Log

Implements the Phase 2 exit criteria of the project's original phased roadmap (that roadmap document is not part of this repository; its criteria are quoted verbatim below):

> "A log that survives a 'one node tries to rewrite its local copy' test
> -- reconciliation catches it -- and a notarization job running on a
> schedule."

## New/extended crates

- **`quorum_audit`** (new) — transport-agnostic hash-chained, multi-signed
  audit log. `AuditLog::try_append` refuses anything that doesn't extend
  the log's current tip (this is the actual "no single node can silently
  rewrite" mechanism); `AuditLog::diverges_from` is the reconciliation
  check; `NotarizationReceipt` is the external-anchor shape. Also defines
  the small shared `wire::NotaryMessage` protocol used by the notary.
- **`quorum_node`** (extended) — each node now also holds an ed25519
  audit-signing keypair (deliberately separate from its TLS identity —
  see the crate's `config.rs` doc comment for why), persists its own
  `AuditLog` replica to disk, and handles four new wire messages:
  `AppendAuditEntry` / `AuditEntrySigned` / `ReplicateAuditEntry` /
  `GetAuditLog`.
- **`quorum_notary`** (new) — a standalone binary with its own identity,
  playing the roadmap's "third-party transparency-log service" role:
  accepts a root hash, stamps it with a sequence number and wall-clock
  time, signs the tuple, appends it to an append-only file, and returns
  an independently-verifiable receipt.
- **`quorum_orchestrator`** (extended) — after the Phase 1 derive +
  round-trip, now also: builds an audit event via
  `ciphersettle_core::audit_action_for` **unchanged** (per the roadmap's
  explicit instruction), collects co-signatures from the 3 live nodes,
  replicates the entry, spawns `quorum_notary` and notarizes the log's
  root hash on a repeating (demo-compressed) schedule, **tampers with one
  node's on-disk log after taking it offline**, and runs reconciliation
  across all 5 nodes' logs.

## Run it

```bash
cargo build -p quorum_node -p quorum_notary -p quorum_orchestrator
cargo run -p quorum_orchestrator
```

Single command, no arguments — it drives Phase 1 and Phase 2 end to end
and tears down every process (nodes + notary) on exit.

## The tamper test, precisely

The roadmap's exit criterion is deliberately the *hard* version of this
test, and that's what's implemented: the orchestrator doesn't just corrupt
a JSON field (which would fail to parse, or fail `verify_chain()`
trivially). It:

1. Takes one node offline (after that node has genuinely co-signed and
   persisted the real entry).
2. Mutates that node's copy of the entry's content.
3. **Fully recomputes every downstream hash** so the tampered file is
   internally self-consistent -- `verify_chain()` on the tampered copy
   alone reports "fine."
4. Only when the orchestrator's reconciliation step compares that node's
   copy against another node's does the mismatch surface, at the exact
   sequence number that was altered.

The demo also deliberately includes two nodes that are simply *behind*
(never having received the entry at all, since they went offline before
the append even happened) and confirms reconciliation reports those as a
length mismatch, not a tamper alert -- an honest reconciler needs to tell
"this replica is stale" apart from "this replica was rewritten," and the
demo checks both directions.

## What's real vs. still open

| | Implemented | Still open |
|---|---|---|
| Hash chaining | Yes -- `entry_hash = H(prev_hash \|\| seq \|\| event)`, enforced by `try_append` | -- |
| Multi-node co-signing | Yes -- individual ed25519 signatures per participating node, collected and merged | No threshold/aggregate signature scheme; deliberately individual for accountability (see `quorum_audit`'s module doc) |
| Replication | Best-effort push to all `n` nodes after co-signing | No retry-on-recovery: an offline node that returns does **not** automatically catch up: this demo prints that gap explicitly rather than papering over it |
| Reconciliation | Pairwise `diverges_from` against a reference node, distinguishing hash-mismatch from length-mismatch | Closed: the reference is no longer a hardcoded node. `AuditLog::majority_reference` takes a per-sequence-number hash vote across every replica that has an entry there and keeps an entry only when a strict majority agrees, so reconciliation no longer depends on node 0 specifically not being the compromised one. What remains is that a colluding *majority* of reporting replicas could still agree on a rewritten entry — that is why external notarization below is a separate control, not a formality |
| External notarization | A genuinely separate process + identity, real signed receipts, runs on a schedule | The notary's receipts file lives on the same sandbox host as everything else -- see `quorum_notary`'s own module doc for exactly what would need to change to point this at a real RFC 3161 TSA / public git commit / transparency log |
| Dispute resolution | -- | Still not implemented (carried over from Phase 1): a node that receives a bad *DKG* share just never finalizes; there's no equivalent complaint mechanism for a node that gets caught trying to rewrite its *audit* log, beyond "reconciliation will notice and an operator has to act on it manually" |

## A note on why TLS identity and audit-signing identity are separate keys

A node's mTLS certificate proves "you're talking to node 3 over the
network." Its audit-signing key proves "node 3 personally attests to this
exact log entry." These are different claims with different failure
modes -- e.g. a TLS cert rotation shouldn't invalidate historical audit
attestations, and an audit key compromise shouldn't require re-keying the
whole node-to-node network fabric. Keeping them as two keypairs from the
start avoids having to retrofit that separation later, the same
reasoning the roadmap applies to designing DKG resharing in from the
start rather than bolting it on.
