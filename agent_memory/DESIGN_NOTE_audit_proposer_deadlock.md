# Design note: audit-proposer deadlock (F-13) and audit/state ordering (F-14)

STATUS: **NEEDS_HUMAN_DECISION.** Not implemented. This touches the vote-slot semantics that SECURITY_REVIEW R-2 / section 8 item 2 already lists as an open decision. Not cryptography, but safety-critical.

## Problem (EXECUTED evidence in SECURITY_FINDINGS F-13)
Vote slot rule (node): one pending vote per seq; a different entry at the same seq is refused until the pending entry commits or `PENDING_AUDIT_VOTE_TTL` (5 s) expires. With >=3 concurrent proposers, an unlucky split leaves nobody at quorum. Retries re-send the same entry, so they cannot move any vote. Client budget (`MAX_PROPOSE_ATTEMPTS`=8, ~0.5-0.8 s backoff + attempt time) ends first. Result: all proposers fail, nothing commits.

## Options (each with what it costs)
| Option | Change | Pros | Cons / risk |
|---|---|---|---|
| A. Serialize proposals inside `quorum_service` (one async mutex around the append in `log_audit_event`) | service only, ~10 lines, no wire change, no check weakened | Removes concurrency for the only production proposer; project already forbids >1 service replica (PRODUCTION_READINESS 1.11) | Throughput serialized; one slow/failed append (up to ~1 s+) blocks others; does nothing for multiple replicas or other proposers; Test E / X still measure the protocol hazard (good: do NOT put this in the client, that would make Test E trivially pass) |
| B. Vote-release / abort message | new node message + client use; wire change | Frees votes immediately on failure | Protocol change; must be designed so a malicious proposer cannot release others' votes; needs review; version bump |
| C. Wait past the TTL before giving up | client only | No wire change | **Widens the R-2 window** (TTL expiry lets a node vote for a second entry at the same seq, enabling two conflicting commits). Do not do this before R-2 is decided |
| D. Single designated writer / leader | architecture | Eliminates the race by construction | Largest change; availability depends on leader |

Recommendation (non-binding): A now (smallest, safe, reversible), then decide B vs D together with R-2. Reject C.

## F-14 ordering (state change vs audit)
Derive already audits first (fail-closed). For register/grant/revoke/settle/prune: either (1) append audit first then mutate (a failed mutation after a successful audit leaves an extra "attempted" record, which is the safer failure for an evidence log), or (2) keep DB-first and add a compensating revert/mark on audit failure. (1) is simpler. Needs product-owner decision on whether "audit says X happened but X did not" is acceptable (it can be made explicit by distinct action names).

## Tests to write first when a decision is made
1. Deterministic: craft a 2/2/1 vote split by sending `AppendAuditEntry` for 3 different entries directly to nodes {0,1},{2,3},{4}; assert `propose_and_cosign_and_replicate` fails (pins the hazard like the existing `ttl_expiry_can_split_quorums_documented_hazard`).
2. Service-level: K>=8 concurrent `register_invoice` calls through the live service; assert all 201 and K audit entries (run >=50 times; expect failures before fix).
3. F-14: force the audit append to fail; assert no state change without a record (or that the compensating action ran).

## Questions for the owner
1. Is a single `quorum_service` replica the committed deployment model for the pilot (makes A sufficient)?
2. For F-14, which failure is acceptable: an audit record for an action that did not complete, or a completed action with no record?

---
# Owner decisions received (session 06) and verification before any production change

## Decisions as given
- F-13: real concurrency bug, NOT to be masked with retries / bigger budgets. Invariant: a protocol attempt must never end with no successful proposer, no audit entry, and no diagnosable record. If progress is impossible it must fail explicitly with a diagnosable error/audit record.
- F-14: no DB <-> audit circular wait; defined ordering and failure semantics; the core protocol must not depend on an audit step that can block indefinitely. Preferred ordering stated: decide/commit -> record audit -> confirm.
- Required before closing: regression test + root-cause fix + repeated concurrency testing. Owner asked to see the exact call path and logs BEFORE production code changes.

## Exact call path (READ, with line refs in the current tree)
1. `quorum_service/src/main.rs` handlers `register_invoice` (~l.327-370), `grant/revoke_settlement_access` (~l.410-446), `settle` (~l.478-480), `prune` (~l.520-522), regulator register/revoke (~l.772-801): DB write (own tx / autocommit) -> `drop(client)` (pool connection released) -> `log_audit_event` (l.240) -> `quorum_client::propose_and_cosign_and_replicate`. Derive (l.598-622): DB reads -> `drop(client)` -> `log_audit_event` -> only then derive (fail-closed).
2. `propose_and_cosign_and_replicate` (`quorum_client/src/lib.rs` l.755): up to 8 x `try_propose_once` with 10 + 15*attempt + <40 ms backoff (~0.9 s total, measured 878-925 ms in Y1). Each attempt rebuilds the entry against the majority tip and sends `AppendAuditEntry` to nodes.
3. Node (`quorum_node/src/main.rs` ~l.580-620): `check_extends`, then `pending.try_vote(seq, hash, now, TTL=5s)` (`quorum_audit/src/lib.rs` l.437): refuses a DIFFERENT hash at the same seq while a vote is pending and younger than 5 s; same hash is re-granted. Only a commit (`ReplicateAuditEntry`, `on_commit`) or TTL expiry clears it.
4. Log evidence: `agent_memory/evidence/test_x_n4_failing_run_nodelogs.log`: 120 lines `refused audit append at seq 0: already voted for a different entry at seq 0; awaiting its commit`, no commit.

## Finding from reading the path: there is NO DB <-> audit circular wait in the current code
- The audit path (quorum_client -> nodes) never touches Postgres; the service releases its pooled DB connection BEFORE calling `log_audit_event` in every handler listed above (`drop(client)` precedes it). So today there is no cycle and no DB slot is held while waiting on audit. The F-14 problem is ORDERING / evidence integrity (DB state commits first, audit may then fail), not a cycle. The owner's constraint (no cycle) is satisfied now and must stay a rule for the fix (do not hold a DB tx or pool slot across the audit await; do not make audit wait on DB).

## Conflict that needs an explicit owner answer
The stated preferred ordering "commit protocol decision -> record audit -> return" is the CURRENT ordering for register/grant/revoke/settle/prune, and it is exactly what produces F-14 (state change exists, audit failed, caller gets 500). It is only safe if one of these is added: (a) a durable "pending audit" record in the SAME DB transaction (transactional outbox) that a worker drains into the audit log, so the change and the obligation to audit commit atomically and failure is observable; or (b) audit-first (intent entry, then mutate), accepting an "attempted" record without effect. Without (a) or (b) the owner's invariant ("failure must leave a diagnosable record") cannot hold when the audit quorum itself is the thing that is down, because an audit record cannot be written to a log that cannot accept writes: the diagnosable record has to live somewhere else (DB outbox row or error table, plus a metric/log line). Recommendation: (a) outbox for the mutation handlers, derive stays audit-first. This is a design decision; not implemented.

## Test added now (test-only, opt-in, no production change)
`quorum_adversarial` group `Y` (`--only Y`): hand-casts votes so a 2/2/1 split ALWAYS exists (entry A -> nodes {0,1}, B -> {2,3}, C -> {4}), then runs a fresh proposer.
- Y1 PASS 5/5 runs: premise holds (5/5 votes granted), proposer returns an explicit Err after ~0.9 s, 0 entries in all 5 logs. This pins CURRENT behaviour (hazard + explicit-Err); it does NOT show the invariant "diagnosable record" is met: the Err is an unstructured String and nothing is recorded anywhere.
- Y2 PASS 5/5: after the 5 s TTL the same proposal succeeds, i.e. only TTL expiry unblocks it (retries cannot).
Not in the default run (verified by construction: Y runs only when named). Pending tests (to write when the design is chosen): typed contention error + recorded failure; service-level K>=8 concurrent registrations all committed or explicitly failed with a record; F-14 forced-audit-failure test.

## What I will NOT do without your OK
Change `try_vote`, TTL, retry budget, or handler ordering. Options A (service-side serialization) and C (wait past TTL) from the table above: C stays rejected (widens R-2). A is compatible with your "no masking" rule only if the invariant (explicit failure + record) is also implemented, since A alone removes concurrency for one replica and leaves the failure mode silent for multi-replica or outage cases.

---
# Decisions delegated to the engineer by the owner (session 06, 2026-10-03)
Recorded as decisions of the assistant under delegation. They are NOT cryptographer/legal sign-off.
1. F-14: adopt (a) transactional outbox for register/grant/revoke/settle/prune/regulator handlers; derive stays audit-first (fail-closed). Rule: never hold a DB tx or pool slot across an audit await; audit never waits on DB.
2. F-13: no retry/budget/TTL widening (option C rejected). Implement explicit typed contention error + recorded failure (DB outbox row / error record + log + metric). Service-side append serialization (option A) allowed only as a supplement, and Test E/X/Y keep exercising the raw protocol.
3. Vote-slot semantics (B release message, D leader) and R-2: remain open for human review; not changed.
4. Production: NO deployment to a real production environment and NO real data. Allowed: pilot on non-real data once Gap 1 (share persistence), Gap 3 (per-request authorization), Gap 6 (CI green on GitHub) and Gap 10 (migrations/backup/restore) are closed with evidence. Real data additionally requires Gaps 4(c), 5 (independent crypto review), external audit, and counsel's opinion (Gap 15).
Order of work from here: F-13/F-14 tests-first -> Gap 1 -> Gap 3 -> Gap 8 -> Gap 10.
