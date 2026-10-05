# Runbook: audit backlog / audit failures (PILOT TIER)

Status: written from the design and the tests in group Z; **never exercised in an incident or a drill.**

## What the signals mean
* `ciphersettle_audit_outbox_oldest_unfinished_age_seconds` high: state changes have committed but their audit
  record is not yet in the quorum's log (F-14 outbox). Evidence is delayed, not lost: rows stay in `audit_outbox`.
* `ciphersettle_audit_failures_total` rising: key derivations are being DENIED (fail-closed) because the audit
  append failed. Users see 503; no key is released without an audit record.

## Diagnose (read-only)
1. `SELECT status, count(*), min(created_at_ms), max(attempts), max(last_error) FROM audit_outbox WHERE status <> 'done' GROUP BY status;`
2. Are >= 3 of 5 quorum nodes reachable and Ready? (each node's log: `DKG finalized` / share-loaded line; a node that
   refuses to start logs `refusing to start` or `FATAL`).
3. `SELECT * FROM audit_failures ORDER BY id DESC LIMIT 20;` for the error text.
4. Vote split (F-13/R-2): contention clears after the 5 s vote TTL; if the same error persists, a node may be
   holding a stale vote or be on a different log tip (compare entry counts across nodes with the audit-log reader).

## Act
* Quorum below 3 nodes: restore nodes (see deploy/README.md node backup/restore). The drainer retries with backoff
  by itself; do NOT delete outbox rows and do NOT hand-edit node audit files.
* A node refuses to start on a damaged audit log: restore that node's file from backup, never replace it with an empty log.
* After recovery confirm: pending rows reach 0, `oldest_unfinished_age_seconds` returns to 0, and failures stop rising.
  A duplicated audit entry after a crash is possible (at-least-once delivery, F-19/F-14 residual) and is not an incident.

## Known gaps
No request latency/error-rate metrics; no log aggregation; no on-call or paging integration is configured; the thresholds
above are guesses until real traffic exists.
