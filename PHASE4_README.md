# Phase 4 — Adversarial Testing & External Review

Implements the "adversarial tests" and "load/liveness" bullets of the
roadmap's Phase 4:

> "Adversarial tests: malicious minority node submitting bad partial
> derivations, node collusion below threshold, replay attacks on derive
> requests, log-reconciliation bypass attempts. Load/liveness testing
> under a real node outage... sustained network partition between quorum
> members. Penetration test of the mTLS node channel and the external
> client API surface separately."

The "independent cryptography review" and "external reviewer sign-off"
bullets are a different kind of deliverable, and **have not been met**. See
`SECURITY_REVIEW.md` for the current technical security assessment and
`CipherSettle_Audit_Remediation_Roadmap.md` Phase 5 for the audit engagement
that would satisfy them. Nothing in this repository substitutes for
independent cryptographic peer review — including this suite, which was
written by the same process that built the system it attacks.

## New crate

**`quorum_adversarial`** — a binary that spins up real, fresh quorums
(via the same `quorum_node` binary every other phase uses) and attacks
them, printing a PASS/FAIL verdict with a concrete explanation for each
of **41 checks across 14 test groups (A–N)**. Nothing here is simulated at the
protocol level: every attack goes over real mTLS, real HTTP, and a real
Postgres, with group H using a real `iptables`-enforced network partition.

> **Verification caveat for group H.** The network-partition test requires
> `iptables` (and root or `CAP_NET_ADMIN`). In the environment where this
> suite was last verified, `iptables` was unavailable, so the partition could
> not take effect and that group's result is **unconfirmed** rather than
> demonstrated. Run it in an environment that has `iptables` before relying on
> it. See `CipherSettle_Audit_Remediation_Roadmap.md` (finding A12).

## Run it

```bash
# Postgres must be running with a ciphersettle_adversarial database (see
# PHASE3_README.md's setup, substituting the database name):
sudo -u postgres psql -c "CREATE DATABASE ciphersettle_adversarial;"

cargo build -p quorum_node -p quorum_service -p quorum_adversarial
cargo run -p quorum_adversarial   # needs root (or CAP_NET_ADMIN) for Test H's iptables rules
```

Runs in 12-20 seconds. Every test cleans up its own processes and
`iptables` rules, including on early exit. Groups G, J, K and N require a
reachable Postgres and will report SKIPPED (which counts as a failure) if it
is not.

## What each test group actually checks

| Test | What it attacks | Expected result |
|---|---|---|
| A | A node (reusing a real, DKG-issued identity) that returns garbage partials on every derive request | The garbage is rejected per-share; derive still succeeds from the honest majority; and correctly *fails* rather than returning a wrong key once too few honest nodes remain |
| B | Combining a signature from exactly `T` (not `T+1`) genuine partials | `quorum_core::combine` refuses fewer than `t + 1` shares, and a `T`-share sealed combine fails final verification |
| C | Deriving a key using ONLY the shared mTLS client certificate, for an invoice that was never registered anywhere | **This one is expected to "fail" — see below** |
| D | Replaying an identical, previously-served `DeriveRequest` over a brand-new TLS session | **Also expected to "fail" — see below** |
| E | Two proposers concurrently appending conflicting audit entries at the same sequence number | Reproduces the documented lost-write race (timing-sensitive; doesn't always trigger in a given run, and is labeled honestly either way). **Known to be flaky under load — see the note below** |
| F | Connecting to a node with no client certificate, and with a valid-but-unpinned client certificate | Both rejected (note: detecting this correctly requires a follow-up read/write, not just checking `.connect()`'s result — see the "testing methodology" note below) |
| G | The HTTP API: no auth header, bad API key, SQL-injection-shaped path parameter, oversized payload, rate-limit exceeded | All correctly rejected with the right status code; the invoices table survives the injection attempt |
| H | A real `iptables`-enforced network partition (not a process kill) during DKG, then healing it | The genuinely cut-off nodes don't finalize while partitioned; ALL nodes finalize once healed, proving `quorum_node`'s unbounded-retry connect loop actually rides out a real partition. **Unconfirmed — see the verification caveat above** |
| I | Killing `node_addrs[0]` outright, then proposing a new audit entry | Propose still succeeds quickly via a majority of the remaining nodes — added in Stage F to close Finding 2.2 (previously the tip read was hardcoded to `node_addrs[0]` specifically, so this would have exhausted every retry and failed outright) |
| J | A malicious node in the first subset the service tries, forcing a retry against a different subset | The sealed-share retry protocol recovers without the caller having to supply the substitution logic |
| K | TLS termination by `quorum_service` | Misconfigured off-loopback without TLS refuses to start; plaintext loopback still works; a configured TLS handshake completes and carries a real HTTP response; a plaintext request against the TLS port is not served in the clear |
| L | Replay of a derive request after a node process restarts | The restart guard refuses any request a previous process would have accepted, given a non-stepping wall clock |
| M | A sealed share whose NIZK proof does not match the group-derived public key share | Rejected before combine, never reaching aggregation |
| N | A database whose `crypto_meta` epoch marker does not match | Refused outright across an exhaustive decision matrix, with no override path |

> **Test E reliability.** Test E was separately observed to be flaky under
> load — 3 passes out of 5 back-to-back runs. The deterministic replacement
> for the property it covers lives in `quorum_audit::vote_slot_tests` (which
> enumerates all 2^5 delivery orders), but Test E itself should not be treated
> as a hard gate until it has been re-run many times under controlled load.
> See `CipherSettle_Audit_Remediation_Roadmap.md` §4.

## Two things this test suite itself surfaced (about the *tests*, not the system)

Writing adversarial tests is itself adversarial — against your own
assumptions about how the thing you built behaves. Two bugs were caught
and fixed while building this suite, worth recording because they're the
kind of mistake that produces a false sense of security if left in:

1. **Test F's original check was too weak.** `tokio_rustls`'s
   `connect()` can return `Ok` even when the server intends to reject the
   connection: in TLS 1.3, the client's `Finished` message can be
   processed as completing the handshake from the client's side before
   the server's fatal alert (rejecting an absent/unpinned certificate)
   arrives. Checking only `.connect()`'s `Result` produced a false
   "vulnerability" (the connection LOOKED accepted). Fixed by following
   up with an actual request/response round-trip (`probe_survives`) and
   only treating the connection as "accepted" if a real message came
   back.
2. **Test H's original partition wasn't bidirectional.** Blocking
   `--dport` for nodes 3/4's listening ports only stops other nodes from
   connecting IN to 3/4 — it doesn't stop 3/4 from connecting OUT to
   0/1/2 (whose destination ports aren't blocked, and whose own
   connections use ephemeral source ports that can't be targeted by a
   simple port rule). Since DKG is a push protocol, this produced an
   *asymmetric* partition where 0/1/2 could still receive everything and
   legitimately finished DKG — which the test's first version incorrectly
   flagged as "the partition didn't apply." Fixed by asserting what this
   specific (achievable) partition shape actually implies, and
   documenting in the test itself that a true bidirectional split-brain
   on loopback needs network namespaces, not port-based `iptables` rules
   — out of scope for this harness.

Neither of these was a bug in the system under test. Both would have
produced a misleading report if not caught — which is itself a small
demonstration of why "the tests pass" is a weaker claim than it sounds
unless someone has separately checked that the tests are testing what
they claim to.
