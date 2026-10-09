//! F-24: a RUNNING component that reconciles the quorum's audit logs and (optionally)
//! notarizes the proven tip. Tests first; implementation follows.

use ed25519_dalek::VerifyingKey;
use quorum_audit::{AuditLog, NodeStatus, ReconcileReport};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tokio_rustls::TlsConnector;

/// One reconciliation pass: the report plus the replicas that could not be read.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub at_unix_ms: u64,
    pub report: ReconcileReport,
    pub unreachable: Vec<usize>,
}

/// Shared state for the background reconciler and the `/metrics` renderer.
pub struct ReconcilerState {
    latest: Mutex<Option<Snapshot>>,
    runs: AtomicU64,
    notarized_ok: AtomicU64,
    notarize_failed: AtomicU64,
}

impl ReconcilerState {
    pub fn new() -> Self {
        Self {
            latest: Mutex::new(None),
            runs: AtomicU64::new(0),
            notarized_ok: AtomicU64::new(0),
            notarize_failed: AtomicU64::new(0),
        }
    }

    pub fn render(&self) -> String {
        let latest = match self.latest.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        render(
            &latest,
            self.runs.load(Ordering::Relaxed),
            self.notarized_ok.load(Ordering::Relaxed),
            self.notarize_failed.load(Ordering::Relaxed),
        )
    }

    fn store(&self, snap: Snapshot) {
        self.runs.fetch_add(1, Ordering::Relaxed);
        match self.latest.lock() {
            Ok(mut g) => *g = Some(snap),
            Err(poisoned) => *poisoned.into_inner() = Some(snap),
        }
    }
}

/// Why the reconciler cannot run, or `Ok(())`.
pub fn check_enabled(
    num_audit_keys: usize,
    num_nodes: usize,
    min_sigs: usize,
    interval_secs: u64,
) -> Result<(), String> {
    if interval_secs == 0 {
        return Err("reconcile_interval_secs is 0".to_string());
    }
    if num_audit_keys == 0 {
        return Err("no audit_public_keys configured".to_string());
    }
    if num_audit_keys < min_sigs || num_nodes < min_sigs {
        return Err(format!(
            "need at least {min_sigs} audit public keys and nodes to prove an entry, have {num_audit_keys} keys and {num_nodes} nodes"
        ));
    }
    Ok(())
}

pub fn should_notarize(tip: Option<[u8; 32]>, last_notarized: Option<[u8; 32]>) -> bool {
    tip.is_some() && tip != last_notarized
}

pub fn summarize(
    logs: &BTreeMap<usize, AuditLog>,
    unreachable: &[usize],
    audit_keys: &BTreeMap<usize, VerifyingKey>,
    min_sigs: usize,
    now_unix_ms: u64,
) -> Snapshot {
    Snapshot {
        at_unix_ms: now_unix_ms,
        report: AuditLog::reconcile(logs, audit_keys, min_sigs),
        unreachable: unreachable.to_vec(),
    }
}

pub fn render(
    snapshot: &Option<Snapshot>,
    runs: u64,
    notarized_ok: u64,
    notarize_failed: u64,
) -> String {
    let mut out = String::new();
    out.push_str("# HELP ciphersettle_audit_reconcile_runs_total Reconciliation passes completed since start.\n# TYPE ciphersettle_audit_reconcile_runs_total counter\n");
    out.push_str(&format!("ciphersettle_audit_reconcile_runs_total {runs}\n"));
    out.push_str("# HELP ciphersettle_audit_notarizations_total Notary receipts obtained for the proven audit tip, and failures.\n# TYPE ciphersettle_audit_notarizations_total counter\n");
    out.push_str(&format!(
        "ciphersettle_audit_notarizations_total{{result=\"ok\"}} {notarized_ok}\nciphersettle_audit_notarizations_total{{result=\"failed\"}} {notarize_failed}\n"
    ));
    let Some(snap) = snapshot else {
        // No pass yet: say nothing about node health rather than report zeros.
        return out;
    };
    let count = |f: fn(&NodeStatus) -> bool| snap.report.nodes.values().filter(|s| f(s)).count();
    let rows: [(&str, usize); 6] = [
        ("matches", count(|s| matches!(s, NodeStatus::Matches))),
        ("behind", count(|s| matches!(s, NodeStatus::Behind { .. }))),
        (
            "ahead_unproven",
            count(|s| matches!(s, NodeStatus::AheadUnproven { .. })),
        ),
        (
            "diverged",
            count(|s| matches!(s, NodeStatus::Diverged { .. })),
        ),
        (
            "chain_invalid",
            count(|s| matches!(s, NodeStatus::ChainInvalid)),
        ),
        ("unreachable", snap.unreachable.len()),
    ];
    out.push_str("# HELP ciphersettle_audit_reconcile_nodes Audit replicas by reconciliation status in the latest pass.\n# TYPE ciphersettle_audit_reconcile_nodes gauge\n");
    for (label, n) in rows {
        out.push_str(&format!(
            "ciphersettle_audit_reconcile_nodes{{status=\"{label}\"}} {n}\n"
        ));
    }
    out.push_str(&format!(
        "# HELP ciphersettle_audit_reconcile_suspicious_nodes Replicas that diverge, hold unproven entries or have a broken chain. Alert when above 0.\n# TYPE ciphersettle_audit_reconcile_suspicious_nodes gauge\nciphersettle_audit_reconcile_suspicious_nodes {}\n",
        snap.report.suspicious().len()
    ));
    out.push_str(&format!(
        "# HELP ciphersettle_audit_reconcile_reference_entries Entries in the signature-proven reference log.\n# TYPE ciphersettle_audit_reconcile_reference_entries gauge\nciphersettle_audit_reconcile_reference_entries {}\n",
        snap.report.reference_len
    ));
    out.push_str(&format!(
        "# HELP ciphersettle_audit_reconcile_last_run_unix_ms Time of the latest pass.\n# TYPE ciphersettle_audit_reconcile_last_run_unix_ms gauge\nciphersettle_audit_reconcile_last_run_unix_ms {}\n",
        snap.at_unix_ms
    ));
    out
}

/// Reads every node's log in parallel; unreachable nodes are listed, not guessed at.
pub async fn fetch_all(
    connector: &TlsConnector,
    nodes: &[(usize, String)],
) -> (BTreeMap<usize, AuditLog>, Vec<usize>) {
    let mut set = tokio::task::JoinSet::new();
    for (id, addr) in nodes.iter().cloned() {
        let c = connector.clone();
        set.spawn(async move { (id, quorum_client::fetch_full_log(&c, &addr).await) });
    }
    let mut logs = BTreeMap::new();
    let mut unreachable = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((id, Ok(log))) => {
                logs.insert(id, log);
            }
            Ok((id, Err(_))) => unreachable.push(id),
            Err(_) => {}
        }
    }
    unreachable.sort_unstable();
    (logs, unreachable)
}

pub struct Settings {
    pub nodes: Vec<(usize, String)>,
    pub audit_keys: BTreeMap<usize, VerifyingKey>,
    pub min_sigs: usize,
    pub interval: Duration,
    pub notary_addr: Option<String>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Runs forever: reconcile, log anything suspicious, notarize a changed proven tip.
pub async fn run_forever(
    state: std::sync::Arc<ReconcilerState>,
    connector: TlsConnector,
    s: Settings,
) {
    let mut last_notarized: Option<[u8; 32]> = None;
    let mut tick = tokio::time::interval(s.interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let (logs, unreachable) = fetch_all(&connector, &s.nodes).await;
        let snap = summarize(&logs, &unreachable, &s.audit_keys, s.min_sigs, now_ms());
        let suspicious = snap.report.suspicious();
        if !suspicious.is_empty() {
            eprintln!(
                "[service] AUDIT RECONCILE WARNING: replicas {suspicious:?} are suspicious: {:?}",
                snap.report.nodes
            );
        }
        let tip = snap.report.reference_tip;
        state.store(snap);
        if let (Some(addr), true) = (&s.notary_addr, should_notarize(tip, last_notarized)) {
            if let Some(tip) = tip {
                match quorum_client::notarize(&connector, addr, tip).await {
                    Ok(_) => {
                        last_notarized = Some(tip);
                        state.notarized_ok.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        state.notarize_failed.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[service] notarization failed: {e}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use quorum_audit::{sign_entry_hash, AuditEvent, AuditLog};
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    fn keys() -> (
        Vec<SigningKey>,
        BTreeMap<usize, ed25519_dalek::VerifyingKey>,
    ) {
        let sk: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let vk = sk
            .iter()
            .enumerate()
            .map(|(i, k)| (i, k.verifying_key()))
            .collect();
        (sk, vk)
    }

    fn log(sk: &[SigningKey], who: &str, n: u64) -> AuditLog {
        let mut l = AuditLog::default();
        for i in 0..n {
            let mut e = l.propose_next(AuditEvent {
                invoice_id: format!("i{i}"),
                actor: who.into(),
                action: "x".into(),
                timestamp_unix_ms: i,
            });
            for (s, key) in sk.iter().enumerate().take(3) {
                e.signatures.insert(s, sign_entry_hash(key, &e.entry_hash));
            }
            l.try_append(e).unwrap();
        }
        l
    }

    #[test]
    fn summarize_counts_every_status_including_unreachable() {
        let (sk, vk) = keys();
        let good = log(&sk, "a", 2);
        // A tampered replica: content rewritten, the ORIGINAL signatures kept (it cannot
        // sign for other nodes), so they verify against nothing.
        let mut tampered = AuditLog::default();
        for e in &good.entries {
            let mut t = tampered.propose_next(AuditEvent {
                invoice_id: e.event.invoice_id.clone(),
                actor: "EVIL".into(),
                action: "x".into(),
                timestamp_unix_ms: e.event.timestamp_unix_ms,
            });
            t.signatures = e.signatures.clone();
            tampered.try_append(t).unwrap();
        }
        let mut logs = BTreeMap::new();
        logs.insert(0, good.clone());
        logs.insert(1, good.clone());
        logs.insert(2, good);
        logs.insert(3, tampered);
        let snap = summarize(&logs, &[4], &vk, 3, 1_000);
        assert_eq!(snap.report.reference_len, 2);
        assert_eq!(snap.unreachable, vec![4]);
        let text = render(&Some(snap.clone()), 7, 1, 0);
        assert!(
            text.contains("ciphersettle_audit_reconcile_nodes{status=\"matches\"} 3"),
            "{text}"
        );
        assert!(
            text.contains("ciphersettle_audit_reconcile_nodes{status=\"diverged\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("ciphersettle_audit_reconcile_nodes{status=\"unreachable\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("ciphersettle_audit_reconcile_suspicious_nodes 1"),
            "{text}"
        );
        assert!(
            text.contains("ciphersettle_audit_reconcile_runs_total 7"),
            "{text}"
        );
        assert!(
            text.contains("ciphersettle_audit_reconcile_last_run_unix_ms 1000"),
            "{text}"
        );
        assert!(
            text.contains("ciphersettle_audit_reconcile_reference_entries 2"),
            "{text}"
        );
    }

    #[test]
    fn render_before_any_run_says_so_and_does_not_claim_health() {
        let text = render(&None, 0, 0, 0);
        assert!(
            text.contains("ciphersettle_audit_reconcile_runs_total 0"),
            "{text}"
        );
        assert!(
            !text.contains("suspicious_nodes 0"),
            "must not report 0 suspicious before a run: {text}"
        );
    }

    #[test]
    fn disabled_reasons_are_explicit() {
        assert!(check_enabled(0, 5, 3, 60).is_err()); // no keys
        assert!(check_enabled(2, 5, 3, 60).is_err()); // fewer keys than the quorum
        assert!(check_enabled(5, 5, 3, 0).is_err()); // interval 0 = off
        assert!(check_enabled(5, 5, 3, 60).is_ok());
    }

    #[test]
    fn notarize_only_when_the_proven_tip_changed() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        assert!(should_notarize(Some(h1), None));
        assert!(!should_notarize(Some(h1), Some(h1)));
        assert!(should_notarize(Some(h2), Some(h1)));
        assert!(!should_notarize(None, Some(h1)));
        assert!(!should_notarize(None, None));
    }
}
