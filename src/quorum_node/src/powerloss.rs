//! Gap 13 power-loss rehearsal helpers. OPERATOR TOOLS, not part of the node
//! protocol: they only exercise `audit_store`, so a rehearsal needs no cluster.
//!
//!   quorum_node audit-powerloss-workload <log_file> <ack_file> [max_entries]
//!   quorum_node audit-powerloss-verify   <log_file> [ack_file]
//!
//! The workload appends one entry, persists the whole log with the production
//! atomic+fsync path, and only THEN durably records the entry count in
//! `ack_file`. After a power cut, `verify` requires that the log parses, its
//! hash chain verifies, and it holds at least as many entries as the last
//! durable ack (acknowledged => durable). Both resume from what is on disk.
//!
//! A pass is evidence for Gap 13's power-loss criterion only after the
//! runbook's repetition count is met on a real power cut or hypervisor
//! power-off (not `kill -9`, which test group Q already covers).

use crate::audit_store::{load_audit_log, persist_audit_log, write_atomic};
use quorum_audit::AuditEvent;
use std::path::Path;

fn read_ack(ack_path: &Path) -> u64 {
    std::fs::read_to_string(ack_path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Runs until `max_entries` entries exist (or until killed when `None`).
pub fn workload(log_path: &Path, ack_path: &Path, max_entries: Option<u64>) -> Result<(), String> {
    let mut log =
        load_audit_log(log_path).map_err(|e| format!("cannot resume from existing log: {e:?}"))?;
    loop {
        let n = log.next_seq();
        if max_entries.is_some_and(|m| n >= m) {
            return Ok(());
        }
        let entry = log.propose_next(AuditEvent {
            invoice_id: format!("powerloss-{n}"),
            actor: "powerloss-workload".to_string(),
            action: "powerloss_append".to_string(),
            timestamp_unix_ms: n,
        });
        log.try_append(entry)?;
        persist_audit_log(log_path, &log).map_err(|e| format!("persist failed: {e:?}"))?;
        write_atomic(ack_path, (n + 1).to_string().as_bytes())
            .map_err(|e| format!("ack write failed: {e}"))?;
    }
}

/// `Ok(summary)` only if the log is intact AND holds every acknowledged entry.
pub fn verify(log_path: &Path, ack_path: Option<&Path>) -> Result<String, String> {
    let acked = ack_path.map(read_ack).unwrap_or(0);
    let log = match load_audit_log(log_path) {
        Ok(l) => l,
        Err(e) => return Err(format!("LOG DAMAGED: {e:?}")),
    };
    let have = log.entries.len() as u64;
    if have < acked {
        return Err(format!(
            "DURABILITY VIOLATION: {acked} entries were acknowledged as durable but only {have} are on disk"
        ));
    }
    Ok(format!(
        "ok: {have} entries, hash chain valid, last durable ack {acked}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("powerloss-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn workload_then_verify_passes_and_resumes() {
        let d = dir("ok");
        let (l, a) = (d.join("audit.json"), d.join("ack"));
        workload(&l, &a, Some(5)).unwrap();
        assert!(verify(&l, Some(&a)).unwrap().contains("5 entries"));
        workload(&l, &a, Some(8)).unwrap();
        assert!(verify(&l, Some(&a)).unwrap().contains("8 entries"));
    }

    #[test]
    fn verify_rejects_a_truncated_log() {
        let d = dir("trunc");
        let (l, a) = (d.join("audit.json"), d.join("ack"));
        workload(&l, &a, Some(4)).unwrap();
        let raw = std::fs::read(&l).unwrap();
        std::fs::write(&l, &raw[..raw.len() / 2]).unwrap();
        assert!(verify(&l, Some(&a)).unwrap_err().contains("LOG DAMAGED"));
    }

    #[test]
    fn verify_rejects_a_tampered_chain() {
        let d = dir("tamper");
        let (l, a) = (d.join("audit.json"), d.join("ack"));
        workload(&l, &a, Some(4)).unwrap();
        let s = std::fs::read_to_string(&l)
            .unwrap()
            .replacen("powerloss-1", "powerloss-X", 1);
        std::fs::write(&l, s).unwrap();
        assert!(verify(&l, Some(&a)).unwrap_err().contains("LOG DAMAGED"));
    }

    #[test]
    fn verify_rejects_an_ack_ahead_of_the_disk() {
        let d = dir("ack");
        let (l, a) = (d.join("audit.json"), d.join("ack"));
        workload(&l, &a, Some(3)).unwrap();
        std::fs::write(&a, b"9").unwrap();
        assert!(verify(&l, Some(&a))
            .unwrap_err()
            .contains("DURABILITY VIOLATION"));
    }

    #[test]
    fn missing_log_with_a_nonzero_ack_is_a_violation_not_an_empty_pass() {
        let d = dir("missing");
        let a = d.join("ack");
        std::fs::write(&a, b"2").unwrap();
        assert!(verify(&d.join("nope.json"), Some(&a))
            .unwrap_err()
            .contains("DURABILITY VIOLATION"));
    }
}
