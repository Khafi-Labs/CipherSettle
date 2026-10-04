//! Gap 13 (F-01): durable, atomic persistence of a node's audit log and its
//! small published files (group public key, ready marker).
//!
//! Guarantees (each has a unit test):
//! * every write is atomic and durable: temp file in the SAME directory
//!   (owner-only), `write_all`, `fsync` file, `rename` over the target, `fsync`
//!   the directory. A crash at any point leaves exactly the old file or exactly
//!   the new one, never a partial one;
//! * every I/O failure is returned; nothing is swallowed;
//! * on load, a missing file is a legitimate first start (empty log), but a
//!   file that exists and cannot be parsed, or whose hash chain does not
//!   verify, is an ERROR. The old behaviour ("corrupt: starting from an empty
//!   log") silently discarded audit evidence;
//! * stale `*.tmp.*` files from a crashed write are ignored and removed.

use quorum_audit::AuditLog;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, PartialEq, Eq)]
pub enum AuditStoreError {
    Io(String),
    Corrupt(String),
    ChainInvalid(String),
}

impl std::fmt::Display for AuditStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditStoreError::Io(e) => write!(f, "i/o error: {e}"),
            AuditStoreError::Corrupt(e) => write!(f, "corrupt audit log file: {e}"),
            AuditStoreError::ChainInvalid(e) => write!(f, "audit log hash chain invalid: {e}"),
        }
    }
}

/// Crash-injection points inside [`write_atomic_with`]. The hook is called
/// AFTER the named step completed; returning `false` simulates the process
/// dying right there (the function returns an error and does no cleanup).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    TempWritten,
    TempSynced,
    Renamed,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let tmp = format!(
        "{name}.tmp.{}.{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::SeqCst)
    );
    path.with_file_name(tmp)
}

fn injected_crash(stage: Stage) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        format!("injected crash after {stage:?}"),
    )
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

pub fn write_atomic_with(
    path: &Path,
    bytes: &[u8],
    mut hook: impl FnMut(Stage) -> bool,
) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    std::fs::create_dir_all(&dir)?;
    let tmp = temp_path_for(path);
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        if !hook(Stage::TempWritten) {
            return Err(injected_crash(Stage::TempWritten));
        }
        f.sync_all()?;
        if !hook(Stage::TempSynced) {
            return Err(injected_crash(Stage::TempSynced));
        }
        drop(f);
        std::fs::rename(&tmp, path)?;
        if !hook(Stage::Renamed) {
            return Err(injected_crash(Stage::Renamed));
        }
        sync_dir(&dir)
    })();
    if let Err(e) = &result {
        // A real failure (not a simulated crash) must not leave the temp file.
        if e.kind() != std::io::ErrorKind::Interrupted {
            let _ = std::fs::remove_file(&tmp);
        }
    }
    result
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with(path, bytes, |_| true)
}

/// Removes leftover temp files of `path` (from a crashed write).
fn remove_stale_temps(path: &Path) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let prefix = format!("{}.tmp.", name.to_string_lossy());
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Missing file => `Ok(empty)` (first start). Present but unreadable,
/// unparseable, or with an invalid hash chain => `Err` (the node must refuse
/// to start rather than silently forget its audit history).
pub fn load_audit_log(path: &Path) -> Result<AuditLog, AuditStoreError> {
    remove_stale_temps(path);
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(AuditLog::default()),
        Err(e) => return Err(AuditStoreError::Io(e.to_string())),
    };
    let log: AuditLog =
        serde_json::from_slice(&raw).map_err(|e| AuditStoreError::Corrupt(e.to_string()))?;
    log.verify_chain().map_err(AuditStoreError::ChainInvalid)?;
    Ok(log)
}

pub fn persist_audit_log(path: &Path, log: &AuditLog) -> Result<(), AuditStoreError> {
    let json =
        serde_json::to_vec_pretty(log).map_err(|e| AuditStoreError::Corrupt(e.to_string()))?;
    write_atomic(path, &json).map_err(|e| AuditStoreError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quorum_audit::AuditEvent;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);
    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "audit_store_test_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn log_with(n: usize) -> AuditLog {
        let mut log = AuditLog::default();
        for i in 0..n {
            let e = log.propose_next(AuditEvent {
                invoice_id: format!("inv-{i}"),
                actor: "a".into(),
                action: format!("act-{i}"),
                timestamp_unix_ms: i as u64,
            });
            log.try_append(e).unwrap();
        }
        log
    }

    #[test]
    fn missing_file_is_an_empty_log() {
        let d = tmpdir();
        let log = load_audit_log(&d.join("nope.json")).unwrap();
        assert_eq!(log.entries.len(), 0);
    }

    #[test]
    fn persist_then_load_round_trips() {
        let d = tmpdir();
        let p = d.join("audit.json");
        let log = log_with(5);
        persist_audit_log(&p, &log).unwrap();
        let back = load_audit_log(&p).unwrap();
        assert_eq!(back.entries.len(), 5);
        assert!(back.verify_chain().is_ok());
    }

    /// What the OLD `fs::write` leaves behind when the process dies mid-write:
    /// a prefix of the new content. Loading ANY proper prefix must be refused,
    /// never treated as an empty log (that would silently erase evidence).
    #[test]
    fn every_truncated_prefix_is_refused_not_treated_as_empty() {
        let d = tmpdir();
        let p = d.join("audit.json");
        persist_audit_log(&p, &log_with(3)).unwrap();
        let full = std::fs::read(&p).unwrap();
        // Every prefix, including the empty file.
        for cut in 0..full.len() {
            std::fs::write(&p, &full[..cut]).unwrap();
            assert!(
                load_audit_log(&p).is_err(),
                "a {cut}-byte prefix of a {}-byte log was accepted",
                full.len()
            );
        }
    }

    #[test]
    fn garbage_and_empty_files_are_refused() {
        let d = tmpdir();
        let p = d.join("audit.json");
        for junk in [&b""[..], b"not json", b"{}", b"null", b"[1,2,3]"] {
            std::fs::write(&p, junk).unwrap();
            assert!(load_audit_log(&p).is_err(), "accepted {junk:?}");
        }
    }

    #[test]
    fn a_log_whose_hash_chain_does_not_verify_is_refused() {
        let d = tmpdir();
        let p = d.join("audit.json");
        persist_audit_log(&p, &log_with(3)).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v["entries"][1]["event"]["action"] = serde_json::Value::String("tampered".into());
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        match load_audit_log(&p) {
            Err(AuditStoreError::ChainInvalid(_)) | Err(AuditStoreError::Corrupt(_)) => {}
            other => panic!(
                "tampered log accepted: {:?}",
                other.map(|l| l.entries.len())
            ),
        }
    }

    #[test]
    fn persist_failures_are_reported_not_swallowed() {
        let d = tmpdir();
        // Parent "directory" is a regular file => the write cannot succeed.
        let blocker = d.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let r = persist_audit_log(&blocker.join("audit.json"), &log_with(1));
        assert!(matches!(r, Err(AuditStoreError::Io(_))), "{r:?}");
    }

    /// Crash injection: abort at every stage. The target must be EXACTLY the
    /// old content or EXACTLY the new content (never partial), the hook must
    /// really have been reached, and the loader must still work afterwards.
    #[test]
    fn crash_at_every_stage_leaves_old_or_new_never_partial() {
        for stage in [Stage::TempWritten, Stage::TempSynced, Stage::Renamed] {
            let d = tmpdir();
            let p = d.join("audit.json");
            let old = serde_json::to_vec_pretty(&log_with(2)).unwrap();
            let new = serde_json::to_vec_pretty(&log_with(4)).unwrap();
            write_atomic(&p, &old).unwrap();
            let mut reached = false;
            let r = write_atomic_with(&p, &new, |s| {
                if s == stage {
                    reached = true;
                    false // simulated crash right here
                } else {
                    true
                }
            });
            assert!(
                reached,
                "stage {stage:?} was never reached (no crash point)"
            );
            assert!(r.is_err(), "an aborted write must report an error");
            let now = std::fs::read(&p).unwrap();
            assert!(
                now == old || now == new,
                "stage {stage:?}: target is neither the old nor the new content ({} bytes)",
                now.len()
            );
            let expect = if stage == Stage::Renamed { 4 } else { 2 };
            assert_eq!(
                load_audit_log(&p).unwrap().entries.len(),
                expect,
                "{stage:?}"
            );
        }
    }

    #[test]
    fn stale_temp_files_are_ignored_and_cleaned_up() {
        let d = tmpdir();
        let p = d.join("audit.json");
        persist_audit_log(&p, &log_with(2)).unwrap();
        let stale = d.join("audit.json.tmp.99999.0");
        std::fs::write(&stale, b"half-written garbage").unwrap();
        assert_eq!(load_audit_log(&p).unwrap().entries.len(), 2);
        assert!(!stale.exists(), "stale temp file was not cleaned up");
    }

    #[test]
    fn successful_write_leaves_no_temp_files_and_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir();
        let p = d.join("audit.json");
        persist_audit_log(&p, &log_with(1)).unwrap();
        persist_audit_log(&p, &log_with(2)).unwrap();
        let names: Vec<String> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["audit.json".to_string()], "{names:?}");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
