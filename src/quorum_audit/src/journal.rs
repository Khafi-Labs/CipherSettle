//! F-20: append-only journal for a node's audit log.
//!
//! Layout on disk (next to the snapshot file `P`, the full-log JSON that the
//! node has always written atomically):
//!   `P`          full snapshot (atomic temp+fsync+rename, unchanged format)
//!   `P.journal`  framed records applied AFTER the snapshot
//!
//! Frame: `len:u32le | hcheck:u32le | payload(len bytes) | pcheck:[u8;16]`
//! where `hcheck` = first 4 bytes of SHA-256(len bytes) and `pcheck` = first
//! 16 bytes of SHA-256(payload). The payload is a JSON [`Record`].
//!
//! Replay policy (fail-safe):
//! * a frame that is INCOMPLETE at the end of the file (header cut short, or a
//!   valid header whose body runs past EOF) is a torn tail: such a write was
//!   never fsynced, so it was never acknowledged. It is reported (`torn_at`),
//!   ignored, and the node truncates it;
//! * anything else wrong (bad header check, bad payload check, unparseable
//!   payload, a record that does not extend the chain, a signature for a
//!   missing entry) is CORRUPTION and a hard error. A flipped bit in the last
//!   frame's length field is caught by `hcheck` and is NOT mistaken for a torn
//!   tail (that would silently drop an acknowledged entry);
//! * replay is idempotent: an `Append` already contained in the snapshot (crash
//!   between snapshot rename and journal removal) is skipped if its hash
//!   matches and is corruption if it does not.

use crate::{AuditEntry, AuditLog};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Upper bound for one record, to refuse absurd lengths from damaged headers.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const HEADER: usize = 8;
const PCHECK: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Record {
    Append {
        entry: AuditEntry,
    },
    Sig {
        seq: u64,
        node_id: usize,
        sig: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum JournalError {
    Io(String),
    /// Unparseable snapshot or journal damage (see module docs).
    Corrupt(String),
    /// The reconstructed log's hash chain does not verify.
    ChainInvalid(String),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Io(e) => write!(f, "i/o error: {e}"),
            JournalError::Corrupt(e) => write!(f, "corrupt audit log file: {e}"),
            JournalError::ChainInvalid(e) => write!(f, "audit log hash chain invalid: {e}"),
        }
    }
}

pub fn journal_path(snapshot: &Path) -> PathBuf {
    let mut name = snapshot
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".journal");
    snapshot.with_file_name(name)
}

fn digest16(bytes: &[u8]) -> [u8; PCHECK] {
    let d = Sha256::digest(bytes);
    let mut out = [0u8; PCHECK];
    out.copy_from_slice(&d[..PCHECK]);
    out
}

fn hcheck(len_le: &[u8; 4]) -> [u8; 4] {
    let d = Sha256::digest(len_le);
    [d[0], d[1], d[2], d[3]]
}

/// Encodes one record as a frame.
pub fn encode_frame(record: &Record) -> Result<Vec<u8>, JournalError> {
    let payload = serde_json::to_vec(record).map_err(|e| JournalError::Corrupt(e.to_string()))?;
    if payload.len() > MAX_RECORD_BYTES {
        return Err(JournalError::Corrupt("record too large".into()));
    }
    let len_le = (payload.len() as u32).to_le_bytes();
    let mut out = Vec::with_capacity(HEADER + payload.len() + PCHECK);
    out.extend_from_slice(&len_le);
    out.extend_from_slice(&hcheck(&len_le));
    out.extend_from_slice(&payload);
    out.extend_from_slice(&digest16(&payload));
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Replayed {
    /// Number of journal bytes that form complete, valid frames.
    pub valid_len: usize,
    /// `Some(valid_len)` when an incomplete final frame was ignored.
    pub torn_at: Option<usize>,
}

/// Applies the journal bytes to `log`. See the module docs for the policy.
pub fn replay(log: &mut AuditLog, bytes: &[u8]) -> Result<Replayed, JournalError> {
    let mut pos = 0usize;
    while pos < bytes.len() {
        let rest = &bytes[pos..];
        let (Some(len_b), Some(hc_b)) = (rest.get(..4), rest.get(4..HEADER)) else {
            return Ok(Replayed {
                valid_len: pos,
                torn_at: Some(pos),
            });
        };
        let mut len_le = [0u8; 4];
        len_le.copy_from_slice(len_b);
        if hc_b != hcheck(&len_le) {
            return Err(JournalError::Corrupt(format!(
                "journal frame header check failed at byte {pos}"
            )));
        }
        let len = u32::from_le_bytes(len_le) as usize;
        if len > MAX_RECORD_BYTES {
            return Err(JournalError::Corrupt(format!(
                "journal frame at byte {pos} claims {len} bytes"
            )));
        }
        let total = HEADER + len + PCHECK;
        let (Some(payload), Some(pc)) = (
            rest.get(HEADER..HEADER + len),
            rest.get(HEADER + len..total),
        ) else {
            return Ok(Replayed {
                valid_len: pos,
                torn_at: Some(pos),
            });
        };
        if pc != digest16(payload) {
            return Err(JournalError::Corrupt(format!(
                "journal frame payload check failed at byte {pos}"
            )));
        }
        let record: Record = serde_json::from_slice(payload)
            .map_err(|e| JournalError::Corrupt(format!("journal record at byte {pos}: {e}")))?;
        apply(log, record, pos)?;
        pos += total;
    }
    Ok(Replayed {
        valid_len: pos,
        torn_at: None,
    })
}

fn apply(log: &mut AuditLog, record: Record, pos: usize) -> Result<(), JournalError> {
    match record {
        Record::Append { entry } => {
            if entry.seq < log.next_seq() {
                let same = log
                    .entries
                    .get(entry.seq as usize)
                    .is_some_and(|e| e.entry_hash == entry.entry_hash);
                if !same {
                    return Err(JournalError::Corrupt(format!(
                        "journal record at byte {pos} contradicts the entry already at seq {}",
                        entry.seq
                    )));
                }
                return Ok(());
            }
            log.try_append(entry)
                .map_err(|e| JournalError::Corrupt(format!("journal record at byte {pos}: {e}")))
        }
        Record::Sig { seq, node_id, sig } => log
            .merge_signature(seq, node_id, sig)
            .map_err(|e| JournalError::Corrupt(format!("journal record at byte {pos}: {e}"))),
    }
}

/// Reads snapshot + journal WITHOUT modifying anything. Missing snapshot and
/// journal = first start (empty log). Returns the log and, if an incomplete
/// final frame was ignored, the byte length the journal should be truncated to.
pub fn load_readonly(snapshot: &Path) -> Result<(AuditLog, Option<usize>), JournalError> {
    let mut log = match std::fs::read(snapshot) {
        Ok(raw) => serde_json::from_slice::<AuditLog>(&raw)
            .map_err(|e| JournalError::Corrupt(e.to_string()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => AuditLog::default(),
        Err(e) => return Err(JournalError::Io(e.to_string())),
    };
    let torn = match std::fs::read(journal_path(snapshot)) {
        Ok(bytes) => replay(&mut log, &bytes)?.torn_at,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(JournalError::Io(e.to_string())),
    };
    log.verify_chain().map_err(JournalError::ChainInvalid)?;
    Ok((log, torn))
}

/// Convenience for readers that only want the log (tests, tools).
pub fn load_log(snapshot: &Path) -> Result<AuditLog, JournalError> {
    load_readonly(snapshot).map(|(l, _)| l)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditEvent;

    fn build(n: usize) -> (AuditLog, Vec<AuditEntry>) {
        let mut log = AuditLog::default();
        let mut es = Vec::new();
        for i in 0..n {
            let e = log.propose_next(AuditEvent {
                invoice_id: format!("i{i}"),
                actor: "a".into(),
                action: "x".into(),
                timestamp_unix_ms: i as u64,
            });
            let _ = log.try_append(e.clone());
            es.push(e);
        }
        (log, es)
    }

    fn journal_of(es: &[AuditEntry]) -> Vec<u8> {
        es.iter()
            .flat_map(|e| encode_frame(&Record::Append { entry: e.clone() }).unwrap_or_default())
            .collect()
    }

    #[test]
    fn replay_rebuilds_the_log() {
        let (want, es) = build(5);
        let mut got = AuditLog::default();
        let r = replay(&mut got, &journal_of(&es)).unwrap();
        assert_eq!(r.torn_at, None);
        assert_eq!(got.entries.len(), 5);
        assert_eq!(got.tip_hash(), want.tip_hash());
    }

    #[test]
    fn every_truncation_point_of_the_last_frame_is_a_torn_tail_not_an_error() {
        let (_, es) = build(3);
        let full = journal_of(&es);
        let last_start = journal_of(&es[..2]).len();
        for cut in last_start..full.len() {
            let mut got = AuditLog::default();
            let r = replay(&mut got, &full[..cut]).unwrap();
            assert_eq!(got.entries.len(), 2, "cut at {cut}");
            assert_eq!(
                r.torn_at,
                if cut == last_start {
                    None
                } else {
                    Some(last_start)
                }
            );
        }
    }

    #[test]
    fn a_flipped_bit_anywhere_in_a_complete_frame_is_corruption() {
        let (_, es) = build(3);
        let full = journal_of(&es);
        for i in 0..full.len() {
            let mut bad = full.clone();
            bad[i] ^= 0x01;
            let mut got = AuditLog::default();
            assert!(
                matches!(replay(&mut got, &bad), Err(JournalError::Corrupt(_))),
                "flip at byte {i} was not rejected"
            );
        }
    }

    #[test]
    fn entries_with_signatures_survive_the_journal_round_trip() {
        // Found by the live suite (Q1), missed by unit tests that used unsigned
        // entries: signatures are a map with integer keys, which an internally
        // tagged serde enum cannot read back.
        let (_, mut es) = build(2);
        for e in es.iter_mut() {
            e.signatures.insert(0, vec![1, 2, 3]);
            e.signatures.insert(4, vec![9]);
        }
        let mut got = AuditLog::default();
        let r = replay(&mut got, &journal_of(&es));
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(got.entries[1].signatures.get(&4), Some(&vec![9]));
        let sig = encode_frame(&Record::Sig {
            seq: 0,
            node_id: 2,
            sig: vec![7],
        })
        .unwrap();
        assert!(replay(&mut got, &sig).is_ok());
        assert_eq!(got.entries[0].signatures.get(&2), Some(&vec![7]));
    }

    #[test]
    fn replay_is_idempotent_over_a_snapshot_that_already_has_the_entries() {
        let (snap, es) = build(4);
        let mut log = snap.clone();
        let r = replay(&mut log, &journal_of(&es)).unwrap();
        assert_eq!(r.torn_at, None);
        assert_eq!(log.entries.len(), 4);
    }

    #[test]
    fn a_record_that_contradicts_the_snapshot_is_corruption() {
        let (_, es) = build(3);
        let (mut other, _) = build(0);
        for i in 0..3 {
            let e = other.propose_next(AuditEvent {
                invoice_id: format!("DIFFERENT{i}"),
                actor: "a".into(),
                action: "x".into(),
                timestamp_unix_ms: 9,
            });
            let _ = other.try_append(e);
        }
        assert!(matches!(
            replay(&mut other, &journal_of(&es)),
            Err(JournalError::Corrupt(_))
        ));
    }

    #[test]
    fn signature_for_a_missing_entry_is_corruption() {
        let bytes = encode_frame(&Record::Sig {
            seq: 7,
            node_id: 1,
            sig: vec![1],
        })
        .unwrap();
        let mut log = AuditLog::default();
        assert!(matches!(
            replay(&mut log, &bytes),
            Err(JournalError::Corrupt(_))
        ));
    }
}
