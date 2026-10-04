//! Gap 1: durable, encrypted-at-rest storage of a node's DKG share.
//!
//! STATUS: NEEDS_HUMAN_CRYPTO_REVIEW. Uses only established primitives
//! (AES-256-GCM from `ring`, the OS RNG); no new construction beyond ordinary
//! envelope encryption. See `agent_memory/DESIGN_NOTE_gap1_share_persistence.md`.
//!
//! Construction (envelope encryption):
//! * a fresh random 256-bit data key (DEK) is generated per saved share;
//! * the 32-byte share scalar is encrypted under the DEK with AES-256-GCM
//!   (random 96-bit nonce, used exactly once because the DEK is single-use);
//! * the DEK is wrapped by a [`KekProvider`] (AES-256-GCM under the node's
//!   key-encryption key for [`FileKek`]; a KMS/HSM `Encrypt` call for a cloud
//!   provider);
//! * both AEAD operations bind the same associated data: format version, node
//!   id, `n`, `t`, crypto epoch and the group public key fingerprint. A share
//!   file therefore cannot be replayed into another node's slot, another
//!   group, or another crypto epoch.
//!
//! Safety properties enforced here (each has a unit test):
//! * writes are atomic and never overwrite (`create_new`): temp file in the
//!   same directory, `fsync`, hard-link into place (fails if the target exists),
//!   `fsync` of the directory;
//! * every failure is a typed error. Nothing in this module panics or falls
//!   back to "generate a new share";
//! * on load the share is verified against the group public commitment
//!   (`SecretKeyShare::restore_verified`) and, if the operator configured one,
//!   against the pinned group key fingerprint.

use quorum_core::{PublicKeySet, SecretKeyShare};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const SHARE_FILE_NAME: &str = "share.v1.json";
const FORMAT_VERSION: u32 = 1;
/// Must match `quorum_service::db::CRYPTO_EPOCH`; bump together on any change
/// that invalidates derived keys.
pub const CRYPTO_EPOCH: &str = "blstrs-rfc9380-v1";
/// A share file is a few hundred bytes. Anything near this is not one.
const MAX_SHARE_FILE_BYTES: u64 = 64 * 1024;
const TAG_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum ShareStoreError {
    /// No share file exists (distinct from "exists but unusable").
    NotFound,
    /// A share file already exists; this store never overwrites.
    AlreadyExists,
    Io(String),
    /// Structurally invalid file (bad JSON, wrong version/sizes, ...).
    Corrupt(String),
    /// AEAD authentication failed: wrong KEK, or the file was modified.
    Decrypt,
    /// Authentic data that does not belong here (node id, group, epoch,
    /// failed commitment check).
    Mismatch(String),
    /// The operator-configured pin does not match the stored group key.
    PinMismatch,
    /// The KEK could not be loaded or is not acceptable.
    Kek(String),
}

impl std::fmt::Display for ShareStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no share file found"),
            Self::AlreadyExists => write!(f, "a share file already exists (never overwritten)"),
            Self::Io(e) => write!(f, "share store I/O error: {e}"),
            Self::Corrupt(e) => write!(f, "share file is corrupt: {e}"),
            Self::Decrypt => write!(
                f,
                "share file failed authenticated decryption (wrong key-encryption key, or the file was modified)"
            ),
            Self::Mismatch(e) => write!(f, "share file does not belong to this node/group: {e}"),
            Self::PinMismatch => write!(
                f,
                "stored group public key does not match the configured pinned fingerprint"
            ),
            Self::Kek(e) => write!(f, "key-encryption key error: {e}"),
        }
    }
}

impl std::error::Error for ShareStoreError {}

// ---------------------------------------------------------------------
// Key-encryption key providers
// ---------------------------------------------------------------------

/// Wraps and unwraps the per-share data key. The seam where a KMS/HSM backend
/// plugs in: a cloud provider's `Encrypt`/`Decrypt` (with `aad` as encryption
/// context) implements this trait without any other change to this module.
/// No such backend is implemented in this repository (it needs an account and
/// a human decision; see the design note).
pub trait KekProvider: Send + Sync {
    fn wrap(&self, dek: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, ShareStoreError>;
    fn unwrap_dek(
        &self,
        wrapped: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, ShareStoreError>;
}

/// Pilot KEK: 32 raw bytes in a file readable only by the node's OS user.
/// Suitable for non-real data. For real data replace with a KMS/HSM provider.
pub struct FileKek {
    key: Zeroizing<[u8; 32]>,
}

impl FileKek {
    pub fn load(path: &Path) -> Result<Self, ShareStoreError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| ShareStoreError::Kek(format!("cannot stat KEK file: {e}")))?;
        if !meta.is_file() {
            return Err(ShareStoreError::Kek(
                "KEK path is not a regular file".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(ShareStoreError::Kek(format!(
                    "KEK file mode is {mode:03o}; it must not be accessible to group/others (use 0600)"
                )));
            }
        }
        let raw = Zeroizing::new(
            std::fs::read(path)
                .map_err(|e| ShareStoreError::Kek(format!("cannot read KEK file: {e}")))?,
        );
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            ShareStoreError::Kek(format!(
                "KEK file must be exactly 32 bytes, got {}",
                raw.len()
            ))
        })?;
        Ok(Self {
            key: Zeroizing::new(arr),
        })
    }

    #[cfg(test)]
    pub fn from_bytes_for_test(b: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(b),
        }
    }
}

fn aead_key(key: &[u8; 32]) -> Result<LessSafeKey, ShareStoreError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| ShareStoreError::Kek("invalid AES-256-GCM key".into()))
}

/// Returns `nonce || ciphertext || tag`.
fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ShareStoreError> {
    let k = aead_key(key)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| ShareStoreError::Io("OS random number generator failed".into()))?;
    let mut buf = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    buf.extend_from_slice(&nonce_bytes);
    let mut in_out = plaintext.to_vec();
    k.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(aad),
        &mut in_out,
    )
    .map_err(|_| ShareStoreError::Io("AEAD seal failed".into()))?;
    buf.extend_from_slice(&in_out);
    Ok(buf)
}

/// Inverse of [`seal`]; the plaintext is returned zeroizing.
fn open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, ShareStoreError> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(ShareStoreError::Corrupt(
            "ciphertext shorter than nonce + tag".into(),
        ));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| ShareStoreError::Corrupt("bad nonce length".into()))?;
    let k = aead_key(key)?;
    let mut in_out = Zeroizing::new(ct.to_vec());
    let n = k
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_arr),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| ShareStoreError::Decrypt)?
        .len();
    in_out.truncate(n);
    Ok(in_out)
}

impl KekProvider for FileKek {
    fn wrap(&self, dek: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, ShareStoreError> {
        seal(&self.key, aad, dek)
    }
    fn unwrap_dek(
        &self,
        wrapped: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, ShareStoreError> {
        let pt = open(&self.key, aad, wrapped)?;
        let arr: [u8; 32] = pt.as_slice().try_into().map_err(|_| {
            ShareStoreError::Corrupt("wrapped data key has the wrong length".into())
        })?;
        Ok(Zeroizing::new(arr))
    }
}

// ---------------------------------------------------------------------
// File format
// ---------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ShareFile {
    version: u32,
    node_id: u64,
    n: u64,
    t: u64,
    crypto_epoch: String,
    /// Public; authenticated through the associated data (its fingerprint).
    group_pks: PublicKeySet,
    wrapped_dek_b64: String,
    share_ct_b64: String,
}

fn b64e(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn b64d(s: &str) -> Result<Vec<u8>, ShareStoreError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| ShareStoreError::Corrupt("invalid base64".into()))
}

fn associated_data(
    purpose: &[u8],
    version: u32,
    node_id: u64,
    n: u64,
    t: u64,
    epoch: &str,
    group_fp: &[u8; 32],
) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(b"ciphersettle/share-store/");
    a.extend_from_slice(purpose);
    a.extend_from_slice(&version.to_be_bytes());
    a.extend_from_slice(&node_id.to_be_bytes());
    a.extend_from_slice(&n.to_be_bytes());
    a.extend_from_slice(&t.to_be_bytes());
    a.extend_from_slice(&(epoch.len() as u64).to_be_bytes());
    a.extend_from_slice(epoch.as_bytes());
    a.extend_from_slice(group_fp);
    a
}

// ---------------------------------------------------------------------
// Atomic, exclusive file creation
// ---------------------------------------------------------------------

fn io_err(ctx: &str, e: std::io::Error) -> ShareStoreError {
    ShareStoreError::Io(format!("{ctx}: {e}"))
}

fn fsync_dir(dir: &Path) -> Result<(), ShareStoreError> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| io_err("fsync directory", e))
}

/// Writes `bytes` to `dir/name` atomically and EXCLUSIVELY: a crash at any
/// point leaves either no `name` or a complete, fsynced `name`; an existing
/// `name` is never replaced.
fn write_new_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), ShareStoreError> {
    let mut rnd = [0u8; 8];
    SystemRandom::new()
        .fill(&mut rnd)
        .map_err(|_| ShareStoreError::Io("OS random number generator failed".into()))?;
    let tmp = dir.join(format!(
        ".{name}.tmp.{}",
        b64e(&rnd).replace(['/', '+', '='], "_")
    ));
    let target = dir.join(name);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| -> Result<(), ShareStoreError> {
        let mut f = opts.open(&tmp).map_err(|e| io_err("create temp file", e))?;
        f.write_all(bytes)
            .map_err(|e| io_err("write temp file", e))?;
        f.sync_all().map_err(|e| io_err("fsync temp file", e))?;
        drop(f);
        // hard_link fails with AlreadyExists instead of replacing the target.
        match std::fs::hard_link(&tmp, &target) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(ShareStoreError::AlreadyExists)
            }
            Err(e) => Err(io_err("link into place", e)),
        }
    })();
    let _ = std::fs::remove_file(&tmp);
    result?;
    fsync_dir(dir)
}

// ---------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------

pub struct ShareStore {
    dir: PathBuf,
    kek: Box<dyn KekProvider>,
}

impl ShareStore {
    pub fn new(dir: PathBuf, kek: Box<dyn KekProvider>) -> Self {
        Self { dir, kek }
    }

    fn file_path(&self) -> PathBuf {
        self.dir.join(SHARE_FILE_NAME)
    }

    /// `Ok(true)` iff a share file is present. Anything other than a clean
    /// "not found" is an error, never "absent".
    pub fn exists(&self) -> Result<bool, ShareStoreError> {
        match std::fs::symlink_metadata(self.file_path()) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_err("stat share file", e)),
        }
    }

    /// Persists a freshly generated share. Fails with `AlreadyExists` instead
    /// of overwriting.
    pub fn create_new(
        &self,
        node_id: usize,
        n: usize,
        t: usize,
        share: &SecretKeyShare,
        group_pks: &PublicKeySet,
    ) -> Result<(), ShareStoreError> {
        // Re-verify before persisting: never write a share that would not load.
        let exported = Zeroizing::new(share.export_for_sealed_storage());
        SecretKeyShare::restore_verified(&exported, node_id, group_pks)
            .map_err(ShareStoreError::Mismatch)?;

        std::fs::create_dir_all(&self.dir).map_err(|e| io_err("create share directory", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
        if self.exists()? {
            return Err(ShareStoreError::AlreadyExists);
        }

        let fp = group_pks.fingerprint_sha256();
        let (node_u, n_u, t_u) = (node_id as u64, n as u64, t as u64);
        let mut dek = Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(dek.as_mut_slice())
            .map_err(|_| ShareStoreError::Io("OS random number generator failed".into()))?;
        let aad_share = associated_data(
            b"share",
            FORMAT_VERSION,
            node_u,
            n_u,
            t_u,
            CRYPTO_EPOCH,
            &fp,
        );
        let aad_wrap = associated_data(b"dek", FORMAT_VERSION, node_u, n_u, t_u, CRYPTO_EPOCH, &fp);
        let share_ct = seal(&dek, &aad_share, exported.as_slice())?;
        let wrapped = self.kek.wrap(&dek, &aad_wrap)?;

        let file = ShareFile {
            version: FORMAT_VERSION,
            node_id: node_u,
            n: n_u,
            t: t_u,
            crypto_epoch: CRYPTO_EPOCH.to_string(),
            group_pks: group_pks.clone(),
            wrapped_dek_b64: b64e(&wrapped),
            share_ct_b64: b64e(&share_ct),
        };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|e| ShareStoreError::Io(format!("serialize share file: {e}")))?;
        write_new_atomic(&self.dir, SHARE_FILE_NAME, &json)?;

        // Paranoia: prove the file we just wrote loads (fail the ceremony now,
        // not at the first restart).
        self.load(node_id, n, t, None).map(|_| ())
    }

    /// Loads and fully validates the share. `pin` is the operator-configured
    /// group key fingerprint, if any.
    pub fn load(
        &self,
        node_id: usize,
        n: usize,
        t: usize,
        pin: Option<&[u8; 32]>,
    ) -> Result<(SecretKeyShare, PublicKeySet), ShareStoreError> {
        let path = self.file_path();
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ShareStoreError::NotFound)
            }
            Err(e) => return Err(io_err("stat share file", e)),
        };
        if !meta.is_file() || meta.len() > MAX_SHARE_FILE_BYTES {
            return Err(ShareStoreError::Corrupt(format!(
                "not a regular file of plausible size (len {})",
                meta.len()
            )));
        }
        let raw = std::fs::read(&path).map_err(|e| io_err("read share file", e))?;
        let file: ShareFile = serde_json::from_slice(&raw)
            .map_err(|e| ShareStoreError::Corrupt(format!("bad JSON: {e}")))?;

        if file.version != FORMAT_VERSION {
            return Err(ShareStoreError::Corrupt(format!(
                "unsupported format version {}",
                file.version
            )));
        }
        if file.crypto_epoch != CRYPTO_EPOCH {
            return Err(ShareStoreError::Mismatch(format!(
                "crypto epoch {:?} (this build expects {CRYPTO_EPOCH:?})",
                file.crypto_epoch
            )));
        }
        if file.node_id != node_id as u64 || file.n != n as u64 || file.t != t as u64 {
            return Err(ShareStoreError::Mismatch(format!(
                "file is for node {} (n={}, t={}), this node is {node_id} (n={n}, t={t})",
                file.node_id, file.n, file.t
            )));
        }
        if file.group_pks.threshold() != t {
            return Err(ShareStoreError::Mismatch(
                "group key threshold differs from configured t".into(),
            ));
        }
        let fp = file.group_pks.fingerprint_sha256();
        if let Some(pin) = pin {
            if pin != &fp {
                return Err(ShareStoreError::PinMismatch);
            }
        }

        let aad_share = associated_data(
            b"share",
            file.version,
            file.node_id,
            file.n,
            file.t,
            &file.crypto_epoch,
            &fp,
        );
        let aad_wrap = associated_data(
            b"dek",
            file.version,
            file.node_id,
            file.n,
            file.t,
            &file.crypto_epoch,
            &fp,
        );
        let dek = self
            .kek
            .unwrap_dek(&b64d(&file.wrapped_dek_b64)?, &aad_wrap)?;
        let pt = open(&dek, &aad_share, &b64d(&file.share_ct_b64)?)?;
        let bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(pt.as_slice().try_into().map_err(|_| {
                ShareStoreError::Corrupt("decrypted share has the wrong length".into())
            })?);
        let share = SecretKeyShare::restore_verified(&bytes, node_id, &file.group_pks)
            .map_err(ShareStoreError::Mismatch)?;
        Ok((share, file.group_pks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quorum_core::DkgSession;
    use rand::thread_rng;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CTR: AtomicUsize = AtomicUsize::new(0);

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "share_store_test_{}_{}",
                std::process::id(),
                CTR.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Full in-process DKG for (n, t); returns each node's (share, group key).
    fn dkg(n: usize, t: usize) -> Vec<(SecretKeyShare, PublicKeySet)> {
        let mut rng = thread_rng();
        let mut sessions = Vec::new();
        let mut commitments = Vec::new();
        for i in 0..n {
            let (s, c) = DkgSession::new(i, n, t, &mut rng);
            sessions.push(s);
            commitments.push(c);
        }
        for session in sessions.iter_mut() {
            for (j, c) in commitments.iter().enumerate() {
                session.receive_commitment(j, c.clone()).unwrap();
            }
        }
        let shares: Vec<Vec<[u8; 32]>> = (0..n)
            .map(|j| (0..n).map(|i| sessions[j].share_for(i)).collect())
            .collect();
        for (i, session) in sessions.iter_mut().enumerate() {
            for (j, from_j) in shares.iter().enumerate() {
                session.receive_share(j, from_j[i]).unwrap();
            }
        }
        sessions
            .into_iter()
            .map(|s| s.finalize().unwrap())
            .collect()
    }

    fn kek(b: u8) -> Box<dyn KekProvider> {
        Box::new(FileKek::from_bytes_for_test([b; 32]))
    }

    fn saved(
        dir: &Path,
        node: usize,
        set: &[(SecretKeyShare, PublicKeySet)],
        kek_byte: u8,
    ) -> ShareStore {
        let store = ShareStore::new(dir.to_path_buf(), kek(kek_byte));
        store
            .create_new(node, 3, 1, &set[node].0, &set[node].1)
            .unwrap();
        store
    }

    #[test]
    fn roundtrip_restores_the_same_share_and_group_key() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        let store = saved(&d.0, 1, &set, 7);
        let (share, gpk) = store.load(1, 3, 1, None).unwrap();
        assert_eq!(share.public_key_share(), set[1].0.public_key_share());
        assert_eq!(gpk.fingerprint_sha256(), set[1].1.fingerprint_sha256());
        // The restored share signs identically (deterministic BLS).
        assert_eq!(
            share.sign(b"inv-1").to_bytes(),
            set[1].0.sign(b"inv-1").to_bytes()
        );
    }

    #[test]
    fn share_file_never_contains_the_plaintext_share() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        saved(&d.0, 0, &set, 7);
        let raw = std::fs::read(d.0.join(SHARE_FILE_NAME)).unwrap();
        let secret = set[0].0.export_for_sealed_storage();
        assert!(
            !raw.windows(32).any(|w| w == secret),
            "raw share bytes appear in the file"
        );
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!String::from_utf8_lossy(&raw).contains(&hex));
    }

    #[test]
    fn wrong_kek_is_a_decrypt_error_not_a_panic_or_success() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        saved(&d.0, 0, &set, 7);
        let other = ShareStore::new(d.0.clone(), kek(8));
        assert_eq!(
            other.load(0, 3, 1, None).err(),
            Some(ShareStoreError::Decrypt)
        );
    }

    #[test]
    fn every_single_byte_flip_in_the_file_is_rejected() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        let store = saved(&d.0, 2, &set, 7);
        let path = d.0.join(SHARE_FILE_NAME);
        let original = std::fs::read(&path).unwrap();
        // Flip each byte in turn (file is small); NO flip may produce Ok with a
        // different group or share. A flip in JSON whitespace/escape-equivalent
        // positions may still parse to identical content: that is only
        // acceptable if the loaded share is exactly the original.
        for i in 0..original.len() {
            let mut m = original.clone();
            m[i] ^= 0x01;
            std::fs::write(&path, &m).unwrap();
            match store.load(2, 3, 1, None) {
                Err(_) => {}
                Ok((s, g)) => {
                    assert_eq!(
                        s.public_key_share(),
                        set[2].0.public_key_share(),
                        "byte {i}"
                    );
                    assert_eq!(
                        g.fingerprint_sha256(),
                        set[2].1.fingerprint_sha256(),
                        "byte {i}"
                    );
                }
            }
        }
    }

    #[test]
    fn truncated_empty_and_oversized_files_are_errors() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        let store = saved(&d.0, 0, &set, 7);
        let path = d.0.join(SHARE_FILE_NAME);
        let original = std::fs::read(&path).unwrap();
        for cut in [0usize, 1, original.len() / 2, original.len() - 1] {
            std::fs::write(&path, &original[..cut]).unwrap();
            assert!(store.load(0, 3, 1, None).is_err(), "cut {cut}");
        }
        std::fs::write(&path, vec![b'x'; (MAX_SHARE_FILE_BYTES + 1) as usize]).unwrap();
        assert!(matches!(
            store.load(0, 3, 1, None),
            Err(ShareStoreError::Corrupt(_))
        ));
    }

    #[test]
    fn missing_file_is_not_found_and_exists_is_false() {
        let d = TmpDir::new();
        let store = ShareStore::new(d.0.clone(), kek(7));
        assert_eq!(store.exists(), Ok(false));
        assert_eq!(
            store.load(0, 3, 1, None).err(),
            Some(ShareStoreError::NotFound)
        );
    }

    #[test]
    fn a_share_file_cannot_be_moved_into_another_nodes_slot() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        saved(&d.0, 0, &set, 7);
        // Same KEK, same group, but node 0's file presented as node 1's.
        let store = ShareStore::new(d.0.clone(), kek(7));
        assert!(matches!(
            store.load(1, 3, 1, None),
            Err(ShareStoreError::Mismatch(_))
        ));
    }

    #[test]
    fn editing_the_node_id_field_does_not_bypass_the_binding() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        let store = saved(&d.0, 0, &set, 7);
        let path = d.0.join(SHARE_FILE_NAME);
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        v["node_id"] = serde_json::json!(1);
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        // Header now says node 1, but the AEAD binds node 0 -> authentication fails.
        assert_eq!(
            store.load(1, 3, 1, None).err(),
            Some(ShareStoreError::Decrypt)
        );
    }

    #[test]
    fn a_different_groups_share_file_is_rejected_by_pin_and_by_binding() {
        let d = TmpDir::new();
        let a = dkg(3, 1);
        let b = dkg(3, 1);
        let store = saved(&d.0, 0, &a, 7);
        // Pin for group B refuses group A's file.
        let pin_b = b[0].1.fingerprint_sha256();
        assert_eq!(
            store.load(0, 3, 1, Some(&pin_b)).err(),
            Some(ShareStoreError::PinMismatch)
        );
        // Pin for the right group is accepted.
        let pin_a = a[0].1.fingerprint_sha256();
        assert!(store.load(0, 3, 1, Some(&pin_a)).is_ok());
        // Substituting group B's public key into group A's file fails authentication.
        let path = d.0.join(SHARE_FILE_NAME);
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        v["group_pks"] = serde_json::to_value(&b[0].1).unwrap();
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(store.load(0, 3, 1, None).is_err());
    }

    #[test]
    fn wrong_n_or_t_in_config_is_a_mismatch() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        let store = saved(&d.0, 0, &set, 7);
        assert!(matches!(
            store.load(0, 5, 1, None),
            Err(ShareStoreError::Mismatch(_))
        ));
        assert!(matches!(
            store.load(0, 3, 2, None),
            Err(ShareStoreError::Mismatch(_))
        ));
    }

    #[test]
    fn create_new_never_overwrites_an_existing_share() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        let store = saved(&d.0, 0, &set, 7);
        let before = std::fs::read(d.0.join(SHARE_FILE_NAME)).unwrap();
        let other = dkg(3, 1);
        let r = store.create_new(0, 3, 1, &other[0].0, &other[0].1);
        assert_eq!(r.err(), Some(ShareStoreError::AlreadyExists));
        assert_eq!(std::fs::read(d.0.join(SHARE_FILE_NAME)).unwrap(), before);
    }

    #[test]
    fn create_new_refuses_a_share_that_does_not_match_the_group() {
        let d = TmpDir::new();
        let a = dkg(3, 1);
        let b = dkg(3, 1);
        let store = ShareStore::new(d.0.clone(), kek(7));
        // Node 0's share from group A with group B's public key: must not be written.
        let r = store.create_new(0, 3, 1, &a[0].0, &b[0].1);
        assert!(matches!(r, Err(ShareStoreError::Mismatch(_))));
        assert_eq!(store.exists(), Ok(false));
    }

    #[test]
    fn a_stale_temp_file_from_a_crashed_write_is_ignored_and_does_not_block_a_save() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        // Simulate a crash after the temp write but before the link.
        std::fs::write(d.0.join(".share.v1.json.tmp.deadbeef"), b"partial garbage").unwrap();
        let store = ShareStore::new(d.0.clone(), kek(7));
        assert_eq!(
            store.exists(),
            Ok(false),
            "a temp file must not count as a share"
        );
        assert_eq!(
            store.load(0, 3, 1, None).err(),
            Some(ShareStoreError::NotFound)
        );
        store.create_new(0, 3, 1, &set[0].0, &set[0].1).unwrap();
        assert!(store.load(0, 3, 1, None).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn share_file_and_directory_are_not_group_or_world_accessible() {
        use std::os::unix::fs::PermissionsExt;
        let d = TmpDir::new();
        let set = dkg(3, 1);
        let sub = d.0.join("shares");
        let store = ShareStore::new(sub.clone(), kek(7));
        store.create_new(0, 3, 1, &set[0].0, &set[0].1).unwrap();
        let fm = std::fs::metadata(sub.join(SHARE_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let dm = std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(fm, 0o600);
        assert_eq!(dm, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn kek_file_must_be_exactly_32_bytes_and_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = TmpDir::new();
        let p = d.0.join("k");
        std::fs::write(&p, [1u8; 32]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            matches!(FileKek::load(&p), Err(ShareStoreError::Kek(_))),
            "0644 must be refused"
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(FileKek::load(&p).is_ok());
        std::fs::write(&p, [1u8; 31]).unwrap();
        assert!(
            matches!(FileKek::load(&p), Err(ShareStoreError::Kek(_))),
            "31 bytes must be refused"
        );
        assert!(matches!(
            FileKek::load(&d.0.join("absent")),
            Err(ShareStoreError::Kek(_))
        ));
    }

    #[test]
    fn backup_restore_a_copied_share_file_plus_the_same_kek_loads_elsewhere() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        saved(&d.0.join("orig"), 2, &set, 9);
        // "Backup": the encrypted file is copied (ciphertext only; the KEK is
        // custodied separately). "Restore": new empty dir + same KEK.
        let restored = d.0.join("restored");
        std::fs::create_dir_all(&restored).unwrap();
        std::fs::copy(
            d.0.join("orig").join(SHARE_FILE_NAME),
            restored.join(SHARE_FILE_NAME),
        )
        .unwrap();
        let store = ShareStore::new(restored, kek(9));
        let (share, _) = store.load(2, 3, 1, None).unwrap();
        assert_eq!(share.public_key_share(), set[2].0.public_key_share());
    }

    #[test]
    fn error_text_never_contains_key_material() {
        let d = TmpDir::new();
        let set = dkg(3, 1);
        saved(&d.0, 0, &set, 7);
        let e = ShareStore::new(d.0.clone(), kek(8))
            .load(0, 3, 1, None)
            .err()
            .unwrap();
        let text = format!("{e} {e:?}");
        let secret_hex: String = set[0]
            .0
            .export_for_sealed_storage()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!text.contains(&secret_hex));
        assert!(!format!("{:?}", set[0].0).contains(&secret_hex));
    }
}
