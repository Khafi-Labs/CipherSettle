//! Invoice commitment scheme.
//!
//! ## Why this exists
//!
//! Prior to this module, this project had no invoice-commitment scheme
//! at all -- not a weak one, none. `quorum_service` stores whatever
//! opaque ciphertext bytes a caller submits (see its `ciphertext_b64`
//! field) but never sees, and has no way to bind, the actual invoice
//! *content* (amount, parties, dates) that ciphertext represents. This
//! module is what makes a claim like "the data used during financing
//! are exactly the data that were originally verified" provable rather
//! than assumed -- a gap identified during this project's own design
//! review, alongside a related one: a plain, unsalted hash of invoice
//! content would be guessable, since invoice amounts, dates, and
//! counterparty names are comparatively low-entropy and a small set of
//! plausible values can be brute-forced against a hash. Both are fixed
//! by the same mechanism: a random salt.
//!
//! ## What this is not
//!
//! This is a **salted hash commitment** (hiding via the salt's entropy,
//! binding via the hash), not a Pedersen commitment or any other
//! algebraic/homomorphic scheme -- those are heavier primitives this
//! project has no stated need for (no requirement to add commitments
//! together or prove relations between them without opening). Don't
//! upgrade the terminology in documentation without upgrading the
//! actual construction to match.
//!
//! Verifying a commitment requires revealing the plaintext fields to
//! whoever checks it -- this is not a zero-knowledge proof. That's
//! consistent with how this system already works: it never receives
//! plaintext invoice content at all (only opaque ciphertext), so
//! opening a commitment is something a caller does for their own later
//! proof (e.g. to an auditor or the counterparty), not something this
//! system evaluates on every access.
//!
//! ## The field list is provisional
//!
//! [`InvoiceFields`] is a reasonable placeholder set (reference, issuer,
//! debtor, amount, currency, dates), not a specification of what a real
//! integration with Egypt's e-invoice system would require. The FRA's
//! digital factoring system links to the Ministry of Finance and the
//! Egyptian Tax Authority; a real deployment would likely want to bind
//! this commitment to that system's own invoice identifier too, once
//! it's confirmed what that identifier is and how it's obtained -- see
//! this project's design-review notes on why that confirmation isn't
//! done yet. Changing the field list changes `canonical_bytes()`'s
//! output and therefore every existing commitment's hash; do so behind
//! a version bump (see [`InvoiceCommitment::version`]), never silently.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Length of the random salt mixed into every commitment. 32 bytes
/// (256 bits) is comfortably more entropy than brute-forcing plausible
/// invoice field combinations could ever compensate for -- the salt's
/// entropy is what makes this commitment *hiding*, not the entropy of
/// the invoice content itself, which can be very low (round amounts,
/// common counterparty names, predictable date ranges).
pub const INVOICE_COMMITMENT_SALT_LEN: usize = 32;

/// Bumped whenever [`InvoiceFields::canonical_bytes`]'s encoding
/// changes (a new field, a reordered field, a changed representation)
/// -- see this module's doc comment. [`InvoiceCommitment::verify`]
/// refuses to compare across versions rather than silently recomputing
/// with today's encoding against a commitment made under a different
/// one.
pub const INVOICE_COMMITMENT_VERSION: u8 = 1;

const DOMAIN_TAG: &[u8] = b"ciphersettle-invoice-commitment-v1";
const COMMITMENT_BYTES_LEN: usize = 1 + INVOICE_COMMITMENT_SALT_LEN + 32;

/// The plaintext invoice fields a commitment binds to. Provisional field
/// list -- see this module's doc comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceFields {
    /// A caller-chosen invoice reference. Distinct from this system's
    /// own `invoice_id` (the primary key `quorum_service` assigns) --
    /// this is whatever identifier the invoice itself carries (an
    /// invoice number, or eventually a Tax Authority e-invoice UUID).
    pub invoice_reference: String,
    pub issuer: String,
    pub debtor: String,
    /// Integer minor units (piastres, not EGP) to avoid any
    /// floating-point representation ambiguity in the commitment's
    /// canonical encoding -- a real amount of "100.00 EGP" is
    /// `10_000` here, not `100.0`.
    pub amount_minor_units: i64,
    /// ISO 4217 currency code, e.g. "EGP".
    pub currency: String,
    /// ISO 8601 calendar date, e.g. "2026-09-24". Stored and hashed as
    /// the exact string provided -- this module does not parse or
    /// validate dates, so callers must agree on a single format
    /// (ISO 8601 is recommended) for commitments to be comparable.
    pub issue_date: String,
    pub due_date: String,
}

impl InvoiceFields {
    /// Domain-separated, length-prefixed, explicitly field-ordered
    /// binary encoding. Deliberately NOT generic JSON canonicalization
    /// (e.g. JCS / RFC 8785): canonical JSON has known correctness
    /// pitfalls around number formatting and Unicode normalization that
    /// are easy to get subtly wrong in one implementation and not
    /// another -- exactly the kind of mismatch that would make two
    /// honest parties compute different commitments for the same
    /// invoice. A fixed field order with explicit length-prefixed
    /// framing has no such ambiguity and is simple enough for anyone to
    /// independently reimplement byte-for-byte from this doc comment
    /// alone.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN_TAG);
        write_field(&mut buf, self.invoice_reference.as_bytes());
        write_field(&mut buf, self.issuer.as_bytes());
        write_field(&mut buf, self.debtor.as_bytes());
        write_field(&mut buf, &self.amount_minor_units.to_be_bytes());
        write_field(&mut buf, self.currency.as_bytes());
        write_field(&mut buf, self.issue_date.as_bytes());
        write_field(&mut buf, self.due_date.as_bytes());
        buf
    }
}

fn write_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

/// A salted commitment to a set of [`InvoiceFields`]. See this module's
/// doc comment for what this construction is (and is not).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceCommitment {
    pub version: u8,
    pub salt: [u8; INVOICE_COMMITMENT_SALT_LEN],
    pub hash: [u8; 32],
}

impl InvoiceCommitment {
    /// Computes a fresh commitment to `fields`, drawing a new random
    /// salt from `rng`. Use a real CSPRNG (`rand::rngs::OsRng` or
    /// equivalent) -- the salt is load-bearing for hiding, not
    /// decorative.
    pub fn compute<R: RngCore + CryptoRng>(fields: &InvoiceFields, rng: &mut R) -> Self {
        let mut salt = [0u8; INVOICE_COMMITMENT_SALT_LEN];
        rng.fill_bytes(&mut salt);
        Self::compute_with_salt(fields, salt)
    }

    /// Recomputes a commitment given an already-known salt -- the
    /// primitive [`compute`](Self::compute) and
    /// [`verify`](Self::verify) both build on. Exposed directly for
    /// callers reconstructing a commitment from stored
    /// (fields, salt) pairs rather than generating a fresh one.
    pub fn compute_with_salt(
        fields: &InvoiceFields,
        salt: [u8; INVOICE_COMMITMENT_SALT_LEN],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(fields.canonical_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        Self {
            version: INVOICE_COMMITMENT_VERSION,
            salt,
            hash,
        }
    }

    /// Does `fields`, combined with this commitment's own stored salt,
    /// reproduce this commitment's hash? A caller who wants to prove
    /// "the data I'm using now is the data originally committed" reveals
    /// `fields` to whoever runs this check -- see this module's doc
    /// comment on why that's not a zero-knowledge operation and why
    /// that's fine here.
    pub fn verify(&self, fields: &InvoiceFields) -> bool {
        if self.version != INVOICE_COMMITMENT_VERSION {
            // Refuse to compare across versions rather than silently
            // recomputing with today's encoding -- see
            // INVOICE_COMMITMENT_VERSION's doc comment.
            return false;
        }
        let recomputed = Self::compute_with_salt(fields, self.salt);
        // Constant-time comparison: this commitment's hash is public
        // once stored, so timing-safety here is defense-in-depth rather
        // than load-bearing against an online guessing oracle -- but
        // it's free, and consistent with how this project already
        // treats hash/digest comparisons elsewhere (audit finding A15).
        bool::from(self.hash.ct_eq(&recomputed.hash))
    }

    /// `1 + salt_len + hash_len` bytes: version, salt, hash, in that
    /// order. Callers that need this as `Vec<u8>` or base64 (matching
    /// how every other binary blob in this workspace's wire/storage
    /// formats is handled) can trivially convert from the fixed array.
    pub fn to_bytes(&self) -> [u8; COMMITMENT_BYTES_LEN] {
        let mut out = [0u8; COMMITMENT_BYTES_LEN];
        out[0] = self.version;
        out[1..1 + INVOICE_COMMITMENT_SALT_LEN].copy_from_slice(&self.salt);
        out[1 + INVOICE_COMMITMENT_SALT_LEN..].copy_from_slice(&self.hash);
        out
    }

    pub fn from_bytes(bytes: &[u8; COMMITMENT_BYTES_LEN]) -> Result<Self, String> {
        let version = bytes[0];
        if version != INVOICE_COMMITMENT_VERSION {
            return Err(format!(
                "unsupported invoice commitment version {version} (this build understands version {INVOICE_COMMITMENT_VERSION})"
            ));
        }
        let mut salt = [0u8; INVOICE_COMMITMENT_SALT_LEN];
        salt.copy_from_slice(&bytes[1..1 + INVOICE_COMMITMENT_SALT_LEN]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[1 + INVOICE_COMMITMENT_SALT_LEN..]);
        Ok(Self {
            version,
            salt,
            hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn sample_fields() -> InvoiceFields {
        InvoiceFields {
            invoice_reference: "INV-1001".to_string(),
            issuer: "Company A".to_string(),
            debtor: "Company B".to_string(),
            amount_minor_units: 1_000_000_000, // 10,000,000.00 EGP in piastres
            currency: "EGP".to_string(),
            issue_date: "2026-09-01".to_string(),
            due_date: "2026-12-01".to_string(),
        }
    }

    #[test]
    fn a_commitment_verifies_against_the_exact_fields_it_was_made_from() {
        let fields = sample_fields();
        let commitment = InvoiceCommitment::compute(&fields, &mut OsRng);
        assert!(commitment.verify(&fields));
    }

    /// The binding property: changing any single field, however
    /// slightly, must break verification against the original
    /// commitment. Exercises every field individually rather than one
    /// combined mutation, since a bug in `canonical_bytes()` could
    /// plausibly affect only one field's encoding.
    #[test]
    fn tampering_with_any_single_field_is_detected() {
        let fields = sample_fields();
        let commitment = InvoiceCommitment::compute(&fields, &mut OsRng);

        let mutations: Vec<InvoiceFields> = vec![
            InvoiceFields {
                invoice_reference: "INV-1002".to_string(),
                ..fields.clone()
            },
            InvoiceFields {
                issuer: "Company C".to_string(),
                ..fields.clone()
            },
            InvoiceFields {
                debtor: "Company D".to_string(),
                ..fields.clone()
            },
            InvoiceFields {
                amount_minor_units: fields.amount_minor_units + 1,
                ..fields.clone()
            },
            InvoiceFields {
                currency: "USD".to_string(),
                ..fields.clone()
            },
            InvoiceFields {
                issue_date: "2026-09-02".to_string(),
                ..fields.clone()
            },
            InvoiceFields {
                due_date: "2026-12-02".to_string(),
                ..fields.clone()
            },
        ];
        for (i, mutated) in mutations.iter().enumerate() {
            assert!(
                !commitment.verify(mutated),
                "mutation {i} was not detected: {mutated:?}"
            );
        }
    }

    /// The hiding property, checked the way it actually matters: two
    /// commitments to the IDENTICAL fields, differing only in salt, must
    /// produce different hashes. If this ever failed, the salt
    /// wouldn't be contributing entropy to the hash at all (e.g. a bug
    /// that hashed the fields alone and the salt separately/unused).
    #[test]
    fn different_salts_for_identical_fields_produce_different_commitments() {
        let fields = sample_fields();
        let a = InvoiceCommitment::compute(&fields, &mut OsRng);
        let b = InvoiceCommitment::compute(&fields, &mut OsRng);
        assert_ne!(
            a.salt, b.salt,
            "two independently-drawn salts collided -- OsRng is broken, not this code"
        );
        assert_ne!(a.hash, b.hash);
        // Both still independently verify against the same fields --
        // hiding doesn't mean "can't be checked", just "can't be
        // guessed without the salt".
        assert!(a.verify(&fields));
        assert!(b.verify(&fields));
    }

    /// A low-entropy field set (this test's whole point): round amount,
    /// common names, near-today dates -- exactly the kind of invoice
    /// content a brute-force guesser would try first. Confirms an
    /// attacker who knows the field VALUES but not the SALT cannot
    /// verify (i.e. cannot use `verify` as a guessing oracle for the
    /// salt itself -- they'd need to already know or guess the salt,
    /// which has 256 bits of entropy regardless of how guessable the
    /// fields are).
    #[test]
    fn a_guessed_salt_does_not_verify_against_the_real_commitment() {
        let fields = sample_fields();
        let real = InvoiceCommitment::compute(&fields, &mut OsRng);
        let wrong_salt_commitment =
            InvoiceCommitment::compute_with_salt(&fields, [0u8; INVOICE_COMMITMENT_SALT_LEN]);
        assert_ne!(
            real.hash, wrong_salt_commitment.hash,
            "an attacker guessing salt=all-zeros must not match a real commitment"
        );
    }

    #[test]
    fn serialization_round_trips() {
        let fields = sample_fields();
        let commitment = InvoiceCommitment::compute(&fields, &mut OsRng);
        let bytes = commitment.to_bytes();
        let restored = InvoiceCommitment::from_bytes(&bytes).unwrap();
        assert_eq!(commitment, restored);
        assert!(restored.verify(&fields));
    }

    #[test]
    fn a_commitment_claiming_an_unsupported_version_is_rejected() {
        let fields = sample_fields();
        let mut commitment = InvoiceCommitment::compute(&fields, &mut OsRng);
        commitment.version = 99;
        assert!(
            !commitment.verify(&fields),
            "a commitment claiming a future/unknown version must not be silently accepted as valid"
        );
        let bytes = commitment.to_bytes();
        assert!(
            InvoiceCommitment::from_bytes(&bytes).is_err(),
            "from_bytes must also reject an unsupported version"
        );
    }

    /// Two different, unrelated invoices should essentially never
    /// collide -- a basic sanity check on SHA-256's collision
    /// resistance being actually exercised, not a substitute for a real
    /// security proof.
    #[test]
    fn unrelated_invoices_do_not_collide() {
        let a = InvoiceCommitment::compute(&sample_fields(), &mut OsRng);
        let other_fields = InvoiceFields {
            invoice_reference: "INV-9999".to_string(),
            issuer: "Totally Different Co".to_string(),
            debtor: "Another Company".to_string(),
            amount_minor_units: 4_200, // 42.00 in minor units
            currency: "USD".to_string(),
            issue_date: "2020-01-01".to_string(),
            due_date: "2020-02-01".to_string(),
        };
        let b = InvoiceCommitment::compute(&other_fields, &mut OsRng);
        assert_ne!(a.hash, b.hash);
    }
}
