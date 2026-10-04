# Glossary

Plain-language definitions for the terms used across this repository,
organized from the outside in: finance → protocol → cryptography →
operations. Each entry says what the term means, and what it means *here*.

---

## Finance and regulation

**Invoice** — a request for payment issued by a supplier to a buyer, carrying
the amount, the goods, and the payment terms. In this system the invoice is
registered **encrypted**; the platform stores ciphertext and a commitment to
it, never the readable terms.

**Invoice factoring / discounting** — buying a receivable before it is paid,
for a fee. The financier needs to read the invoice to decide. That read
access is exactly what this system grants and records.

**Confidential settlement** — arranging a payment while keeping the
commercial terms of the underlying invoice hidden from parties not entitled
to see them. The system records that settlement happened; it never moves the
money.

**Double financing** — the same receivable being financed twice. **This system
does not detect or prevent it.** That determination belongs to the Egyptian
Financial Regulatory Authority's own systems. What this system does refuse is
re-registering the same invoice or nullifier through itself, which is a replay
and idempotency guard — a different thing, and labelled as such in the API.

**FRA** — the Financial Regulatory Authority, Egypt's financial-sector
supervisor. This project is designed to sit alongside FRA-regulated systems,
not to perform their functions.

## Roles in the protocol

**Issuer** — the party that registered the invoice (the supplier). Only the
issuer can grant or revoke a financier's access.

**Bank / financier** — the party nominated by the issuer for a specific
invoice. Entitled to derive that invoice's key, and to nothing else.

**Regulator** — a supervisory caller, registered by the admin. Its accesses
are logged under `disclosure_request` rather than as a normal financier read,
so that supervisory disclosure is as visible as any other.

**Operator** — whoever runs the servers. The central claim of the design is
that this role confers **no ability to read invoice contents**.

**Node operator** — whoever runs one of the threshold nodes. Distinct from
"the operator" in the target deployment: node independence is what the
threshold depends on.

## Protocol

**DKG (Distributed Key Generation)** — the ceremony in which the nodes
jointly create one shared secret without any of them ever holding it.
Feldman VSS is the variant used here. Without DKG, someone would have to
generate the secret and distribute it — which recreates exactly the "one
party holds everything" problem this system exists to avoid.

**Share** — one node's piece of the group secret. A single share reveals
nothing about the secret.

**Threshold (`t+1` of `n`)** — any `t+1` of the `n` shares can reconstruct,
or act on, the group secret; any `t` fewer cannot. Currently 3 of 5.

**k-of-n liveness** — the system keeps working when up to `n − (t+1)` nodes
are unavailable. Demonstrated by killing 2 of 5 real node processes and
completing a derivation from the 3 survivors.

**Derive, don't decrypt** — the model this system follows, borrowed from
vetKeys. The system derives a *key* for a stated purpose; it does not
decrypt data it was not asked to decrypt, and it holds nothing that would let
it do so later.

**Commitment** — a fixed-size, salted, hiding-and-binding value computed from
the invoice's fields. It proves the registered invoice's contents have not
changed without revealing them, and it is what the append-only Merkle log
commits to.

**Nullifier** — a unique token attached to an invoice at registration. Its
uniqueness is the replay/idempotency guard. Not a double-financing check.

**Sealing (`quorum_vetseal`)** — encrypting a node's partial signature to the
*end caller's* transport public key, so that even the nodes and the broker
hold only ciphertext. Homomorphic combine happens on the ciphertexts.

**Transport key** — a keypair generated locally by the true end caller (a
browser or CLI). Its public half travels with the derive request; the private
half never leaves the caller's machine. It is what makes the derived key
unreadable to every intermediary.

**NIZK (non-interactive zero-knowledge proof)** — a proof that a sealed share
genuinely encrypts *that node's own genuine partial signature*, verifiable by
anyone without revealing the secret. It lets a dishonest node be identified
and excluded *before* aggregation, rather than only after decryption fails.

**Audit log** — the append-only, hash-chained record of every action. Each
entry extends the previous entry's hash, so no entry can be altered or removed
without breaking the chain.

**Co-signing** — each node independently signs an audit entry with its own
audit key. A single party cannot produce a valid entry for an action it did
not perform.

**Reconciliation** — comparing the nodes' replicas to detect a divergence. The
reference is built by a per-sequence-number majority vote across replicas, so
no single node's copy is trusted as "the truth."

**Notarization / notary** — a separate process, with its own identity,
outside the quorum's control, that timestamps and signs the log's root hash.
It anchors history somewhere the quorum cannot rewrite, so even a colluding
majority cannot erase it unnoticed.

**Merkle log / inclusion proof** — an append-only list of commitments with a
rolling root hash. An inclusion proof shows a given commitment is in the list
without revealing the other entries.

---

## Cryptography

**BLS (Boneh–Lynn–Shacham)** — the signature scheme used. Its useful property
here is that signatures can be aggregated from shares and verified against a
single public key.

**IBE (Identity-Based Encryption)** — a scheme where a key is derived from an
identity string, `sk_id = s · H(id)`, so no key ever has to be stored or
transmitted. This system's derived key follows that construction, which is
why "the invoice's identity *is* the key name".

**Pairing (BLS12-381)** — the algebraic operation connecting the two groups
G1 and G2, and the reason threshold construction works at all.

**G1 / G2** — the two elliptic-curve groups in the BLS12-381 scheme. Signatures
live in G2; public keys in G1.

**Feldman VSS** — the verifiable-secret-sharing scheme used in the DKG, based
on discrete logarithms. Each dealer publishes a commitment polynomial, so a
recipient can check its own share is consistent without the dealer revealing
anything.

**ElGamal encryption** — the scheme used for sealing, applied directly to
curve points in G2.

**AEAD** — authenticated encryption (encrypt *and* authenticate). ElGamal over
curve points is not an AEAD: it provides confidentiality but no integrity
tag, and it is malleable. That is accepted by design here, because the
homomorphic combine requires it and the result's authenticity is checked by
signature verification instead. See CRYPTO-008.

**Malleability** — the property that ciphertexts can be transformed
meaningfully. Required for the homomorphic combine; a deliberate tradeoff, not
an oversight.

**Collusion** — several nodes acting together. The design assumes fewer than
`t+1` honest-independent nodes cannot do damage; a colluding threshold **can**,
and that is the construction's fundamental assumption.

**Zeroize** — overwriting a secret in memory when it is dropped. Here it is
best-effort only: the compiler may have copied the value, and there is no
`mlock`.

---

## Operations

**mutual TLS (mTLS)** — both ends of a connection present certificates. Used
between every component; pinning is by exact certificate bytes, with no
certificate authority in the loop.

**Pinning** — accepting exactly one known certificate rather than trusting a
CA. Stronger and simpler, at the cost of manual certificate distribution.

**Nominated / authorized party** — the node operator trusted to hand back an
honest result. Used loosely for a node's audit identity, which is
deliberately separate from its TLS identity.

**Resharing / key rotation** — changing the group secret without re-issuing
every key. **Not implemented**, and a real blocker for production.

**Fault injection / adversarial test** — deliberately misbehaving as an
attacker would, to check the system's defenses actually fire. This repository
runs 41 such checks against a live quorum over real mTLS.

---

**Next:** `README.md` (scope and non-claims) ·
`docs/FINANCIAL_CONTEXT.md` (the commercial case) ·
`docs/ARCHITECTURE.md` (structure) ·
`docs/security/THREAT_MODEL.md` (attack paths) ·
`docs/cryptography/CRYPTO_DECISIONS.md` (design records)