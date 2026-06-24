//! `sluice-crypto` — the centralized cryptography seam: key hierarchy, AEAD
//! seal/open, KDFs (Argon2id, BLAKE3 `derive_key`), and hashing.
//!
//! All cryptographic side effects in sluice flow through this crate so they can
//! be audited and tested in one place (see `DESIGN.md` §5.4 and §9). Pre-alpha
//! skeleton (milestone M3).
