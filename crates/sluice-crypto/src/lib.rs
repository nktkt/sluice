//! `sluice-crypto` — the centralized cryptography seam: key hierarchy, AEAD
//! seal/open, KDFs (Argon2id, BLAKE3 `derive_key`), hashing, compression, and
//! randomness.
//!
//! All cryptographic side effects in sluice flow through this crate so they can
//! be audited and tested in one place (see `DESIGN.md` §5.3-§5.4 and §9).

mod aead;
mod compress;
mod hash;
mod keys;
mod rng;

pub use aead::{AeadError, NONCE_LEN, TAG_LEN, open, seal};
pub use compress::{CompressError, DEFAULT_LEVEL, compress, decompress};
pub use hash::{Key, derive_key, hash, keyed_hash};
pub use keys::{KdfParams, KeyError, KeySet, unwrap_master, wrap_master};
pub use rng::{fill_random, random_key};
