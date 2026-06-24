//! The key hierarchy (see `DESIGN.md` §5.4).
//!
//! ```text
//! passphrase --Argon2id(salt)--> KEK --AEAD--> wraps random 256-bit MASTER
//! MASTER --BLAKE3 derive_key--> { id_key, data_key, meta_key }
//! ```
//!
//! Multiple key objects can wrap the same master under different passphrases,
//! so passphrase rotation is O(1) and never touches stored data.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::{Key, derive_key, open, seal};

/// Associated data binding a wrapped master to its purpose and version.
const WRAP_AAD: &[u8] = b"sluice.v1 master-key";

/// The subkeys derived from the master key.
///
/// `Debug` is redacted so key material never lands in logs.
#[derive(Clone)]
pub struct KeySet {
    /// Keyed-BLAKE3 key for content addresses (chunk and tree IDs).
    pub id_key: Key,
    /// Per-blob AEAD key for data and tree blobs.
    pub data_key: Key,
    /// AEAD key for config, index, and header objects.
    pub meta_key: Key,
}

impl KeySet {
    /// Derive the subkeys from `master` using domain-separated `derive_key`.
    #[must_use]
    pub fn derive(master: &Key) -> Self {
        Self {
            id_key: derive_key("sluice.v1 id-key", master),
            data_key: derive_key("sluice.v1 data-key", master),
            meta_key: derive_key("sluice.v1 meta-key", master),
        }
    }
}

impl fmt::Debug for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySet").finish_non_exhaustive()
    }
}

/// Argon2id cost parameters for deriving the KEK from a passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl KdfParams {
    /// Production defaults: Argon2id, ~256 MiB, 3 passes (see `DESIGN.md` §5.4).
    pub const DEFAULT: Self = Self {
        m_cost_kib: 256 * 1024,
        t_cost: 3,
        p_cost: 1,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Error from key wrapping or unwrapping.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    /// Argon2 rejected the parameters or inputs.
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// The passphrase was wrong, or the key object was tampered with.
    #[error("wrong passphrase or corrupt key object")]
    WrongPassphrase,
    /// The unwrapped key did not have the expected length.
    #[error("unwrapped key has the wrong length")]
    Corrupt,
}

/// Derive a 32-byte key-encryption key from a passphrase and salt. The returned
/// value zeroizes its memory when dropped.
fn derive_kek(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<Key>, KeyError> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
            .map_err(|e| KeyError::Kdf(e.to_string()))?,
    );
    let mut kek = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, &mut *kek)
        .map_err(|e| KeyError::Kdf(e.to_string()))?;
    Ok(kek)
}

/// Wrap (encrypt) `master` under a key derived from `passphrase` and `salt`.
///
/// The returned bytes are the contents of a key object; store the `salt` and
/// `params` alongside them.
pub fn wrap_master(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
    master: &Key,
) -> Result<Vec<u8>, KeyError> {
    let kek = derive_kek(passphrase, salt, params)?;
    Ok(seal(&kek, WRAP_AAD, master))
}

/// Unwrap the master key wrapped by [`wrap_master`].
///
/// Fails with [`KeyError::WrongPassphrase`] if the passphrase is wrong or the
/// key object has been altered.
pub fn unwrap_master(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
    wrapped: &[u8],
) -> Result<Key, KeyError> {
    let kek = derive_kek(passphrase, salt, params)?;
    let master = open(&kek, WRAP_AAD, wrapped).map_err(|_| KeyError::WrongPassphrase)?;
    master.try_into().map_err(|_| KeyError::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so tests stay fast; production uses [`KdfParams::DEFAULT`].
    fn fast() -> KdfParams {
        KdfParams {
            m_cost_kib: 16,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn subkeys_are_distinct_and_deterministic() {
        let master: Key = [9u8; 32];
        let ks = KeySet::derive(&master);
        assert_ne!(ks.id_key, ks.data_key);
        assert_ne!(ks.data_key, ks.meta_key);
        assert_ne!(ks.id_key, ks.meta_key);
        assert_eq!(ks.id_key, KeySet::derive(&master).id_key);
    }

    #[test]
    fn wrap_unwrap_roundtrips() {
        let master: Key = [3u8; 32];
        let salt = [1u8; 16];
        let wrapped = wrap_master(b"correct horse", &salt, fast(), &master).unwrap();
        assert_eq!(
            unwrap_master(b"correct horse", &salt, fast(), &wrapped).unwrap(),
            master
        );
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let master: Key = [3u8; 32];
        let salt = [1u8; 16];
        let wrapped = wrap_master(b"correct horse", &salt, fast(), &master).unwrap();
        assert_eq!(
            unwrap_master(b"wrong horse", &salt, fast(), &wrapped),
            Err(KeyError::WrongPassphrase)
        );
    }

    #[test]
    fn passphrase_rotation_preserves_master() {
        // Two key objects wrapping the same master under different passphrases.
        let master: Key = [42u8; 32];
        let (salt1, salt2) = ([1u8; 16], [2u8; 16]);
        let w1 = wrap_master(b"old", &salt1, fast(), &master).unwrap();
        let w2 = wrap_master(b"new", &salt2, fast(), &master).unwrap();
        assert_eq!(unwrap_master(b"old", &salt1, fast(), &w1).unwrap(), master);
        assert_eq!(unwrap_master(b"new", &salt2, fast(), &w2).unwrap(), master);
    }
}
