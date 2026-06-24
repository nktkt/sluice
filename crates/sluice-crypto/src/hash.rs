//! BLAKE3 hashing: unkeyed (self-verifying storage names), keyed (content
//! addresses that double as a repository MAC), and key derivation for the key
//! hierarchy. See `DESIGN.md` §3, §5.2, and §5.4.

use sluice_core::Id;

/// A 256-bit key used for keyed hashing and key derivation.
pub type Key = [u8; 32];

/// Unkeyed BLAKE3 of `data`.
///
/// Used for self-verifying storage names such as pack IDs (the hash of the
/// ciphertext), which any party can recompute without a key.
#[must_use]
pub fn hash(data: &[u8]) -> Id {
    Id::from_bytes(*blake3::hash(data).as_bytes())
}

/// Keyed BLAKE3 of `data` under `key`.
///
/// This is the content address for data and tree blobs. Keying turns the
/// repository's identifiers into a MAC, so an attacker holding only ciphertext
/// cannot confirm whether a known plaintext is stored (confirmation-attack
/// resistance, see `DESIGN.md` §5.2).
#[must_use]
pub fn keyed_hash(key: &Key, data: &[u8]) -> Id {
    Id::from_bytes(*blake3::keyed_hash(key, data).as_bytes())
}

/// Derive a 256-bit subkey from `key_material`, domain-separated by `context`.
///
/// A HKDF-like split used to derive the `id_key`, `data_key`, and `meta_key`
/// from the master key (see `DESIGN.md` §5.4). `context` should be a unique,
/// hard-coded, application-specific string per derived key.
#[must_use]
pub fn derive_key(context: &str, key_material: &[u8]) -> Key {
    blake3::derive_key(context, key_material)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official BLAKE3 test vector: the hash of the empty input.
    const EMPTY_HASH: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

    #[test]
    fn unkeyed_matches_blake3_empty_vector() {
        assert_eq!(hash(b"").to_string(), EMPTY_HASH);
    }

    #[test]
    fn unkeyed_is_deterministic_and_input_sensitive() {
        assert_eq!(hash(b"sluice"), hash(b"sluice"));
        assert_ne!(hash(b"sluice"), hash(b"Sluice"));
    }

    #[test]
    fn keyed_differs_from_unkeyed_and_between_keys() {
        let k1: Key = [1u8; 32];
        let k2: Key = [2u8; 32];
        let data = b"chunk";
        assert_ne!(keyed_hash(&k1, data), hash(data));
        assert_ne!(keyed_hash(&k1, data), keyed_hash(&k2, data));
        assert_eq!(keyed_hash(&k1, data), keyed_hash(&k1, data));
    }

    #[test]
    fn derive_key_is_context_separated_and_deterministic() {
        let master = b"master key material";
        let id_key = derive_key("sluice.test id-key", master);
        let data_key = derive_key("sluice.test data-key", master);
        assert_ne!(id_key, data_key);
        assert_eq!(id_key, derive_key("sluice.test id-key", master));
    }

    #[test]
    fn derived_key_drives_keyed_hash() {
        let id_key = derive_key("sluice.test id-key", b"master");
        assert_eq!(keyed_hash(&id_key, b"x"), keyed_hash(&id_key, b"x"));
    }
}
