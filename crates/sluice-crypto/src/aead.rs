//! Authenticated encryption: blob seal/open with XChaCha20-Poly1305.
//!
//! A sealed blob is `nonce(24) || ciphertext || tag(16)`. XChaCha20's 192-bit
//! nonce means a fresh random nonce per blob is collision-safe with no state to
//! track (see `DESIGN.md` §5.4). The caller passes associated data (`aad`) that
//! is authenticated but not encrypted — used to bind a blob to its repository,
//! format version, kind, and key epoch.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::Key;

/// Length of the random nonce prepended to every sealed blob.
pub const NONCE_LEN: usize = 24;

/// Length of the Poly1305 authentication tag the AEAD appends.
pub const TAG_LEN: usize = 16;

/// Error returned when opening a sealed blob fails.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AeadError {
    /// The input is too short to hold a nonce and a tag.
    #[error("sealed blob is too short")]
    TooShort,
    /// Authentication failed: wrong key, wrong associated data, or tampering.
    #[error("AEAD authentication failed")]
    Unauthenticated,
}

/// Seal `plaintext` under `key`, authenticating `aad`.
///
/// Returns `nonce || ciphertext || tag`. The nonce is freshly random.
#[must_use]
pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    out
}

/// Open a blob produced by [`seal`] using the same `key` and `aad`.
///
/// Fails if the input is truncated, the key or `aad` differ, or any byte has
/// been altered.
pub fn open(key: &Key, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, AeadError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(AeadError::TooShort);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError::Unauthenticated)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Key = [7u8; 32];

    #[test]
    fn seal_open_roundtrips() {
        let pt = b"sensitive blob contents";
        let sealed = seal(&KEY, b"aad", pt);
        assert_eq!(open(&KEY, b"aad", &sealed).unwrap(), pt);
    }

    #[test]
    fn random_nonce_makes_ciphertexts_differ() {
        let pt = b"same plaintext";
        let a = seal(&KEY, b"", pt);
        let b = seal(&KEY, b"", pt);
        assert_ne!(a, b);
        assert_eq!(open(&KEY, b"", &a).unwrap(), pt);
        assert_eq!(open(&KEY, b"", &b).unwrap(), pt);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sealed = seal(&KEY, b"aad", b"x");
        let mut other = KEY;
        other[0] ^= 1;
        assert_eq!(
            open(&other, b"aad", &sealed),
            Err(AeadError::Unauthenticated)
        );
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let sealed = seal(&KEY, b"aad-1", b"x");
        assert_eq!(
            open(&KEY, b"aad-2", &sealed),
            Err(AeadError::Unauthenticated)
        );
    }

    #[test]
    fn tampering_is_detected() {
        let mut sealed = seal(&KEY, b"aad", b"hello");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert_eq!(open(&KEY, b"aad", &sealed), Err(AeadError::Unauthenticated));
    }

    #[test]
    fn too_short_is_rejected() {
        assert_eq!(open(&KEY, b"", &[0u8; 8]), Err(AeadError::TooShort));
    }

    #[test]
    fn works_with_a_derived_key() {
        let k = crate::derive_key("sluice.test data-key", b"master");
        let sealed = seal(&k, b"", b"payload");
        assert_eq!(open(&k, b"", &sealed).unwrap(), b"payload");
    }
}
