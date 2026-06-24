//! Cryptographically secure randomness, sourced from the OS CSPRNG.

use crate::Key;

/// Fill `buf` with cryptographically secure random bytes.
///
/// Panics if the OS CSPRNG is unavailable — an unrecoverable condition for a
/// tool whose security depends on fresh randomness.
pub fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG must be available");
}

/// Generate a fresh random 256-bit key.
#[must_use]
pub fn random_key() -> Key {
    let mut key: Key = [0u8; 32];
    fill_random(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_keys_differ() {
        // Collision is astronomically unlikely.
        assert_ne!(random_key(), random_key());
    }

    #[test]
    fn fill_random_overwrites_the_buffer() {
        let mut buf = [0u8; 32];
        fill_random(&mut buf);
        assert_ne!(buf, [0u8; 32]);
    }
}
