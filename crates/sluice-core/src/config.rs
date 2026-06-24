//! The repository configuration object (see `DESIGN.md` §3).

use serde::{Deserialize, Serialize};

use crate::Id;

/// Magic bytes identifying a sluice repository config object.
pub const REPO_MAGIC: [u8; 8] = *b"SLUICE01";

/// Current repository config format version.
pub const CONFIG_VERSION: u32 = 1;

/// The authenticated-encryption suite a repository uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// XChaCha20-Poly1305 with a 192-bit random nonce (the default).
    XChaCha20Poly1305,
    /// AES-256-GCM with per-blob single-use key derivation.
    Aes256Gcm,
}

/// The chunker parameters pinned for a repository's lifetime.
///
/// Fixed at `init`; changing them would break deduplication against all
/// existing data (see `DESIGN.md` §5.2). The runtime chunker in `sluice-chunk`
/// is built from this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkerConfig {
    /// Minimum chunk size in bytes.
    pub min: u32,
    /// Target average chunk size in bytes (a power of two).
    pub avg: u32,
    /// Maximum chunk size in bytes.
    pub max: u32,
    /// Seed for the content-defined-chunking gear table.
    pub gear_seed: [u8; 32],
}

/// The repository configuration object, written once at `init` and AEAD-sealed.
///
/// It pins the format so an untrusted backend cannot silently downgrade the
/// cipher or chunker (see `DESIGN.md` §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoConfig {
    /// Format magic; see [`REPO_MAGIC`].
    pub magic: [u8; 8],
    /// Format version; see [`CONFIG_VERSION`].
    pub version: u32,
    /// Random per-repository identifier (used in AEAD associated data).
    pub repo_id: Id,
    /// Pinned chunker parameters.
    pub chunker: ChunkerConfig,
    /// The encryption suite in use.
    pub cipher: CipherSuite,
    /// Target pack-file size in bytes.
    pub pack_target: u64,
    /// Creation time, nanoseconds since the Unix epoch.
    pub created_ns: i64,
}

impl RepoConfig {
    /// Whether this build recognizes the config's magic and version.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.magic == REPO_MAGIC && self.version == CONFIG_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{from_cbor, to_cbor};

    fn sample() -> RepoConfig {
        RepoConfig {
            magic: REPO_MAGIC,
            version: CONFIG_VERSION,
            repo_id: Id::from_bytes([3u8; 32]),
            chunker: ChunkerConfig {
                min: 262_144,
                avg: 1_048_576,
                max: 4_194_304,
                gear_seed: [5u8; 32],
            },
            cipher: CipherSuite::XChaCha20Poly1305,
            pack_target: 16 * 1024 * 1024,
            created_ns: 1_700_000_000_000_000_000,
        }
    }

    #[test]
    fn repo_config_roundtrips() {
        let c = sample();
        assert_eq!(from_cbor::<RepoConfig>(&to_cbor(&c).unwrap()).unwrap(), c);
    }

    #[test]
    fn is_supported_checks_magic_and_version() {
        assert!(sample().is_supported());
        let mut bad = sample();
        bad.version = 999;
        assert!(!bad.is_supported());
    }

    #[test]
    fn magic_is_stable() {
        assert_eq!(&REPO_MAGIC, b"SLUICE01");
    }
}
