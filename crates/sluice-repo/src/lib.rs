//! `sluice-repo` — the repository handle.
//!
//! Ties `sluice-store`, `sluice-crypto`, and `sluice-core` together to create
//! and open an encrypted repository (see `DESIGN.md` §3). On `init`, a random
//! master key is generated, split into subkeys, used to seal the config, and
//! itself wrapped under the passphrase; on `open`, the passphrase unwraps the
//! master and authenticates the config.

use serde::{Deserialize, Serialize};
use sluice_core::{
    CONFIG_VERSION, ChunkerConfig, CipherSuite, Id, REPO_MAGIC, RepoConfig, from_cbor, to_cbor,
};
use sluice_crypto::{
    KdfParams, KeyError, KeySet, fill_random, open, random_key, seal, unwrap_master, wrap_master,
};
use sluice_store::{FileType, StorageBackend, StoreError};

/// Well-known id of the single (encrypted) config object.
const CONFIG_ID: Id = Id::from_bytes([0u8; 32]);
/// Well-known id of the master-key object.
const KEY_ID: Id = Id::from_bytes([0u8; 32]);
/// AEAD associated data for the config object. It cannot be the repo id, which
/// lives *inside* the config and so is unknown until after decryption.
const CONFIG_AAD: &[u8] = b"sluice.v1 config";
/// Default target pack size (16 MiB).
const PACK_TARGET: u64 = 16 * 1024 * 1024;

/// Errors from repository operations.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// A storage backend error.
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
    /// A key wrapping/unwrapping error (e.g. a wrong passphrase).
    #[error("key error: {0}")]
    Key(#[from] KeyError),
    /// A serialization error.
    #[error("serialization error: {0}")]
    Codec(String),
    /// The config object failed authentication or could not be decrypted.
    #[error("config authentication failed")]
    Config,
    /// The repository uses an unsupported format.
    #[error("unsupported repository format")]
    Unsupported,
}

/// Convenience alias for fallible repository operations.
pub type Result<T> = std::result::Result<T, RepoError>;

/// The on-disk master-key object: Argon2id parameters, salt, and wrapped master.
#[derive(Serialize, Deserialize)]
struct KeyObject {
    salt: Vec<u8>,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    wrapped: Vec<u8>,
}

/// An open repository over a storage backend `B`.
pub struct Repository<B> {
    backend: B,
    keys: KeySet,
    config: RepoConfig,
}

impl<B: StorageBackend> Repository<B> {
    /// Initialize a new encrypted repository on `backend`, protected by
    /// `passphrase` (stretched with the given Argon2id parameters).
    pub async fn init(backend: B, passphrase: &[u8], kdf: KdfParams) -> Result<Self> {
        let master = random_key();
        let keys = KeySet::derive(&master);

        let mut repo_id = [0u8; 32];
        fill_random(&mut repo_id);
        let mut gear_seed = [0u8; 32];
        fill_random(&mut gear_seed);

        let config = RepoConfig {
            magic: REPO_MAGIC,
            version: CONFIG_VERSION,
            repo_id: Id::from_bytes(repo_id),
            chunker: ChunkerConfig {
                min: 262_144,
                avg: 1_048_576,
                max: 4_194_304,
                gear_seed,
            },
            cipher: CipherSuite::XChaCha20Poly1305,
            pack_target: PACK_TARGET,
            created_ns: now_ns(),
        };

        // Seal the config under meta_key and store it.
        let sealed_config = seal(
            &keys.meta_key,
            CONFIG_AAD,
            &to_cbor(&config).map_err(codec)?,
        );
        backend
            .put(FileType::Config, &CONFIG_ID, sealed_config.into())
            .await?;

        // Wrap the master under the passphrase and store the key object.
        let mut salt = [0u8; 16];
        fill_random(&mut salt);
        let key_object = KeyObject {
            salt: salt.to_vec(),
            m_cost_kib: kdf.m_cost_kib,
            t_cost: kdf.t_cost,
            p_cost: kdf.p_cost,
            wrapped: wrap_master(passphrase, &salt, kdf, &master)?,
        };
        backend
            .put(
                FileType::Key,
                &KEY_ID,
                to_cbor(&key_object).map_err(codec)?.into(),
            )
            .await?;

        Ok(Self {
            backend,
            keys,
            config,
        })
    }

    /// Open an existing repository on `backend` using `passphrase`.
    pub async fn open(backend: B, passphrase: &[u8]) -> Result<Self> {
        let key_object: KeyObject =
            from_cbor(&backend.get(FileType::Key, &KEY_ID).await?).map_err(codec)?;
        let kdf = KdfParams {
            m_cost_kib: key_object.m_cost_kib,
            t_cost: key_object.t_cost,
            p_cost: key_object.p_cost,
        };
        let master = unwrap_master(passphrase, &key_object.salt, kdf, &key_object.wrapped)?;
        let keys = KeySet::derive(&master);

        let sealed = backend.get(FileType::Config, &CONFIG_ID).await?;
        let config_bytes =
            open(&keys.meta_key, CONFIG_AAD, &sealed).map_err(|_| RepoError::Config)?;
        let config: RepoConfig = from_cbor(&config_bytes).map_err(codec)?;
        if !config.is_supported() {
            return Err(RepoError::Unsupported);
        }

        Ok(Self {
            backend,
            keys,
            config,
        })
    }

    /// The repository configuration.
    #[must_use]
    pub fn config(&self) -> &RepoConfig {
        &self.config
    }

    /// The repository's unique id.
    #[must_use]
    pub fn id(&self) -> Id {
        self.config.repo_id
    }

    /// The derived subkey set (consumed by the engine when sealing blobs).
    #[must_use]
    pub fn keys(&self) -> &KeySet {
        &self.keys
    }

    /// Borrow the storage backend.
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

/// Map a core (CBOR) error into a repository error.
fn codec(e: sluice_core::Error) -> RepoError {
    RepoError::Codec(e.to_string())
}

/// Current wall-clock time in nanoseconds since the Unix epoch (0 if before it).
fn now_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluice_store::{LocalBackend, MemoryBackend};

    /// Cheap KDF parameters so tests stay fast.
    fn fast() -> KdfParams {
        KdfParams {
            m_cost_kib: 16,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[tokio::test]
    async fn init_then_open_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let id = {
            let be = LocalBackend::create(dir.path()).await.unwrap();
            Repository::init(be, b"correct horse", fast())
                .await
                .unwrap()
                .id()
        };

        let be = LocalBackend::open(dir.path());
        let repo = Repository::open(be, b"correct horse").await.unwrap();
        assert_eq!(repo.id(), id);
        assert_eq!(repo.config().cipher, CipherSuite::XChaCha20Poly1305);
        assert!(repo.config().is_supported());
    }

    #[tokio::test]
    async fn wrong_passphrase_fails_to_open() {
        let dir = tempfile::tempdir().unwrap();
        {
            let be = LocalBackend::create(dir.path()).await.unwrap();
            Repository::init(be, b"right", fast()).await.unwrap();
        }
        let be = LocalBackend::open(dir.path());
        assert!(matches!(
            Repository::open(be, b"wrong").await,
            Err(RepoError::Key(_))
        ));
    }

    #[tokio::test]
    async fn open_uninitialized_is_error() {
        let be = MemoryBackend::new();
        assert!(Repository::open(be, b"pass").await.is_err());
    }

    #[tokio::test]
    async fn init_persists_config_and_key_objects() {
        let be = MemoryBackend::new();
        let repo = Repository::init(be, b"pass", fast()).await.unwrap();
        assert!(
            repo.backend()
                .exists(FileType::Config, &CONFIG_ID)
                .await
                .unwrap()
        );
        assert!(repo.backend().exists(FileType::Key, &KEY_ID).await.unwrap());
        // Each distinct repo gets a distinct random id.
        let other = Repository::init(MemoryBackend::new(), b"pass", fast())
            .await
            .unwrap();
        assert_ne!(repo.id(), other.id());
    }
}
