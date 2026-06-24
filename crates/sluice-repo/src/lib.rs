//! `sluice-repo` — the repository handle.
//!
//! Ties `sluice-store`, `sluice-crypto`, and `sluice-core` together to create
//! and open an encrypted repository and to read and write content-addressed,
//! deduplicated, encrypted blobs (see `DESIGN.md` §3, §5.2, §5.4).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sluice_chunk::{Chunker, ChunkerParams, Gear};
use sluice_core::{
    BlobKind, CONFIG_VERSION, ChunkerConfig, CipherSuite, Id, REPO_MAGIC, RepoConfig, Snapshot,
    Tree, from_cbor, to_cbor,
};
use sluice_crypto::{
    KdfParams, KeyError, KeySet, compress, decompress, fill_random, hash, keyed_hash, open,
    random_key, seal, unwrap_master, wrap_master,
};
use sluice_store::{BlobEntry, FileType, PackBuilder, PackReader, StorageBackend, StoreError};

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
    /// A blob's contents failed authentication or could not be decrypted.
    #[error("blob authentication failed")]
    Blob,
    /// No blob with the given id is known to this repository.
    #[error("blob not found: {0}")]
    BlobNotFound(Id),
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
    /// chunk id -> (pack id, directory entry). Rebuilt from pack footers on open.
    index: HashMap<Id, (Id, BlobEntry)>,
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
            index: HashMap::new(),
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

        let index = build_index(&backend).await?;

        Ok(Self {
            backend,
            keys,
            config,
            index,
        })
    }

    /// Store `plaintext` as a blob, returning its content-address id.
    ///
    /// The id is `keyed_hash(id_key, plaintext)`; if that blob is already
    /// present the store is skipped (deduplication). Otherwise the plaintext is
    /// AEAD-sealed under `data_key` and written in a new pack.
    pub async fn save_blob(&mut self, kind: BlobKind, plaintext: &[u8]) -> Result<Id> {
        let id = keyed_hash(&self.keys.id_key, plaintext);
        if self.index.contains_key(&id) {
            return Ok(id);
        }

        let frame = compress(plaintext);
        let sealed = seal(&self.keys.data_key, &self.blob_aad(kind), &frame);
        let mut builder = PackBuilder::new();
        builder.add(id, kind, &sealed);
        let (bytes, directory) = builder.finish()?;
        let pack_id = hash(&bytes);
        self.backend
            .put(FileType::Pack, &pack_id, bytes.into())
            .await?;

        for entry in &directory {
            self.index.insert(entry.id, (pack_id, *entry));
        }
        Ok(id)
    }

    /// Load and decrypt the blob with the given id.
    pub async fn load_blob(&self, id: &Id) -> Result<Vec<u8>> {
        let (pack_id, entry) = self
            .index
            .get(id)
            .copied()
            .ok_or(RepoError::BlobNotFound(*id))?;
        let bytes = self.backend.get(FileType::Pack, &pack_id).await?;
        let reader = PackReader::parse(&bytes)?;
        let sealed = reader.blob(id).ok_or(RepoError::BlobNotFound(*id))?;
        let frame = open(&self.keys.data_key, &self.blob_aad(entry.kind), sealed)
            .map_err(|_| RepoError::Blob)?;
        decompress(&frame).map_err(|_| RepoError::Blob)
    }

    /// Split `data` into content-defined chunks, store each as a `Data` blob,
    /// and return the ordered chunk ids that make up the file's content.
    pub async fn save_file(&mut self, data: &[u8]) -> Result<Vec<Id>> {
        let chunker = self.chunker();
        let mut spans = Vec::new();
        let mut offset = 0usize;
        for chunk in chunker.chunks(data) {
            spans.push((offset, chunk.len()));
            offset += chunk.len();
        }
        let mut ids = Vec::with_capacity(spans.len());
        for (start, len) in spans {
            ids.push(
                self.save_blob(BlobKind::Data, &data[start..start + len])
                    .await?,
            );
        }
        Ok(ids)
    }

    /// Reassemble a file from its ordered chunk ids.
    pub async fn load_file(&self, content: &[Id]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for id in content {
            out.extend_from_slice(&self.load_blob(id).await?);
        }
        Ok(out)
    }

    /// Build the FastCDC chunker pinned by this repository's config.
    fn chunker(&self) -> Chunker {
        let c = &self.config.chunker;
        Chunker::new(
            ChunkerParams {
                min: c.min as usize,
                avg: c.avg as usize,
                max: c.max as usize,
            },
            Gear::from_seed_bytes(&c.gear_seed),
        )
    }

    /// Serialize and store a directory `tree` as a `Tree` blob, returning its
    /// id. Identical trees deduplicate.
    pub async fn save_tree(&mut self, tree: &Tree) -> Result<Id> {
        let cbor = to_cbor(tree).map_err(codec)?;
        self.save_blob(BlobKind::Tree, &cbor).await
    }

    /// Load and deserialize a tree by id.
    pub async fn load_tree(&self, id: &Id) -> Result<Tree> {
        let bytes = self.load_blob(id).await?;
        from_cbor(&bytes).map_err(codec)
    }

    /// Commit a `snapshot` as a sealed object, returning its id. Committing an
    /// identical snapshot again is idempotent.
    pub async fn commit_snapshot(&self, snapshot: &Snapshot) -> Result<Id> {
        let cbor = to_cbor(snapshot).map_err(codec)?;
        let id = keyed_hash(&self.keys.id_key, &cbor);
        if self.backend.exists(FileType::Snapshot, &id).await? {
            return Ok(id);
        }
        let sealed = seal(&self.keys.meta_key, &self.snapshot_aad(), &cbor);
        self.backend
            .put(FileType::Snapshot, &id, sealed.into())
            .await?;
        Ok(id)
    }

    /// Load and decrypt a snapshot by id.
    pub async fn load_snapshot(&self, id: &Id) -> Result<Snapshot> {
        let sealed = self.backend.get(FileType::Snapshot, id).await?;
        let cbor = open(&self.keys.meta_key, &self.snapshot_aad(), &sealed)
            .map_err(|_| RepoError::Blob)?;
        from_cbor(&cbor).map_err(codec)
    }

    /// List the ids of all snapshots in the repository.
    pub async fn list_snapshots(&self) -> Result<Vec<Id>> {
        Ok(self.backend.list(FileType::Snapshot).await?)
    }

    /// Associated data binding a sealed snapshot to this repository.
    fn snapshot_aad(&self) -> Vec<u8> {
        let mut aad = self.config.repo_id.as_bytes().to_vec();
        aad.push(2);
        aad
    }

    /// Whether a blob with the given id is present.
    #[must_use]
    pub fn has_blob(&self, id: &Id) -> bool {
        self.index.contains_key(id)
    }

    /// Associated data binding a sealed blob to this repository and its kind.
    fn blob_aad(&self, kind: BlobKind) -> Vec<u8> {
        let mut aad = Vec::with_capacity(Id::LEN + 1);
        aad.extend_from_slice(self.config.repo_id.as_bytes());
        aad.push(match kind {
            BlobKind::Data => 0,
            BlobKind::Tree => 1,
        });
        aad
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

    /// Borrow the storage backend.
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

/// Rebuild the chunk index by reading every pack's plaintext directory footer.
async fn build_index<B: StorageBackend>(backend: &B) -> Result<HashMap<Id, (Id, BlobEntry)>> {
    let mut index = HashMap::new();
    for pack_id in backend.list(FileType::Pack).await? {
        let bytes = backend.get(FileType::Pack, &pack_id).await?;
        let reader = PackReader::parse(&bytes)?;
        for entry in reader.entries() {
            index.insert(entry.id, (pack_id, *entry));
        }
    }
    Ok(index)
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

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
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
    async fn distinct_repos_have_distinct_ids() {
        let a = Repository::init(MemoryBackend::new(), b"pass", fast())
            .await
            .unwrap();
        let b = Repository::init(MemoryBackend::new(), b"pass", fast())
            .await
            .unwrap();
        assert_ne!(a.id(), b.id());
    }

    #[tokio::test]
    async fn save_then_load_blob_roundtrips() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let id = repo
            .save_blob(BlobKind::Data, b"hello world")
            .await
            .unwrap();
        assert!(repo.has_blob(&id));
        assert_eq!(repo.load_blob(&id).await.unwrap(), b"hello world");
    }

    #[tokio::test]
    async fn identical_content_deduplicates() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let a = repo.save_blob(BlobKind::Data, b"dup").await.unwrap();
        let b = repo.save_blob(BlobKind::Data, b"dup").await.unwrap();
        assert_eq!(a, b);
        assert_eq!(repo.backend().list(FileType::Pack).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn blobs_are_encrypted_at_rest() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let secret = b"TOP-SECRET-PLAINTEXT-MARKER";
        repo.save_blob(BlobKind::Data, secret).await.unwrap();
        for pid in repo.backend().list(FileType::Pack).await.unwrap() {
            let bytes = repo.backend().get(FileType::Pack, &pid).await.unwrap();
            assert!(
                !contains_subslice(&bytes, secret),
                "plaintext leaked into a stored pack"
            );
        }
    }

    #[tokio::test]
    async fn index_rebuilds_on_open_so_blobs_survive() {
        let dir = tempfile::tempdir().unwrap();
        let id = {
            let be = LocalBackend::create(dir.path()).await.unwrap();
            let mut repo = Repository::init(be, b"pw", fast()).await.unwrap();
            repo.save_blob(BlobKind::Data, b"persisted blob")
                .await
                .unwrap()
        };
        let be = LocalBackend::open(dir.path());
        let repo = Repository::open(be, b"pw").await.unwrap();
        assert!(repo.has_blob(&id));
        assert_eq!(repo.load_blob(&id).await.unwrap(), b"persisted blob");
    }

    #[tokio::test]
    async fn load_unknown_blob_is_error() {
        let repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        assert!(matches!(
            repo.load_blob(&Id::from_bytes([5u8; 32])).await,
            Err(RepoError::BlobNotFound(_))
        ));
    }

    fn pseudo_random(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut s = 0xABCD_1234u64;
        for _ in 0..n {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            v.push((s >> 33) as u8);
        }
        v
    }

    #[tokio::test]
    async fn save_file_load_file_roundtrips_small() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let content = repo.save_file(b"hello file").await.unwrap();
        assert_eq!(repo.load_file(&content).await.unwrap(), b"hello file");
    }

    #[tokio::test]
    async fn save_file_load_file_roundtrips_multichunk() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // Larger than the 4 MiB max chunk size, so it must span multiple chunks.
        let data = pseudo_random(5 * 1024 * 1024);
        let content = repo.save_file(&data).await.unwrap();
        assert!(content.len() >= 2, "expected multiple chunks");
        assert_eq!(repo.load_file(&content).await.unwrap(), data);
    }

    #[tokio::test]
    async fn resaving_a_file_dedups_its_chunks() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let data = pseudo_random(2 * 1024 * 1024);
        let ids1 = repo.save_file(&data).await.unwrap();
        let packs = repo.backend().list(FileType::Pack).await.unwrap().len();
        let ids2 = repo.save_file(&data).await.unwrap();
        assert_eq!(ids1, ids2);
        assert_eq!(
            repo.backend().list(FileType::Pack).await.unwrap().len(),
            packs
        );
    }

    #[tokio::test]
    async fn empty_file_has_no_chunks() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let content = repo.save_file(b"").await.unwrap();
        assert!(content.is_empty());
        assert_eq!(repo.load_file(&content).await.unwrap(), b"");
    }

    #[tokio::test]
    async fn save_tree_load_tree_roundtrips_and_dedups() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let tree = Tree {
            version: sluice_core::TREE_VERSION,
            nodes: Vec::new(),
        };
        let id = repo.save_tree(&tree).await.unwrap();
        assert_eq!(repo.load_tree(&id).await.unwrap(), tree);
        assert_eq!(repo.save_tree(&tree).await.unwrap(), id);
    }

    #[tokio::test]
    async fn commit_load_and_list_snapshots() {
        let repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = Snapshot {
            version: sluice_core::SNAPSHOT_VERSION,
            time_ns: 0,
            tree: Id::from_bytes([1u8; 32]),
            paths: vec![b"/data".to_vec()],
            hostname: "host".into(),
            username: "user".into(),
            uid: 0,
            gid: 0,
            tags: Vec::new(),
            parent: None,
            program_version: "0.0.0".into(),
            summary: Default::default(),
        };
        let id = repo.commit_snapshot(&snap).await.unwrap();
        assert_eq!(repo.load_snapshot(&id).await.unwrap(), snap);
        assert_eq!(repo.list_snapshots().await.unwrap(), vec![id]);
        // Re-committing the same snapshot is idempotent.
        assert_eq!(repo.commit_snapshot(&snap).await.unwrap(), id);
    }

    #[tokio::test]
    async fn blobs_are_compressed_at_rest() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let data = vec![0u8; 100_000]; // highly compressible
        let id = repo.save_blob(BlobKind::Data, &data).await.unwrap();

        let mut stored = 0usize;
        for pid in repo.backend().list(FileType::Pack).await.unwrap() {
            stored += repo
                .backend()
                .get(FileType::Pack, &pid)
                .await
                .unwrap()
                .len();
        }
        assert!(
            stored < data.len() / 2,
            "expected compression: stored {stored} bytes for {} of plaintext",
            data.len()
        );
        assert_eq!(repo.load_blob(&id).await.unwrap(), data);
    }

    #[tokio::test]
    async fn blob_roundtrips_over_many_random_inputs() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let mut state = 0x1234_5678u64;
        for _ in 0..200 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let len = (state % 5000) as usize;
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                data.push((state >> 33) as u8);
            }
            let id = repo.save_blob(BlobKind::Data, &data).await.unwrap();
            assert_eq!(repo.load_blob(&id).await.unwrap(), data);
        }
    }
}
