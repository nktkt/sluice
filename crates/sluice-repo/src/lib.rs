//! `sluice-repo` — the repository handle.
//!
//! Ties `sluice-store`, `sluice-crypto`, and `sluice-core` together to create
//! and open an encrypted repository and to read and write content-addressed,
//! deduplicated, encrypted blobs (see `DESIGN.md` §3, §5.2, §5.4).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sluice_chunk::{Chunker, ChunkerParams, Gear};
use sluice_core::{
    BlobKind, CONFIG_VERSION, ChunkerConfig, CipherSuite, Id, REPO_MAGIC, RepoConfig, Snapshot,
    Tree, from_cbor, to_cbor,
};
use sluice_crypto::{
    DEFAULT_LEVEL, KdfParams, Key, KeyError, KeySet, compress, decompress, fill_random, hash,
    keyed_hash, open, random_key, seal, unwrap_master, wrap_master,
};
use sluice_store::{BlobEntry, FileType, PackBuilder, PackReader, StorageBackend, StoreError};
use zeroize::Zeroizing;

/// Well-known id of the single (encrypted) config object.
const CONFIG_ID: Id = Id::from_bytes([0u8; 32]);
/// AEAD associated data for the config object. It cannot be the repo id, which
/// lives *inside* the config and so is unknown until after decryption.
const CONFIG_AAD: &[u8] = b"sluice.v1 config";
/// Default target pack size (16 MiB).
const PACK_TARGET: u64 = 16 * 1024 * 1024;
/// Concurrent chunk reads when reassembling a file in [`Repository::load_file`].
const LOAD_CONCURRENCY: usize = 16;

/// Errors from repository operations.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// A storage backend error.
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
    /// An I/O error reading a source stream (e.g. during streaming backup).
    #[error("io error: {0}")]
    Io(String),
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
    /// A conflicting advisory lock is already held (see [`Repository::acquire_lock`]).
    #[error("repository is locked by another operation")]
    Locked,
    /// Refused to remove the repository's last key (it would become unopenable).
    #[error("cannot remove the last key")]
    LastKey,
    /// No repository was found at the location (no key objects are present).
    #[error("no repository found at this location")]
    NotFound,
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

/// Counts returned by [`Repository::sweep`] (and `engine::prune`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PruneReport {
    /// Fully-dead packs removed.
    pub deleted: usize,
    /// Partially-dead packs repacked (or that would be, under dry-run).
    pub repacked: usize,
    /// Total bytes reclaimed: the full size of each deleted pack plus the size
    /// reduction from repacking each partially-dead pack.
    pub reclaimed_bytes: u64,
}

/// An advisory repository lock (see `DESIGN.md` §5.2). An *exclusive* lock
/// (taken by prune) conflicts with any other lock; a *shared* lock (taken by
/// backup) conflicts only with exclusive locks. Stored unencrypted: it carries
/// no secrets, only coordination metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    /// Whether this lock is exclusive.
    pub exclusive: bool,
    /// The host that acquired the lock (informational).
    pub hostname: String,
    /// When the lock was acquired (ns since the Unix epoch).
    pub time_ns: i64,
}

/// An open repository over a storage backend `B`.
pub struct Repository<B> {
    backend: B,
    keys: KeySet,
    /// The master key, retained (zeroized on drop) so new key objects can be
    /// wrapped under additional passphrases without re-deriving it.
    master: Zeroizing<Key>,
    /// Id of the key object that unlocked this handle (the one `change_passphrase`
    /// rotates out).
    key_id: Id,
    config: RepoConfig,
    /// chunk id -> (pack id, directory entry). Rebuilt from pack footers on open.
    index: HashMap<Id, (Id, BlobEntry)>,
    /// Blobs sealed but not yet flushed to a pack.
    pending: PackBuilder,
    /// chunk id -> directory entry within `pending`.
    pending_index: HashMap<Id, BlobEntry>,
    /// Per-run override for the zstd level used to compress newly stored file
    /// data; `None` ⇒ use `config.compression`. Set by [`set_data_compression`].
    ///
    /// [`set_data_compression`]: Self::set_data_compression
    compression_override: Option<i32>,
    /// Per-run override for the timestamp recorded on a committed snapshot, in
    /// nanoseconds since the Unix epoch; `None` ⇒ the current time. Set by
    /// [`set_snapshot_time`](Self::set_snapshot_time).
    snapshot_time_override: Option<i64>,
}

impl<B: StorageBackend> Repository<B> {
    /// Initialize a new encrypted repository on `backend`, protected by
    /// `passphrase` (stretched with the given Argon2id parameters).
    pub async fn init(backend: B, passphrase: &[u8], kdf: KdfParams) -> Result<Self> {
        Self::init_with_compression(backend, passphrase, kdf, DEFAULT_LEVEL).await
    }

    /// Like [`init`](Self::init) but pinning a zstd compression `level` for the
    /// repository's blobs. The chunk id is the plaintext hash, so the level does
    /// not affect deduplication or interoperability — only stored size and speed.
    pub async fn init_with_compression(
        backend: B,
        passphrase: &[u8],
        kdf: KdfParams,
        compression: i32,
    ) -> Result<Self> {
        let master = Zeroizing::new(random_key());
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
            compression,
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

        // Wrap the master under the passphrase and store the first key object.
        let key_id = put_key_object(&backend, passphrase, kdf, &master).await?;

        Ok(Self {
            backend,
            keys,
            master,
            key_id,
            config,
            index: HashMap::new(),
            pending: PackBuilder::new(),
            pending_index: HashMap::new(),
            compression_override: None,
            snapshot_time_override: None,
        })
    }

    /// Open an existing repository on `backend` using `passphrase`. Every stored
    /// key object is tried, so any of the repository's passphrases unlocks it.
    pub async fn open(backend: B, passphrase: &[u8]) -> Result<Self> {
        let key_ids = backend.list(FileType::Key).await?;
        if key_ids.is_empty() {
            return Err(RepoError::NotFound);
        }
        let mut unlocked: Option<(Id, Zeroizing<Key>)> = None;
        let mut last_err: Option<KeyError> = None;
        for key_id in key_ids {
            let Ok(key_object) =
                from_cbor::<KeyObject>(&backend.get(FileType::Key, &key_id).await?)
            else {
                continue; // unparseable key object; try the next
            };
            let kdf = KdfParams {
                m_cost_kib: key_object.m_cost_kib,
                t_cost: key_object.t_cost,
                p_cost: key_object.p_cost,
            };
            match unwrap_master(passphrase, &key_object.salt, kdf, &key_object.wrapped) {
                Ok(m) => {
                    unlocked = Some((key_id, m));
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let (key_id, master) = unlocked
            .ok_or_else(|| RepoError::Key(last_err.unwrap_or(KeyError::WrongPassphrase)))?;
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
            master,
            key_id,
            config,
            index,
            pending: PackBuilder::new(),
            pending_index: HashMap::new(),
            compression_override: None,
            snapshot_time_override: None,
        })
    }

    /// Store `plaintext` as a blob, returning its content-address id.
    ///
    /// The id is `keyed_hash(id_key, plaintext)`; if that blob is already
    /// present the store is skipped (deduplication). Otherwise the plaintext is
    /// AEAD-sealed under `data_key` and written in a new pack.
    pub async fn save_blob(&mut self, kind: BlobKind, plaintext: &[u8]) -> Result<Id> {
        let id = keyed_hash(&self.keys.id_key, plaintext);
        if self.index.contains_key(&id) || self.pending_index.contains_key(&id) {
            return Ok(id);
        }

        // File data honors a per-run level override; metadata (trees) does not.
        let level = match kind {
            BlobKind::Data => self.compression_override.unwrap_or(self.config.compression),
            BlobKind::Tree => self.config.compression,
        };
        let frame = compress(plaintext, level);
        let sealed = seal(&self.keys.data_key, &self.blob_aad(kind), &frame);
        let entry = self.pending.add(id, kind, &sealed);
        self.pending_index.insert(id, entry);

        if self.pending.body_len() as u64 >= self.config.pack_target {
            self.flush().await?;
        }
        Ok(id)
    }

    /// Flush buffered blobs into a new pack so they become durable. Call this at
    /// the end of a backup, before committing the snapshot that references them;
    /// it is also called automatically when the pending pack reaches the target
    /// size.
    pub async fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let builder = std::mem::take(&mut self.pending);
        self.pending_index.clear();
        let (bytes, directory) = builder.finish()?;
        let pack_id = hash(&bytes);
        self.backend
            .put(FileType::Pack, &pack_id, bytes.into())
            .await?;
        // Persist the pack's blob directory as an index segment (id == pack id)
        // so a later open need not re-scan the pack. Best-effort: the pack footer
        // stays the source of truth and open falls back to scanning if absent.
        if let Ok(index_bytes) = to_cbor(&directory) {
            let _ = self
                .backend
                .put(FileType::Index, &pack_id, index_bytes.into())
                .await;
        }
        for entry in &directory {
            self.index.insert(entry.id, (pack_id, *entry));
        }
        Ok(())
    }

    /// Sweep stored packs against the `live` blob set: delete packs whose blobs
    /// are all unreferenced and, unless `dry_run`, repack packs that are only
    /// partially live (copying the live blobs into a fresh pack and dropping the
    /// old) to reclaim the dead blobs' space. Updates the in-memory index.
    /// Returns the counts of packs deleted and repacked (a dry run reports the
    /// same counts it would act on without touching storage).
    pub async fn sweep(
        &mut self,
        live: &HashSet<Id>,
        dry_run: bool,
        max_unused: u8,
        progress: Option<&(dyn Fn() + Sync)>,
    ) -> Result<PruneReport> {
        let mut report = PruneReport::default();
        for pack_id in self.backend.list(FileType::Pack).await? {
            if let Some(p) = progress {
                p();
            }
            let bytes = self.backend.get(FileType::Pack, &pack_id).await?;
            let reader = PackReader::parse(&bytes)?;
            let entries: Vec<BlobEntry> = reader.entries().to_vec();
            let live_count = entries.iter().filter(|e| live.contains(&e.id)).count();

            if live_count == 0 {
                report.deleted += 1;
                report.reclaimed_bytes += bytes.len() as u64;
                if !dry_run {
                    self.backend.remove(FileType::Pack, &pack_id).await?;
                    let _ = self.backend.remove(FileType::Index, &pack_id).await;
                    for entry in &entries {
                        self.index.remove(&entry.id);
                    }
                }
            } else if live_count < entries.len() {
                // Tolerate up to `max_unused`% dead bytes: skip repacking packs at
                // or below the threshold, leaving their waste in place.
                let total_bytes: u64 = entries.iter().map(|e| u64::from(e.length)).sum();
                let dead_bytes: u64 = entries
                    .iter()
                    .filter(|e| !live.contains(&e.id))
                    .map(|e| u64::from(e.length))
                    .sum();
                let dead_pct = if total_bytes == 0 {
                    0
                } else {
                    dead_bytes * 100 / total_bytes
                };
                // max_unused == 0 means "repack any partially-dead pack"; a
                // positive threshold leaves packs at or below it alone.
                if max_unused > 0 && dead_pct <= u64::from(max_unused) {
                    continue;
                }
                report.repacked += 1;
                // Build the repacked pack (in dry-run too, to measure the savings).
                let mut builder = PackBuilder::new();
                for entry in &entries {
                    if live.contains(&entry.id) {
                        let sealed = reader.blob(&entry.id).expect("entry in its own pack");
                        builder.add(entry.id, entry.kind, sealed);
                    }
                }
                let (new_bytes, directory) = builder.finish()?;
                report.reclaimed_bytes += (bytes.len() - new_bytes.len()) as u64;
                if !dry_run {
                    // Swap the old pack for the repacked one and refresh the index.
                    let new_pack_id = hash(&new_bytes);
                    self.backend
                        .put(FileType::Pack, &new_pack_id, new_bytes.into())
                        .await?;
                    if let Ok(index_bytes) = to_cbor(&directory) {
                        let _ = self
                            .backend
                            .put(FileType::Index, &new_pack_id, index_bytes.into())
                            .await;
                    }
                    self.backend.remove(FileType::Pack, &pack_id).await?;
                    let _ = self.backend.remove(FileType::Index, &pack_id).await;
                    for entry in &entries {
                        self.index.remove(&entry.id);
                    }
                    for entry in &directory {
                        self.index.insert(entry.id, (new_pack_id, *entry));
                    }
                }
            }
        }
        Ok(report)
    }

    /// Load and decrypt the blob with the given id.
    pub async fn load_blob(&self, id: &Id) -> Result<Vec<u8>> {
        // The blob may still be buffered in the pending pack (not yet flushed).
        if let Some(entry) = self.pending_index.get(id) {
            let sealed = self.pending.blob_at(entry);
            let frame = open(&self.keys.data_key, &self.blob_aad(entry.kind), sealed)
                .map_err(|_| RepoError::Blob)?;
            return decompress(&frame).map_err(|_| RepoError::Blob);
        }
        let (pack_id, entry) = self
            .index
            .get(id)
            .copied()
            .ok_or(RepoError::BlobNotFound(*id))?;
        // Read only this blob's sealed bytes (its slice of the pack body, which
        // begins at offset 0), not the whole pack.
        let sealed = self
            .backend
            .get_range(
                FileType::Pack,
                &pack_id,
                u64::from(entry.offset),
                u64::from(entry.length),
            )
            .await?;
        let frame = open(&self.keys.data_key, &self.blob_aad(entry.kind), &sealed)
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

    /// Stream `reader` through the chunker, storing each content-defined chunk as
    /// a `Data` blob, and return the ordered chunk ids plus the total byte count.
    ///
    /// Peak memory is bounded by the chunker's maximum chunk size (plus a read
    /// window), not the file size, so arbitrarily large files back up without
    /// being loaded whole. Because the chunker only inspects the first `max`
    /// bytes when finding a boundary, buffering `max` bytes before each cut
    /// yields exactly the same chunks — and therefore the same ids — as
    /// [`save_file`] on the equivalent buffer.
    pub async fn save_file_reader<R: std::io::Read>(
        &mut self,
        mut reader: R,
    ) -> Result<(Vec<Id>, u64)> {
        use std::io::ErrorKind;
        const READ_WINDOW: usize = 1 << 20; // 1 MiB
        // Gather roughly this many plaintext bytes of chunks, then compress and
        // encrypt the whole batch in parallel. Peak memory stays bounded at
        // ~2x this regardless of file size, while there is enough work per batch
        // to keep the cores busy.
        const BATCH_BYTES: usize = 8 << 20; // 8 MiB

        let chunker = self.chunker();
        let max = chunker.max();
        let mut ids = Vec::new();
        let mut total: u64 = 0;
        let mut buf: Vec<u8> = Vec::with_capacity(max + READ_WINDOW);
        let mut eof = false;
        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut batch_bytes = 0usize;

        loop {
            // Fill the buffer to at least `max` bytes (so a cut sees a full
            // window) or until the reader is exhausted.
            while !eof && buf.len() < max {
                let start = buf.len();
                buf.resize(start + READ_WINDOW, 0);
                match reader.read(&mut buf[start..]) {
                    Ok(0) => {
                        buf.truncate(start);
                        eof = true;
                    }
                    Ok(n) => buf.truncate(start + n),
                    Err(e) if e.kind() == ErrorKind::Interrupted => buf.truncate(start),
                    Err(e) => return Err(RepoError::Io(e.to_string())),
                }
            }

            if buf.is_empty() {
                break;
            }

            if eof {
                // Final window: emit every remaining chunk, including the short
                // trailing one.
                let mut off = 0;
                while off < buf.len() {
                    let n = chunker.cut(&buf[off..]);
                    total += n as u64;
                    batch_bytes += n;
                    batch.push(buf[off..off + n].to_vec());
                    off += n;
                    if batch_bytes >= BATCH_BYTES {
                        self.save_chunk_batch(std::mem::take(&mut batch), &mut ids)
                            .await?;
                        batch_bytes = 0;
                    }
                }
                break;
            }

            // `buf.len() >= max`: `cut` returns a real boundary in `[min, max]`.
            let n = chunker.cut(&buf);
            total += n as u64;
            batch_bytes += n;
            batch.push(buf[..n].to_vec());
            buf.drain(..n);
            if batch_bytes >= BATCH_BYTES {
                self.save_chunk_batch(std::mem::take(&mut batch), &mut ids)
                    .await?;
                batch_bytes = 0;
            }
        }
        // Seal and store the final partial batch.
        if !batch.is_empty() {
            self.save_chunk_batch(batch, &mut ids).await?;
        }
        Ok((ids, total))
    }

    /// Compress, encrypt, deduplicate and append a batch of data chunks in order,
    /// pushing each chunk's id onto `ids`. The per-chunk compress+encrypt runs in
    /// parallel (rayon, the CPU bottleneck of a backup); deduplication and pack
    /// assembly stay serial, so the stored result — ids, dedup, pack boundaries —
    /// is identical to processing the chunks one at a time.
    async fn save_chunk_batch(&mut self, batch: Vec<Vec<u8>>, ids: &mut Vec<Id>) -> Result<()> {
        use rayon::prelude::*;
        let id_key = self.keys.id_key;
        let data_key = self.keys.data_key;
        let compression = self.compression_override.unwrap_or(self.config.compression);
        let aad = self.blob_aad(BlobKind::Data);
        // Parallel CPU work: each chunk's id, plus its compressed-and-sealed bytes.
        let sealed: Vec<(Id, Vec<u8>)> = batch
            .into_par_iter()
            .map(|plaintext| {
                let id = keyed_hash(&id_key, &plaintext);
                let frame = compress(&plaintext, compression);
                (id, seal(&data_key, &aad, &frame))
            })
            .collect();
        // Serial: deduplicate and append, flushing whenever the pack fills.
        for (id, blob) in sealed {
            ids.push(id);
            if self.index.contains_key(&id) || self.pending_index.contains_key(&id) {
                continue;
            }
            let entry = self.pending.add(id, BlobKind::Data, &blob);
            self.pending_index.insert(id, entry);
            if self.pending.body_len() as u64 >= self.config.pack_target {
                self.flush().await?;
            }
        }
        Ok(())
    }

    /// Reassemble a file from its ordered chunk ids.
    pub async fn load_file(&self, content: &[Id]) -> Result<Vec<u8>> {
        use futures::stream::{StreamExt, TryStreamExt};
        // Read the chunks concurrently while preserving order (`buffered`), then
        // concatenate — much faster for multi-chunk files on a high-latency
        // (object-store) backend, where the reads are round-trip bound.
        let chunks: Vec<Vec<u8>> =
            futures::stream::iter(content.iter().map(|id| self.load_blob(id)))
                .buffered(LOAD_CONCURRENCY)
                .try_collect()
                .await?;
        let mut out = Vec::with_capacity(chunks.iter().map(Vec::len).sum());
        for chunk in chunks {
            out.extend_from_slice(&chunk);
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
        self.index.contains_key(id) || self.pending_index.contains_key(id)
    }

    /// Stored (compressed + encrypted) length of a blob as it sits in its pack,
    /// or `None` if the blob is not present. This is the blob's true on-disk
    /// footprint, used to size a snapshot's deduplicated raw data.
    #[must_use]
    pub fn blob_stored_len(&self, id: &Id) -> Option<u64> {
        self.index
            .get(id)
            .map(|(_, e)| u64::from(e.length))
            .or_else(|| self.pending_index.get(id).map(|e| u64::from(e.length)))
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

    /// Override the zstd level used to compress newly stored **file data** —
    /// whether written by a backup or a copy into this handle; `None` restores the
    /// repository default (`config().compression`). Because a chunk's id is the
    /// hash of its *plaintext*, the level never affects deduplication or the data
    /// read back — only the stored size of chunks written from here on. Metadata
    /// blobs (trees, snapshots, config) always use the repository default.
    pub fn set_data_compression(&mut self, level: Option<i32>) {
        self.compression_override = level;
    }

    /// Override the timestamp recorded on the next committed snapshot (nanoseconds
    /// since the Unix epoch), or `None` to use the current time. Lets a snapshot
    /// be dated to its logical time — e.g. when importing history from another
    /// tool, so retention rules bucket it correctly.
    pub fn set_snapshot_time(&mut self, time_ns: Option<i64>) {
        self.snapshot_time_override = time_ns;
    }

    /// The overriding snapshot timestamp set by [`set_snapshot_time`], if any. The
    /// engine consults this when stamping a snapshot, falling back to wall-clock.
    ///
    /// [`set_snapshot_time`]: Self::set_snapshot_time
    #[must_use]
    pub fn snapshot_time(&self) -> Option<i64> {
        self.snapshot_time_override
    }

    /// Id of the key object whose passphrase unlocked this handle. This is the
    /// "current" key — the one [`change_passphrase`](Self::change_passphrase)
    /// rotates out, and the one a caller should keep when pruning other keys.
    #[must_use]
    pub fn active_key_id(&self) -> Id {
        self.key_id
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

    /// List the advisory locks currently held on the repository.
    pub async fn list_locks(&self) -> Result<Vec<(Id, LockInfo)>> {
        let mut locks = Vec::new();
        for id in self.backend.list(FileType::Lock).await? {
            let bytes = self.backend.get(FileType::Lock, &id).await?;
            let info: LockInfo = from_cbor(&bytes).map_err(codec)?;
            locks.push((id, info));
        }
        Ok(locks)
    }

    /// Acquire an advisory lock, returning its id. An exclusive lock conflicts
    /// with any existing lock; a shared lock conflicts only with exclusive ones.
    /// Fails with [`RepoError::Locked`] on conflict. A write-then-recheck guards
    /// against two acquirers racing. Release with [`Repository::release_lock`].
    pub async fn acquire_lock(&self, exclusive: bool) -> Result<Id> {
        let conflicts = |locks: &[(Id, LockInfo)], own: Option<&Id>| {
            locks
                .iter()
                .any(|(id, info)| Some(id) != own && (exclusive || info.exclusive))
        };
        if conflicts(&self.list_locks().await?, None) {
            return Err(RepoError::Locked);
        }
        let mut raw = [0u8; Id::LEN];
        fill_random(&mut raw);
        let id = Id::from_bytes(raw);
        let info = LockInfo {
            exclusive,
            hostname: hostname(),
            time_ns: now_ns(),
        };
        let bytes = to_cbor(&info).map_err(codec)?;
        self.backend.put(FileType::Lock, &id, bytes.into()).await?;
        // A conflicting lock may have been written concurrently with ours; if so,
        // drop ours and report the conflict so neither side wrongly proceeds.
        if conflicts(&self.list_locks().await?, Some(&id)) {
            self.backend.remove(FileType::Lock, &id).await.ok();
            return Err(RepoError::Locked);
        }
        Ok(id)
    }

    /// Release a lock previously returned by [`Repository::acquire_lock`]. Absent
    /// locks are ignored, so this is safe to call during cleanup.
    pub async fn release_lock(&self, id: &Id) -> Result<()> {
        match self.backend.remove(FileType::Lock, id).await {
            Ok(()) | Err(StoreError::NotFound { .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Rebuild every index segment by rescanning packs: rewrite each pack's
    /// segment from its footer, drop orphan segments (whose pack is gone), and
    /// refresh the in-memory index. Repairs missing, corrupt, or stale segments
    /// (see `DESIGN.md` §5.2). Returns the number of packs indexed.
    pub async fn rebuild_index(&mut self) -> Result<usize> {
        let packs: HashSet<Id> = self
            .backend
            .list(FileType::Pack)
            .await?
            .into_iter()
            .collect();

        // Drop index segments whose pack no longer exists.
        for idx_id in self.backend.list(FileType::Index).await? {
            if !packs.contains(&idx_id) {
                let _ = self.backend.remove(FileType::Index, &idx_id).await;
            }
        }

        // Rewrite each pack's segment from its plaintext footer.
        for pack_id in &packs {
            let bytes = self.backend.get(FileType::Pack, pack_id).await?;
            let reader = PackReader::parse(&bytes)?;
            let directory: Vec<BlobEntry> = reader.entries().to_vec();
            let _ = self.backend.remove(FileType::Index, pack_id).await;
            let index_bytes = to_cbor(&directory).map_err(codec)?;
            self.backend
                .put(FileType::Index, pack_id, index_bytes.into())
                .await?;
        }

        // Refresh the in-memory index from the now-consistent segments.
        let index = build_index(&self.backend).await?;
        self.index = index;
        Ok(packs.len())
    }

    /// List the ids of the repository's key objects (each unlocks it with one
    /// passphrase).
    pub async fn list_keys(&self) -> Result<Vec<Id>> {
        Ok(self.backend.list(FileType::Key).await?)
    }

    /// Add a key object that unlocks the repository with `passphrase` (stretched
    /// with `kdf`), returning its id. Existing passphrases keep working.
    pub async fn add_key(&self, passphrase: &[u8], kdf: KdfParams) -> Result<Id> {
        put_key_object(&self.backend, passphrase, kdf, &self.master).await
    }

    /// Remove the key object `id`, refusing ([`RepoError::LastKey`]) if it is the
    /// repository's only key, which would leave the repository unopenable.
    pub async fn remove_key(&self, id: &Id) -> Result<()> {
        if self.list_keys().await?.len() <= 1 {
            return Err(RepoError::LastKey);
        }
        self.backend.remove(FileType::Key, id).await?;
        Ok(())
    }

    /// Rotate the passphrase: add a key for `passphrase` (stretched with `kdf`)
    /// and remove the key that unlocked this handle. Returns the new key's id.
    pub async fn change_passphrase(&self, passphrase: &[u8], kdf: KdfParams) -> Result<Id> {
        let new_id = self.add_key(passphrase, kdf).await?;
        self.remove_key(&self.key_id).await?;
        Ok(new_id)
    }
}

/// Build the chunk index, preferring persisted per-pack index segments and
/// falling back to scanning any pack not covered by a valid, current segment.
/// Packs are the source of truth, so missing or stale segments are self-healing.
async fn build_index<B: StorageBackend>(backend: &B) -> Result<HashMap<Id, (Id, BlobEntry)>> {
    let packs: HashSet<Id> = backend.list(FileType::Pack).await?.into_iter().collect();
    let mut index = HashMap::new();
    let mut covered: HashSet<Id> = HashSet::new();

    // Fast path: read each index segment whose pack still exists (id == pack id).
    for idx_id in backend.list(FileType::Index).await? {
        if !packs.contains(&idx_id) {
            continue; // segment for a pack that is gone
        }
        let bytes = backend.get(FileType::Index, &idx_id).await?;
        let Ok(entries) = from_cbor::<Vec<BlobEntry>>(&bytes) else {
            continue; // unreadable segment: scan the pack instead
        };
        for entry in &entries {
            index.insert(entry.id, (idx_id, *entry));
        }
        covered.insert(idx_id);
    }

    // Fallback: scan packs with no usable index segment (legacy or failed write).
    for pack_id in &packs {
        if covered.contains(pack_id) {
            continue;
        }
        let bytes = backend.get(FileType::Pack, pack_id).await?;
        let reader = PackReader::parse(&bytes)?;
        for entry in reader.entries() {
            index.insert(entry.id, (*pack_id, *entry));
        }
    }
    Ok(index)
}

/// Wrap `master` under `passphrase` and store the resulting key object at a
/// fresh random id, returning that id. Used by `init` and `add_key`.
async fn put_key_object<B: StorageBackend>(
    backend: &B,
    passphrase: &[u8],
    kdf: KdfParams,
    master: &Key,
) -> Result<Id> {
    let mut salt = [0u8; 16];
    fill_random(&mut salt);
    let key_object = KeyObject {
        salt: salt.to_vec(),
        m_cost_kib: kdf.m_cost_kib,
        t_cost: kdf.t_cost,
        p_cost: kdf.p_cost,
        wrapped: wrap_master(passphrase, &salt, kdf, master)?,
    };
    let mut raw = [0u8; Id::LEN];
    fill_random(&mut raw);
    let id = Id::from_bytes(raw);
    backend
        .put(
            FileType::Key,
            &id,
            to_cbor(&key_object).map_err(codec)?.into(),
        )
        .await?;
    Ok(id)
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

/// Best-effort host name for tagging a lock (informational only).
fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
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
        repo.flush().await.unwrap();
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
        repo.flush().await.unwrap();
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
            let id = repo
                .save_blob(BlobKind::Data, b"persisted blob")
                .await
                .unwrap();
            repo.flush().await.unwrap();
            id
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
    async fn init_with_compression_pins_the_level_and_still_roundtrips() {
        let mut repo = Repository::init_with_compression(MemoryBackend::new(), b"pw", fast(), 19)
            .await
            .unwrap();
        assert_eq!(repo.config().compression, 19);
        // The level changes only the stored size, not correctness: data still
        // round-trips, and the default repo reads it fine (frames self-describe).
        let data = vec![7u8; 50_000];
        let content = repo.save_file(&data).await.unwrap();
        assert_eq!(repo.load_file(&content).await.unwrap(), data);
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
    async fn save_file_reader_matches_save_file() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // Spans several chunks with a short tail, exercising the streaming refill
        // and the final flush.
        let data = pseudo_random(5 * 1024 * 1024 + 12_345);
        let whole = repo.save_file(&data).await.unwrap();
        let (streamed, total) = repo
            .save_file_reader(std::io::Cursor::new(&data))
            .await
            .unwrap();
        // Identical boundaries => identical ids => streamed backups dedup against
        // whole-buffer ones.
        assert_eq!(streamed, whole, "streaming must chunk identically");
        assert_eq!(total, data.len() as u64);
        assert!(streamed.len() >= 2, "expected multiple chunks");
        assert_eq!(repo.load_file(&streamed).await.unwrap(), data);

        // Edge cases: a sub-min file and an empty stream.
        let small = b"tiny".to_vec();
        assert_eq!(
            repo.save_file_reader(std::io::Cursor::new(&small))
                .await
                .unwrap()
                .0,
            repo.save_file(&small).await.unwrap()
        );
        let (empty_ids, empty_total) = repo
            .save_file_reader(std::io::Cursor::new(Vec::new()))
            .await
            .unwrap();
        assert!(empty_ids.is_empty());
        assert_eq!(empty_total, 0);
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
        repo.flush().await.unwrap();

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

    #[tokio::test]
    async fn load_file_reassembles_multichunk_files_in_order() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // ~5 MiB of incompressible data so the chunker emits several chunks.
        let mut data = vec![0u8; 5 * 1024 * 1024];
        let mut state = 0x9E37_79B9u32;
        for b in data.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (state >> 24) as u8;
        }
        let ids = repo.save_file(&data).await.unwrap();
        assert!(ids.len() > 1, "expected the file to span multiple chunks");
        repo.flush().await.unwrap();

        // The concurrent reads must reassemble the bytes in their original order.
        assert_eq!(repo.load_file(&ids).await.unwrap(), data);
    }

    #[tokio::test]
    async fn flush_persists_pack_index_and_open_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![7u8; 5000];
        let blob_id = {
            let mut repo = Repository::init(
                LocalBackend::create(dir.path()).await.unwrap(),
                b"pw",
                fast(),
            )
            .await
            .unwrap();
            let id = repo.save_blob(BlobKind::Data, &data).await.unwrap();
            repo.flush().await.unwrap();
            // An index segment was written, one per pack, keyed by pack id.
            let packs = repo.backend().list(FileType::Pack).await.unwrap();
            let indexes = repo.backend().list(FileType::Index).await.unwrap();
            assert_eq!(packs.len(), 1);
            assert_eq!(indexes, packs);
            id
        };

        // Reopen: the index is built from the persisted segment and serves blobs.
        let repo = Repository::open(LocalBackend::open(dir.path()), b"pw")
            .await
            .unwrap();
        assert_eq!(repo.load_blob(&blob_id).await.unwrap(), data);

        // Delete every index segment; a reopen must fall back to scanning packs.
        for id in repo.backend().list(FileType::Index).await.unwrap() {
            repo.backend().remove(FileType::Index, &id).await.unwrap();
        }
        let rescanned = Repository::open(LocalBackend::open(dir.path()), b"pw")
            .await
            .unwrap();
        assert_eq!(rescanned.load_blob(&blob_id).await.unwrap(), data);
    }

    #[tokio::test]
    async fn sweep_rewrites_index_segments_on_repack() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let keep = repo
            .save_blob(BlobKind::Data, &vec![1u8; 4000])
            .await
            .unwrap();
        let drop = repo
            .save_blob(BlobKind::Data, &vec![2u8; 4000])
            .await
            .unwrap();
        repo.flush().await.unwrap();

        // Only `keep` is live, so the shared pack is repacked into a fresh one.
        let report = repo
            .sweep(&HashSet::from([keep]), false, 0, None)
            .await
            .unwrap();
        assert_eq!(report.repacked, 1);

        // The old pack's index segment is gone and the new pack's is present.
        let packs = repo.backend().list(FileType::Pack).await.unwrap();
        let indexes = repo.backend().list(FileType::Index).await.unwrap();
        assert_eq!(packs.len(), 1);
        assert_eq!(indexes, packs);
        assert_eq!(repo.load_blob(&keep).await.unwrap(), vec![1u8; 4000]);
        assert!(repo.load_blob(&drop).await.is_err());
    }

    #[tokio::test]
    async fn rebuild_index_repairs_damaged_segments() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let id1 = repo
            .save_blob(BlobKind::Data, &vec![1u8; 3000])
            .await
            .unwrap();
        repo.flush().await.unwrap();
        let id2 = repo
            .save_blob(BlobKind::Data, &vec![2u8; 3000])
            .await
            .unwrap();
        repo.flush().await.unwrap();
        let packs = repo.backend().list(FileType::Pack).await.unwrap();
        assert_eq!(packs.len(), 2);

        // Damage the index: delete one segment, corrupt another, add an orphan.
        repo.backend()
            .remove(FileType::Index, &packs[0])
            .await
            .unwrap();
        repo.backend()
            .remove(FileType::Index, &packs[1])
            .await
            .unwrap();
        repo.backend()
            .put(FileType::Index, &packs[1], b"garbage".to_vec().into())
            .await
            .unwrap();
        let orphan = Id::from_bytes([0xAB; Id::LEN]);
        repo.backend()
            .put(FileType::Index, &orphan, b"orphan".to_vec().into())
            .await
            .unwrap();

        let n = repo.rebuild_index().await.unwrap();
        assert_eq!(n, 2);

        // Segments now correspond 1:1 with packs and the orphan is gone.
        let mut idx = repo.backend().list(FileType::Index).await.unwrap();
        let mut pk = repo.backend().list(FileType::Pack).await.unwrap();
        idx.sort();
        pk.sort();
        assert_eq!(idx, pk);
        // The refreshed in-memory index still serves both blobs.
        assert_eq!(repo.load_blob(&id1).await.unwrap(), vec![1u8; 3000]);
        assert_eq!(repo.load_blob(&id2).await.unwrap(), vec![2u8; 3000]);
    }

    #[tokio::test]
    async fn multiple_keys_each_unlock_the_repository() {
        use std::sync::Arc;

        let backend = Arc::new(MemoryBackend::new());
        let added = {
            let repo = Repository::init(backend.clone(), b"first", fast())
                .await
                .unwrap();
            repo.add_key(b"second", fast()).await.unwrap()
        };

        // Either passphrase opens the repository.
        assert!(Repository::open(backend.clone(), b"first").await.is_ok());
        assert!(Repository::open(backend.clone(), b"second").await.is_ok());
        // A wrong passphrase still fails with a key error.
        assert!(matches!(
            Repository::open(backend.clone(), b"third").await,
            Err(RepoError::Key(_))
        ));

        let repo = Repository::open(backend.clone(), b"first").await.unwrap();
        let keys = repo.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&added));
    }

    #[tokio::test]
    async fn active_key_id_tracks_the_unlocking_passphrase() {
        use std::sync::Arc;

        let backend = Arc::new(MemoryBackend::new());
        let second = {
            let repo = Repository::init(backend.clone(), b"first", fast())
                .await
                .unwrap();
            // The init handle's active key is its sole (first) key.
            assert_eq!(repo.list_keys().await.unwrap(), vec![repo.active_key_id()]);
            repo.add_key(b"second", fast()).await.unwrap()
        };

        // Opening with each passphrase reports that passphrase's key as active.
        let by_second = Repository::open(backend.clone(), b"second").await.unwrap();
        assert_eq!(by_second.active_key_id(), second);
        let by_first = Repository::open(backend.clone(), b"first").await.unwrap();
        assert_ne!(
            by_first.active_key_id(),
            second,
            "the first passphrase is not the second key"
        );
        assert!(
            by_first
                .list_keys()
                .await
                .unwrap()
                .contains(&by_first.active_key_id())
        );
    }

    #[tokio::test]
    async fn change_passphrase_rotates_the_unlocking_key() {
        use std::sync::Arc;

        let backend = Arc::new(MemoryBackend::new());
        {
            let repo = Repository::init(backend.clone(), b"first", fast())
                .await
                .unwrap();
            repo.change_passphrase(b"rotated", fast()).await.unwrap();
        }
        // The new passphrase opens it; the old one no longer does.
        assert!(Repository::open(backend.clone(), b"rotated").await.is_ok());
        assert!(matches!(
            Repository::open(backend.clone(), b"first").await,
            Err(RepoError::Key(_))
        ));
        let repo = Repository::open(backend.clone(), b"rotated").await.unwrap();
        assert_eq!(repo.list_keys().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn remove_key_refuses_the_last_one() {
        use std::sync::Arc;

        let backend = Arc::new(MemoryBackend::new());
        let repo = Repository::init(backend.clone(), b"only", fast())
            .await
            .unwrap();
        let only = repo.list_keys().await.unwrap()[0];
        assert!(matches!(
            repo.remove_key(&only).await,
            Err(RepoError::LastKey)
        ));

        // With a second key present, the first can be removed.
        let second = repo.add_key(b"second", fast()).await.unwrap();
        repo.remove_key(&only).await.unwrap();
        assert_eq!(repo.list_keys().await.unwrap(), vec![second]);
        // The removed passphrase no longer opens the repository.
        assert!(matches!(
            Repository::open(backend.clone(), b"only").await,
            Err(RepoError::Key(_))
        ));
    }

    #[tokio::test]
    async fn locks_are_advisory_shared_and_exclusive() {
        let repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // Shared locks coexist; an exclusive lock is refused while they are held.
        let a = repo.acquire_lock(false).await.unwrap();
        let b = repo.acquire_lock(false).await.unwrap();
        assert_eq!(repo.list_locks().await.unwrap().len(), 2);
        assert!(matches!(
            repo.acquire_lock(true).await,
            Err(RepoError::Locked)
        ));

        repo.release_lock(&a).await.unwrap();
        repo.release_lock(&b).await.unwrap();
        // With none held, an exclusive lock blocks every other acquirer.
        let x = repo.acquire_lock(true).await.unwrap();
        assert!(matches!(
            repo.acquire_lock(false).await,
            Err(RepoError::Locked)
        ));
        assert!(matches!(
            repo.acquire_lock(true).await,
            Err(RepoError::Locked)
        ));

        repo.release_lock(&x).await.unwrap();
        assert!(repo.acquire_lock(true).await.is_ok());
        // Releasing an absent lock is a no-op.
        repo.release_lock(&Id::from_bytes([9u8; Id::LEN]))
            .await
            .unwrap();
    }
}
