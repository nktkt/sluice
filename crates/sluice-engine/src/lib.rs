//! `sluice-engine` — backup and restore orchestration (see `DESIGN.md` §6, §8).
//!
//! It walks a directory tree, storing each regular file as deduplicated chunks
//! and each directory as a `Tree`, then commits a snapshot; restore rebuilds the
//! tree and replays metadata. Files, directories, symlinks, and special files
//! (FIFOs, device nodes, hardlinks) are all handled. An optional on-disk
//! [`StatCache`] accelerates re-backups. The walk uses blocking `std::fs`;
//! offloading to a thread pool is a later refinement.

mod statcache;

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;

use globset::{Glob, GlobSet, GlobSetBuilder};
use sluice_core::{
    BlobKind, EntryKind, Id, Node, SNAPSHOT_VERSION, Snapshot, SnapshotStats, TREE_VERSION, Tree,
};
use sluice_repo::{PruneReport, RepoError, Repository};
use sluice_store::{FileType, StorageBackend};

pub use statcache::{CacheEntry, StatCache};

/// Errors from engine operations.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// An underlying repository error.
    #[error("repository error: {0}")]
    Repo(#[from] RepoError),
    /// A filesystem error, annotated with the offending path.
    #[error("io error at {path}: {source}")]
    Io {
        /// The path being operated on.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// An invalid exclude glob pattern.
    #[error("invalid exclude pattern: {0}")]
    Pattern(String),
    /// A requested path was not found in the snapshot.
    #[error("path not found in snapshot: {0}")]
    NotInSnapshot(String),
    /// The backup source is not an existing directory.
    #[error("backup source is not a file or directory: {0}")]
    NotADirectory(String),
    /// Two backup sources share the same final path component.
    #[error("duplicate source name: {0}")]
    DuplicateSource(String),
    /// A restored file's contents did not match the snapshot (`restore --verify`).
    #[error("verification failed: restored {0} does not match the snapshot")]
    VerifyFailed(String),
}

/// Convenience alias for fallible engine operations.
pub type Result<T> = std::result::Result<T, EngineError>;

fn io_err(path: &Path, source: std::io::Error) -> EngineError {
    EngineError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Back up the directory `source` into `repo`, returning the new snapshot id.
///
/// Incremental: the most recent snapshot is used as the parent, and files whose
/// size and mtime are unchanged reuse their stored chunks without being re-read.
pub async fn backup<B: StorageBackend>(repo: &mut Repository<B>, source: &Path) -> Result<Id> {
    backup_excluding(repo, source, &[], &[]).await
}

/// Back up `source`, skipping entries whose name matches one of `exclude_globs`
/// (a skipped directory is pruned along with its contents).
pub async fn backup_excluding<B: StorageBackend>(
    repo: &mut Repository<B>,
    source: &Path,
    exclude_globs: &[String],
    tags: &[String],
) -> Result<Id> {
    let outcome = backup_sources(
        repo,
        std::slice::from_ref(&source.to_path_buf()),
        exclude_globs,
        tags,
        false,
    )
    .await?;
    Ok(outcome
        .snapshot
        .expect("a non-dry-run backup commits a snapshot"))
}

/// The result of a backup: the committed snapshot id (absent for a dry run) and
/// the new/changed/unmodified summary.
#[derive(Debug, Clone, Copy)]
pub struct BackupOutcome {
    /// The committed snapshot id, or `None` under `dry_run`.
    pub snapshot: Option<Id>,
    /// What the backup did (or, under `dry_run`, would do).
    pub summary: SnapshotStats,
}

/// How a regular file compared to the parent snapshot, reported via a
/// [`ProgressFn`] as it is backed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// Not present in the parent snapshot.
    New,
    /// Present but with changed size or mtime, so its content was re-read.
    Changed,
    /// Unchanged since the parent; its stored chunks were reused without reading.
    Unmodified,
}

/// A callback invoked once per regular file as it is processed, with the file's
/// source path — used for `--verbose`/progress output. See
/// [`backup_sources_with_progress`].
pub type ProgressFn<'a> = &'a dyn Fn(&Path, FileStatus);

/// Filters applied to a backup walk. Construct with `..Default::default()` and
/// set only the fields you need; an all-default value backs up everything.
#[derive(Clone, Default)]
pub struct BackupOptions {
    /// Skip entries whose name matches one of these globs.
    pub exclude_globs: Vec<String>,
    /// Skip a regular file discovered during a directory walk that is larger than
    /// this many bytes (explicitly named single-file sources are always kept).
    pub max_file_size: Option<u64>,
    /// Do not descend into a subdirectory on a different filesystem than its
    /// source root (e.g. a mount point).
    pub one_file_system: bool,
    /// Skip a subdirectory that contains any of these marker filenames (e.g.
    /// `.nobackup`); the directory and everything under it is excluded.
    pub exclude_if_present: Vec<String>,
    /// Skip a subdirectory holding a `CACHEDIR.TAG` that carries the standard
    /// cache signature (the convention used by build tools and browsers).
    pub exclude_caches: bool,
    /// Path to an on-disk [`StatCache`]. When set, an unchanged file is reused
    /// from its cached chunk ids without re-reading it or loading the previous
    /// snapshot's trees (see `DESIGN.md` §5.2). Absent ⇒ reuse comes from the
    /// parent snapshot's trees, as before.
    pub cache_path: Option<PathBuf>,
    /// Preview only — walk and count, but write nothing; the snapshot is `None`.
    pub dry_run: bool,
}

/// Back up one or more `sources` into a single snapshot, skipping entries whose
/// name matches one of `exclude_globs`. A single source becomes the snapshot
/// root directly (backward-compatible); multiple sources are placed under a
/// synthetic root, one directory entry per source named by its final path
/// component — duplicate names are rejected. With `dry_run`, nothing is written
/// and the returned `snapshot` is `None`.
pub async fn backup_sources<B: StorageBackend>(
    repo: &mut Repository<B>,
    sources: &[PathBuf],
    exclude_globs: &[String],
    tags: &[String],
    dry_run: bool,
) -> Result<BackupOutcome> {
    backup_sources_with_progress(
        repo,
        sources,
        exclude_globs,
        tags,
        dry_run,
        None,
        false,
        None,
    )
    .await
}

/// Like [`backup_sources`], but `progress` (if any) is invoked once per regular
/// file as it is processed (for `--verbose`/progress output); a regular file
/// discovered during a directory walk larger than `max_file_size` is skipped
/// (explicitly named single-file sources are always backed up); and with
/// `one_file_system`, the walk does not descend into subdirectories on a
/// different filesystem than their source root.
///
/// A thin wrapper over [`backup_sources_with_options`]; new walk filters live on
/// [`BackupOptions`] rather than as ever-more positional parameters here.
pub async fn backup_sources_with_progress<B: StorageBackend>(
    repo: &mut Repository<B>,
    sources: &[PathBuf],
    exclude_globs: &[String],
    tags: &[String],
    dry_run: bool,
    max_file_size: Option<u64>,
    one_file_system: bool,
    progress: Option<ProgressFn<'_>>,
) -> Result<BackupOutcome> {
    let options = BackupOptions {
        exclude_globs: exclude_globs.to_vec(),
        max_file_size,
        one_file_system,
        dry_run,
        ..Default::default()
    };
    backup_sources_with_options(repo, sources, tags, &options, progress).await
}

/// Back up `sources` into one snapshot under the filters in `options`, invoking
/// `progress` (if any) once per regular file. This is the full entry point; the
/// other `backup_sources*` functions are conveniences over it.
pub async fn backup_sources_with_options<B: StorageBackend>(
    repo: &mut Repository<B>,
    sources: &[PathBuf],
    tags: &[String],
    options: &BackupOptions,
    progress: Option<ProgressFn<'_>>,
) -> Result<BackupOutcome> {
    if sources.is_empty() {
        return Err(EngineError::NotADirectory("(no source given)".to_string()));
    }
    for source in sources {
        if !source.is_dir() && !source.is_file() {
            return Err(EngineError::NotADirectory(source.display().to_string()));
        }
    }
    // A real backup holds a shared lock (it blocks a concurrent prune from
    // deleting data this snapshot references); a dry run only reads, so takes none.
    let lock = if options.dry_run {
        None
    } else {
        Some(repo.acquire_lock(false).await?)
    };
    let result = backup_sources_inner(repo, sources, tags, options, progress).await;
    if let Some(lock) = lock {
        let _ = repo.release_lock(&lock).await;
    }
    result
}

/// The body of [`backup_sources_with_options`], run while holding the shared lock
/// (if any).
async fn backup_sources_inner<B: StorageBackend>(
    repo: &mut Repository<B>,
    sources: &[PathBuf],
    tags: &[String],
    options: &BackupOptions,
    progress: Option<ProgressFn<'_>>,
) -> Result<BackupOutcome> {
    let excludes = build_globset(&options.exclude_globs)?;
    let dry_run = options.dry_run;
    // Open the stat cache (an optimization, never touched on a dry run). When
    // present it becomes the incremental oracle, so the parent snapshot's trees
    // are not loaded for reuse.
    let cache = match &options.cache_path {
        Some(p) if !dry_run => Some(StatCache::open(p).map_err(|e| io_err(p, e))?),
        _ => None,
    };
    let cache_updates = cache.as_ref().map(|_| Mutex::new(Vec::new()));
    let base_ctx = BackupCtx {
        excludes: &excludes,
        dry_run,
        max_file_size: options.max_file_size,
        root_dev: None,
        exclude_if_present: &options.exclude_if_present,
        exclude_caches: options.exclude_caches,
        cache: cache.as_ref(),
        cache_updates: cache_updates.as_ref(),
        progress,
    };
    let one_file_system = options.one_file_system;
    // The device of a directory source, for --one-file-system.
    let root_dev = |dir: &Path| -> Option<u64> {
        one_file_system.then(|| {
            std::fs::symlink_metadata(dir)
                .map(|m| dev_of(&m))
                .unwrap_or(0)
        })
    };
    // With a stat cache, reuse is driven entirely by it; skip loading the parent
    // snapshot's trees (the expensive part on a high-latency backend).
    let use_parent_trees = cache.is_none();
    let parent = latest_snapshot(repo).await?;
    let mut summary = SnapshotStats::default();

    let root_tree = if let [source] = sources {
        if source.is_file() {
            // Single file: the snapshot root is a tree holding one File node.
            let meta = std::fs::symlink_metadata(source).map_err(|e| io_err(source, e))?;
            let name = source
                .file_name()
                .ok_or_else(|| EngineError::NotADirectory(source.display().to_string()))?
                .as_encoded_bytes()
                .to_vec();
            let parent_node = match &parent {
                Some((_, snap)) if use_parent_trees => repo
                    .load_tree(&snap.tree)
                    .await
                    .ok()
                    .and_then(|t| t.nodes.into_iter().find(|n| n.name == name)),
                _ => None,
            };
            let node = backup_file(
                repo,
                source,
                name,
                &meta,
                parent_node.as_ref(),
                &mut summary,
                base_ctx,
            )
            .await?;
            let tree = Tree {
                version: TREE_VERSION,
                nodes: vec![node],
            };
            if dry_run {
                Id::from_bytes([0u8; 32])
            } else {
                repo.save_tree(&tree).await?
            }
        } else {
            // Single directory: its tree is the snapshot root.
            let parent_tree = use_parent_trees
                .then(|| parent.as_ref().map(|(_, snap)| snap.tree))
                .flatten();
            let ctx = BackupCtx {
                root_dev: root_dev(source),
                ..base_ctx
            };
            backup_dir(repo, source.clone(), parent_tree, &mut summary, ctx).await?
        }
    } else {
        // Multiple sources: a synthetic root with one directory entry per source.
        let parent_root: HashMap<Vec<u8>, Node> = match &parent {
            Some((_, snap)) if use_parent_trees => match repo.load_tree(&snap.tree).await {
                Ok(tree) => tree
                    .nodes
                    .into_iter()
                    .map(|n| (n.name.clone(), n))
                    .collect(),
                Err(_) => HashMap::new(),
            },
            _ => HashMap::new(),
        };
        let mut names = HashSet::new();
        let mut nodes = Vec::with_capacity(sources.len());
        for source in sources {
            let name = source
                .file_name()
                .ok_or_else(|| EngineError::NotADirectory(source.display().to_string()))?
                .as_encoded_bytes()
                .to_vec();
            if !names.insert(name.clone()) {
                return Err(EngineError::DuplicateSource(
                    String::from_utf8_lossy(&name).into_owned(),
                ));
            }
            let meta = std::fs::symlink_metadata(source).map_err(|e| io_err(source, e))?;
            if source.is_file() {
                let parent_node = parent_root.get(&name);
                nodes.push(
                    backup_file(
                        repo,
                        source,
                        name,
                        &meta,
                        parent_node,
                        &mut summary,
                        base_ctx,
                    )
                    .await?,
                );
            } else {
                let parent_sub = parent_root
                    .get(&name)
                    .and_then(|n| (n.kind == EntryKind::Dir).then_some(n.subtree).flatten());
                let ctx = BackupCtx {
                    root_dev: root_dev(source),
                    ..base_ctx
                };
                let subtree =
                    backup_dir(repo, source.clone(), parent_sub, &mut summary, ctx).await?;
                summary.dirs += 1;
                nodes.push(Node {
                    name,
                    kind: EntryKind::Dir,
                    mode: mode_of(&meta),
                    uid: uid_of(&meta),
                    gid: gid_of(&meta),
                    mtime_ns: mtime_ns(&meta),
                    ctime_ns: 0,
                    size: 0,
                    content: Vec::new(),
                    subtree: Some(subtree),
                    link_target: None,
                    dev: 0,
                    ino: 0,
                    xattrs: read_xattrs(&source),
                    rdev: 0,
                    sparse: false,
                });
            }
        }
        nodes.sort_by(|a, b| a.name.cmp(&b.name));
        let tree = Tree {
            version: TREE_VERSION,
            nodes,
        };
        if dry_run {
            Id::from_bytes([0u8; 32])
        } else {
            repo.save_tree(&tree).await?
        }
    };

    // Persist the batched stat-cache updates in a single transaction (a no-op
    // when no cache is in use).
    if let (Some(cache), Some(updates)) = (&cache, &cache_updates) {
        cache.commit(&updates.lock().unwrap());
    }

    if dry_run {
        return Ok(BackupOutcome {
            snapshot: None,
            summary,
        });
    }
    repo.flush().await?;
    let (snapshot_uid, snapshot_gid) = process_owner();
    let snapshot = Snapshot {
        version: SNAPSHOT_VERSION,
        time_ns: now_ns(),
        tree: root_tree,
        paths: sources
            .iter()
            .map(|p| p.as_os_str().as_encoded_bytes().to_vec())
            .collect(),
        hostname: env_or("HOSTNAME", "localhost"),
        username: env_or("USER", "unknown"),
        uid: snapshot_uid,
        gid: snapshot_gid,
        tags: tags.to_vec(),
        parent: parent.map(|(id, _)| id),
        program_version: env!("CARGO_PKG_VERSION").to_string(),
        summary,
    };
    let id = repo.commit_snapshot(&snapshot).await?;
    Ok(BackupOutcome {
        snapshot: Some(id),
        summary,
    })
}

/// Preview a backup of `source`: walk the tree against the latest snapshot and
/// return the new/changed/unmodified summary it *would* produce, **without**
/// writing any blob, tree, or snapshot (and without taking a lock). New or
/// changed files are counted from their metadata; their data is not read.
pub async fn backup_dry_run<B: StorageBackend>(
    repo: &mut Repository<B>,
    source: &Path,
    exclude_globs: &[String],
) -> Result<SnapshotStats> {
    Ok(backup_sources(
        repo,
        std::slice::from_ref(&source.to_path_buf()),
        exclude_globs,
        &[],
        true,
    )
    .await?
    .summary)
}

/// Back up the bytes read from `reader` as a single-file snapshot named `name`
/// — for piping a stream (a database dump, a `tar`, a `dd` image). The stream is
/// chunked and deduplicated like any file (so repeated content still dedups);
/// metadata is synthesized (mode `0644`, the current time). Holds the shared lock
/// like a normal backup.
pub async fn backup_stdin<B: StorageBackend, R: std::io::Read>(
    repo: &mut Repository<B>,
    reader: R,
    name: &[u8],
    tags: &[String],
) -> Result<BackupOutcome> {
    let lock = repo.acquire_lock(false).await?;
    let result = backup_stdin_inner(repo, reader, name, tags).await;
    let _ = repo.release_lock(&lock).await;
    result
}

async fn backup_stdin_inner<B: StorageBackend, R: std::io::Read>(
    repo: &mut Repository<B>,
    reader: R,
    name: &[u8],
    tags: &[String],
) -> Result<BackupOutcome> {
    let parent = latest_snapshot(repo).await?;
    let (content, size) = repo.save_file_reader(reader).await?;
    let now = now_ns();
    let (uid, gid) = process_owner();
    let node = Node {
        name: name.to_vec(),
        kind: EntryKind::File,
        mode: 0o100644,
        uid,
        gid,
        mtime_ns: now,
        ctime_ns: 0,
        size,
        content,
        subtree: None,
        link_target: None,
        dev: 0,
        ino: 0,
        xattrs: Vec::new(),
        rdev: 0,
        sparse: false,
    };
    let tree = Tree {
        version: TREE_VERSION,
        nodes: vec![node],
    };
    let root_tree = repo.save_tree(&tree).await?;
    repo.flush().await?;
    let summary = SnapshotStats {
        files_new: 1,
        bytes_processed: size,
        ..Default::default()
    };
    let snapshot = Snapshot {
        version: SNAPSHOT_VERSION,
        time_ns: now,
        tree: root_tree,
        paths: vec![name.to_vec()],
        hostname: env_or("HOSTNAME", "localhost"),
        username: env_or("USER", "unknown"),
        uid,
        gid,
        tags: tags.to_vec(),
        parent: parent.map(|(id, _)| id),
        program_version: env!("CARGO_PKG_VERSION").to_string(),
        summary,
    };
    let id = repo.commit_snapshot(&snapshot).await?;
    Ok(BackupOutcome {
        snapshot: Some(id),
        summary,
    })
}

/// Copy `snapshot` from `src` into `dst`, re-encrypting every blob under `dst`'s
/// keys and rebuilding the trees, then committing the snapshot in `dst` (which
/// takes a shared lock for the write). The two repositories may use different
/// passphrases. The copy keeps the original's metadata (time, tags, paths) but
/// has no parent, since the source's history does not exist in `dst`. Returns
/// the new snapshot id in `dst`.
pub async fn copy_snapshot<S: StorageBackend, D: StorageBackend>(
    src: &Repository<S>,
    dst: &mut Repository<D>,
    snapshot: &Id,
) -> Result<Id> {
    copy_snapshot_with_progress(src, dst, snapshot, None).await
}

/// A callback invoked once per content blob as it is copied into the destination,
/// for progress display.
pub type CopyProgressFn<'a> = &'a dyn Fn();

/// Like [`copy_snapshot`], invoking `progress` (if any) once per copied blob.
pub async fn copy_snapshot_with_progress<S: StorageBackend, D: StorageBackend>(
    src: &Repository<S>,
    dst: &mut Repository<D>,
    snapshot: &Id,
    progress: Option<CopyProgressFn<'_>>,
) -> Result<Id> {
    let snap = src.load_snapshot(snapshot).await?;
    let lock = dst.acquire_lock(false).await?;
    let result = copy_snapshot_inner(src, dst, &snap, progress).await;
    let _ = dst.release_lock(&lock).await;
    result
}

/// Copy every snapshot from `src` into `dst` (see [`copy_snapshot`]), returning
/// the new ids in `dst`. Re-running is safe: a snapshot already copied commits
/// to the same id and is a no-op, and shared blobs are deduplicated in `dst`.
pub async fn copy_all<S: StorageBackend, D: StorageBackend>(
    src: &Repository<S>,
    dst: &mut Repository<D>,
) -> Result<Vec<Id>> {
    copy_all_with_progress(src, dst, None).await
}

/// Like [`copy_all`], invoking `progress` (if any) once per copied blob.
pub async fn copy_all_with_progress<S: StorageBackend, D: StorageBackend>(
    src: &Repository<S>,
    dst: &mut Repository<D>,
    progress: Option<CopyProgressFn<'_>>,
) -> Result<Vec<Id>> {
    let mut ids = Vec::new();
    for snapshot in src.list_snapshots().await? {
        ids.push(copy_snapshot_with_progress(src, dst, &snapshot, progress).await?);
    }
    Ok(ids)
}

/// The body of [`copy_snapshot`], run while holding `dst`'s shared lock.
async fn copy_snapshot_inner<S: StorageBackend, D: StorageBackend>(
    src: &Repository<S>,
    dst: &mut Repository<D>,
    snap: &Snapshot,
    progress: Option<CopyProgressFn<'_>>,
) -> Result<Id> {
    let tree = copy_tree(src, dst, snap.tree, progress).await?;
    dst.flush().await?;
    let new_snapshot = Snapshot {
        tree,
        parent: None,
        ..snap.clone()
    };
    Ok(dst.commit_snapshot(&new_snapshot).await?)
}

/// Recursively copy the tree `tree_id` from `src` into `dst`, re-keying every
/// content blob and rebuilding each node, returning the new tree id in `dst`.
fn copy_tree<'a, S: StorageBackend, D: StorageBackend>(
    src: &'a Repository<S>,
    dst: &'a mut Repository<D>,
    tree_id: Id,
    progress: Option<CopyProgressFn<'a>>,
) -> Pin<Box<dyn Future<Output = Result<Id>> + 'a>> {
    Box::pin(async move {
        let tree = src.load_tree(&tree_id).await?;
        let mut nodes = Vec::with_capacity(tree.nodes.len());
        for node in tree.nodes {
            let (content, subtree) = match node.kind {
                EntryKind::Dir => {
                    let sub = match node.subtree {
                        Some(child) => Some(copy_tree(src, dst, child, progress).await?),
                        None => None,
                    };
                    (Vec::new(), sub)
                }
                EntryKind::File => {
                    let mut copied = Vec::with_capacity(node.content.len());
                    for chunk in &node.content {
                        let data = src.load_blob(chunk).await?;
                        copied.push(dst.save_blob(BlobKind::Data, &data).await?);
                        if let Some(p) = progress {
                            p();
                        }
                    }
                    (copied, None)
                }
                // Symlinks and special files reference no blobs.
                _ => (Vec::new(), None),
            };
            nodes.push(Node {
                content,
                subtree,
                ..node
            });
        }
        Ok(dst
            .save_tree(&Tree {
                version: TREE_VERSION,
                nodes,
            })
            .await?)
    })
}

/// Compile exclude globs (matched against entry names) into a [`GlobSet`].
fn build_globset(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).map_err(|e| EngineError::Pattern(e.to_string()))?);
    }
    builder
        .build()
        .map_err(|e| EngineError::Pattern(e.to_string()))
}

/// Find the most recent snapshot (by timestamp), if any.
async fn latest_snapshot<B: StorageBackend>(
    repo: &Repository<B>,
) -> Result<Option<(Id, Snapshot)>> {
    let mut best: Option<(Id, Snapshot)> = None;
    for id in repo.list_snapshots().await? {
        let snap = repo.load_snapshot(&id).await?;
        if best
            .as_ref()
            .map_or(true, |(_, b)| snap.time_ns > b.time_ns)
        {
            best = Some((id, snap));
        }
    }
    Ok(best)
}

/// Best-effort metadata a restore could not fully apply: ownership it could not
/// set, extended attributes it could not write, or device nodes it had to skip
/// (e.g. an unprivileged restore lacking `CAP_MKNOD`). File data and tree
/// structure are still restored — these are warnings, not failures.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// Total number of best-effort operations that failed.
    pub warnings: u64,
    /// A bounded sample of the warning messages, for display.
    pub messages: Vec<String>,
}

/// Tunables for a restore; see [`restore_with`].
#[derive(Debug, Default, Clone, Copy)]
pub struct RestoreOptions {
    /// Skip an entry whose target already exists and (for files) matches the
    /// snapshot's size and mtime. Makes a restore idempotent and resumable: a
    /// re-run after an interruption leaves finished entries untouched.
    pub skip_existing: bool,
    /// After writing each file, re-read it and confirm its contents match the
    /// snapshot, failing with [`EngineError::VerifyFailed`] if not.
    pub verify: bool,
}

/// Path globs selecting which entries a restore writes. Both sets match an
/// entry's path **relative to the restore root** (e.g. `docs/report.pdf`), with
/// `**` spanning directory separators. The default (empty) filter restores
/// everything.
#[derive(Default)]
pub struct RestoreFilter {
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
}

impl RestoreFilter {
    /// Build a filter from `--include`/`--exclude` patterns (either may be empty).
    /// With any include pattern, only matching leaf entries are restored; an
    /// exclude pattern prunes a matching entry (and, for a directory, its whole
    /// subtree).
    pub fn new(include: &[String], exclude: &[String]) -> Result<Self> {
        let set = |pats: &[String]| -> Result<Option<GlobSet>> {
            if pats.is_empty() {
                Ok(None)
            } else {
                Ok(Some(build_globset(pats)?))
            }
        };
        Ok(Self {
            include: set(include)?,
            exclude: set(exclude)?,
        })
    }

    /// Whether a leaf at relative path `rel` would be restored. For previewing a
    /// filtered restore (e.g. `restore --dry-run`); the recursive walk uses the
    /// private helpers directly.
    #[must_use]
    pub fn allows_path(&self, rel: &Path) -> bool {
        self.allows_leaf(rel)
    }

    /// Whether a leaf entry (file, symlink, special) at relative path `rel` is
    /// restored: it matches an include pattern (or there are none) and no exclude.
    fn allows_leaf(&self, rel: &Path) -> bool {
        self.include.as_ref().map_or(true, |g| g.is_match(rel))
            && !self.exclude.as_ref().is_some_and(|g| g.is_match(rel))
    }

    /// Whether a directory at relative path `rel` is descended into (an exclude
    /// match prunes it; include patterns never prune dirs, only gate leaves).
    fn allows_dir(&self, rel: &Path) -> bool {
        !self.exclude.as_ref().is_some_and(|g| g.is_match(rel))
    }
}

/// Concurrent collector for [`RestoreReport`] entries during a restore.
type Reporter = std::sync::Mutex<RestoreReport>;

/// A callback invoked with each file's path as it is restored (skipped files are
/// not reported), for `--verbose`/progress output. See [`restore_with`].
pub type RestoreProgressFn<'a> = &'a (dyn Fn(&Path) + Sync);

/// How many distinct messages to retain. The count stays exact; only the sample
/// is bounded, so a flood of failures cannot exhaust memory.
const WARN_SAMPLE_CAP: usize = 20;

fn record_warning(reporter: &Reporter, msg: String) {
    let mut report = reporter.lock().expect("restore reporter poisoned");
    report.warnings += 1;
    if report.messages.len() < WARN_SAMPLE_CAP {
        report.messages.push(msg);
    }
}

/// Restore the snapshot `snapshot` from `repo` into the directory `target`,
/// returning any best-effort metadata that could not be applied.
pub async fn restore<B: StorageBackend>(
    repo: &Repository<B>,
    snapshot: &Id,
    target: &Path,
) -> Result<RestoreReport> {
    restore_with(
        repo,
        snapshot,
        None,
        target,
        RestoreOptions::default(),
        None,
    )
    .await
}

/// Restore a snapshot into `target`. With `subpath`, restore only that entry
/// (a directory subtree, file, or symlink), placed under `target` by base name.
pub async fn restore_subpath<B: StorageBackend>(
    repo: &Repository<B>,
    snapshot: &Id,
    subpath: Option<&str>,
    target: &Path,
) -> Result<RestoreReport> {
    restore_with(
        repo,
        snapshot,
        subpath,
        target,
        RestoreOptions::default(),
        None,
    )
    .await
}

/// Restore a snapshot (optionally just `subpath`) into `target` under `options`,
/// invoking `progress` (if any) with each restored file's path. [`restore`] and
/// [`restore_subpath`] are thin wrappers with default options and no progress;
/// [`restore_filtered`] additionally takes glob filters.
pub async fn restore_with<B: StorageBackend>(
    repo: &Repository<B>,
    snapshot: &Id,
    subpath: Option<&str>,
    target: &Path,
    options: RestoreOptions,
    progress: Option<RestoreProgressFn<'_>>,
) -> Result<RestoreReport> {
    restore_filtered(
        repo,
        snapshot,
        subpath,
        target,
        options,
        &RestoreFilter::default(),
        progress,
    )
    .await
}

/// Like [`restore_with`], but only entries permitted by `filter` (include/exclude
/// globs matched against each entry's path relative to the restore root) are
/// written.
pub async fn restore_filtered<B: StorageBackend>(
    repo: &Repository<B>,
    snapshot: &Id,
    subpath: Option<&str>,
    target: &Path,
    options: RestoreOptions,
    filter: &RestoreFilter,
    progress: Option<RestoreProgressFn<'_>>,
) -> Result<RestoreReport> {
    let snap = repo.load_snapshot(snapshot).await?;
    std::fs::create_dir_all(target).map_err(|e| io_err(target, e))?;
    // Maps a source (dev, ino) to the first path restored for it, so hardlinked
    // files are recreated as links rather than duplicated.
    let links = std::sync::Mutex::new(HashMap::new());
    let reporter = Reporter::default();

    if let Some(path) = subpath {
        let node = find_node(repo, snap.tree, path).await?;
        let dest = target.join(osstring_from_bytes(&node.name));
        match node.kind {
            EntryKind::Dir => {
                std::fs::create_dir_all(&dest).map_err(|e| io_err(&dest, e))?;
                if let Some(subtree) = node.subtree {
                    // Filter relative to this subpath's base name.
                    restore_tree(
                        repo,
                        subtree,
                        dest.clone(),
                        PathBuf::from(osstring_from_bytes(&node.name)),
                        &links,
                        &reporter,
                        options,
                        filter,
                        progress,
                    )
                    .await?;
                }
                apply_metadata(&dest, &node, &reporter);
            }
            EntryKind::File => {
                restore_file(repo, &dest, &node, &reporter, options, progress).await?;
            }
            EntryKind::Symlink => {
                if let Some(link_target) = &node.link_target {
                    if !(options.skip_existing && exists(&dest)) {
                        symlink(&osstring_from_bytes(link_target), &dest)?;
                        set_owner(&dest, node.uid, node.gid, false, &reporter);
                        write_xattrs(&dest, &node.xattrs, &reporter);
                    }
                }
            }
            EntryKind::Fifo => {
                if !(options.skip_existing && exists(&dest)) {
                    make_fifo(&dest, node.mode)?;
                    apply_special_metadata(&dest, &node, &reporter);
                }
            }
            EntryKind::CharDevice | EntryKind::BlockDevice => {
                if !(options.skip_existing && exists(&dest)) {
                    match make_device(&dest, node.mode, node.kind, node.rdev) {
                        Ok(()) => apply_special_metadata(&dest, &node, &reporter),
                        Err(e) => record_warning(
                            &reporter,
                            format!("skipped device node {}: {e}", dest.display()),
                        ),
                    }
                }
            }
            _ => {}
        }
    } else {
        restore_tree(
            repo,
            snap.tree,
            target.to_path_buf(),
            PathBuf::new(),
            &links,
            &reporter,
            options,
            filter,
            progress,
        )
        .await?;
    }
    Ok(reporter.into_inner().expect("restore reporter poisoned"))
}

/// Whether anything exists at `path` (a final symlink counts, not its target).
fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Whether `path` is an existing regular file with the node's size and mtime —
/// the cheap "already restored" check used by skip-existing.
fn file_matches(path: &Path, node: &Node) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.is_file() && meta.len() == node.size && mtime_ns(&meta) == node.mtime_ns,
        Err(_) => false,
    }
}

/// Restore one regular file's content and metadata, honoring skip-existing and
/// (post-write) verify. Used by the full restore, the hardlink path, and subpath.
async fn restore_file<B: StorageBackend>(
    repo: &Repository<B>,
    path: &Path,
    node: &Node,
    reporter: &Reporter,
    options: RestoreOptions,
    progress: Option<RestoreProgressFn<'_>>,
) -> Result<()> {
    if options.skip_existing && file_matches(path, node) {
        return Ok(());
    }
    restore_file_streaming(repo, path, &node.content, node.sparse).await?;
    apply_metadata(path, node, reporter);
    if options.verify {
        verify_restored_file(repo, path, &node.content).await?;
    }
    if let Some(report) = progress {
        report(path);
    }
    Ok(())
}

/// Re-read a just-restored file and confirm it matches the snapshot content,
/// streaming so peak memory stays bounded. A holey sparse file reads its holes
/// back as zeros, matching the stored zero chunks.
async fn verify_restored_file<B: StorageBackend>(
    repo: &Repository<B>,
    path: &Path,
    content: &[Id],
) -> Result<()> {
    use futures::stream::{StreamExt, TryStreamExt};
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| io_err(path, e))?;
    let mut chunks = futures::stream::iter(content.iter().map(|id| repo.load_blob(id)))
        .buffered(RESTORE_FILE_CONCURRENCY);
    let mut buf = Vec::new();
    while let Some(expected) = chunks.try_next().await? {
        buf.resize(expected.len(), 0);
        file.read_exact(&mut buf).map_err(|e| io_err(path, e))?;
        if buf != expected {
            return Err(EngineError::VerifyFailed(path.display().to_string()));
        }
    }
    // No trailing bytes beyond the snapshot's content.
    if file.read(&mut [0u8; 1]).map_err(|e| io_err(path, e))? != 0 {
        return Err(EngineError::VerifyFailed(path.display().to_string()));
    }
    Ok(())
}

/// A summary produced by [`verify`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct VerifyReport {
    /// Number of snapshots checked.
    pub snapshots: usize,
    /// Number of tree objects read and authenticated.
    pub trees: usize,
    /// Number of unique content (file chunk) blobs read and authenticated. When
    /// sampling (see [`VerifyOptions`]) this is the size of the chosen subset.
    pub blobs: usize,
    /// Total number of unique content blobs referenced by the snapshots. Equals
    /// `blobs` for a full verify; for a sampled verify it is the denominator.
    pub total_blobs: usize,
}

/// Options controlling [`verify_with`].
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// Percentage of the unique content blobs to read and authenticate, in
    /// `1..=100`. Trees are always walked and authenticated in full; only the
    /// expensive content-blob reads are sampled. A value of `100` reads
    /// everything; a smaller value trades completeness for speed, so a large
    /// repository can be spot-checked often and fully verified occasionally.
    pub sample_percent: u8,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            sample_percent: 100,
        }
    }
}

/// Concurrent content-blob reads during [`verify`].
const VERIFY_CONCURRENCY: usize = 16;

/// Concurrent file reconstructions per directory during restore.
const RESTORE_CONCURRENCY: usize = 16;

/// Verify every snapshot in `repo` by reading and authenticating all reachable
/// trees and content blobs (a full read-data check; see `DESIGN.md` §5.7).
///
/// Equivalent to [`verify_with`] with the default options. Returns the counts
/// on success, or an error identifying a missing or corrupt object.
pub async fn verify<B: StorageBackend>(repo: &Repository<B>) -> Result<VerifyReport> {
    verify_with(repo, VerifyOptions::default()).await
}

/// A callback invoked once per content blob as it is read and authenticated by
/// [`verify_with_progress`], for progress display.
pub type VerifyProgressFn<'a> = &'a (dyn Fn() + Sync);

/// Verify `repo`, optionally reading only a random sample of the content blobs.
/// Equivalent to [`verify_with_progress`] without a progress callback.
pub async fn verify_with<B: StorageBackend>(
    repo: &Repository<B>,
    options: VerifyOptions,
) -> Result<VerifyReport> {
    verify_with_progress(repo, options, None).await
}

/// Verify `repo`, invoking `progress` (if any) once per content blob as it is
/// read.
///
/// The trees are always walked and authenticated in full (this is cheap and
/// proves the snapshot structure), collecting the set of referenced content
/// blobs. When `options.sample_percent` is below 100, a uniformly random subset
/// of that set — at least one blob — is selected; the chosen blobs are then read
/// and AEAD-authenticated concurrently, which is far faster on a high-latency
/// (object-store) backend. Sampling lets a large repository be spot-checked
/// cheaply and often, catching bit-rot probabilistically, while a periodic full
/// verify still reads everything.
///
/// Returns the counts on success, or an error identifying a missing or corrupt
/// object.
pub async fn verify_with_progress<B: StorageBackend>(
    repo: &Repository<B>,
    options: VerifyOptions,
    progress: Option<VerifyProgressFn<'_>>,
) -> Result<VerifyReport> {
    use futures::stream::{StreamExt, TryStreamExt};

    let mut report = VerifyReport::default();
    let mut content: HashSet<Id> = HashSet::new();
    for snapshot in repo.list_snapshots().await? {
        let snap = repo.load_snapshot(&snapshot).await?;
        report.snapshots += 1;
        collect_verify(repo, snap.tree, &mut report, &mut content).await?;
    }
    report.total_blobs = content.len();

    // Choose which blobs to read: all of them for a full verify, or a uniformly
    // random subset (at least one) when sampling.
    let percent = options.sample_percent.clamp(1, 100);
    let to_read: Vec<Id> = if percent >= 100 {
        content.into_iter().collect()
    } else {
        sample_ids(content.into_iter().collect(), percent)
    };
    report.blobs = to_read.len();

    // Read and authenticate each selected content blob concurrently; load_blob
    // checks the AEAD tag, so any corrupt or missing blob surfaces as an error.
    futures::stream::iter(to_read.iter().map(|id| repo.load_blob(id)))
        .buffer_unordered(VERIFY_CONCURRENCY)
        .try_for_each(|_| async {
            if let Some(p) = progress {
                p();
            }
            Ok(())
        })
        .await?;
    Ok(report)
}

/// Select `ceil(len * percent / 100)` ids (at least one when non-empty) from
/// `ids` uniformly at random, via a partial Fisher-Yates shuffle seeded from the
/// OS CSPRNG.
fn sample_ids(mut ids: Vec<Id>, percent: u8) -> Vec<Id> {
    let n = ids.len();
    if n == 0 {
        return ids;
    }
    let target = (n * percent as usize).div_ceil(100).clamp(1, n);
    for i in 0..target {
        let r = i + random_below(n - i);
        ids.swap(i, r);
    }
    ids.truncate(target);
    ids
}

/// A uniform random `usize` in `0..bound` drawn from the OS CSPRNG (`bound >= 1`).
fn random_below(bound: usize) -> usize {
    debug_assert!(bound >= 1);
    if bound <= 1 {
        return 0;
    }
    let mut buf = [0u8; 8];
    sluice_crypto::fill_random(&mut buf);
    (u64::from_le_bytes(buf) % bound as u64) as usize
}

/// Recursively authenticate the tree `tree_id` (counting trees) and collect the
/// ids of every content blob it references; the blobs are read by [`verify`].
fn collect_verify<'a, B: StorageBackend>(
    repo: &'a Repository<B>,
    tree_id: Id,
    report: &'a mut VerifyReport,
    content: &'a mut HashSet<Id>,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let tree = repo.load_tree(&tree_id).await?;
        report.trees += 1;
        for node in &tree.nodes {
            match node.kind {
                EntryKind::Dir => {
                    if let Some(subtree) = node.subtree {
                        collect_verify(repo, subtree, report, content).await?;
                    }
                }
                EntryKind::File => {
                    for id in &node.content {
                        content.insert(*id);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    })
}

/// A summary produced by [`check`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// Number of snapshots inspected.
    pub snapshots: usize,
    /// Number of tree objects read and authenticated.
    pub trees: usize,
    /// Number of referenced content (file chunk) blobs.
    pub blobs: usize,
    /// Referenced content blobs absent from the repository.
    pub missing: Vec<Id>,
}

/// Structural integrity check: walk every snapshot's trees (decrypting and
/// authenticating each) and confirm every referenced content blob is present,
/// *without* reading or decrypting the file data (see `DESIGN.md` §5.7). Much
/// cheaper than [`verify`], which authenticates all data; use it for routine
/// integrity checks. Missing blobs are collected in [`CheckReport::missing`].
pub async fn check<B: StorageBackend>(repo: &Repository<B>) -> Result<CheckReport> {
    let mut report = CheckReport::default();
    for snapshot in repo.list_snapshots().await? {
        let snap = repo.load_snapshot(&snapshot).await?;
        report.snapshots += 1;
        check_tree(repo, snap.tree, &mut report).await?;
    }
    Ok(report)
}

/// Recursively authenticate the tree `tree_id` and record whether each content
/// blob it references is present (by index lookup, not by reading the data).
fn check_tree<'a, B: StorageBackend>(
    repo: &'a Repository<B>,
    tree_id: Id,
    report: &'a mut CheckReport,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let tree = repo.load_tree(&tree_id).await?;
        report.trees += 1;
        for node in &tree.nodes {
            match node.kind {
                EntryKind::Dir => {
                    if let Some(subtree) = node.subtree {
                        check_tree(repo, subtree, report).await?;
                    }
                }
                EntryKind::File => {
                    for id in &node.content {
                        report.blobs += 1;
                        if !repo.has_blob(id) {
                            report.missing.push(*id);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    })
}

/// Remove a snapshot so it can no longer be restored. The data it referenced is
/// reclaimed only by a subsequent [`prune`].
pub async fn forget<B: StorageBackend>(repo: &Repository<B>, snapshot: &Id) -> Result<()> {
    repo.backend()
        .remove(FileType::Snapshot, snapshot)
        .await
        .map_err(RepoError::from)?;
    Ok(())
}

/// Rewrite a snapshot's tags: drop every tag in `remove`, then add every tag in
/// `add` not already present. Because snapshots are immutable and content-
/// addressed, this commits a new snapshot (same tree, time, and history) and
/// forgets the old one, returning the new id. The shared tree keeps the data
/// live, so no `prune` is needed. A no-op change returns the original id.
pub async fn retag<B: StorageBackend>(
    repo: &Repository<B>,
    snapshot: &Id,
    add: &[String],
    remove: &[String],
) -> Result<Id> {
    let snap = repo.load_snapshot(snapshot).await?;
    let mut tags = snap.tags.clone();
    tags.retain(|t| !remove.contains(t));
    for tag in add {
        if !tags.contains(tag) {
            tags.push(tag.clone());
        }
    }
    if tags == snap.tags {
        return Ok(*snapshot);
    }
    let new_id = repo.commit_snapshot(&Snapshot { tags, ..snap }).await?;
    forget(repo, snapshot).await?;
    Ok(new_id)
}

/// A snapshot retention policy. A snapshot is kept if it satisfies *any* enabled
/// rule (the union, as in restic); a rule with a count of 0 is disabled. See
/// `DESIGN.md` §8.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Keep the N most recent snapshots.
    pub last: usize,
    /// Keep the most recent snapshot of each of the last N UTC days.
    pub daily: usize,
    /// Keep the most recent snapshot of each of the last N (Monday-aligned) weeks.
    pub weekly: usize,
    /// Keep the most recent snapshot of each of the last N calendar months.
    pub monthly: usize,
    /// Keep the most recent snapshot of each of the last N calendar years.
    pub yearly: usize,
    /// Always keep snapshots carrying any of these tags, regardless of counts.
    pub keep_tags: Vec<String>,
    /// Always keep snapshots taken within this many nanoseconds of now (0 = off).
    pub keep_within_ns: i64,
    /// Always keep these specific snapshots (by full id), regardless of counts.
    pub keep_ids: Vec<Id>,
}

impl RetentionPolicy {
    /// Whether every rule is disabled (so the policy would keep nothing).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.last == 0
            && self.daily == 0
            && self.weekly == 0
            && self.monthly == 0
            && self.yearly == 0
            && self.keep_tags.is_empty()
            && self.keep_within_ns == 0
            && self.keep_ids.is_empty()
    }
}

/// How to partition snapshots before applying a [`RetentionPolicy`]. Retention
/// rules are applied independently within each group, and the kept sets are
/// unioned — so e.g. `--keep-last 7 --group-by host` keeps the 7 newest
/// snapshots *of each host* (see `DESIGN.md` §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupBy {
    /// One group of all snapshots (global retention).
    #[default]
    None,
    /// Group snapshots by source hostname.
    Host,
    /// Group snapshots by their set of source paths.
    Paths,
}

/// The grouping key for a snapshot under `group_by`.
fn group_key(group_by: GroupBy, snap: &Snapshot) -> String {
    match group_by {
        GroupBy::None => String::new(),
        GroupBy::Host => snap.hostname.clone(),
        GroupBy::Paths => snap
            .paths
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect::<Vec<_>>()
            .join("\u{0}"),
    }
}

/// Select the ids to keep from one group's snapshots (sorted newest-first),
/// adding them to `keep`: the N most recent, the most recent per daily/weekly/
/// monthly/yearly bucket, and any carrying a protected tag.
fn select_kept(
    snapshots: &[(Id, i64, Vec<String>)],
    policy: &RetentionPolicy,
    keep: &mut HashSet<Id>,
) {
    // `--keep-last N`: the N most recent snapshots outright.
    for (id, _, _) in snapshots.iter().take(policy.last) {
        keep.insert(*id);
    }
    // `--keep-daily`/`weekly`/`monthly`/`yearly`: most recent per bucket, last N.
    let bucketed: [(usize, fn(i64) -> i64); 4] = [
        (policy.daily, day_bucket),
        (policy.weekly, week_bucket),
        (policy.monthly, month_bucket),
        (policy.yearly, year_bucket),
    ];
    for (budget, bucket_of) in bucketed {
        let mut kept_buckets: Vec<i64> = Vec::new();
        for (id, time, _) in snapshots {
            let bucket = bucket_of(*time);
            if kept_buckets.last() != Some(&bucket) && kept_buckets.len() < budget {
                kept_buckets.push(bucket);
                keep.insert(*id);
            }
        }
    }
    // `--keep-tag T`: any snapshot carrying a protected tag survives outright.
    if !policy.keep_tags.is_empty() {
        for (id, _, tags) in snapshots {
            if tags.iter().any(|t| policy.keep_tags.contains(t)) {
                keep.insert(*id);
            }
        }
    }
    // `--keep-id`: pin specific snapshots by id, regardless of counts.
    if !policy.keep_ids.is_empty() {
        for (id, _, _) in snapshots {
            if policy.keep_ids.contains(id) {
                keep.insert(*id);
            }
        }
    }
}

/// Nanoseconds per UTC day; `Snapshot::time_ns` is ns since the Unix epoch.
const NS_PER_DAY: i64 = 86_400_000_000_000;

/// The UTC day index (days since the epoch) containing `time_ns`.
fn day_bucket(time_ns: i64) -> i64 {
    time_ns.div_euclid(NS_PER_DAY)
}

/// The Monday-aligned week index containing `time_ns`. Epoch day 0 is a
/// Thursday, so `+3` shifts week boundaries onto Mondays.
fn week_bucket(time_ns: i64) -> i64 {
    (day_bucket(time_ns) + 3).div_euclid(7)
}

/// Civil `(year, month)` for a day index (days since 1970-01-01), via Howard
/// Hinnant's `civil_from_days`. Month is in `1..=12`; handles days before the
/// epoch. Used to bucket snapshots by calendar month and year.
fn year_month(day: i64) -> (i64, i64) {
    let z = day + 719_468; // shift epoch to 0000-03-01
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, [0, 365]
    let mp = (5 * doy + 2) / 153; // month shifted so March = 0, [0, 11]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12], Jan/Feb roll to next year
    (if m <= 2 { y + 1 } else { y }, m)
}

/// The calendar-month index (months since year 0) containing `time_ns`.
fn month_bucket(time_ns: i64) -> i64 {
    let (y, m) = year_month(day_bucket(time_ns));
    y * 12 + (m - 1)
}

/// The calendar year containing `time_ns`.
fn year_bucket(time_ns: i64) -> i64 {
    year_month(day_bucket(time_ns)).0
}

/// Apply a retention `policy`, forgetting every snapshot kept by no rule, and
/// return the ids forgotten (or, with `dry_run`, the ids that *would* be
/// forgotten, removing nothing). Reclaim their data afterwards with [`prune`].
///
/// Each bucketed rule keeps the most recent snapshot of each of its last N
/// buckets: walking newest-first, the first snapshot seen for a bucket is that
/// bucket's most recent, and buckets only decrease, so one pass per rule with a
/// running list of kept buckets suffices. The kept sets are unioned.
pub async fn forget_with_policy<B: StorageBackend>(
    repo: &Repository<B>,
    policy: &RetentionPolicy,
    group_by: GroupBy,
    dry_run: bool,
) -> Result<Vec<Id>> {
    // (id, time, tags, group key), sorted newest-first across the whole repo.
    let mut snapshots: Vec<(Id, i64, Vec<String>, String)> = Vec::new();
    for id in repo.list_snapshots().await? {
        let snap = repo.load_snapshot(&id).await?;
        let key = group_key(group_by, &snap);
        snapshots.push((id, snap.time_ns, snap.tags, key));
    }
    snapshots.sort_by(|a, b| b.1.cmp(&a.1)); // most recent first

    // Partition into groups (each preserving the global newest-first order) and
    // apply the policy independently within each, unioning the kept sets.
    let mut groups: HashMap<String, Vec<(Id, i64, Vec<String>)>> = HashMap::new();
    for (id, time, tags, key) in &snapshots {
        groups
            .entry(key.clone())
            .or_default()
            .push((*id, *time, tags.clone()));
    }
    let mut keep: HashSet<Id> = HashSet::new();
    for group in groups.values() {
        select_kept(group, policy, &mut keep);
    }
    // `--keep-within`: keep every snapshot newer than `now - keep_within_ns`,
    // independent of grouping.
    if policy.keep_within_ns > 0 {
        let cutoff = now_ns() - policy.keep_within_ns;
        for (id, time, _, _) in &snapshots {
            if *time >= cutoff {
                keep.insert(*id);
            }
        }
    }

    let mut forgotten = Vec::new();
    for (id, _, _, _) in &snapshots {
        if !keep.contains(id) {
            if !dry_run {
                forget(repo, id).await?;
            }
            forgotten.push(*id);
        }
    }
    Ok(forgotten)
}

/// Keep the `keep` most recent snapshots and forget the rest, returning the ids
/// that were forgotten. Reclaim their data afterwards with [`prune`].
pub async fn forget_keep_last<B: StorageBackend>(
    repo: &Repository<B>,
    keep: usize,
) -> Result<Vec<Id>> {
    forget_with_policy(
        repo,
        &RetentionPolicy {
            last: keep,
            ..Default::default()
        },
        GroupBy::None,
        false,
    )
    .await
}

/// Apply a daily retention policy: keep the most recent snapshot of each of the
/// `keep` most recent UTC days and forget the rest. Returns the ids forgotten.
/// Reclaim their data afterwards with [`prune`].
pub async fn forget_keep_daily<B: StorageBackend>(
    repo: &Repository<B>,
    keep: usize,
) -> Result<Vec<Id>> {
    forget_with_policy(
        repo,
        &RetentionPolicy {
            daily: keep,
            ..Default::default()
        },
        GroupBy::None,
        false,
    )
    .await
}

/// Forget every snapshot tagged `tag`, returning the ids forgotten (or, with
/// `dry_run`, the ids that *would* be forgotten, removing nothing). Reclaim
/// their data afterwards with [`prune`].
pub async fn forget_tagged<B: StorageBackend>(
    repo: &Repository<B>,
    tag: &str,
    dry_run: bool,
) -> Result<Vec<Id>> {
    let mut forgotten = Vec::new();
    for id in repo.list_snapshots().await? {
        if repo.load_snapshot(&id).await?.tags.iter().any(|t| t == tag) {
            if !dry_run {
                forget(repo, &id).await?;
            }
            forgotten.push(id);
        }
    }
    Ok(forgotten)
}

/// Delete packs no longer referenced by any surviving snapshot, returning the
/// counts of packs deleted and repacked (mark-and-sweep GC; see `DESIGN.md` §8).
/// With `dry_run`, report what would happen without touching storage.
pub async fn prune<B: StorageBackend>(
    repo: &mut Repository<B>,
    dry_run: bool,
    max_unused: u8,
) -> Result<PruneReport> {
    prune_excluding(repo, dry_run, &HashSet::new(), max_unused).await
}

/// Like [`prune`], but treat the snapshots in `excluded` as already gone — their
/// blobs are not marked live. This lets a dry run preview the reclamation of a
/// pending `forget` (the snapshots it would remove) without removing them first.
pub async fn prune_excluding<B: StorageBackend>(
    repo: &mut Repository<B>,
    dry_run: bool,
    excluded: &HashSet<Id>,
    max_unused: u8,
) -> Result<PruneReport> {
    // A dry run only reads, so it needs no lock; a real prune takes the exclusive
    // lock that guards deletion against concurrent operations (`DESIGN.md` §8).
    if dry_run {
        return prune_marked(repo, true, excluded, max_unused).await;
    }
    let lock = repo.acquire_lock(true).await?;
    let result = prune_marked(repo, false, excluded, max_unused).await;
    let _ = repo.release_lock(&lock).await;
    result
}

/// MARK every blob reachable from a surviving (non-`excluded`) snapshot, then
/// SWEEP + repack, updating the repository's index in place.
async fn prune_marked<B: StorageBackend>(
    repo: &mut Repository<B>,
    dry_run: bool,
    excluded: &HashSet<Id>,
    max_unused: u8,
) -> Result<PruneReport> {
    let mut live: HashSet<Id> = HashSet::new();
    for snapshot in repo.list_snapshots().await? {
        if excluded.contains(&snapshot) {
            continue;
        }
        let snap = repo.load_snapshot(&snapshot).await?;
        mark_tree(repo, snap.tree, &mut live).await?;
    }
    Ok(repo.sweep(&live, dry_run, max_unused).await?)
}

/// Repair the repository's index segments by rescanning packs (see
/// [`Repository::rebuild_index`]). Holds the exclusive lock for the rewrite and
/// returns the number of packs indexed.
pub async fn rebuild_index<B: StorageBackend>(repo: &mut Repository<B>) -> Result<usize> {
    let lock = repo.acquire_lock(true).await?;
    let result = repo.rebuild_index().await;
    let _ = repo.release_lock(&lock).await;
    Ok(result?)
}

/// Mark the tree `tree_id` and everything it references as live.
fn mark_tree<'a, B: StorageBackend>(
    repo: &'a Repository<B>,
    tree_id: Id,
    live: &'a mut HashSet<Id>,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        live.insert(tree_id);
        let tree = repo.load_tree(&tree_id).await?;
        for node in &tree.nodes {
            match node.kind {
                EntryKind::Dir => {
                    if let Some(subtree) = node.subtree {
                        mark_tree(repo, subtree, live).await?;
                    }
                }
                EntryKind::File => {
                    for id in &node.content {
                        live.insert(*id);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    })
}

/// An entry returned by [`list_files`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    /// Path relative to the backup root.
    pub path: String,
    /// The kind of entry.
    pub kind: EntryKind,
    /// Logical size in bytes (0 for directories).
    pub size: u64,
    /// Unix mode bits.
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: i64,
    /// Device number for `CharDevice`/`BlockDevice` entries; `0` otherwise.
    pub rdev: u64,
    /// Symlink target as raw bytes, for symlinks.
    pub link_target: Option<Vec<u8>>,
}

/// List a snapshot's entries (path, kind, size) without restoring any data.
pub async fn list_files<B: StorageBackend>(
    repo: &Repository<B>,
    snapshot: &Id,
) -> Result<Vec<ListEntry>> {
    let snap = repo.load_snapshot(snapshot).await?;
    let mut out = Vec::new();
    list_tree(repo, snap.tree, String::new(), &mut out).await?;
    Ok(out)
}

/// One hit from [`find`]: the snapshot a matching entry lives in, and the entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindMatch {
    /// The snapshot containing the match.
    pub snapshot: Id,
    /// Path of the matching entry, relative to the backup root.
    pub path: String,
    /// The kind of entry.
    pub kind: EntryKind,
    /// Logical size in bytes (0 for directories).
    pub size: u64,
}

/// Find every entry whose path matches the glob `pattern` across all snapshots.
/// The pattern is matched against the full relative path, so `**` is needed to
/// cross directories (e.g. `**/*.log`). Results are grouped by snapshot in the
/// repository's snapshot order.
pub async fn find<B: StorageBackend>(
    repo: &Repository<B>,
    pattern: &str,
) -> Result<Vec<FindMatch>> {
    let matcher = Glob::new(pattern)
        .map_err(|e| EngineError::Pattern(e.to_string()))?
        .compile_matcher();
    let mut matches = Vec::new();
    for snapshot in repo.list_snapshots().await? {
        for entry in list_files(repo, &snapshot).await? {
            if matcher.is_match(&entry.path) {
                matches.push(FindMatch {
                    snapshot,
                    path: entry.path,
                    kind: entry.kind,
                    size: entry.size,
                });
            }
        }
    }
    Ok(matches)
}

/// Recursively append the entries of tree `tree_id` (under `prefix`) to `out`.
fn list_tree<'a, B: StorageBackend>(
    repo: &'a Repository<B>,
    tree_id: Id,
    prefix: String,
    out: &'a mut Vec<ListEntry>,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let tree = repo.load_tree(&tree_id).await?;
        for node in &tree.nodes {
            let name = String::from_utf8_lossy(&node.name);
            let path = if prefix.is_empty() {
                name.into_owned()
            } else {
                format!("{prefix}/{name}")
            };
            out.push(ListEntry {
                path: path.clone(),
                kind: node.kind,
                size: node.size,
                mode: node.mode,
                uid: node.uid,
                gid: node.gid,
                mtime_ns: node.mtime_ns,
                rdev: node.rdev,
                link_target: node.link_target.clone(),
            });
            if let (EntryKind::Dir, Some(subtree)) = (node.kind, node.subtree) {
                list_tree(repo, subtree, path, out).await?;
            }
        }
        Ok(())
    })
}

/// How a path changed between two snapshots; see [`diff`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    /// Present only in the newer snapshot.
    Added,
    /// Present only in the older snapshot.
    Removed,
    /// Present in both, but with a different kind, size, or metadata.
    Modified,
}

/// Which aspects of a [`Modified`](DiffKind::Modified) entry changed. Every field
/// is `false` for added and removed entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiffDetail {
    /// The entry type changed (e.g. a file became a symlink).
    pub kind: bool,
    /// The logical size changed.
    pub size: bool,
    /// The permission bits changed.
    pub mode: bool,
    /// The owning uid or gid changed.
    pub owner: bool,
    /// The modification time changed.
    pub mtime: bool,
    /// A symlink's target or a device node's number changed.
    pub target: bool,
}

impl DiffDetail {
    /// What changed between two entries at the same path.
    fn between(old: &ListEntry, new: &ListEntry) -> Self {
        Self {
            kind: old.kind != new.kind,
            size: old.size != new.size,
            mode: old.mode != new.mode,
            owner: old.uid != new.uid || old.gid != new.gid,
            mtime: old.mtime_ns != new.mtime_ns,
            target: old.link_target != new.link_target || old.rdev != new.rdev,
        }
    }

    /// Whether any aspect changed.
    #[must_use]
    pub fn any(self) -> bool {
        self.kind || self.size || self.mode || self.owner || self.mtime || self.target
    }

    /// The names of the changed aspects, for display (`["mode", "mtime"]`).
    #[must_use]
    pub fn labels(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.kind {
            out.push("type");
        }
        if self.size {
            out.push("size");
        }
        if self.mode {
            out.push("mode");
        }
        if self.owner {
            out.push("owner");
        }
        if self.mtime {
            out.push("mtime");
        }
        if self.target {
            out.push("target");
        }
        out
    }
}

/// A single change reported by [`diff`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    /// Path relative to the backup root.
    pub path: String,
    /// The kind of change.
    pub change: DiffKind,
    /// For a [`Modified`](DiffKind::Modified) entry, which aspects changed.
    pub detail: DiffDetail,
}

/// Compare two snapshots by path, reporting added, removed, and modified entries.
/// An entry is modified if its kind, size, mode, owner, mtime, symlink target, or
/// device number differs; [`DiffEntry::detail`] says which. Unchanged entries are
/// omitted and the result is sorted by path.
pub async fn diff<B: StorageBackend>(
    repo: &Repository<B>,
    from: &Id,
    to: &Id,
) -> Result<Vec<DiffEntry>> {
    let old: HashMap<String, ListEntry> = list_files(repo, from)
        .await?
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();
    let new: HashMap<String, ListEntry> = list_files(repo, to)
        .await?
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();

    let mut changes = Vec::new();
    for (path, entry) in &new {
        match old.get(path) {
            None => changes.push(DiffEntry {
                path: path.clone(),
                change: DiffKind::Added,
                detail: DiffDetail::default(),
            }),
            Some(prev) => {
                let detail = DiffDetail::between(prev, entry);
                if detail.any() {
                    changes.push(DiffEntry {
                        path: path.clone(),
                        change: DiffKind::Modified,
                        detail,
                    });
                }
            }
        }
    }
    for path in old.keys() {
        if !new.contains_key(path) {
            changes.push(DiffEntry {
                path: path.clone(),
                change: DiffKind::Removed,
                detail: DiffDetail::default(),
            });
        }
    }
    changes.sort_by(|x, y| x.path.cmp(&y.path));
    Ok(changes)
}

/// Extract the contents of a single file at `path` (relative to the backup
/// root) from `snapshot`, without restoring anything else.
pub async fn dump<B: StorageBackend>(
    repo: &Repository<B>,
    snapshot: &Id,
    path: &str,
) -> Result<Vec<u8>> {
    let root = repo.load_snapshot(snapshot).await?.tree;
    let node = find_node(repo, root, path).await?;
    match node.kind {
        EntryKind::File => Ok(repo.load_file(&node.content).await?),
        _ => Err(EngineError::NotInSnapshot(format!(
            "{path} is not a regular file"
        ))),
    }
}

/// Navigate a tree DAG to the node at `path`.
async fn find_node<B: StorageBackend>(
    repo: &Repository<B>,
    root_tree: Id,
    path: &str,
) -> Result<Node> {
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return Err(EngineError::NotInSnapshot(path.to_string()));
    }
    let mut tree_id = root_tree;
    for (i, component) in components.iter().enumerate() {
        let tree = repo.load_tree(&tree_id).await?;
        let node = tree
            .nodes
            .into_iter()
            .find(|n| n.name.as_slice() == component.as_bytes())
            .ok_or_else(|| EngineError::NotInSnapshot(path.to_string()))?;
        if i + 1 == components.len() {
            return Ok(node);
        }
        match node.subtree {
            Some(subtree) => tree_id = subtree,
            None => return Err(EngineError::NotInSnapshot(path.to_string())),
        }
    }
    Err(EngineError::NotInSnapshot(path.to_string()))
}

/// Back up the regular file at `path` into a `File` [`Node`] named `name`. If
/// `parent` (the matching node from the previous snapshot) has the same size and
/// mtime, its chunk list is reused without re-reading; otherwise the file is read
/// and chunked (unless `dry_run`). Updates `stats`.
/// Read-only configuration threaded through the recursive backup walk, bundled
/// to keep [`backup_dir`]/[`backup_file`] signatures small.
#[derive(Clone, Copy)]
struct BackupCtx<'a> {
    /// Entry-name globs to skip.
    excludes: &'a GlobSet,
    /// Preview only — read and count, but write nothing.
    dry_run: bool,
    /// Skip a discovered regular file larger than this.
    max_file_size: Option<u64>,
    /// With `--one-file-system`, the device of the source root; a subdirectory on
    /// a different device is not descended into.
    root_dev: Option<u64>,
    /// Marker filenames whose presence in a subdirectory excludes it.
    exclude_if_present: &'a [String],
    /// Whether a subdirectory bearing a signed `CACHEDIR.TAG` is excluded.
    exclude_caches: bool,
    /// On-disk stat cache to reuse unchanged files from, if enabled.
    cache: Option<&'a StatCache>,
    /// Batched cache updates (flushed once after the walk); present iff `cache`.
    cache_updates: Option<&'a Mutex<Vec<(u64, u64, CacheEntry)>>>,
    /// Per-file progress callback (`--verbose`).
    progress: Option<ProgressFn<'a>>,
}

/// The standard `CACHEDIR.TAG` signature (the Bryce/Pearce cache-directory
/// convention); a directory whose `CACHEDIR.TAG` begins with these bytes is a
/// cache and is skipped under `--exclude-caches`.
const CACHEDIR_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// Whether directory `dir` should be skipped: it holds one of the
/// `--exclude-if-present` marker files, or (with `--exclude-caches`) a
/// `CACHEDIR.TAG` carrying the standard cache signature.
fn dir_has_exclude_marker(dir: &Path, ctx: &BackupCtx<'_>) -> bool {
    if ctx.exclude_if_present.iter().any(|m| dir.join(m).exists()) {
        return true;
    }
    if ctx.exclude_caches {
        if let Ok(bytes) = std::fs::read(dir.join("CACHEDIR.TAG")) {
            return bytes.starts_with(CACHEDIR_SIGNATURE);
        }
    }
    false
}

async fn backup_file<B: StorageBackend>(
    repo: &mut Repository<B>,
    path: &Path,
    name: Vec<u8>,
    meta: &std::fs::Metadata,
    parent: Option<&Node>,
    stats: &mut SnapshotStats,
    ctx: BackupCtx<'_>,
) -> Result<Node> {
    let mtime = mtime_ns(meta);
    let (dev, ino) = hardlink_ids(meta);
    // The cache is keyed by the file's true (device, inode), populated for every
    // file (hardlink_ids is zero for non-hardlinks, by design).
    let (cache_dev, cache_ino) = file_identity(meta);
    // Reuse the chunk list of an unchanged file (same size and mtime) without
    // re-reading it. First try the matching node from the parent snapshot's
    // tree; otherwise, if a stat cache is in use, look the file up by its
    // (device, inode) identity — which also catches a renamed or moved file. A
    // cache hit is trusted only if every chunk it names is still present in the
    // repository, so a stale or foreign cache degrades to a re-read.
    let mut from_cache = false;
    let mut reuse = parent.and_then(|prev| {
        (prev.kind == EntryKind::File && prev.size == meta.len() && prev.mtime_ns == mtime)
            .then(|| prev.content.clone())
    });
    if reuse.is_none() && cache_ino != 0 {
        if let Some(cache) = ctx.cache {
            if let Some(entry) = cache.lookup(cache_dev, cache_ino) {
                if entry.size == meta.len()
                    && entry.mtime_ns == mtime
                    && entry.ids.iter().all(|id| repo.has_blob(id))
                {
                    reuse = Some(entry.ids);
                    from_cache = true;
                }
            }
        }
    }
    let status = if reuse.is_some() {
        FileStatus::Unmodified
    } else if parent.is_some() {
        FileStatus::Changed
    } else {
        FileStatus::New
    };
    if let Some(report) = ctx.progress {
        report(path, status);
    }
    let (content, size) = if let Some(content) = reuse {
        stats.files_unmodified += 1;
        (content, meta.len())
    } else {
        if parent.is_some() {
            stats.files_changed += 1;
        } else {
            stats.files_new += 1;
        }
        if ctx.dry_run {
            (Vec::new(), meta.len())
        } else {
            // Stream the file through the chunker so peak memory is bounded by the
            // chunk size, not the file size — large files don't load whole. A
            // sparse file's holes are skipped (read as synthesized zeros) instead
            // of being read from disk.
            let source = open_file_source(path, meta)?;
            repo.save_file_reader(source).await?
        }
    };
    stats.bytes_processed += size;
    // Record this file's identity → chunk ids for the next backup, unless it was
    // served verbatim from the cache (the entry is already current). Skipped on a
    // dry run, where `content` is empty.
    if !from_cache && !ctx.dry_run && cache_ino != 0 {
        if let Some(updates) = ctx.cache_updates {
            updates.lock().unwrap().push((
                cache_dev,
                cache_ino,
                CacheEntry {
                    size,
                    mtime_ns: mtime,
                    ids: content.clone(),
                },
            ));
        }
    }
    Ok(Node {
        name,
        kind: EntryKind::File,
        mode: mode_of(meta),
        uid: uid_of(meta),
        gid: gid_of(meta),
        mtime_ns: mtime,
        ctime_ns: 0,
        size,
        content,
        subtree: None,
        link_target: None,
        dev,
        ino,
        xattrs: read_xattrs(path),
        rdev: 0,
        sparse: is_sparse(meta),
    })
}

/// Recursively back up `dir`, returning the id of its `Tree` object. `parent`
/// is the id of the same directory's tree in the previous snapshot, if any, and
/// `stats` accumulates new/changed/unmodified counters.
fn backup_dir<'a, B: StorageBackend>(
    repo: &'a mut Repository<B>,
    dir: PathBuf,
    parent: Option<Id>,
    stats: &'a mut SnapshotStats,
    ctx: BackupCtx<'a>,
) -> Pin<Box<dyn Future<Output = Result<Id>> + 'a>> {
    Box::pin(async move {
        // Load the parent directory's entries for incremental reuse.
        let parent_nodes: HashMap<Vec<u8>, Node> = match parent {
            Some(tree_id) => match repo.load_tree(&tree_id).await {
                Ok(tree) => tree
                    .nodes
                    .into_iter()
                    .map(|n| (n.name.clone(), n))
                    .collect(),
                Err(_) => HashMap::new(),
            },
            None => HashMap::new(),
        };

        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .map_err(|e| io_err(&dir, e))?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| io_err(&dir, e))?;
        // Sort by name for a deterministic, dedup-friendly tree.
        entries.sort_by_key(std::fs::DirEntry::file_name);

        let mut nodes = Vec::with_capacity(entries.len());
        for entry in entries {
            let file_name = entry.file_name();
            if ctx.excludes.is_match(&file_name) {
                continue;
            }
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).map_err(|e| io_err(&path, e))?;
            let name = file_name.as_encoded_bytes().to_vec();
            let kind = meta.file_type();
            let mtime = mtime_ns(&meta);

            // Skip regular files over the size limit (--exclude-larger-than).
            if let Some(limit) = ctx.max_file_size {
                if kind.is_file() && meta.len() > limit {
                    continue;
                }
            }
            // With --one-file-system, don't descend into a mounted subdirectory.
            if let Some(root_dev) = ctx.root_dev {
                if kind.is_dir() && dev_of(&meta) != root_dev {
                    continue;
                }
            }
            // Skip a subdirectory marked for exclusion (--exclude-if-present /
            // --exclude-caches): the directory and all its contents are omitted.
            if kind.is_dir() && dir_has_exclude_marker(&path, &ctx) {
                continue;
            }

            let node = if kind.is_dir() {
                let parent_sub = parent_nodes
                    .get(&name)
                    .and_then(|n| (n.kind == EntryKind::Dir).then_some(n.subtree).flatten());
                let subtree = backup_dir(repo, path.clone(), parent_sub, stats, ctx).await?;
                stats.dirs += 1;
                Node {
                    name,
                    kind: EntryKind::Dir,
                    mode: mode_of(&meta),
                    uid: uid_of(&meta),
                    gid: gid_of(&meta),
                    mtime_ns: mtime,
                    ctime_ns: 0,
                    size: 0,
                    content: Vec::new(),
                    subtree: Some(subtree),
                    link_target: None,
                    dev: 0,
                    ino: 0,
                    xattrs: read_xattrs(&path),
                    rdev: 0,
                    sparse: false,
                }
            } else if kind.is_file() {
                let parent_node = parent_nodes.get(&name);
                backup_file(repo, &path, name, &meta, parent_node, stats, ctx).await?
            } else if kind.is_symlink() {
                let target = std::fs::read_link(&path).map_err(|e| io_err(&path, e))?;
                Node {
                    name,
                    kind: EntryKind::Symlink,
                    mode: mode_of(&meta),
                    uid: uid_of(&meta),
                    gid: gid_of(&meta),
                    mtime_ns: mtime,
                    ctime_ns: 0,
                    size: 0,
                    content: Vec::new(),
                    subtree: None,
                    link_target: Some(target.into_os_string().into_encoded_bytes()),
                    dev: 0,
                    ino: 0,
                    xattrs: read_xattrs(&path),
                    rdev: 0,
                    sparse: false,
                }
            } else if let Some(special) = special_kind(&kind) {
                // FIFO / socket / device: record the node (no content) so the
                // snapshot faithfully reflects the tree; restore recreates FIFOs
                // and devices (sockets are runtime-only and stay record-only).
                stats.files_new += 1;
                Node {
                    name,
                    kind: special,
                    mode: mode_of(&meta),
                    uid: uid_of(&meta),
                    gid: gid_of(&meta),
                    mtime_ns: mtime,
                    ctime_ns: 0,
                    size: 0,
                    content: Vec::new(),
                    subtree: None,
                    link_target: None,
                    dev: 0,
                    ino: 0,
                    xattrs: read_xattrs(&path),
                    rdev: rdev_of(&meta),
                    sparse: false,
                }
            } else {
                continue; // unknown entry type
            };
            nodes.push(node);
        }

        let tree = Tree {
            version: TREE_VERSION,
            nodes,
        };
        if ctx.dry_run {
            // No snapshot is committed, so the tree id is never referenced.
            Ok(Id::from_bytes([0u8; 32]))
        } else {
            Ok(repo.save_tree(&tree).await?)
        }
    })
}

/// Recursively restore the tree `tree_id` into the directory `dir`, where `rel`
/// is `dir`'s path relative to the restore root (for `filter` matching).
#[allow(clippy::too_many_arguments)]
fn restore_tree<'a, B: StorageBackend>(
    repo: &'a Repository<B>,
    tree_id: Id,
    dir: PathBuf,
    rel: PathBuf,
    links: &'a std::sync::Mutex<HashMap<(u64, u64), PathBuf>>,
    reporter: &'a Reporter,
    options: RestoreOptions,
    filter: &'a RestoreFilter,
    progress: Option<RestoreProgressFn<'a>>,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        use futures::stream::{StreamExt, TryStreamExt};

        let tree = repo.load_tree(&tree_id).await?;
        // Directories (recurse) and symlinks first, sequentially, to build the
        // structure. A subdirectory's mtime is replayed after its own subtree.
        for node in &tree.nodes {
            let name = osstring_from_bytes(&node.name);
            let path = dir.join(&name);
            let rel_child = rel.join(&name);
            // Apply the include/exclude filter: an excluded directory is pruned,
            // and any leaf entry not permitted is skipped (plain files are gated
            // again in the passes below).
            if node.kind == EntryKind::Dir {
                if !filter.allows_dir(&rel_child) {
                    continue;
                }
            } else if !filter.allows_leaf(&rel_child) {
                continue;
            }
            // For non-file entries, skip-existing means "leave it if already there".
            let present = options.skip_existing && exists(&path);
            match node.kind {
                EntryKind::Dir => {
                    std::fs::create_dir_all(&path).map_err(|e| io_err(&path, e))?;
                    if let Some(subtree) = node.subtree {
                        restore_tree(
                            repo,
                            subtree,
                            path.clone(),
                            rel_child.clone(),
                            links,
                            reporter,
                            options,
                            filter,
                            progress,
                        )
                        .await?;
                    }
                    apply_metadata(&path, node, reporter);
                }
                EntryKind::Symlink => {
                    if let (false, Some(target)) = (present, &node.link_target) {
                        symlink(&osstring_from_bytes(target), &path)?;
                        set_owner(&path, node.uid, node.gid, false, reporter);
                        write_xattrs(&path, &node.xattrs, reporter);
                    }
                }
                EntryKind::Fifo if !present => {
                    make_fifo(&path, node.mode)?;
                    apply_special_metadata(&path, node, reporter);
                }
                EntryKind::CharDevice | EntryKind::BlockDevice if !present => {
                    // Device nodes need CAP_MKNOD; warn and skip (rather than fail
                    // the restore) when unprivileged, replaying metadata only if
                    // the node was actually created.
                    match make_device(&path, node.mode, node.kind, node.rdev) {
                        Ok(()) => apply_special_metadata(&path, node, reporter),
                        Err(e) => record_warning(
                            reporter,
                            format!("skipped device node {}: {e}", path.display()),
                        ),
                    }
                }
                // Files are handled below; sockets are runtime-only and are
                // recorded but not recreated; already-present specials are kept.
                _ => {}
            }
        }
        // Plain files (no hardlinks): reconstruct concurrently — each reads its
        // chunks and writes a distinct path, so the writes don't conflict. This
        // directory's own mtime is replayed by the caller after this call
        // returns, i.e. after the files.
        futures::stream::iter(
            tree.nodes
                .iter()
                .filter(|n| {
                    n.kind == EntryKind::File
                        && n.ino == 0
                        && filter.allows_leaf(&rel.join(osstring_from_bytes(&n.name)))
                })
                .map(|node| {
                    let path = dir.join(osstring_from_bytes(&node.name));
                    async move {
                        restore_file(repo, &path, node, reporter, options, progress).await?;
                        Ok::<(), EngineError>(())
                    }
                }),
        )
        .buffer_unordered(RESTORE_CONCURRENCY)
        .try_collect::<Vec<()>>()
        .await?;

        // Hardlinked files (nlink > 1 at backup): the first entry seen for each
        // source (dev, ino) materializes the content; later entries — possibly in
        // other directories — become hard links to it. Done sequentially against
        // the shared inode map; hardlinks are rare, so this isn't a hot path.
        for node in tree.nodes.iter().filter(|n| {
            n.kind == EntryKind::File
                && n.ino != 0
                && filter.allows_leaf(&rel.join(osstring_from_bytes(&n.name)))
        }) {
            let path = dir.join(osstring_from_bytes(&node.name));
            let target = {
                let mut map = links.lock().expect("restore link map poisoned");
                match map.get(&(node.dev, node.ino)) {
                    Some(existing) => Some(existing.clone()),
                    None => {
                        map.insert((node.dev, node.ino), path.clone());
                        None
                    }
                }
            };
            match target {
                Some(existing) => {
                    // Leave an already-present link in place when resuming.
                    if !(options.skip_existing && exists(&path)) {
                        std::fs::hard_link(&existing, &path).map_err(|e| io_err(&path, e))?;
                    }
                }
                None => {
                    restore_file(repo, &path, node, reporter, options, progress).await?;
                }
            }
        }
        Ok(())
    })
}

/// Reconstruct an `OsString` from bytes produced by `OsStr::as_encoded_bytes`.
fn osstring_from_bytes(bytes: &[u8]) -> OsString {
    // SAFETY: `bytes` were produced by `OsStr::as_encoded_bytes` during backup,
    // which is exactly the precondition of `from_encoded_bytes_unchecked`.
    unsafe { OsString::from_encoded_bytes_unchecked(bytes.to_vec()) }
}

/// Concurrent chunk reads while streaming a single file's content to disk.
const RESTORE_FILE_CONCURRENCY: usize = 4;

/// Stream a file's content from the repository straight to `path`, holding only a
/// few chunks in memory regardless of the file's size — the restore counterpart
/// to streaming backup. Chunks are read with bounded look-ahead concurrency
/// (helpful on a high-latency object store) and written in order.
///
/// When `sparse`, each all-zero 4 KiB block is skipped so the filesystem leaves
/// it unallocated; the written bytes are identical either way (holes read back as
/// zeros). Blocks are aligned to each chunk rather than the absolute file grid,
/// so a chunk straddling a hole edge may allocate one extra block — negligible,
/// since a hole's interior chunks are wholly zero and skipped entirely.
async fn restore_file_streaming<B: StorageBackend>(
    repo: &Repository<B>,
    path: &Path,
    content: &[Id],
    sparse: bool,
) -> Result<()> {
    use futures::stream::{StreamExt, TryStreamExt};
    use std::io::{Seek, SeekFrom, Write};
    const BLOCK: usize = 4096;

    let mut file = std::fs::File::create(path).map_err(|e| io_err(path, e))?;
    let mut offset: u64 = 0;
    let mut chunks = futures::stream::iter(content.iter().map(|id| repo.load_blob(id)))
        .buffered(RESTORE_FILE_CONCURRENCY);
    while let Some(chunk) = chunks.try_next().await? {
        if sparse {
            for (i, block) in chunk.chunks(BLOCK).enumerate() {
                if block.iter().any(|&b| b != 0) {
                    file.seek(SeekFrom::Start(offset + (i * BLOCK) as u64))
                        .map_err(|e| io_err(path, e))?;
                    file.write_all(block).map_err(|e| io_err(path, e))?;
                }
            }
        } else {
            file.write_all(&chunk).map_err(|e| io_err(path, e))?;
        }
        offset += chunk.len() as u64;
    }
    if sparse {
        // Reflect the exact length (and any trailing hole) in the file size.
        file.set_len(offset).map_err(|e| io_err(path, e))?;
    }
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &std::ffi::OsStr, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link).map_err(|e| io_err(link, e))
}

#[cfg(not(unix))]
fn symlink(_target: &std::ffi::OsStr, link: &Path) -> Result<()> {
    Err(io_err(
        link,
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlinks are not supported on this platform",
        ),
    ))
}

/// The [`EntryKind`] of a FIFO, socket, or device file, or `None` for others.
#[cfg(unix)]
fn special_kind(kind: &std::fs::FileType) -> Option<EntryKind> {
    use std::os::unix::fs::FileTypeExt;
    if kind.is_fifo() {
        Some(EntryKind::Fifo)
    } else if kind.is_socket() {
        Some(EntryKind::Socket)
    } else if kind.is_char_device() {
        Some(EntryKind::CharDevice)
    } else if kind.is_block_device() {
        Some(EntryKind::BlockDevice)
    } else {
        None
    }
}

#[cfg(not(unix))]
fn special_kind(_kind: &std::fs::FileType) -> Option<EntryKind> {
    None
}

/// Recreate a FIFO at `path` with the given mode bits.
#[cfg(unix)]
fn make_fifo(path: &Path, mode: u32) -> Result<()> {
    use rustix::fs::{CWD, FileType, Mode, mknodat};
    mknodat(
        CWD,
        path,
        FileType::Fifo,
        Mode::from_raw_mode((mode & 0o7777) as _),
        0,
    )
    .map_err(|e| io_err(path, e.into()))
}

#[cfg(not(unix))]
fn make_fifo(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Recreate a character or block device node at `path`. `rdev` is the device
/// number in the same encoding `stat` reported it (rustix's `Dev` matches the C
/// library's), so it round-trips for any major/minor. Returns `Err` if `mknod`
/// fails — notably `EPERM` when unprivileged — so the caller can skip rather
/// than abort the whole restore.
#[cfg(unix)]
fn make_device(path: &Path, mode: u32, kind: EntryKind, rdev: u64) -> Result<()> {
    use rustix::fs::{CWD, FileType, Mode, mknodat};
    let file_type = match kind {
        EntryKind::CharDevice => FileType::CharacterDevice,
        EntryKind::BlockDevice => FileType::BlockDevice,
        _ => return Ok(()),
    };
    mknodat(
        CWD,
        path,
        file_type,
        Mode::from_raw_mode((mode & 0o7777) as _),
        rdev,
    )
    .map_err(|e| io_err(path, e.into()))
}

#[cfg(not(unix))]
fn make_device(_path: &Path, _mode: u32, _kind: EntryKind, _rdev: u64) -> Result<()> {
    Ok(())
}

/// Best-effort replay of a node's owner (Unix), mode (Unix), and mtime onto `path`.
fn apply_metadata(path: &Path, node: &Node, reporter: &Reporter) {
    #[cfg(unix)]
    {
        // chown before chmod: chown can clear setuid/setgid bits.
        set_owner(path, node.uid, node.gid, true, reporter);
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(node.mode));
    }
    write_xattrs(path, &node.xattrs, reporter);
    let mtime = filetime::FileTime::from_unix_time(
        node.mtime_ns.div_euclid(1_000_000_000),
        node.mtime_ns.rem_euclid(1_000_000_000) as u32,
    );
    let _ = filetime::set_file_mtime(path, mtime);
}

/// Replay mode + mtime onto a freshly created special file (FIFO).
///
/// Unlike [`apply_metadata`], this never opens the target: `filetime` would
/// open the path to set times, and opening a FIFO blocks until a writer
/// appears. We use `utimensat` (path-based, no open) and leave atime untouched
/// via `UTIME_OMIT`. The explicit `chmod` also corrects for umask applied by
/// `mknodat`.
#[cfg(unix)]
fn apply_special_metadata(path: &Path, node: &Node, reporter: &Reporter) {
    use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, UTIME_OMIT, utimensat};
    use std::os::unix::fs::PermissionsExt;
    // chown before chmod: chown can clear setuid/setgid bits.
    set_owner(path, node.uid, node.gid, true, reporter);
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(node.mode & 0o7777));
    write_xattrs(path, &node.xattrs, reporter);
    let times = Timestamps {
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        last_modification: Timespec {
            tv_sec: node.mtime_ns.div_euclid(1_000_000_000) as _,
            tv_nsec: node.mtime_ns.rem_euclid(1_000_000_000) as _,
        },
    };
    let _ = utimensat(CWD, path, &times, AtFlags::empty());
}

#[cfg(not(unix))]
fn apply_special_metadata(_path: &Path, _node: &Node, _reporter: &Reporter) {}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    if meta.is_dir() { 0o755 } else { 0o644 }
}

#[cfg(unix)]
fn uid_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.uid()
}

#[cfg(not(unix))]
fn uid_of(_meta: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn gid_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.gid()
}

#[cfg(not(unix))]
fn gid_of(_meta: &std::fs::Metadata) -> u32 {
    0
}

/// The `(dev, ino)` hardlink-group key for a regular file, or `(0, 0)` when the
/// file has only one link (so restore treats it as an ordinary file). Only
/// `nlink > 1` files can be hardlinks, so the common case stays zero-cost.
#[cfg(unix)]
fn hardlink_ids(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    if meta.nlink() > 1 {
        (meta.dev(), meta.ino())
    } else {
        (0, 0)
    }
}

#[cfg(not(unix))]
fn hardlink_ids(_meta: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// The `(device, inode)` identity of a file, used as the stat-cache key (unlike
/// [`hardlink_ids`], it is populated for every file, not only hardlinks).
/// Returns `(0, 0)` on platforms without inode numbers, where the cache is a
/// no-op.
#[cfg(unix)]
fn file_identity(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn file_identity(_meta: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// The represented device number (`st_rdev`) of `meta`; non-zero only for
/// device files, so it doubles as the value to store on any special node.
#[cfg(unix)]
fn rdev_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.rdev()
}

#[cfg(not(unix))]
fn rdev_of(_meta: &std::fs::Metadata) -> u64 {
    0
}

/// Whether `meta` describes a file with holes — fewer allocated 512-byte blocks
/// than its logical size. The standard sparse heuristic; recorded so restore can
/// recreate the holes.
#[cfg(unix)]
fn is_sparse(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.blocks().saturating_mul(512) < meta.size()
}

#[cfg(not(unix))]
fn is_sparse(_meta: &std::fs::Metadata) -> bool {
    false
}

/// The id of the filesystem `meta` lives on, for `--one-file-system`.
#[cfg(unix)]
fn dev_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.dev()
}

#[cfg(not(unix))]
fn dev_of(_meta: &std::fs::Metadata) -> u64 {
    0
}

/// A [`Read`] over a file's content that skips reading holes: it consults
/// `SEEK_DATA`/`SEEK_HOLE` and synthesizes zeros for hole regions instead of
/// reading them from disk. The byte stream is identical to reading the file
/// normally (holes read back as zeros), so the chunker produces the same chunks
/// and the backup still dedups — but a mostly-empty sparse file is barely read.
#[cfg(unix)]
struct SparseReader {
    file: std::fs::File,
    pos: u64,
    size: u64,
}

#[cfg(unix)]
impl std::io::Read for SparseReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use rustix::fs::{SeekFrom, seek};
        use std::os::unix::fs::FileExt;
        if buf.is_empty() || self.pos >= self.size {
            return Ok(0);
        }
        // Find where the next data begins at or after `pos`. The seek moves the
        // descriptor's offset, but we read with `read_at` (pread), so it's moot.
        let data_start = match seek(&self.file, SeekFrom::Data(self.pos)) {
            Ok(d) => d,
            // No data at/after `pos`: the remainder is a hole running to EOF.
            Err(rustix::io::Errno::NXIO) => self.size,
            Err(e) => return Err(e.into()),
        };
        if data_start > self.pos {
            // `[pos, data_start)` is a hole — emit zeros without touching disk.
            let n = (data_start - self.pos).min(buf.len() as u64) as usize;
            buf[..n].fill(0);
            self.pos += n as u64;
            return Ok(n);
        }
        // `pos` is within data; read up to the next hole (the extent's end).
        let data_end = seek(&self.file, SeekFrom::Hole(self.pos)).map_err(std::io::Error::from)?;
        let n = (data_end - self.pos).min(buf.len() as u64) as usize;
        let read = self.file.read_at(&mut buf[..n], self.pos)?;
        self.pos += read as u64;
        Ok(read)
    }
}

/// The byte source for backing up a regular file: a plain handle, or a
/// hole-skipping [`SparseReader`] for sparse files. Both yield identical bytes.
enum FileSource {
    Plain(std::fs::File),
    #[cfg(unix)]
    Sparse(SparseReader),
}

impl std::io::Read for FileSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            FileSource::Plain(f) => f.read(buf),
            #[cfg(unix)]
            FileSource::Sparse(s) => s.read(buf),
        }
    }
}

/// Open `path` for backup, choosing a hole-skipping reader for sparse files.
fn open_file_source(path: &Path, meta: &std::fs::Metadata) -> Result<FileSource> {
    let file = std::fs::File::open(path).map_err(|e| io_err(path, e))?;
    if is_sparse(meta) {
        Ok(sparse_source(file, meta.len()))
    } else {
        Ok(FileSource::Plain(file))
    }
}

#[cfg(unix)]
fn sparse_source(file: std::fs::File, size: u64) -> FileSource {
    FileSource::Sparse(SparseReader { file, pos: 0, size })
}

#[cfg(not(unix))]
fn sparse_source(file: std::fs::File, _size: u64) -> FileSource {
    FileSource::Plain(file)
}

/// The effective owner of the running process, recorded on the snapshot object.
#[cfg(unix)]
fn process_owner() -> (u32, u32) {
    (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    )
}

#[cfg(not(unix))]
fn process_owner() -> (u32, u32) {
    (0, 0)
}

/// Best-effort replay of ownership onto a restored entry. `chown` requires
/// privilege (CAP_CHOWN); a failure is recorded as a warning (an unprivileged
/// restore keeps the running user's ownership, matching restic/borg) rather than
/// aborting. `follow` controls whether a symlink is dereferenced (false =
/// `lchown` the link itself).
#[cfg(unix)]
fn set_owner(path: &Path, uid: u32, gid: u32, follow: bool, reporter: &Reporter) {
    use rustix::fs::{AtFlags, CWD, Gid, Uid, chownat};
    let flags = if follow {
        AtFlags::empty()
    } else {
        AtFlags::SYMLINK_NOFOLLOW
    };
    if let Err(e) = chownat(
        CWD,
        path,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
        flags,
    ) {
        record_warning(
            reporter,
            format!("could not set owner of {}: {e}", path.display()),
        );
    }
}

#[cfg(not(unix))]
fn set_owner(_path: &Path, _uid: u32, _gid: u32, _follow: bool, _reporter: &Reporter) {}

/// Read all extended attributes of `path` without following symlinks, as a
/// list of `(name, value)` byte pairs sorted by name. Best-effort: returns
/// empty on any error (including filesystems without xattr support) so a backup
/// is never blocked by xattrs.
#[cfg(unix)]
fn read_xattrs(path: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    use rustix::fs::{lgetxattr, llistxattr};
    // List names (NUL-separated): query the size with an empty buffer, then fetch.
    let list_len = match llistxattr(path, &mut Vec::<u8>::new()) {
        Ok(n) if n > 0 => n,
        _ => return Vec::new(),
    };
    let mut names = vec![0u8; list_len];
    let n = match llistxattr(path, &mut names) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    names.truncate(n);

    let mut out = Vec::new();
    for name in names.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        let Ok(cname) = std::ffi::CString::new(name) else {
            continue;
        };
        let value_len = match lgetxattr(path, cname.as_c_str(), &mut Vec::<u8>::new()) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let mut value = vec![0u8; value_len];
        match lgetxattr(path, cname.as_c_str(), &mut value) {
            Ok(n) => {
                value.truncate(n);
                out.push((name.to_vec(), value));
            }
            Err(_) => continue,
        }
    }
    out.sort();
    out
}

#[cfg(not(unix))]
fn read_xattrs(_path: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    Vec::new()
}

/// Replay extended attributes onto a restored `path` without following symlinks.
/// Best-effort: `security.*`/`trusted.*` may need privilege, so a failure is
/// recorded as a warning rather than aborting, matching restic/borg.
#[cfg(unix)]
fn write_xattrs(path: &Path, xattrs: &[(Vec<u8>, Vec<u8>)], reporter: &Reporter) {
    use rustix::fs::{XattrFlags, lsetxattr};
    for (name, value) in xattrs {
        if let Ok(cname) = std::ffi::CString::new(name.clone()) {
            if let Err(e) = lsetxattr(path, cname.as_c_str(), value, XattrFlags::empty()) {
                record_warning(
                    reporter,
                    format!(
                        "could not set xattr {} on {}: {e}",
                        String::from_utf8_lossy(name),
                        path.display()
                    ),
                );
            }
        }
    }
}

#[cfg(not(unix))]
fn write_xattrs(_path: &Path, _xattrs: &[(Vec<u8>, Vec<u8>)], _reporter: &Reporter) {}

fn mtime_ns(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluice_crypto::KdfParams;
    use sluice_store::{FileType, MemoryBackend};

    fn fast() -> KdfParams {
        KdfParams {
            m_cost_kib: 16,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[tokio::test]
    async fn backup_restore_roundtrips_a_directory_tree() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b.txt"), b"bravo bravo").unwrap();
        std::fs::write(src.path().join("sub/c.bin"), vec![7u8; 1000]).unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let dst = tempfile::tempdir().unwrap();
        let report = restore(&repo, &snap, dst.path()).await.unwrap();
        assert_eq!(report.warnings, 0, "clean restore should have no warnings");

        assert_eq!(std::fs::read(dst.path().join("a.txt")).unwrap(), b"alpha");
        assert_eq!(
            std::fs::read(dst.path().join("sub/b.txt")).unwrap(),
            b"bravo bravo"
        );
        assert_eq!(
            std::fs::read(dst.path().join("sub/c.bin")).unwrap(),
            vec![7u8; 1000]
        );
    }

    #[tokio::test]
    async fn restore_reconstructs_many_files_concurrently() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        for i in 0..25u8 {
            std::fs::write(
                src.path().join(format!("f{i}")),
                format!("contents {i}").as_bytes(),
            )
            .unwrap();
            std::fs::write(
                src.path().join(format!("sub/g{i}")),
                vec![i; 100 + i as usize],
            )
            .unwrap();
        }
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        for i in 0..25u8 {
            assert_eq!(
                std::fs::read(out.path().join(format!("f{i}"))).unwrap(),
                format!("contents {i}").as_bytes()
            );
            assert_eq!(
                std::fs::read(out.path().join(format!("sub/g{i}"))).unwrap(),
                vec![i; 100 + i as usize]
            );
        }
    }

    #[tokio::test]
    async fn backup_restore_streams_a_large_multichunk_file() {
        // Larger than the 4 MiB max chunk and incompressible, so it spans several
        // content-defined chunks and exercises the streaming restore writer across
        // chunk boundaries.
        let mut data = vec![0u8; 5 * 1024 * 1024 + 777];
        let mut state = 0x9E37_79B9u32;
        for b in data.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (state >> 24) as u8;
        }
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("big"), &data).unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        assert_eq!(std::fs::read(out.path().join("big")).unwrap(), data);
    }

    #[tokio::test]
    async fn backup_restore_handles_empty_files_and_dirs() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("empty.txt"), b"").unwrap(); // zero bytes
        std::fs::create_dir(src.path().join("emptydir")).unwrap(); // empty directory
        std::fs::create_dir_all(src.path().join("a/b/c")).unwrap(); // deeply nested, empty
        std::fs::write(src.path().join("normal"), b"data").unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();
        assert!(verify(&repo).await.is_ok());

        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        assert_eq!(std::fs::read(out.path().join("empty.txt")).unwrap(), b"");
        assert!(out.path().join("emptydir").is_dir());
        assert!(out.path().join("a/b/c").is_dir());
        assert_eq!(std::fs::read(out.path().join("normal")).unwrap(), b"data");
    }

    #[tokio::test]
    async fn backup_restore_preserves_unusual_filenames() {
        let src = tempfile::tempdir().unwrap();
        let names = [
            "café.txt",
            "日本語.md",
            "with space.bin",
            "emoji-🎉",
            "dot.in.name",
        ];
        for name in names {
            std::fs::write(src.path().join(name), name.as_bytes()).unwrap();
        }
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        for name in names {
            assert_eq!(
                std::fs::read(out.path().join(name)).unwrap(),
                name.as_bytes(),
                "filename {name} should round-trip"
            );
        }
    }

    #[tokio::test]
    async fn backup_deduplicates_identical_files() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("x"), b"same content here").unwrap();
        std::fs::write(src.path().join("y"), b"same content here").unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        // Two identical files share one Data blob; plus one Tree blob => 2 packs.
        let packs = repo.backend().list(FileType::Pack).await.unwrap().len();
        assert!(packs <= 2, "expected dedup, got {packs} packs");
    }

    #[tokio::test]
    async fn restored_snapshot_lists_in_repo() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"data").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();
        assert_eq!(repo.list_snapshots().await.unwrap(), vec![snap]);
    }

    #[tokio::test]
    async fn verify_passes_after_backup() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a"), b"alpha").unwrap();
        std::fs::create_dir(src.path().join("d")).unwrap();
        std::fs::write(src.path().join("d/b"), vec![1u8; 5000]).unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        let report = verify(&repo).await.unwrap();
        assert_eq!(report.snapshots, 1);
        assert!(report.trees >= 2, "root + subdir trees");
        assert!(report.blobs >= 2, "two file chunks");
        assert_eq!(
            report.blobs, report.total_blobs,
            "a full verify reads every unique blob"
        );
    }

    #[test]
    fn sample_ids_picks_the_right_count() {
        let ids: Vec<Id> = (0..100u8).map(|i| Id::from_bytes([i; 32])).collect();
        // ceil(100 * pct / 100), at least one, never more than the whole set.
        assert_eq!(sample_ids(ids.clone(), 10).len(), 10);
        assert_eq!(sample_ids(ids.clone(), 25).len(), 25);
        assert_eq!(sample_ids(ids.clone(), 1).len(), 1);
        assert_eq!(sample_ids(ids.clone(), 100).len(), 100);
        // A tiny set still yields at least one, and the picks are real members.
        let three: Vec<Id> = ids[..3].to_vec();
        let picked = sample_ids(three.clone(), 10);
        assert_eq!(picked.len(), 1, "ceil(3 * 10/100) == 1");
        assert!(picked.iter().all(|p| three.contains(p)));
        assert!(sample_ids(Vec::new(), 50).is_empty());
    }

    #[tokio::test]
    async fn sampled_verify_reads_only_a_subset() {
        let src = tempfile::tempdir().unwrap();
        // 40 files with distinct content => 40 distinct content blobs.
        for i in 0..40u32 {
            std::fs::write(
                src.path().join(format!("f{i}")),
                format!("unique-contents-{i}").into_bytes(),
            )
            .unwrap();
        }
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        let full = verify(&repo).await.unwrap();
        assert_eq!(full.blobs, 40);
        assert_eq!(full.blobs, full.total_blobs);

        // A 25% sample reads ten of the forty, still reporting the true total,
        // and the reads themselves authenticate (so it returns Ok).
        let sampled = verify_with(&repo, VerifyOptions { sample_percent: 25 })
            .await
            .unwrap();
        assert_eq!(sampled.total_blobs, 40, "denominator is the full set");
        assert_eq!(sampled.blobs, 10, "ceil(40 * 25/100) == 10 read");
        assert_eq!(sampled.snapshots, full.snapshots);
        assert_eq!(sampled.trees, full.trees, "trees are always fully walked");

        // 100% behaves exactly like the default full verify.
        let whole = verify_with(
            &repo,
            VerifyOptions {
                sample_percent: 100,
            },
        )
        .await
        .unwrap();
        assert_eq!(whole.blobs, 40);
    }

    #[tokio::test]
    async fn verify_fails_when_a_pack_is_missing() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a"), vec![9u8; 5000]).unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        let packs = repo.backend().list(FileType::Pack).await.unwrap();
        repo.backend()
            .remove(FileType::Pack, &packs[0])
            .await
            .unwrap();
        assert!(verify(&repo).await.is_err());
    }

    #[tokio::test]
    async fn verify_fails_on_a_missing_content_blob() {
        use sluice_core::BlobKind;
        use std::sync::Arc;

        let backend = Arc::new(MemoryBackend::new());
        let mut repo = Repository::init(backend.clone(), b"pw", fast())
            .await
            .unwrap();
        // A content blob alone in its own pack.
        let chunk = repo
            .save_blob(BlobKind::Data, b"file contents")
            .await
            .unwrap();
        repo.flush().await.unwrap();
        let content_pack = repo.backend().list(FileType::Pack).await.unwrap()[0];
        // A tree referencing it (in a separate pack) and a snapshot.
        let node = Node {
            name: b"f".to_vec(),
            kind: EntryKind::File,
            mode: 0,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            size: 13,
            content: vec![chunk],
            subtree: None,
            link_target: None,
            dev: 0,
            ino: 0,
            xattrs: Vec::new(),
            rdev: 0,
            sparse: false,
        };
        let tree = repo
            .save_tree(&Tree {
                version: TREE_VERSION,
                nodes: vec![node],
            })
            .await
            .unwrap();
        repo.flush().await.unwrap();
        repo.commit_snapshot(&Snapshot {
            version: SNAPSHOT_VERSION,
            time_ns: 0,
            tree,
            paths: vec![],
            hostname: "h".into(),
            username: "u".into(),
            uid: 0,
            gid: 0,
            tags: vec![],
            parent: None,
            program_version: "test".into(),
            summary: SnapshotStats::default(),
        })
        .await
        .unwrap();
        assert!(verify(&repo).await.is_ok());

        // Remove the content blob's pack (the tree's pack stays): the tree loads
        // during the walk, but the concurrent content read then fails.
        backend.remove(FileType::Pack, &content_pack).await.unwrap();
        let reopened = Repository::open(backend.clone(), b"pw").await.unwrap();
        assert!(verify(&reopened).await.is_err());
    }

    #[tokio::test]
    async fn incremental_backup_skips_unchanged_files() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("keep.txt"), b"unchanged data").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        let snap2 = backup(&mut repo, src.path()).await.unwrap();
        let s = repo.load_snapshot(&snap2).await.unwrap();
        assert_eq!(s.summary.files_unmodified, 1);
        assert_eq!(s.summary.files_new, 0);
        assert!(s.parent.is_some());
    }

    #[tokio::test]
    async fn backup_reports_per_file_progress() {
        use std::sync::Mutex;
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a"), b"alpha").unwrap();
        std::fs::write(src.path().join("b"), b"bravo").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let sources = [src.path().to_path_buf()];

        let collect = |events: &Mutex<Vec<(String, FileStatus)>>, p: &Path, s: FileStatus| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            events.lock().unwrap().push((name, s));
        };

        // First backup: both files are new.
        let first = Mutex::new(Vec::new());
        let report = |p: &Path, s: FileStatus| collect(&first, p, s);
        backup_sources_with_progress(
            &mut repo,
            &sources,
            &[],
            &[],
            false,
            None,
            false,
            Some(&report),
        )
        .await
        .unwrap();
        let mut got = first.into_inner().unwrap();
        got.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(
            got,
            vec![("a".into(), FileStatus::New), ("b".into(), FileStatus::New),]
        );

        // Change one file: it reports Changed; the other reports Unmodified.
        std::fs::write(src.path().join("a"), b"alpha is now longer").unwrap();
        let second = Mutex::new(Vec::new());
        let report2 = |p: &Path, s: FileStatus| collect(&second, p, s);
        backup_sources_with_progress(
            &mut repo,
            &sources,
            &[],
            &[],
            false,
            None,
            false,
            Some(&report2),
        )
        .await
        .unwrap();
        let mut got = second.into_inner().unwrap();
        got.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(
            got,
            vec![
                ("a".into(), FileStatus::Changed),
                ("b".into(), FileStatus::Unmodified),
            ]
        );
    }

    #[tokio::test]
    async fn backup_excludes_files_over_the_size_limit() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("small"), vec![0u8; 100]).unwrap();
        std::fs::write(src.path().join("big"), vec![0u8; 100_000]).unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // A 1 KiB limit skips the 100 KiB file but keeps the 100-byte one.
        let outcome = backup_sources_with_progress(
            &mut repo,
            &[src.path().to_path_buf()],
            &[],
            &[],
            false,
            Some(1024),
            false,
            None,
        )
        .await
        .unwrap();
        let snap = outcome.snapshot.unwrap();
        let names: Vec<String> = list_files(&repo, &snap)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(names.iter().any(|p| p == "small"));
        assert!(
            !names.iter().any(|p| p == "big"),
            "the oversized file must be skipped"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_one_file_system_skips_mount_points() {
        use std::process::Command;
        // Mounting a tmpfs needs root; skip when unprivileged.
        if rustix::process::geteuid().as_raw() != 0 {
            return;
        }
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("local.txt"), b"on the root fs").unwrap();
        let mnt = src.path().join("mnt");
        std::fs::create_dir(&mnt).unwrap();
        // A tmpfs at `mnt` is a different filesystem; skip if mount is denied.
        let mounted = Command::new("mount")
            .args(["-t", "tmpfs", "tmpfs"])
            .arg(&mnt)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !mounted {
            return;
        }
        std::fs::write(mnt.join("on_tmpfs.txt"), b"different fs").unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let outcome = backup_sources_with_progress(
            &mut repo,
            &[src.path().to_path_buf()],
            &[],
            &[],
            false,
            None,
            true,
            None,
        )
        .await;
        // Always unmount before asserting (and before the tempdir is dropped).
        let _ = Command::new("umount").arg(&mnt).status();

        let snap = outcome.unwrap().snapshot.unwrap();
        let names: Vec<String> = list_files(&repo, &snap)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(names.iter().any(|p| p == "local.txt"));
        assert!(
            !names.iter().any(|p| p.contains("on_tmpfs")),
            "files on the mounted filesystem must be skipped"
        );
        assert!(
            !names.iter().any(|p| p == "mnt"),
            "the mount-point directory is not descended into"
        );
    }

    #[tokio::test]
    async fn exclude_if_present_skips_marked_subdirectories() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("keep.txt"), b"keep me").unwrap();
        // A subdirectory carrying the marker is skipped wholesale.
        let cache = src.path().join("cache");
        std::fs::create_dir(&cache).unwrap();
        std::fs::write(cache.join(".nobackup"), b"").unwrap();
        std::fs::write(cache.join("junk.bin"), vec![7u8; 4096]).unwrap();
        // A subdirectory without the marker is backed up normally.
        let data = src.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("real.txt"), b"important").unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let options = BackupOptions {
            exclude_if_present: vec![".nobackup".to_string()],
            ..Default::default()
        };
        let snap = backup_sources_with_options(
            &mut repo,
            &[src.path().to_path_buf()],
            &[],
            &options,
            None,
        )
        .await
        .unwrap()
        .snapshot
        .unwrap();
        let paths: Vec<String> = list_files(&repo, &snap)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(paths.iter().any(|p| p == "keep.txt"));
        assert!(paths.iter().any(|p| p == "data/real.txt"));
        assert!(
            !paths.iter().any(|p| p.starts_with("cache")),
            "the marked directory and its contents are omitted: {paths:?}"
        );
    }

    #[tokio::test]
    async fn exclude_caches_skips_only_signed_cachedir_tags() {
        let src = tempfile::tempdir().unwrap();
        // A real cache: a CACHEDIR.TAG bearing the standard signature -> skipped.
        let cache = src.path().join("buildcache");
        std::fs::create_dir(&cache).unwrap();
        std::fs::write(
            cache.join("CACHEDIR.TAG"),
            b"Signature: 8a477f597d28d172789f06886806bc55\n# generated by the build tool",
        )
        .unwrap();
        std::fs::write(cache.join("artifact.o"), vec![1u8; 2048]).unwrap();
        // A decoy: a CACHEDIR.TAG without the signature is not a cache -> kept.
        let decoy = src.path().join("notcache");
        std::fs::create_dir(&decoy).unwrap();
        std::fs::write(decoy.join("CACHEDIR.TAG"), b"just a coincidence").unwrap();
        std::fs::write(decoy.join("keep.txt"), b"keep").unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let options = BackupOptions {
            exclude_caches: true,
            ..Default::default()
        };
        let snap = backup_sources_with_options(
            &mut repo,
            &[src.path().to_path_buf()],
            &[],
            &options,
            None,
        )
        .await
        .unwrap()
        .snapshot
        .unwrap();
        let paths: Vec<String> = list_files(&repo, &snap)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(
            !paths.iter().any(|p| p.starts_with("buildcache")),
            "a signed cache directory is skipped: {paths:?}"
        );
        assert!(
            paths.iter().any(|p| p == "notcache/keep.txt"),
            "a directory whose CACHEDIR.TAG lacks the signature is kept: {paths:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stat_cache_reuses_unchanged_files() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir(src.path().join("d")).unwrap();
        std::fs::write(src.path().join("d/b.bin"), vec![7u8; 9000]).unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let opts = BackupOptions {
            cache_path: Some(cache_dir.path().join("cache.redb")),
            ..Default::default()
        };

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // First backup: the cache is empty, so both files are read and recorded.
        let first =
            backup_sources_with_options(&mut repo, &[src.path().to_path_buf()], &[], &opts, None)
                .await
                .unwrap()
                .summary;
        assert_eq!(first.files_new, 2);
        assert_eq!(first.files_unmodified, 0);

        // Second backup of the unchanged tree: every file is served from the cache
        // (no parent trees are loaded), so nothing is re-read.
        let second =
            backup_sources_with_options(&mut repo, &[src.path().to_path_buf()], &[], &opts, None)
                .await
                .unwrap()
                .summary;
        assert_eq!(
            second.files_unmodified, 2,
            "both files reused from the cache"
        );
        assert_eq!(second.files_new, 0);
        assert_eq!(second.files_changed, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stat_cache_invalidates_on_change() {
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("a.txt");
        std::fs::write(&f, b"original").unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let opts = BackupOptions {
            cache_path: Some(cache_dir.path().join("c.redb")),
            ..Default::default()
        };
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup_sources_with_options(&mut repo, &[src.path().to_path_buf()], &[], &opts, None)
            .await
            .unwrap();

        // Rewrite the file (new size) with a distinct mtime so the cached
        // (size, mtime) no longer matches.
        std::fs::write(&f, b"changed contents, now quite a bit longer").unwrap();
        filetime::set_file_mtime(&f, filetime::FileTime::from_unix_time(1_000_000_000, 0)).unwrap();
        let second =
            backup_sources_with_options(&mut repo, &[src.path().to_path_buf()], &[], &opts, None)
                .await
                .unwrap()
                .summary;
        assert_eq!(second.files_unmodified, 0, "the changed file is not reused");
        assert_eq!(second.files_new, 1, "it is re-read");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stat_cache_falls_back_when_chunks_are_absent() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"alpha beta gamma delta").unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let opts = BackupOptions {
            cache_path: Some(cache_dir.path().join("c.redb")),
            ..Default::default()
        };

        // Populate the cache against repo1.
        let mut repo1 = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup_sources_with_options(&mut repo1, &[src.path().to_path_buf()], &[], &opts, None)
            .await
            .unwrap();

        // Back up the same files into a FRESH repo2 with the same cache: the
        // cached chunk ids are absent from repo2's index, so the safety check
        // forces a real read rather than referencing blobs that do not exist.
        let mut repo2 = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let summary =
            backup_sources_with_options(&mut repo2, &[src.path().to_path_buf()], &[], &opts, None)
                .await
                .unwrap()
                .summary;
        assert_eq!(
            summary.files_unmodified, 0,
            "a foreign cache is not trusted"
        );
        assert_eq!(summary.files_new, 1, "the file is actually read into repo2");

        // repo2 is self-contained and restores byte-identical.
        assert!(verify(&repo2).await.is_ok());
        let snap = repo2.list_snapshots().await.unwrap()[0];
        let out = tempfile::tempdir().unwrap();
        restore(&repo2, &snap, out.path()).await.unwrap();
        assert_eq!(
            std::fs::read(out.path().join("a.txt")).unwrap(),
            b"alpha beta gamma delta"
        );
    }

    #[tokio::test]
    async fn backup_stdin_stores_a_stream_as_one_file() {
        // Multi-chunk, incompressible, to exercise the streaming path.
        let mut data = vec![0u8; 5 * 1024 * 1024 + 321];
        let mut state = 0x1234_5678u32;
        for b in data.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (state >> 24) as u8;
        }
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let outcome = backup_stdin(
            &mut repo,
            std::io::Cursor::new(&data),
            b"dump.tar",
            &["nightly".into()],
        )
        .await
        .unwrap();
        let snap = outcome.snapshot.unwrap();
        assert_eq!(outcome.summary.files_new, 1);
        assert_eq!(outcome.summary.bytes_processed, data.len() as u64);

        // The snapshot is a single file under the given name.
        let entries = list_files(&repo, &snap).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "dump.tar");
        assert_eq!(entries[0].kind, EntryKind::File);

        // Tag is recorded, and the content round-trips on restore.
        let snap_obj = repo.load_snapshot(&snap).await.unwrap();
        assert_eq!(snap_obj.tags, vec!["nightly".to_string()]);
        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        assert_eq!(std::fs::read(out.path().join("dump.tar")).unwrap(), data);
    }

    #[tokio::test]
    async fn incremental_backup_detects_and_restores_changes() {
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("f.txt");
        std::fs::write(&f, b"v1").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        std::fs::write(&f, b"v2 with more content").unwrap();
        let snap2 = backup(&mut repo, src.path()).await.unwrap();
        let s = repo.load_snapshot(&snap2).await.unwrap();
        assert_eq!(s.summary.files_changed, 1);
        assert_eq!(s.summary.files_unmodified, 0);

        let dst = tempfile::tempdir().unwrap();
        restore(&repo, &snap2, dst.path()).await.unwrap();
        assert_eq!(
            std::fs::read(dst.path().join("f.txt")).unwrap(),
            b"v2 with more content"
        );
    }

    #[tokio::test]
    async fn forget_removes_a_snapshot() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"data").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();
        assert_eq!(repo.list_snapshots().await.unwrap(), vec![snap]);

        forget(&repo, &snap).await.unwrap();
        assert!(repo.list_snapshots().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn prune_reclaims_unreferenced_packs() {
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("f");
        std::fs::write(&f, b"unique content for the first snapshot").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap1 = backup(&mut repo, src.path()).await.unwrap();

        std::fs::write(&f, b"completely different bytes for the second snapshot").unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        let before = repo.backend().list(FileType::Pack).await.unwrap().len();
        forget(&repo, &snap1).await.unwrap();
        let report = prune(&mut repo, false, 0).await.unwrap();
        let after = repo.backend().list(FileType::Pack).await.unwrap().len();

        assert!(report.deleted >= 1, "expected to reclaim packs");
        assert_eq!(before - after, report.deleted);
        // The surviving snapshot still verifies.
        assert!(verify(&repo).await.is_ok());
    }

    #[tokio::test]
    async fn list_files_walks_the_snapshot() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"12345").unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b"), b"xy").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let entries = list_files(&repo, &snap).await.unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"a.txt"));
        assert!(paths.contains(&"sub"));
        assert!(paths.contains(&"sub/b"));

        let a = entries.iter().find(|e| e.path == "a.txt").unwrap();
        assert_eq!(a.kind, EntryKind::File);
        assert_eq!(a.size, 5);
    }

    #[tokio::test]
    async fn forget_keep_last_retains_recent_snapshots() {
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("f");
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // Three distinct snapshots (distinct content => distinct ids).
        for content in [b"v1".as_slice(), b"v2", b"v3"] {
            std::fs::write(&f, content).unwrap();
            backup(&mut repo, src.path()).await.unwrap();
        }
        assert_eq!(repo.list_snapshots().await.unwrap().len(), 3);

        let forgotten = forget_keep_last(&repo, 2).await.unwrap();
        assert_eq!(forgotten.len(), 1);
        assert_eq!(repo.list_snapshots().await.unwrap().len(), 2);

        // Keeping more than exist forgets nothing.
        assert!(forget_keep_last(&repo, 5).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn forget_keep_daily_keeps_one_per_day_within_budget() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // An empty tree for the synthetic snapshots to reference.
        let tree = repo
            .save_tree(&Tree {
                version: TREE_VERSION,
                nodes: vec![],
            })
            .await
            .unwrap();
        let at = |time_ns: i64| Snapshot {
            version: SNAPSHOT_VERSION,
            time_ns,
            tree,
            paths: vec![],
            hostname: "h".into(),
            username: "u".into(),
            uid: 0,
            gid: 0,
            tags: vec![],
            parent: None,
            program_version: "test".into(),
            summary: SnapshotStats::default(),
        };
        const DAY: i64 = 86_400_000_000_000;
        // day 0: two snapshots; day 1: one; day 2: two.
        let d0_old = repo.commit_snapshot(&at(10)).await.unwrap();
        let d0_new = repo.commit_snapshot(&at(20)).await.unwrap();
        let d1 = repo.commit_snapshot(&at(DAY + 10)).await.unwrap();
        let d2_old = repo.commit_snapshot(&at(2 * DAY + 10)).await.unwrap();
        let d2_new = repo.commit_snapshot(&at(2 * DAY + 20)).await.unwrap();

        // keep-daily 2: keep days 2 and 1 (most recent two), one snapshot each.
        let forgotten = forget_keep_daily(&repo, 2).await.unwrap();
        assert_eq!(forgotten.len(), 3); // d2_old (same day) + both of evicted day 0

        let remaining: HashSet<Id> = repo.list_snapshots().await.unwrap().into_iter().collect();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.contains(&d2_new)); // day 2's most recent kept
        assert!(remaining.contains(&d1)); // day 1 kept
        assert!(!remaining.contains(&d2_old)); // older within a kept day -> gone
        assert!(!remaining.contains(&d0_old));
        assert!(!remaining.contains(&d0_new)); // whole day beyond budget -> gone

        // Keeping more days than exist forgets nothing further.
        assert!(forget_keep_daily(&repo, 9).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn forget_with_policy_unions_daily_and_weekly() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let tree = repo
            .save_tree(&Tree {
                version: TREE_VERSION,
                nodes: vec![],
            })
            .await
            .unwrap();
        let at = |time_ns: i64| Snapshot {
            version: SNAPSHOT_VERSION,
            time_ns,
            tree,
            paths: vec![],
            hostname: "h".into(),
            username: "u".into(),
            uid: 0,
            gid: 0,
            tags: vec![],
            parent: None,
            program_version: "test".into(),
            summary: SnapshotStats::default(),
        };
        const DAY: i64 = 86_400_000_000_000;
        // days 3, 9, 10 -> weeks (day+3)/7 = 0, 1, 1.
        let d3 = repo.commit_snapshot(&at(3 * DAY + 10)).await.unwrap();
        let d9 = repo.commit_snapshot(&at(9 * DAY + 10)).await.unwrap();
        let d10 = repo.commit_snapshot(&at(10 * DAY + 10)).await.unwrap();

        // daily 1 keeps only d10; weekly 2 additionally keeps d3 (week 0's newest).
        // d9 is the newest of week 1 only after d10, so neither rule keeps it.
        let policy = RetentionPolicy {
            daily: 1,
            weekly: 2,
            ..Default::default()
        };
        // Dry run previews the same removal without touching the repo.
        let preview = forget_with_policy(&repo, &policy, GroupBy::None, true)
            .await
            .unwrap();
        assert_eq!(preview, vec![d9]);
        assert_eq!(repo.list_snapshots().await.unwrap().len(), 3);

        let forgotten = forget_with_policy(&repo, &policy, GroupBy::None, false)
            .await
            .unwrap();
        assert_eq!(forgotten, vec![d9]);

        let remaining: HashSet<Id> = repo.list_snapshots().await.unwrap().into_iter().collect();
        assert_eq!(remaining, HashSet::from([d10, d3]));
    }

    #[tokio::test]
    async fn forget_keep_id_pins_a_snapshot() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let tree = repo
            .save_tree(&Tree {
                version: TREE_VERSION,
                nodes: vec![],
            })
            .await
            .unwrap();
        let at = |time_ns: i64| Snapshot {
            version: SNAPSHOT_VERSION,
            time_ns,
            tree,
            paths: vec![],
            hostname: "h".into(),
            username: "u".into(),
            uid: 0,
            gid: 0,
            tags: vec![],
            parent: None,
            program_version: "test".into(),
            summary: SnapshotStats::default(),
        };
        const DAY: i64 = 86_400_000_000_000;
        let old = repo.commit_snapshot(&at(DAY)).await.unwrap();
        let mid = repo.commit_snapshot(&at(2 * DAY)).await.unwrap();
        let new = repo.commit_snapshot(&at(3 * DAY)).await.unwrap();

        // keep-last 1 keeps `new`; --keep-id pins `old`; only `mid` is forgotten.
        let policy = RetentionPolicy {
            last: 1,
            keep_ids: vec![old],
            ..Default::default()
        };
        let forgotten = forget_with_policy(&repo, &policy, GroupBy::None, false)
            .await
            .unwrap();
        assert_eq!(forgotten, vec![mid]);
        let remaining: HashSet<Id> = repo.list_snapshots().await.unwrap().into_iter().collect();
        assert_eq!(remaining, HashSet::from([new, old]));
    }

    #[tokio::test]
    async fn forget_with_policy_protects_keep_tagged_snapshots() {
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("f");
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // Three snapshots; the middle one is tagged "important".
        std::fs::write(&f, b"v1").unwrap();
        backup(&mut repo, src.path()).await.unwrap();
        std::fs::write(&f, b"v2").unwrap();
        let important = backup_excluding(&mut repo, src.path(), &[], &["important".into()][..])
            .await
            .unwrap();
        std::fs::write(&f, b"v3").unwrap();
        let newest = backup(&mut repo, src.path()).await.unwrap();

        // keep-last 1 would drop the older two, but keep-tag rescues "important".
        let policy = RetentionPolicy {
            last: 1,
            keep_tags: vec!["important".into()],
            ..Default::default()
        };
        forget_with_policy(&repo, &policy, GroupBy::None, false)
            .await
            .unwrap();
        let remaining: HashSet<Id> = repo.list_snapshots().await.unwrap().into_iter().collect();
        assert_eq!(remaining, HashSet::from([newest, important]));
    }

    #[tokio::test]
    async fn forget_with_policy_keeps_within_a_window() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let tree = repo
            .save_tree(&Tree {
                version: TREE_VERSION,
                nodes: vec![],
            })
            .await
            .unwrap();
        let at = |time_ns: i64| Snapshot {
            version: SNAPSHOT_VERSION,
            time_ns,
            tree,
            paths: vec![],
            hostname: "h".into(),
            username: "u".into(),
            uid: 0,
            gid: 0,
            tags: vec![],
            parent: None,
            program_version: "test".into(),
            summary: SnapshotStats::default(),
        };
        const HOUR: i64 = 3_600_000_000_000;
        const DAY: i64 = 86_400_000_000_000;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        let recent = repo.commit_snapshot(&at(now - HOUR)).await.unwrap(); // ~1h ago
        let _old = repo.commit_snapshot(&at(now - 30 * DAY)).await.unwrap(); // ~30d ago

        // keep-within 7 days keeps only the recent snapshot (no count rules).
        let policy = RetentionPolicy {
            keep_within_ns: 7 * DAY,
            ..Default::default()
        };
        forget_with_policy(&repo, &policy, GroupBy::None, false)
            .await
            .unwrap();
        let remaining: HashSet<Id> = repo.list_snapshots().await.unwrap().into_iter().collect();
        assert_eq!(remaining, HashSet::from([recent]));
    }

    #[tokio::test]
    async fn forget_with_policy_groups_by_host() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let tree = repo
            .save_tree(&Tree {
                version: TREE_VERSION,
                nodes: vec![],
            })
            .await
            .unwrap();
        let at = |host: &str, time_ns: i64| Snapshot {
            version: SNAPSHOT_VERSION,
            time_ns,
            tree,
            paths: vec![],
            hostname: host.to_string(),
            username: "u".into(),
            uid: 0,
            gid: 0,
            tags: vec![],
            parent: None,
            program_version: "test".into(),
            summary: SnapshotStats::default(),
        };
        // host h1 at times 10, 20; host h2 at 30, 40.
        let _h1_old = repo.commit_snapshot(&at("h1", 10)).await.unwrap();
        let h1_new = repo.commit_snapshot(&at("h1", 20)).await.unwrap();
        let _h2_old = repo.commit_snapshot(&at("h2", 30)).await.unwrap();
        let h2_new = repo.commit_snapshot(&at("h2", 40)).await.unwrap();

        // keep-last 1 grouped by host keeps the newest of *each* host (not just the
        // single globally-newest, which is what GroupBy::None would keep).
        let policy = RetentionPolicy {
            last: 1,
            ..Default::default()
        };
        forget_with_policy(&repo, &policy, GroupBy::Host, false)
            .await
            .unwrap();
        let remaining: HashSet<Id> = repo.list_snapshots().await.unwrap().into_iter().collect();
        assert_eq!(remaining, HashSet::from([h1_new, h2_new]));
    }

    #[test]
    fn year_month_matches_known_dates() {
        assert_eq!(year_month(0), (1970, 1)); // 1970-01-01
        assert_eq!(year_month(31), (1970, 2)); // 1970-02-01
        assert_eq!(year_month(59), (1970, 3)); // 1970-03-01 (1970 is not a leap year)
        assert_eq!(year_month(365), (1971, 1)); // 1971-01-01
        assert_eq!(year_month(10_957), (2000, 1)); // 2000-01-01
        assert_eq!(year_month(11_016), (2000, 2)); // 2000-02-29 (leap day)
        assert_eq!(year_month(11_017), (2000, 3)); // 2000-03-01
        assert_eq!(year_month(-1), (1969, 12)); // 1969-12-31 (pre-epoch)
    }

    #[tokio::test]
    async fn forget_with_policy_keeps_monthly_and_yearly() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let tree = repo
            .save_tree(&Tree {
                version: TREE_VERSION,
                nodes: vec![],
            })
            .await
            .unwrap();
        let at = |time_ns: i64| Snapshot {
            version: SNAPSHOT_VERSION,
            time_ns,
            tree,
            paths: vec![],
            hostname: "h".into(),
            username: "u".into(),
            uid: 0,
            gid: 0,
            tags: vec![],
            parent: None,
            program_version: "test".into(),
            summary: SnapshotStats::default(),
        };
        const DAY: i64 = 86_400_000_000_000;
        // 1970-01 (two snapshots), 1970-02 (one), 1971-01 (one).
        let jan_a = repo.commit_snapshot(&at(10)).await.unwrap(); // 1970-01-01
        let jan_b = repo.commit_snapshot(&at(5 * DAY + 10)).await.unwrap(); // 1970-01-06
        let feb = repo.commit_snapshot(&at(31 * DAY + 10)).await.unwrap(); // 1970-02-01
        let y1971 = repo.commit_snapshot(&at(365 * DAY + 10)).await.unwrap(); // 1971-01-01

        // monthly 1 keeps 1971-01 (y1971); yearly 2 adds 1970's newest (feb).
        let policy = RetentionPolicy {
            monthly: 1,
            yearly: 2,
            ..Default::default()
        };
        let forgotten = forget_with_policy(&repo, &policy, GroupBy::None, false)
            .await
            .unwrap();
        let remaining: HashSet<Id> = repo.list_snapshots().await.unwrap().into_iter().collect();
        assert_eq!(remaining, HashSet::from([y1971, feb]));
        // Both January 1970 snapshots are dropped (older year, non-newest month).
        assert_eq!(forgotten.len(), 2);
        assert!(forgotten.contains(&jan_a) && forgotten.contains(&jan_b));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_restore_preserves_fifos() {
        use std::os::unix::fs::FileTypeExt;
        let src = tempfile::tempdir().unwrap();
        make_fifo(&src.path().join("pipe"), 0o644).unwrap();
        std::fs::write(src.path().join("normal"), b"data").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();
        assert!(verify(&repo).await.is_ok());

        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        let meta = std::fs::symlink_metadata(out.path().join("pipe")).unwrap();
        assert!(
            meta.file_type().is_fifo(),
            "restored entry should be a FIFO"
        );
        assert_eq!(std::fs::read(out.path().join("normal")).unwrap(), b"data");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_restore_preserves_devices() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        // Creating and recreating a device node needs CAP_MKNOD.
        if rustix::process::geteuid().as_raw() != 0 {
            return;
        }
        let src = tempfile::tempdir().unwrap();
        let dev = src.path().join("zero");
        let rdev = rustix::fs::makedev(1, 5); // char 1:5 is /dev/zero
        make_device(&dev, 0o644, EntryKind::CharDevice, rdev).unwrap();
        let sm = std::fs::symlink_metadata(&dev).unwrap();
        assert!(sm.file_type().is_char_device(), "test setup");
        assert_eq!(sm.rdev(), rdev);

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();
        assert!(verify(&repo).await.is_ok());

        // The node records the device kind and number.
        let snap_obj = repo.load_snapshot(&snap).await.unwrap();
        let tree = repo.load_tree(&snap_obj.tree).await.unwrap();
        let node = tree.nodes.iter().find(|n| n.name == b"zero").unwrap();
        assert_eq!(node.kind, EntryKind::CharDevice);
        assert_eq!(node.rdev, rdev);

        // Restore recreates the device with the same major/minor.
        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        let rm = std::fs::symlink_metadata(out.path().join("zero")).unwrap();
        assert!(
            rm.file_type().is_char_device(),
            "restored entry should be a char device"
        );
        assert_eq!(rm.rdev(), rdev);
    }

    #[cfg(unix)]
    #[test]
    fn reporter_records_best_effort_metadata_failures() {
        // A path whose parent does not exist makes chown and setxattr fail with
        // ENOENT regardless of privilege, so this exercises the warning path even
        // when the tests run as root.
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no-such-dir").join("entry");
        let reporter = Reporter::default();
        set_owner(&missing, 0, 0, true, &reporter);
        write_xattrs(&missing, &[(b"user.x".to_vec(), b"v".to_vec())], &reporter);
        let report = reporter.into_inner().unwrap();
        assert!(
            report.warnings >= 2,
            "expected the failures to be recorded, got {}",
            report.warnings
        );
        assert!(!report.messages.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn sparse_reader_yields_the_dense_byte_stream() {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sp");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"HEAD").unwrap();
            f.seek(SeekFrom::Start(1 << 20)).unwrap(); // 1 MiB hole
            f.write_all(b"TAIL").unwrap();
        }
        let meta = std::fs::metadata(&path).unwrap();
        if meta.blocks().saturating_mul(512) >= meta.size() {
            return; // filesystem didn't punch a hole
        }
        let mut reader = SparseReader {
            file: std::fs::File::open(&path).unwrap(),
            pos: 0,
            size: meta.size(),
        };
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();

        // Identical to reading the file densely: head, a zero-filled hole, tail.
        let mut want = vec![0u8; (1 << 20) + 4];
        want[..4].copy_from_slice(b"HEAD");
        want[1 << 20..].copy_from_slice(b"TAIL");
        assert_eq!(got, want);
        // And exactly what a plain read returns.
        assert_eq!(got, std::fs::read(&path).unwrap());
    }

    #[tokio::test]
    async fn restore_reports_per_file_progress() {
        use std::sync::Mutex;
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a"), b"alpha").unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b"), b"bravo").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        // A fresh restore reports every file (directories are not reported).
        let out = tempfile::tempdir().unwrap();
        let restored = Mutex::new(Vec::new());
        let report = |p: &Path| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            restored.lock().unwrap().push(name);
        };
        restore_with(
            &repo,
            &snap,
            None,
            out.path(),
            RestoreOptions::default(),
            Some(&report),
        )
        .await
        .unwrap();
        let mut got = restored.into_inner().unwrap();
        got.sort();
        assert_eq!(got, vec!["a".to_string(), "b".to_string()]);

        // A resumed restore reports nothing — every file already matched.
        let again = Mutex::new(0u32);
        let report2 = |_: &Path| *again.lock().unwrap() += 1;
        let opts = RestoreOptions {
            skip_existing: true,
            verify: false,
        };
        restore_with(&repo, &snap, None, out.path(), opts, Some(&report2))
            .await
            .unwrap();
        assert_eq!(
            again.into_inner().unwrap(),
            0,
            "skipped files aren't reported"
        );
    }

    #[tokio::test]
    async fn restore_skip_existing_leaves_matching_files() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"hello").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        let target = out.path().join("f");
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");

        // Replace the content but keep the size and mtime, so the cheap
        // "already restored" check still matches.
        let mtime =
            filetime::FileTime::from_last_modification_time(&std::fs::metadata(&target).unwrap());
        std::fs::write(&target, b"world").unwrap(); // same length
        filetime::set_file_mtime(&target, mtime).unwrap();

        // skip-existing keeps the matching file untouched...
        let opts = RestoreOptions {
            skip_existing: true,
            verify: false,
        };
        restore_with(&repo, &snap, None, out.path(), opts, None)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"world");

        // ...while a default restore overwrites it with the snapshot content.
        restore(&repo, &snap, out.path()).await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
    }

    #[tokio::test]
    async fn verify_restored_file_detects_mismatch() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"correct content here").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();
        let snap_obj = repo.load_snapshot(&snap).await.unwrap();
        let tree = repo.load_tree(&snap_obj.tree).await.unwrap();
        let node = tree.nodes.iter().find(|n| n.name == b"f").unwrap();

        let dir = tempfile::tempdir().unwrap();
        // A faithful copy verifies.
        let good = dir.path().join("good");
        std::fs::write(&good, b"correct content here").unwrap();
        assert!(
            verify_restored_file(&repo, &good, &node.content)
                .await
                .is_ok()
        );
        // Wrong bytes (same length) fail with VerifyFailed.
        let bad = dir.path().join("bad");
        std::fs::write(&bad, b"WRONG content here..").unwrap();
        assert!(matches!(
            verify_restored_file(&repo, &bad, &node.content).await,
            Err(EngineError::VerifyFailed(_))
        ));
        // A short file fails too (it can't supply enough bytes).
        let short = dir.path().join("short");
        std::fs::write(&short, b"correct").unwrap();
        assert!(
            verify_restored_file(&repo, &short, &node.content)
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_restore_preserves_sparse_files() {
        use std::io::{Seek, SeekFrom, Write};
        use std::os::unix::fs::MetadataExt;
        let src = tempfile::tempdir().unwrap();
        let path = src.path().join("sparse.img");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"head").unwrap();
            f.seek(SeekFrom::Start(1 << 20)).unwrap(); // a 1 MiB hole
            f.write_all(b"tail").unwrap();
        }
        let sm = std::fs::metadata(&path).unwrap();
        // Skip if the filesystem didn't actually punch a hole.
        if sm.blocks().saturating_mul(512) >= sm.size() {
            return;
        }

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let snap_obj = repo.load_snapshot(&snap).await.unwrap();
        let tree = repo.load_tree(&snap_obj.tree).await.unwrap();
        let node = tree.nodes.iter().find(|n| n.name == b"sparse.img").unwrap();
        assert!(node.sparse, "node should be flagged sparse");

        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        let restored = out.path().join("sparse.img");
        // Byte-for-byte identical contents...
        assert_eq!(
            std::fs::read(&restored).unwrap(),
            std::fs::read(&path).unwrap()
        );
        // ...and still sparse on disk (the 1 MiB hole was not allocated).
        let rm = std::fs::metadata(&restored).unwrap();
        assert!(
            rm.blocks().saturating_mul(512) < rm.size(),
            "restored file should remain sparse (blocks={}, size={})",
            rm.blocks(),
            rm.size()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_restore_preserves_ownership() {
        use std::os::unix::fs::MetadataExt;
        // Assigning an arbitrary owner (and chown on restore) needs privilege;
        // skip the assertion when unprivileged rather than fail in CI.
        if rustix::process::geteuid().as_raw() != 0 {
            return;
        }
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("owned");
        std::fs::write(&f, b"data").unwrap();
        set_owner(&f, 1, 2, true, &Reporter::default());
        assert_eq!(
            std::fs::metadata(&f).unwrap().uid(),
            1,
            "test setup chown failed"
        );

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        // Backup recorded the real owner, not a hardcoded zero.
        let snap_obj = repo.load_snapshot(&snap).await.unwrap();
        let tree = repo.load_tree(&snap_obj.tree).await.unwrap();
        let node = tree.nodes.iter().find(|n| n.name == b"owned").unwrap();
        assert_eq!((node.uid, node.gid), (1, 2));

        // Restore replays it.
        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        let m = std::fs::metadata(out.path().join("owned")).unwrap();
        assert_eq!((m.uid(), m.gid()), (1, 2));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_restore_preserves_hardlinks() {
        use std::os::unix::fs::MetadataExt;
        let src = tempfile::tempdir().unwrap();
        let a = src.path().join("a");
        let b = src.path().join("b");
        std::fs::write(&a, b"shared content").unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        assert_eq!(std::fs::metadata(&a).unwrap().nlink(), 2, "test setup");

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();
        assert!(verify(&repo).await.is_ok());

        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();

        let ra = std::fs::metadata(out.path().join("a")).unwrap();
        let rb = std::fs::metadata(out.path().join("b")).unwrap();
        // The two entries are reunited into one inode with two links, not two
        // independent copies.
        assert_eq!(ra.ino(), rb.ino(), "restored entries should share an inode");
        assert_eq!(ra.nlink(), 2, "restored inode should have two links");
        assert_eq!(
            std::fs::read(out.path().join("a")).unwrap(),
            b"shared content"
        );
        assert_eq!(
            std::fs::read(out.path().join("b")).unwrap(),
            b"shared content"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_restore_preserves_xattrs() {
        use rustix::fs::{XattrFlags, lsetxattr};
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("f");
        std::fs::write(&f, b"data").unwrap();
        // Skip if the filesystem rejects user xattrs (e.g. older tmpfs).
        if lsetxattr(f.as_path(), c"user.sluice", b"hello", XattrFlags::empty()).is_err() {
            return;
        }

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        // The attribute is captured in the stored tree node.
        let snap_obj = repo.load_snapshot(&snap).await.unwrap();
        let tree = repo.load_tree(&snap_obj.tree).await.unwrap();
        let node = tree.nodes.iter().find(|n| n.name == b"f").unwrap();
        assert!(
            node.xattrs
                .iter()
                .any(|(k, v)| k == b"user.sluice" && v == b"hello"),
            "xattr should be captured, got {:?}",
            node.xattrs
        );

        // ...and replayed on restore.
        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        let restored = read_xattrs(&out.path().join("f"));
        assert!(
            restored
                .iter()
                .any(|(k, v)| k == b"user.sluice" && v == b"hello"),
            "xattr should be restored, got {restored:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_restore_preserves_symlinks() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("target.txt"), b"the target").unwrap();
        std::os::unix::fs::symlink("target.txt", src.path().join("link")).unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let dst = tempfile::tempdir().unwrap();
        restore(&repo, &snap, dst.path()).await.unwrap();

        let link = dst.path().join("link");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            std::path::Path::new("target.txt")
        );
        // Reading through the link yields the target's content.
        assert_eq!(std::fs::read(&link).unwrap(), b"the target");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restore_replays_mode_and_mtime() {
        use std::os::unix::fs::PermissionsExt;
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("script.sh");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        filetime::set_file_mtime(&f, filetime::FileTime::from_unix_time(1_600_000_000, 0)).unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();
        let dst = tempfile::tempdir().unwrap();
        restore(&repo, &snap, dst.path()).await.unwrap();

        let meta = std::fs::metadata(dst.path().join("script.sh")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o755);
        assert_eq!(
            filetime::FileTime::from_last_modification_time(&meta).unix_seconds(),
            1_600_000_000
        );
    }

    #[tokio::test]
    async fn backup_excludes_matching_names() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("keep.txt"), b"keep").unwrap();
        std::fs::write(src.path().join("skip.log"), b"skip").unwrap();
        std::fs::create_dir(src.path().join("cache")).unwrap();
        std::fs::write(src.path().join("cache/x"), b"x").unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup_excluding(
            &mut repo,
            src.path(),
            &["*.log".into(), "cache".into()],
            &[],
        )
        .await
        .unwrap();

        let paths: Vec<String> = list_files(&repo, &snap)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(paths.contains(&"keep.txt".to_string()));
        assert!(!paths.iter().any(|p| p.contains("skip.log")));
        assert!(!paths.iter().any(|p| p.contains("cache")));
    }

    #[tokio::test]
    async fn diff_reports_added_removed_modified() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("stable"), b"same").unwrap();
        std::fs::write(src.path().join("gone"), b"to be removed").unwrap();
        std::fs::write(src.path().join("changes"), b"v1").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let a = backup(&mut repo, src.path()).await.unwrap();

        std::fs::remove_file(src.path().join("gone")).unwrap();
        std::fs::write(src.path().join("changes"), b"v2 a different size").unwrap();
        std::fs::write(src.path().join("brand_new"), b"hi").unwrap();
        let b = backup(&mut repo, src.path()).await.unwrap();

        let changes = diff(&repo, &a, &b).await.unwrap();
        let of = |k: DiffKind| -> Vec<&str> {
            changes
                .iter()
                .filter(|d| d.change == k)
                .map(|d| d.path.as_str())
                .collect()
        };
        assert_eq!(of(DiffKind::Added), vec!["brand_new"]);
        assert_eq!(of(DiffKind::Removed), vec!["gone"]);
        assert_eq!(of(DiffKind::Modified), vec!["changes"]);
        assert!(!changes.iter().any(|d| d.path == "stable"));
        // The size+content change is categorized as such, not as metadata.
        let changed = changes.iter().find(|d| d.path == "changes").unwrap();
        assert!(changed.detail.size && !changed.detail.mode && !changed.detail.owner);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn diff_detects_metadata_only_changes() {
        use std::os::unix::fs::PermissionsExt;
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("f");
        std::fs::write(&f, b"content").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let a = backup(&mut repo, src.path()).await.unwrap();

        // chmod only: the content, size, and mtime are untouched.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let b = backup(&mut repo, src.path()).await.unwrap();

        let changes = diff(&repo, &a, &b).await.unwrap();
        let m = changes
            .iter()
            .find(|d| d.path == "f")
            .expect("f is modified");
        assert_eq!(m.change, DiffKind::Modified);
        assert!(m.detail.mode, "a permission change must be detected");
        assert!(!m.detail.size, "size did not change");
        assert!(
            !m.detail.mtime,
            "mtime did not change (chmod touches ctime)"
        );
    }

    #[tokio::test]
    async fn dump_extracts_a_single_file() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/file.txt"), b"hello dump").unwrap();
        std::fs::write(src.path().join("top"), b"top-level").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        assert_eq!(
            dump(&repo, &snap, "sub/file.txt").await.unwrap(),
            b"hello dump"
        );
        assert_eq!(dump(&repo, &snap, "top").await.unwrap(), b"top-level");
        assert!(dump(&repo, &snap, "missing").await.is_err());
        assert!(dump(&repo, &snap, "sub").await.is_err()); // a directory, not a file
    }

    #[tokio::test]
    async fn backup_records_tags() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"x").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup_excluding(
            &mut repo,
            src.path(),
            &[],
            &["weekly".into(), "important".into()],
        )
        .await
        .unwrap();
        assert_eq!(
            repo.load_snapshot(&snap).await.unwrap().tags,
            vec!["weekly".to_string(), "important".to_string()]
        );
    }

    #[tokio::test]
    async fn forget_tagged_removes_matching_snapshots() {
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("f");
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        for (content, tag) in [(b"a".as_slice(), "keep"), (b"b", "temp"), (b"c", "temp")] {
            std::fs::write(&f, content).unwrap();
            backup_excluding(&mut repo, src.path(), &[], &[tag.to_string()])
                .await
                .unwrap();
        }
        assert_eq!(repo.list_snapshots().await.unwrap().len(), 3);

        // A dry run reports the same ids but removes nothing.
        let preview = forget_tagged(&repo, "temp", true).await.unwrap();
        assert_eq!(preview.len(), 2);
        assert_eq!(repo.list_snapshots().await.unwrap().len(), 3);

        let forgotten = forget_tagged(&repo, "temp", false).await.unwrap();
        assert_eq!(forgotten, preview);
        assert_eq!(repo.list_snapshots().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn lifecycle_old_snapshots_survive_new_backups_and_prune() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a"), b"alpha v1").unwrap();
        std::fs::write(src.path().join("b"), b"bravo unchanged").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap1 = backup(&mut repo, src.path()).await.unwrap();

        // Change "a", add "c"; "b" is untouched (its chunk is shared via dedup).
        std::fs::write(src.path().join("a"), b"alpha v2 changed and longer").unwrap();
        std::fs::write(src.path().join("c"), b"charlie new").unwrap();
        let snap2 = backup(&mut repo, src.path()).await.unwrap();

        // The older snapshot still restores to its own (v1) state.
        let out1 = tempfile::tempdir().unwrap();
        restore(&repo, &snap1, out1.path()).await.unwrap();
        assert_eq!(std::fs::read(out1.path().join("a")).unwrap(), b"alpha v1");
        assert_eq!(
            std::fs::read(out1.path().join("b")).unwrap(),
            b"bravo unchanged"
        );
        assert!(!out1.path().join("c").exists());

        // Forget the old snapshot and prune; the survivor must stay intact —
        // including "b", whose chunk is still referenced by snap2.
        forget(&repo, &snap1).await.unwrap();
        prune(&mut repo, false, 0).await.unwrap();
        assert!(verify(&repo).await.is_ok());

        let out2 = tempfile::tempdir().unwrap();
        restore(&repo, &snap2, out2.path()).await.unwrap();
        assert_eq!(
            std::fs::read(out2.path().join("a")).unwrap(),
            b"alpha v2 changed and longer"
        );
        assert_eq!(
            std::fs::read(out2.path().join("b")).unwrap(),
            b"bravo unchanged"
        );
        assert_eq!(
            std::fs::read(out2.path().join("c")).unwrap(),
            b"charlie new"
        );
    }

    /// Model-based data-safety test (`DESIGN.md` §11): drive a random sequence of
    /// backup / forget / prune operations and, after every step, assert the two
    /// invariants that matter for a backup tool — `verify` passes, and *every*
    /// surviving snapshot still restores byte-identical to the source state it
    /// captured. In other words, prune never removes data a live snapshot needs.
    #[tokio::test]
    async fn model_random_ops_keep_every_surviving_snapshot_intact() {
        use std::collections::BTreeMap;

        for seed in [7u64, 101, 31_337] {
            let src = tempfile::tempdir().unwrap();
            let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
                .await
                .unwrap();
            let mut s = seed;
            // Each surviving snapshot id -> the exact file tree it should restore to.
            let mut expected: BTreeMap<Id, BTreeMap<PathBuf, Vec<u8>>> = BTreeMap::new();

            for round in 0..12 {
                // Mutate the source: rewrite a few files (from a small name pool, so
                // chunks are shared and superseded across snapshots), sometimes delete.
                for _ in 0..(1 + rnd(&mut s) % 4) {
                    let name = format!("f{}", rnd(&mut s) % 6);
                    let len = (rnd(&mut s) % 2500) as usize;
                    let data: Vec<u8> = (0..len).map(|_| (rnd(&mut s) >> 33) as u8).collect();
                    std::fs::write(src.path().join(name), data).unwrap();
                }
                if rnd(&mut s) % 4 == 0 {
                    let _ = std::fs::remove_file(src.path().join(format!("f{}", rnd(&mut s) % 6)));
                }

                let snap = backup(&mut repo, src.path()).await.unwrap();
                expected.insert(snap, collect_files(src.path()));

                // Sometimes forget a random surviving snapshot.
                if expected.len() > 1 && rnd(&mut s) % 3 == 0 {
                    let victims: Vec<Id> = expected.keys().copied().collect();
                    let victim = victims[(rnd(&mut s) as usize) % victims.len()];
                    forget(&repo, &victim).await.unwrap();
                    expected.remove(&victim);
                }
                // Sometimes reclaim space; this is where a bug could delete live data.
                if rnd(&mut s) % 2 == 0 {
                    prune(&mut repo, false, 0).await.unwrap();
                }

                assert!(
                    verify(&repo).await.is_ok(),
                    "verify failed at round {round}, seed {seed}"
                );
                for (id, want) in &expected {
                    let out = tempfile::tempdir().unwrap();
                    restore(&repo, id, out.path()).await.unwrap();
                    assert_eq!(
                        &collect_files(out.path()),
                        want,
                        "snapshot {id} no longer restores at round {round}, seed {seed}"
                    );
                }
            }
        }
    }

    /// A backend that wraps a shared `MemoryBackend` and fails every `put` of a
    /// chosen `FileType`, to simulate a crash that interrupts a backup before it
    /// commits its snapshot.
    struct FaultBackend {
        inner: std::sync::Arc<MemoryBackend>,
        fail_on: FileType,
    }

    #[async_trait::async_trait]
    impl StorageBackend for FaultBackend {
        async fn get(&self, ty: FileType, id: &Id) -> sluice_store::Result<bytes::Bytes> {
            self.inner.get(ty, id).await
        }
        async fn put(&self, ty: FileType, id: &Id, data: bytes::Bytes) -> sluice_store::Result<()> {
            if ty == self.fail_on {
                return Err(sluice_store::StoreError::Backend("injected crash".into()));
            }
            self.inner.put(ty, id, data).await
        }
        async fn exists(&self, ty: FileType, id: &Id) -> sluice_store::Result<bool> {
            self.inner.exists(ty, id).await
        }
        async fn list(&self, ty: FileType) -> sluice_store::Result<Vec<Id>> {
            self.inner.list(ty).await
        }
        async fn remove(&self, ty: FileType, id: &Id) -> sluice_store::Result<()> {
            self.inner.remove(ty, id).await
        }
        async fn size(&self, ty: FileType, id: &Id) -> sluice_store::Result<u64> {
            self.inner.size(ty, id).await
        }
    }

    #[tokio::test]
    async fn crash_before_commit_keeps_existing_snapshots_intact() {
        use std::sync::Arc;
        let mem = Arc::new(MemoryBackend::new());

        // A first backup completes normally.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("keep"), b"durable data").unwrap();
        let snap1 = {
            let mut repo = Repository::init(mem.clone(), b"pw", fast()).await.unwrap();
            backup(&mut repo, src.path()).await.unwrap()
        };

        // A second backup writes its data but "crashes" committing the snapshot
        // (the snapshot is always written last, after the data it references).
        std::fs::write(src.path().join("more"), b"data that will be orphaned").unwrap();
        let interrupted = {
            let fault = FaultBackend {
                inner: mem.clone(),
                fail_on: FileType::Snapshot,
            };
            let mut repo = Repository::open(fault, b"pw").await.unwrap();
            backup(&mut repo, src.path()).await
        };
        assert!(interrupted.is_err(), "the interrupted backup must fail");

        // Reopen normally: the first snapshot is the only one, it still restores
        // byte-identical, and verify passes despite the orphaned data.
        let mut repo = Repository::open(mem.clone(), b"pw").await.unwrap();
        assert_eq!(repo.list_snapshots().await.unwrap(), vec![snap1]);
        assert!(verify(&repo).await.is_ok());
        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap1, out.path()).await.unwrap();
        assert_eq!(
            std::fs::read(out.path().join("keep")).unwrap(),
            b"durable data"
        );
        assert!(
            !out.path().join("more").exists(),
            "the uncommitted backup's new file is absent"
        );

        // The orphaned data is reclaimable, and pruning leaves the survivor intact.
        prune(&mut repo, false, 0).await.unwrap();
        assert!(verify(&repo).await.is_ok());
        assert_eq!(repo.list_snapshots().await.unwrap(), vec![snap1]);
    }

    #[tokio::test]
    async fn restore_subpath_restores_only_a_subtree() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("a/b")).unwrap();
        std::fs::write(src.path().join("a/b/file"), b"deep").unwrap();
        std::fs::write(src.path().join("top"), b"top").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let dst = tempfile::tempdir().unwrap();
        restore_subpath(&repo, &snap, Some("a/b"), dst.path())
            .await
            .unwrap();
        assert_eq!(std::fs::read(dst.path().join("b/file")).unwrap(), b"deep");
        assert!(!dst.path().join("top").exists());
        assert!(!dst.path().join("a").exists());
    }

    #[tokio::test]
    async fn restore_subpath_restores_a_single_file() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("d")).unwrap();
        std::fs::write(src.path().join("d/f"), b"content").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let dst = tempfile::tempdir().unwrap();
        restore_subpath(&repo, &snap, Some("d/f"), dst.path())
            .await
            .unwrap();
        assert_eq!(std::fs::read(dst.path().join("f")).unwrap(), b"content");
    }

    #[tokio::test]
    async fn restore_filter_includes_and_excludes_by_glob() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("docs")).unwrap();
        std::fs::write(src.path().join("docs/a.pdf"), b"pdf").unwrap();
        std::fs::write(src.path().join("docs/notes.txt"), b"text").unwrap();
        std::fs::create_dir_all(src.path().join("img")).unwrap();
        std::fs::write(src.path().join("img/photo.jpg"), b"jpeg").unwrap();
        std::fs::write(src.path().join("readme.md"), b"md").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        // --include '**/*.pdf': only the pdf is written.
        let inc = tempfile::tempdir().unwrap();
        let filter = RestoreFilter::new(&["**/*.pdf".to_string()], &[]).unwrap();
        restore_filtered(
            &repo,
            &snap,
            None,
            inc.path(),
            RestoreOptions::default(),
            &filter,
            None,
        )
        .await
        .unwrap();
        assert!(inc.path().join("docs/a.pdf").exists());
        assert!(!inc.path().join("docs/notes.txt").exists());
        assert!(!inc.path().join("img/photo.jpg").exists());
        assert!(!inc.path().join("readme.md").exists());

        // --exclude '**/*.txt' and the whole 'img' directory.
        let exc = tempfile::tempdir().unwrap();
        let filter = RestoreFilter::new(&[], &["**/*.txt".to_string(), "img".to_string()]).unwrap();
        restore_filtered(
            &repo,
            &snap,
            None,
            exc.path(),
            RestoreOptions::default(),
            &filter,
            None,
        )
        .await
        .unwrap();
        assert!(exc.path().join("docs/a.pdf").exists());
        assert!(exc.path().join("readme.md").exists());
        assert!(!exc.path().join("docs/notes.txt").exists(), "txt excluded");
        assert!(!exc.path().join("img").exists(), "excluded dir pruned");
    }

    fn rnd(s: &mut u64) -> u64 {
        *s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *s
    }

    fn build_random_tree(dir: &Path, depth: u32, s: &mut u64) {
        for i in 0..(rnd(s) % 4) {
            let len = (rnd(s) % 3000) as usize;
            let data: Vec<u8> = (0..len).map(|_| (rnd(s) >> 33) as u8).collect();
            std::fs::write(dir.join(format!("f{i}")), data).unwrap();
        }
        if depth > 0 {
            for i in 0..(rnd(s) % 3) {
                let sub = dir.join(format!("d{i}"));
                std::fs::create_dir(&sub).unwrap();
                build_random_tree(&sub, depth - 1, s);
            }
        }
    }

    fn collect_files(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let rel = path.strip_prefix(root).unwrap().to_path_buf();
                    out.insert(rel, std::fs::read(&path).unwrap());
                }
            }
        }
        out
    }

    #[tokio::test]
    async fn random_tree_backup_restore_roundtrips() {
        for seed in [1u64, 42, 12_345, 9_999] {
            let src = tempfile::tempdir().unwrap();
            let mut s = seed;
            build_random_tree(src.path(), 3, &mut s);

            let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
                .await
                .unwrap();
            let snap = backup(&mut repo, src.path()).await.unwrap();

            let dst = tempfile::tempdir().unwrap();
            restore(&repo, &snap, dst.path()).await.unwrap();

            assert_eq!(
                collect_files(src.path()),
                collect_files(dst.path()),
                "tree mismatch for seed {seed}"
            );
        }
    }

    /// Full-stack round trip over the object-store backend (the offsite/S3 code
    /// path): init, back up, reopen via a fresh handle on the same store (which
    /// rebuilds the index from the store), then verify and restore. Uses an
    /// in-memory object store, so no network or MinIO is needed. This exercises
    /// the object-store put/list and especially the native ranged `GET` used to
    /// read one blob out of a pack — a path no `MemoryBackend` test covers.
    #[tokio::test]
    async fn object_store_backend_full_roundtrip() {
        use object_store::{ObjectStore, memory::InMemory};
        use sluice_store::ObjectStoreBackend;
        use std::sync::Arc;

        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let src = tempfile::tempdir().unwrap();
        let mut s = 0x5104_1ce5u64;
        build_random_tree(src.path(), 3, &mut s);
        // A multi-megabyte incompressible file spans several packs, so restore and
        // verify must read individual blobs back with ranged GETs.
        let mut big = vec![0u8; 5 * 1024 * 1024];
        let mut x = 1u32;
        for b in big.iter_mut() {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (x >> 24) as u8;
        }
        std::fs::write(src.path().join("big.bin"), &big).unwrap();

        // init + backup over the object store.
        let snap = {
            let mut repo = Repository::init(ObjectStoreBackend::new(store.clone()), b"pw", fast())
                .await
                .unwrap();
            backup(&mut repo, src.path()).await.unwrap()
        };

        // Reopen through a fresh backend on the same store, then verify + restore.
        let repo = Repository::open(ObjectStoreBackend::new(store.clone()), b"pw")
            .await
            .unwrap();
        assert_eq!(repo.list_snapshots().await.unwrap(), vec![snap]);
        assert!(verify(&repo).await.is_ok());
        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        assert_eq!(collect_files(src.path()), collect_files(out.path()));
    }

    /// Like [`build_random_tree`], but also varies file modes and drops in
    /// relative symlinks, for the metadata-fidelity round-trip below.
    #[cfg(unix)]
    fn build_random_tree_meta(dir: &Path, depth: u32, s: &mut u64) {
        use std::os::unix::fs::PermissionsExt;
        let nfiles = rnd(s) % 4;
        for i in 0..nfiles {
            let len = (rnd(s) % 3000) as usize;
            let data: Vec<u8> = (0..len).map(|_| (rnd(s) >> 33) as u8).collect();
            let f = dir.join(format!("f{i}"));
            std::fs::write(&f, data).unwrap();
            // Give some files a non-default mode so the comparison can detect a
            // mode-replay regression.
            if rnd(s) % 2 == 0 {
                std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
            }
        }
        // A relative symlink to one of this directory's files.
        if nfiles > 0 && rnd(s) % 2 == 0 {
            symlink(
                &OsString::from(format!("f{}", rnd(s) % nfiles)),
                &dir.join("link"),
            )
            .unwrap();
        }
        if depth > 0 {
            for i in 0..(rnd(s) % 3) {
                let sub = dir.join(format!("d{i}"));
                std::fs::create_dir(&sub).unwrap();
                build_random_tree_meta(&sub, depth - 1, s);
            }
        }
    }

    /// A fingerprint of every entry under `root` (paths relative to it): mode and
    /// mtime plus content for files, mode and mtime for directories, and the
    /// target for symlinks (whose own mode/mtime are not part of the claim).
    #[cfg(unix)]
    fn collect_meta(root: &Path) -> std::collections::BTreeMap<PathBuf, (String, Vec<u8>)> {
        use std::os::unix::fs::PermissionsExt;
        let mut out = std::collections::BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                let rel = path.strip_prefix(root).unwrap().to_path_buf();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                let ft = meta.file_type();
                let mode = meta.permissions().mode() & 0o7777;
                let entry = if ft.is_symlink() {
                    (
                        "link".to_string(),
                        std::fs::read_link(&path)
                            .unwrap()
                            .into_os_string()
                            .into_encoded_bytes(),
                    )
                } else if ft.is_dir() {
                    stack.push(path.clone());
                    (
                        format!("dir mode={mode:o} mtime={}", mtime_ns(&meta)),
                        Vec::new(),
                    )
                } else {
                    (
                        format!("file mode={mode:o} mtime={}", mtime_ns(&meta)),
                        std::fs::read(&path).unwrap(),
                    )
                };
                out.insert(rel, entry);
            }
        }
        out
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn random_tree_roundtrip_preserves_metadata() {
        for seed in [3u64, 71, 5_000, 88_888] {
            let src = tempfile::tempdir().unwrap();
            let mut s = seed;
            build_random_tree_meta(src.path(), 3, &mut s);

            let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
                .await
                .unwrap();
            let snap = backup(&mut repo, src.path()).await.unwrap();

            let dst = tempfile::tempdir().unwrap();
            restore(&repo, &snap, dst.path()).await.unwrap();

            // Every entry's structure, content, mode, mtime, and link target survive.
            assert_eq!(
                collect_meta(src.path()),
                collect_meta(dst.path()),
                "metadata mismatch for seed {seed}"
            );
        }
    }

    #[tokio::test]
    async fn backup_of_a_nonexistent_source_errors() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let missing = std::path::Path::new("/no/such/path/sluice-xyz");
        assert!(matches!(
            backup(&mut repo, missing).await,
            Err(EngineError::NotADirectory(_))
        ));
    }

    #[tokio::test]
    async fn backup_restores_a_single_file_source() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        std::fs::write(&file, b"key = 1\n").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();

        let snap = backup(&mut repo, &file).await.unwrap();
        assert_eq!(
            repo.load_snapshot(&snap).await.unwrap().summary.files_new,
            1
        );
        assert!(verify(&repo).await.is_ok());

        // It restores under the target by its base name.
        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        assert_eq!(
            std::fs::read(out.path().join("config.toml")).unwrap(),
            b"key = 1\n"
        );

        // A re-backup with the file unchanged reports it unmodified.
        let again = backup(&mut repo, &file).await.unwrap();
        assert_eq!(
            repo.load_snapshot(&again)
                .await
                .unwrap()
                .summary
                .files_unmodified,
            1
        );
    }

    #[tokio::test]
    async fn prune_dry_run_removes_nothing() {
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("f");
        std::fs::write(&f, b"first").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap1 = backup(&mut repo, src.path()).await.unwrap();
        std::fs::write(&f, b"second, different content").unwrap();
        backup(&mut repo, src.path()).await.unwrap();
        forget(&repo, &snap1).await.unwrap();

        let before = repo.backend().list(FileType::Pack).await.unwrap().len();
        let would = prune(&mut repo, true, 0).await.unwrap();
        assert!(would.deleted >= 1, "dry-run should find packs to prune");
        assert_eq!(
            repo.backend().list(FileType::Pack).await.unwrap().len(),
            before,
            "dry-run must not delete anything"
        );

        let removed = prune(&mut repo, false, 0).await.unwrap();
        // A dry run is an exact preview: same deleted/repacked/reclaimed counts.
        assert_eq!(removed, would);
        assert!(repo.backend().list(FileType::Pack).await.unwrap().len() < before);
    }

    async fn total_pack_bytes<B: StorageBackend>(repo: &Repository<B>) -> u64 {
        let mut total = 0;
        for pid in repo.backend().list(FileType::Pack).await.unwrap() {
            total += repo.backend().size(FileType::Pack, &pid).await.unwrap();
        }
        total
    }

    #[tokio::test]
    async fn prune_repacks_partially_dead_packs() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a"), vec![1u8; 3000]).unwrap();
        std::fs::write(src.path().join("b"), vec![2u8; 3000]).unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // snap1: a and b share one accumulated pack.
        let snap1 = backup(&mut repo, src.path()).await.unwrap();
        // Change a; b is untouched, so its chunk stays referenced via dedup.
        std::fs::write(src.path().join("a"), vec![9u8; 3000]).unwrap();
        let snap2 = backup(&mut repo, src.path()).await.unwrap();

        forget(&repo, &snap1).await.unwrap();
        let before = total_pack_bytes(&repo).await;
        let report = prune(&mut repo, false, 0).await.unwrap();
        let after = total_pack_bytes(&repo).await;
        // snap1's pack was partially live (b) -> repacked, reclaiming a-v1 + tree1.
        assert!(
            after < before,
            "repack should reclaim space: {before} -> {after}"
        );
        // The reported reclaimed bytes equal the actual on-disk reduction.
        assert_eq!(report.repacked, 1);
        assert_eq!(report.reclaimed_bytes, before - after);

        // The survivor still verifies and restores fully (b moved to a new pack).
        assert!(verify(&repo).await.is_ok());
        let dst = tempfile::tempdir().unwrap();
        restore(&repo, &snap2, dst.path()).await.unwrap();
        assert_eq!(
            std::fs::read(dst.path().join("a")).unwrap(),
            vec![9u8; 3000]
        );
        assert_eq!(
            std::fs::read(dst.path().join("b")).unwrap(),
            vec![2u8; 3000]
        );
    }

    #[tokio::test]
    async fn prune_excluding_previews_a_pending_forget() {
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("f");
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        std::fs::write(&f, vec![1u8; 4000]).unwrap();
        let snap1 = backup(&mut repo, src.path()).await.unwrap();
        std::fs::write(&f, vec![2u8; 4000]).unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        // Excluding snap1 (still present) previews reclaiming its now-dead data.
        let excluded = HashSet::from([snap1]);
        let report = prune_excluding(&mut repo, true, &excluded, 0)
            .await
            .unwrap();
        assert!(
            report.reclaimed_bytes > 0,
            "should preview reclaimable bytes"
        );
        // Nothing was actually removed: both snapshots remain and verify.
        assert_eq!(repo.list_snapshots().await.unwrap().len(), 2);
        assert!(verify(&repo).await.is_ok());

        // A plain prune (excluding nothing) finds nothing dead yet.
        let none = prune(&mut repo, true, 0).await.unwrap();
        assert_eq!(none.reclaimed_bytes, 0);
    }

    #[tokio::test]
    async fn prune_refuses_to_run_while_locked() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"data").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        // A concurrent operation holds a (shared) lock.
        let held = repo.acquire_lock(false).await.unwrap();
        assert!(prune(&mut repo, false, 0).await.is_err());
        // A dry run takes no lock, so it still works.
        assert!(prune(&mut repo, true, 0).await.is_ok());

        // Once released, prune proceeds and releases its own lock afterwards.
        repo.release_lock(&held).await.unwrap();
        assert!(prune(&mut repo, false, 0).await.is_ok());
        assert!(repo.list_locks().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn prune_max_unused_skips_low_waste_packs() {
        let src = tempfile::tempdir().unwrap();
        // A large *incompressible* file (so its stored size dominates the pack),
        // reused across backups, plus a tiny one.
        let mut big = vec![0u8; 200_000];
        let mut state = 0x1234_5678u32;
        for b in big.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (state >> 24) as u8;
        }
        std::fs::write(src.path().join("big"), &big).unwrap();
        std::fs::write(src.path().join("small"), b"v1").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap1 = backup(&mut repo, src.path()).await.unwrap();
        std::fs::write(src.path().join("small"), b"v2").unwrap(); // change only the tiny file
        backup(&mut repo, src.path()).await.unwrap();
        forget(&repo, &snap1).await.unwrap();

        // snap1's pack is almost entirely the still-live big chunk; only small-v1
        // and tree1 are dead (well under 50%), so a 50% tolerance leaves it.
        let report = prune(&mut repo, false, 50).await.unwrap();
        assert_eq!(report.repacked, 0, "low-waste pack should be left alone");
        assert!(verify(&repo).await.is_ok());

        // Zero tolerance repacks it.
        let report = prune(&mut repo, false, 0).await.unwrap();
        assert_eq!(report.repacked, 1);
        assert!(verify(&repo).await.is_ok());
    }

    #[tokio::test]
    async fn backup_refuses_under_an_exclusive_lock() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"data").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();

        // An exclusive lock (as prune holds) blocks backup's shared lock.
        let held = repo.acquire_lock(true).await.unwrap();
        assert!(backup(&mut repo, src.path()).await.is_err());

        // Released: backup proceeds and leaves no lock behind.
        repo.release_lock(&held).await.unwrap();
        assert!(backup(&mut repo, src.path()).await.is_ok());
        assert!(repo.list_locks().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn backup_dry_run_counts_without_writing() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a"), b"alpha").unwrap();
        std::fs::write(src.path().join("b"), vec![7u8; 2000]).unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();

        let summary = backup_dry_run(&mut repo, src.path(), &[]).await.unwrap();
        assert_eq!(summary.files_new, 2);
        assert_eq!(summary.files_unmodified, 0);
        // Nothing was persisted.
        assert!(repo.list_snapshots().await.unwrap().is_empty());
        assert!(
            repo.backend()
                .list(FileType::Pack)
                .await
                .unwrap()
                .is_empty()
        );

        // After a real backup, a dry run sees everything as unmodified.
        backup(&mut repo, src.path()).await.unwrap();
        let again = backup_dry_run(&mut repo, src.path(), &[]).await.unwrap();
        assert_eq!(again.files_new, 0);
        assert_eq!(again.files_unmodified, 2);
        // The dry run added no second snapshot.
        assert_eq!(repo.list_snapshots().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn copy_snapshot_between_repositories() {
        let src_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(src_dir.path().join("sub")).unwrap();
        std::fs::write(src_dir.path().join("a.txt"), b"alpha").unwrap();
        std::fs::write(src_dir.path().join("sub/b.bin"), vec![7u8; 3000]).unwrap();

        let mut src = Repository::init(MemoryBackend::new(), b"src-pw", fast())
            .await
            .unwrap();
        let snap = backup_excluding(&mut src, src_dir.path(), &[], &["weekly".into()][..])
            .await
            .unwrap();

        // A separate repository with a *different* passphrase.
        let mut dst = Repository::init(MemoryBackend::new(), b"dst-pw", fast())
            .await
            .unwrap();
        let new_id = copy_snapshot(&src, &mut dst, &snap).await.unwrap();

        // The copy authenticates in dst, keeps the metadata, and has no parent.
        assert!(verify(&dst).await.is_ok());
        let copied = dst.load_snapshot(&new_id).await.unwrap();
        assert_eq!(copied.tags, vec!["weekly".to_string()]);
        assert!(copied.parent.is_none());

        // Restoring from dst reproduces the original bytes.
        let out = tempfile::tempdir().unwrap();
        restore(&dst, &new_id, out.path()).await.unwrap();
        assert_eq!(std::fs::read(out.path().join("a.txt")).unwrap(), b"alpha");
        assert_eq!(
            std::fs::read(out.path().join("sub/b.bin")).unwrap(),
            vec![7u8; 3000]
        );
    }

    #[tokio::test]
    async fn copy_all_replicates_every_snapshot() {
        let src_dir = tempfile::tempdir().unwrap();
        let f = src_dir.path().join("f");
        let mut src = Repository::init(MemoryBackend::new(), b"src-pw", fast())
            .await
            .unwrap();
        std::fs::write(&f, b"v1").unwrap();
        backup(&mut src, src_dir.path()).await.unwrap();
        std::fs::write(&f, b"v2").unwrap();
        backup(&mut src, src_dir.path()).await.unwrap();

        let mut dst = Repository::init(MemoryBackend::new(), b"dst-pw", fast())
            .await
            .unwrap();
        let ids = copy_all(&src, &mut dst).await.unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(dst.list_snapshots().await.unwrap().len(), 2);
        assert!(verify(&dst).await.is_ok());

        // Re-running copies nothing new (idempotent at the snapshot level).
        copy_all(&src, &mut dst).await.unwrap();
        assert_eq!(dst.list_snapshots().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn backup_sources_combines_multiple_dirs() {
        let base = tempfile::tempdir().unwrap();
        let one = base.path().join("one");
        std::fs::create_dir(&one).unwrap();
        std::fs::write(one.join("a"), b"A").unwrap();
        let two = base.path().join("two");
        std::fs::create_dir(&two).unwrap();
        std::fs::write(two.join("b"), b"B").unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let outcome = backup_sources(&mut repo, &[one.clone(), two.clone()], &[], &[], false)
            .await
            .unwrap();
        let snap = outcome.snapshot.unwrap();
        assert_eq!(outcome.summary.files_new, 2);

        // Each source is restored under its own basename.
        let out = tempfile::tempdir().unwrap();
        restore(&repo, &snap, out.path()).await.unwrap();
        assert_eq!(std::fs::read(out.path().join("one/a")).unwrap(), b"A");
        assert_eq!(std::fs::read(out.path().join("two/b")).unwrap(), b"B");

        // A second run is incremental across the synthetic root: all unmodified.
        let again = backup_sources(&mut repo, &[one.clone(), two.clone()], &[], &[], false)
            .await
            .unwrap();
        assert_eq!(again.summary.files_new, 0);
        assert_eq!(again.summary.files_unmodified, 2);

        // Two sources with the same final component are rejected.
        let x = base.path().join("x/data");
        std::fs::create_dir_all(&x).unwrap();
        let y = base.path().join("y/data");
        std::fs::create_dir_all(&y).unwrap();
        assert!(matches!(
            backup_sources(&mut repo, &[x, y], &[], &[], false).await,
            Err(EngineError::DuplicateSource(_))
        ));
    }

    #[tokio::test]
    async fn find_locates_paths_across_snapshots() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"a").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap1 = backup(&mut repo, src.path()).await.unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/needle.log"), b"x").unwrap();
        let snap2 = backup(&mut repo, src.path()).await.unwrap();

        // An exact nested path: only the second snapshot has it.
        let hits = find(&repo, "sub/needle.log").await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].snapshot, snap2);
        assert_eq!(hits[0].path, "sub/needle.log");

        // A.txt is present in both snapshots.
        let both = find(&repo, "a.txt").await.unwrap();
        let snaps: HashSet<Id> = both.iter().map(|m| m.snapshot).collect();
        assert_eq!(snaps, HashSet::from([snap1, snap2]));

        // A glob that matches nothing anywhere.
        assert!(find(&repo, "*.nope").await.unwrap().is_empty());
        // A `**` glob crosses directories.
        let logs = find(&repo, "**/*.log").await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].path, "sub/needle.log");
    }

    #[tokio::test]
    async fn retag_rewrites_a_snapshots_tags() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"data").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let id = backup_excluding(&mut repo, src.path(), &[], &["keep".into()])
            .await
            .unwrap();

        let new_id = retag(&repo, &id, &["weekly".into()], &["keep".into()])
            .await
            .unwrap();
        assert_ne!(new_id, id);
        // The old snapshot is gone; the new one carries the rewritten tags.
        assert!(repo.load_snapshot(&id).await.is_err());
        assert_eq!(
            repo.load_snapshot(&new_id).await.unwrap().tags,
            vec!["weekly".to_string()]
        );
        assert_eq!(repo.list_snapshots().await.unwrap(), vec![new_id]);
        // The data is untouched: the tree is shared and still referenced.
        assert!(verify(&repo).await.is_ok());

        // A change that adds nothing new returns the same id (no rewrite).
        let same = retag(&repo, &new_id, &["weekly".into()], &[])
            .await
            .unwrap();
        assert_eq!(same, new_id);
        assert_eq!(repo.list_snapshots().await.unwrap(), vec![new_id]);
    }

    #[tokio::test]
    async fn check_passes_for_a_healthy_backup() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a"), b"alpha").unwrap();
        std::fs::create_dir(src.path().join("d")).unwrap();
        std::fs::write(src.path().join("d/b"), vec![5u8; 2000]).unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        let report = check(&repo).await.unwrap();
        assert_eq!(report.snapshots, 1);
        assert!(report.trees >= 2, "root + subdir trees");
        assert!(report.blobs >= 2, "a and d/b content");
        assert!(report.missing.is_empty());
    }

    #[tokio::test]
    async fn check_reports_a_missing_content_blob() {
        use sluice_core::BlobKind;
        use std::sync::Arc;

        let backend = Arc::new(MemoryBackend::new());
        let mut repo = Repository::init(backend.clone(), b"pw", fast())
            .await
            .unwrap();

        // A content chunk, alone in its own pack.
        let chunk = repo
            .save_blob(BlobKind::Data, b"file contents")
            .await
            .unwrap();
        repo.flush().await.unwrap();
        let packs = repo.backend().list(FileType::Pack).await.unwrap();
        assert_eq!(packs.len(), 1);
        let pack_c = packs[0];

        // A tree referencing the chunk (in a separate pack) and a snapshot.
        let node = Node {
            name: b"f".to_vec(),
            kind: EntryKind::File,
            mode: 0,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            size: 13,
            content: vec![chunk],
            subtree: None,
            link_target: None,
            dev: 0,
            ino: 0,
            xattrs: Vec::new(),
            rdev: 0,
            sparse: false,
        };
        let tree = repo
            .save_tree(&Tree {
                version: TREE_VERSION,
                nodes: vec![node],
            })
            .await
            .unwrap();
        repo.flush().await.unwrap();
        repo.commit_snapshot(&Snapshot {
            version: SNAPSHOT_VERSION,
            time_ns: 0,
            tree,
            paths: vec![],
            hostname: "h".into(),
            username: "u".into(),
            uid: 0,
            gid: 0,
            tags: vec![],
            parent: None,
            program_version: "test".into(),
            summary: SnapshotStats::default(),
        })
        .await
        .unwrap();

        // Healthy while the chunk is present.
        assert!(check(&repo).await.unwrap().missing.is_empty());

        // Drop the chunk's pack and its index segment, then reopen so the rebuilt
        // index no longer knows the chunk.
        backend.remove(FileType::Pack, &pack_c).await.unwrap();
        backend.remove(FileType::Index, &pack_c).await.ok();
        let reopened = Repository::open(backend.clone(), b"pw").await.unwrap();

        let report = check(&reopened).await.unwrap();
        assert_eq!(report.trees, 1);
        assert_eq!(report.blobs, 1);
        assert_eq!(report.missing, vec![chunk]);
    }
}
