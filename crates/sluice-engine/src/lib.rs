//! `sluice-engine` — backup and restore orchestration (see `DESIGN.md` §6, §8).
//!
//! This first cut walks a directory tree, storing each regular file as
//! deduplicated chunks and each directory as a `Tree`, then commits a snapshot;
//! restore rebuilds the tree and replays mode/mtime. Files, directories, and
//! symlinks are handled; special files (fifo/socket/device) remain. The walk
//! uses blocking `std::fs` for now; offloading to a thread pool is a later
//! refinement.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use globset::{Glob, GlobSet, GlobSetBuilder};
use sluice_core::{
    EntryKind, Id, Node, SNAPSHOT_VERSION, Snapshot, SnapshotStats, TREE_VERSION, Tree,
};
use sluice_repo::{RepoError, Repository};
use sluice_store::{FileType, PackReader, StorageBackend};

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
    backup_excluding(repo, source, &[]).await
}

/// Back up `source`, skipping entries whose name matches one of `exclude_globs`
/// (a skipped directory is pruned along with its contents).
pub async fn backup_excluding<B: StorageBackend>(
    repo: &mut Repository<B>,
    source: &Path,
    exclude_globs: &[String],
) -> Result<Id> {
    let excludes = build_globset(exclude_globs)?;
    let parent = latest_snapshot(repo).await?;
    let parent_tree = parent.as_ref().map(|(_, snap)| snap.tree);
    let mut summary = SnapshotStats::default();
    let root_tree = backup_dir(
        repo,
        source.to_path_buf(),
        parent_tree,
        &excludes,
        &mut summary,
    )
    .await?;
    let snapshot = Snapshot {
        version: SNAPSHOT_VERSION,
        time_ns: now_ns(),
        tree: root_tree,
        paths: vec![source.as_os_str().as_encoded_bytes().to_vec()],
        hostname: env_or("HOSTNAME", "localhost"),
        username: env_or("USER", "unknown"),
        uid: 0,
        gid: 0,
        tags: Vec::new(),
        parent: parent.map(|(id, _)| id),
        program_version: env!("CARGO_PKG_VERSION").to_string(),
        summary,
    };
    Ok(repo.commit_snapshot(&snapshot).await?)
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

/// Restore the snapshot `snapshot` from `repo` into the directory `target`.
pub async fn restore<B: StorageBackend>(
    repo: &Repository<B>,
    snapshot: &Id,
    target: &Path,
) -> Result<()> {
    let snap = repo.load_snapshot(snapshot).await?;
    std::fs::create_dir_all(target).map_err(|e| io_err(target, e))?;
    restore_tree(repo, snap.tree, target.to_path_buf()).await
}

/// A summary produced by [`verify`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct VerifyReport {
    /// Number of snapshots checked.
    pub snapshots: usize,
    /// Number of tree objects read and authenticated.
    pub trees: usize,
    /// Number of content (file chunk) blobs read and authenticated.
    pub blobs: usize,
}

/// Verify every snapshot in `repo` by reading and authenticating all reachable
/// trees and content blobs (a full read-data check; see `DESIGN.md` §5.7).
///
/// Returns the counts on success, or the first error identifying a missing or
/// corrupt object.
pub async fn verify<B: StorageBackend>(repo: &Repository<B>) -> Result<VerifyReport> {
    let mut report = VerifyReport::default();
    for snapshot in repo.list_snapshots().await? {
        let snap = repo.load_snapshot(&snapshot).await?;
        report.snapshots += 1;
        verify_tree(repo, snap.tree, &mut report).await?;
    }
    Ok(report)
}

/// Recursively read and authenticate the tree `tree_id` and its content blobs.
fn verify_tree<'a, B: StorageBackend>(
    repo: &'a Repository<B>,
    tree_id: Id,
    report: &'a mut VerifyReport,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let tree = repo.load_tree(&tree_id).await?;
        report.trees += 1;
        for node in &tree.nodes {
            match node.kind {
                EntryKind::Dir => {
                    if let Some(subtree) = node.subtree {
                        verify_tree(repo, subtree, report).await?;
                    }
                }
                EntryKind::File => {
                    for id in &node.content {
                        // load_blob authenticates (AEAD) and decompresses.
                        repo.load_blob(id).await?;
                        report.blobs += 1;
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

/// Keep the `keep` most recent snapshots and forget the rest, returning the ids
/// that were forgotten. Reclaim their data afterwards with [`prune`].
pub async fn forget_keep_last<B: StorageBackend>(
    repo: &Repository<B>,
    keep: usize,
) -> Result<Vec<Id>> {
    let mut snapshots = Vec::new();
    for id in repo.list_snapshots().await? {
        let time = repo.load_snapshot(&id).await?.time_ns;
        snapshots.push((id, time));
    }
    snapshots.sort_by(|a, b| b.1.cmp(&a.1)); // most recent first
    let mut forgotten = Vec::new();
    for (id, _) in snapshots.into_iter().skip(keep) {
        forget(repo, &id).await?;
        forgotten.push(id);
    }
    Ok(forgotten)
}

/// Delete packs no longer referenced by any surviving snapshot, returning the
/// number removed (mark-and-sweep GC; see `DESIGN.md` §8).
pub async fn prune<B: StorageBackend>(repo: &Repository<B>) -> Result<usize> {
    // MARK: collect every blob reachable from a surviving snapshot.
    let mut live: HashSet<Id> = HashSet::new();
    for snapshot in repo.list_snapshots().await? {
        let snap = repo.load_snapshot(&snapshot).await?;
        mark_tree(repo, snap.tree, &mut live).await?;
    }

    // SWEEP: delete any pack whose blobs are all unreferenced.
    let mut removed = 0;
    for pack_id in repo
        .backend()
        .list(FileType::Pack)
        .await
        .map_err(RepoError::from)?
    {
        let bytes = repo
            .backend()
            .get(FileType::Pack, &pack_id)
            .await
            .map_err(RepoError::from)?;
        let reader = PackReader::parse(&bytes).map_err(RepoError::from)?;
        if !reader.entries().iter().any(|e| live.contains(&e.id)) {
            repo.backend()
                .remove(FileType::Pack, &pack_id)
                .await
                .map_err(RepoError::from)?;
            removed += 1;
        }
    }
    Ok(removed)
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
    /// Present in both, but with a different kind or size.
    Modified,
}

/// A single change reported by [`diff`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    /// Path relative to the backup root.
    pub path: String,
    /// The kind of change.
    pub change: DiffKind,
}

/// Compare two snapshots by path, reporting added, removed, and modified entries
/// (modification is detected by a change in kind or size). Unchanged entries are
/// omitted; the result is sorted by path.
pub async fn diff<B: StorageBackend>(
    repo: &Repository<B>,
    from: &Id,
    to: &Id,
) -> Result<Vec<DiffEntry>> {
    let old: HashMap<String, (EntryKind, u64)> = list_files(repo, from)
        .await?
        .into_iter()
        .map(|e| (e.path, (e.kind, e.size)))
        .collect();
    let new: HashMap<String, (EntryKind, u64)> = list_files(repo, to)
        .await?
        .into_iter()
        .map(|e| (e.path, (e.kind, e.size)))
        .collect();

    let mut changes = Vec::new();
    for (path, meta) in &new {
        match old.get(path) {
            None => changes.push(DiffEntry {
                path: path.clone(),
                change: DiffKind::Added,
            }),
            Some(prev) if prev != meta => changes.push(DiffEntry {
                path: path.clone(),
                change: DiffKind::Modified,
            }),
            _ => {}
        }
    }
    for path in old.keys() {
        if !new.contains_key(path) {
            changes.push(DiffEntry {
                path: path.clone(),
                change: DiffKind::Removed,
            });
        }
    }
    changes.sort_by(|x, y| x.path.cmp(&y.path));
    Ok(changes)
}

/// Recursively back up `dir`, returning the id of its `Tree` object. `parent`
/// is the id of the same directory's tree in the previous snapshot, if any, and
/// `stats` accumulates new/changed/unmodified counters.
fn backup_dir<'a, B: StorageBackend>(
    repo: &'a mut Repository<B>,
    dir: PathBuf,
    parent: Option<Id>,
    excludes: &'a GlobSet,
    stats: &'a mut SnapshotStats,
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
            if excludes.is_match(&file_name) {
                continue;
            }
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).map_err(|e| io_err(&path, e))?;
            let name = file_name.as_encoded_bytes().to_vec();
            let kind = meta.file_type();
            let mtime = mtime_ns(&meta);

            let node = if kind.is_dir() {
                let parent_sub = parent_nodes
                    .get(&name)
                    .and_then(|n| (n.kind == EntryKind::Dir).then_some(n.subtree).flatten());
                let subtree = backup_dir(repo, path.clone(), parent_sub, excludes, stats).await?;
                stats.dirs += 1;
                Node {
                    name,
                    kind: EntryKind::Dir,
                    mode: mode_of(&meta),
                    uid: 0,
                    gid: 0,
                    mtime_ns: mtime,
                    ctime_ns: 0,
                    size: 0,
                    content: Vec::new(),
                    subtree: Some(subtree),
                    link_target: None,
                }
            } else if kind.is_file() {
                // Reuse the parent's chunks if size and mtime are unchanged.
                let reuse = parent_nodes.get(&name).and_then(|prev| {
                    (prev.kind == EntryKind::File
                        && prev.size == meta.len()
                        && prev.mtime_ns == mtime)
                        .then(|| prev.content.clone())
                });
                let (content, size) = if let Some(content) = reuse {
                    stats.files_unmodified += 1;
                    (content, meta.len())
                } else {
                    if parent_nodes.contains_key(&name) {
                        stats.files_changed += 1;
                    } else {
                        stats.files_new += 1;
                    }
                    let data = std::fs::read(&path).map_err(|e| io_err(&path, e))?;
                    let content = repo.save_file(&data).await?;
                    (content, data.len() as u64)
                };
                stats.bytes_processed += size;
                Node {
                    name,
                    kind: EntryKind::File,
                    mode: mode_of(&meta),
                    uid: 0,
                    gid: 0,
                    mtime_ns: mtime,
                    ctime_ns: 0,
                    size,
                    content,
                    subtree: None,
                    link_target: None,
                }
            } else if kind.is_symlink() {
                let target = std::fs::read_link(&path).map_err(|e| io_err(&path, e))?;
                Node {
                    name,
                    kind: EntryKind::Symlink,
                    mode: mode_of(&meta),
                    uid: 0,
                    gid: 0,
                    mtime_ns: mtime,
                    ctime_ns: 0,
                    size: 0,
                    content: Vec::new(),
                    subtree: None,
                    link_target: Some(target.into_os_string().into_encoded_bytes()),
                }
            } else {
                continue; // special files (fifo, socket, device): follow-up work
            };
            nodes.push(node);
        }

        let tree = Tree {
            version: TREE_VERSION,
            nodes,
        };
        Ok(repo.save_tree(&tree).await?)
    })
}

/// Recursively restore the tree `tree_id` into the directory `dir`.
fn restore_tree<'a, B: StorageBackend>(
    repo: &'a Repository<B>,
    tree_id: Id,
    dir: PathBuf,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let tree = repo.load_tree(&tree_id).await?;
        for node in &tree.nodes {
            let path = dir.join(osstring_from_bytes(&node.name));
            match node.kind {
                EntryKind::Dir => {
                    std::fs::create_dir_all(&path).map_err(|e| io_err(&path, e))?;
                    if let Some(subtree) = node.subtree {
                        restore_tree(repo, subtree, path.clone()).await?;
                    }
                    // Replay the directory's mtime after its children are written.
                    apply_metadata(&path, node);
                }
                EntryKind::File => {
                    let data = repo.load_file(&node.content).await?;
                    std::fs::write(&path, &data).map_err(|e| io_err(&path, e))?;
                    apply_metadata(&path, node);
                }
                EntryKind::Symlink => {
                    if let Some(target) = &node.link_target {
                        symlink(&osstring_from_bytes(target), &path)?;
                    }
                }
                _ => continue, // special files (fifo, socket, device): follow-up work
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

/// Best-effort replay of a node's mode (Unix) and mtime onto `path`.
fn apply_metadata(path: &Path, node: &Node) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(node.mode));
    }
    let mtime = filetime::FileTime::from_unix_time(
        node.mtime_ns.div_euclid(1_000_000_000),
        node.mtime_ns.rem_euclid(1_000_000_000) as u32,
    );
    let _ = filetime::set_file_mtime(path, mtime);
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    if meta.is_dir() { 0o755 } else { 0o644 }
}

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
        restore(&repo, &snap, dst.path()).await.unwrap();

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
        let removed = prune(&repo).await.unwrap();
        let after = repo.backend().list(FileType::Pack).await.unwrap().len();

        assert!(removed >= 1, "expected to reclaim packs");
        assert_eq!(before - after, removed);
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
        let snap = backup_excluding(&mut repo, src.path(), &["*.log".into(), "cache".into()])
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
    }
}
