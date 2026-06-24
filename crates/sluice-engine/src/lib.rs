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
use sluice_repo::{PruneReport, RepoError, Repository};
use sluice_store::{FileType, StorageBackend};

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
    #[error("backup source is not a directory: {0}")]
    NotADirectory(String),
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
    if !source.is_dir() {
        return Err(EngineError::NotADirectory(source.display().to_string()));
    }
    // Hold a shared lock for the run: it blocks a concurrent prune from deleting
    // data this snapshot will reference, while letting other backups proceed.
    let lock = repo.acquire_lock(false).await?;
    let result = backup_inner(repo, source, exclude_globs, tags).await;
    let _ = repo.release_lock(&lock).await;
    result
}

/// The body of [`backup_excluding`], run while holding a shared lock.
async fn backup_inner<B: StorageBackend>(
    repo: &mut Repository<B>,
    source: &Path,
    exclude_globs: &[String],
    tags: &[String],
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
        false,
    )
    .await?;
    repo.flush().await?;
    let snapshot = Snapshot {
        version: SNAPSHOT_VERSION,
        time_ns: now_ns(),
        tree: root_tree,
        paths: vec![source.as_os_str().as_encoded_bytes().to_vec()],
        hostname: env_or("HOSTNAME", "localhost"),
        username: env_or("USER", "unknown"),
        uid: 0,
        gid: 0,
        tags: tags.to_vec(),
        parent: parent.map(|(id, _)| id),
        program_version: env!("CARGO_PKG_VERSION").to_string(),
        summary,
    };
    Ok(repo.commit_snapshot(&snapshot).await?)
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
    if !source.is_dir() {
        return Err(EngineError::NotADirectory(source.display().to_string()));
    }
    let excludes = build_globset(exclude_globs)?;
    let parent = latest_snapshot(repo).await?;
    let parent_tree = parent.as_ref().map(|(_, snap)| snap.tree);
    let mut summary = SnapshotStats::default();
    backup_dir(
        repo,
        source.to_path_buf(),
        parent_tree,
        &excludes,
        &mut summary,
        true,
    )
    .await?;
    Ok(summary)
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
    restore_subpath(repo, snapshot, None, target).await
}

/// Restore a snapshot into `target`. With `subpath`, restore only that entry
/// (a directory subtree, file, or symlink), placed under `target` by base name.
pub async fn restore_subpath<B: StorageBackend>(
    repo: &Repository<B>,
    snapshot: &Id,
    subpath: Option<&str>,
    target: &Path,
) -> Result<()> {
    let snap = repo.load_snapshot(snapshot).await?;
    std::fs::create_dir_all(target).map_err(|e| io_err(target, e))?;
    let Some(path) = subpath else {
        return restore_tree(repo, snap.tree, target.to_path_buf()).await;
    };

    let node = find_node(repo, snap.tree, path).await?;
    let dest = target.join(osstring_from_bytes(&node.name));
    match node.kind {
        EntryKind::Dir => {
            std::fs::create_dir_all(&dest).map_err(|e| io_err(&dest, e))?;
            if let Some(subtree) = node.subtree {
                restore_tree(repo, subtree, dest.clone()).await?;
            }
            apply_metadata(&dest, &node);
        }
        EntryKind::File => {
            let data = repo.load_file(&node.content).await?;
            std::fs::write(&dest, &data).map_err(|e| io_err(&dest, e))?;
            apply_metadata(&dest, &node);
        }
        EntryKind::Symlink => {
            if let Some(link_target) = &node.link_target {
                symlink(&osstring_from_bytes(link_target), &dest)?;
            }
        }
        _ => {}
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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
    policy: RetentionPolicy,
    dry_run: bool,
) -> Result<Vec<Id>> {
    let mut snapshots = Vec::new();
    for id in repo.list_snapshots().await? {
        let time = repo.load_snapshot(&id).await?.time_ns;
        snapshots.push((id, time));
    }
    snapshots.sort_by(|a, b| b.1.cmp(&a.1)); // most recent first

    let mut keep: HashSet<Id> = HashSet::new();
    // `--keep-last N`: the N most recent snapshots outright.
    for (id, _) in snapshots.iter().take(policy.last) {
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
        for (id, time) in &snapshots {
            let bucket = bucket_of(*time);
            if kept_buckets.last() != Some(&bucket) && kept_buckets.len() < budget {
                kept_buckets.push(bucket);
                keep.insert(*id);
            }
        }
    }

    let mut forgotten = Vec::new();
    for (id, _) in &snapshots {
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
        RetentionPolicy {
            last: keep,
            ..Default::default()
        },
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
        RetentionPolicy {
            daily: keep,
            ..Default::default()
        },
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
) -> Result<PruneReport> {
    prune_excluding(repo, dry_run, &HashSet::new()).await
}

/// Like [`prune`], but treat the snapshots in `excluded` as already gone — their
/// blobs are not marked live. This lets a dry run preview the reclamation of a
/// pending `forget` (the snapshots it would remove) without removing them first.
pub async fn prune_excluding<B: StorageBackend>(
    repo: &mut Repository<B>,
    dry_run: bool,
    excluded: &HashSet<Id>,
) -> Result<PruneReport> {
    // A dry run only reads, so it needs no lock; a real prune takes the exclusive
    // lock that guards deletion against concurrent operations (`DESIGN.md` §8).
    if dry_run {
        return prune_marked(repo, true, excluded).await;
    }
    let lock = repo.acquire_lock(true).await?;
    let result = prune_marked(repo, false, excluded).await;
    let _ = repo.release_lock(&lock).await;
    result
}

/// MARK every blob reachable from a surviving (non-`excluded`) snapshot, then
/// SWEEP + repack, updating the repository's index in place.
async fn prune_marked<B: StorageBackend>(
    repo: &mut Repository<B>,
    dry_run: bool,
    excluded: &HashSet<Id>,
) -> Result<PruneReport> {
    let mut live: HashSet<Id> = HashSet::new();
    for snapshot in repo.list_snapshots().await? {
        if excluded.contains(&snapshot) {
            continue;
        }
        let snap = repo.load_snapshot(&snapshot).await?;
        mark_tree(repo, snap.tree, &mut live).await?;
    }
    Ok(repo.sweep(&live, dry_run).await?)
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

/// Recursively back up `dir`, returning the id of its `Tree` object. `parent`
/// is the id of the same directory's tree in the previous snapshot, if any, and
/// `stats` accumulates new/changed/unmodified counters.
fn backup_dir<'a, B: StorageBackend>(
    repo: &'a mut Repository<B>,
    dir: PathBuf,
    parent: Option<Id>,
    excludes: &'a GlobSet,
    stats: &'a mut SnapshotStats,
    dry_run: bool,
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
                let subtree =
                    backup_dir(repo, path.clone(), parent_sub, excludes, stats, dry_run).await?;
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
                    if dry_run {
                        // Count it, but read nothing and store nothing.
                        (Vec::new(), meta.len())
                    } else {
                        let data = std::fs::read(&path).map_err(|e| io_err(&path, e))?;
                        let len = data.len() as u64;
                        (repo.save_file(&data).await?, len)
                    }
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
        if dry_run {
            // No snapshot is committed, so the tree id is never referenced.
            Ok(Id::from_bytes([0u8; 32]))
        } else {
            Ok(repo.save_tree(&tree).await?)
        }
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
        let report = prune(&mut repo, false).await.unwrap();
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
        let preview = forget_with_policy(&repo, policy, true).await.unwrap();
        assert_eq!(preview, vec![d9]);
        assert_eq!(repo.list_snapshots().await.unwrap().len(), 3);

        let forgotten = forget_with_policy(&repo, policy, false).await.unwrap();
        assert_eq!(forgotten, vec![d9]);

        let remaining: HashSet<Id> = repo.list_snapshots().await.unwrap().into_iter().collect();
        assert_eq!(remaining, HashSet::from([d10, d3]));
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
        let forgotten = forget_with_policy(&repo, policy, false).await.unwrap();
        let remaining: HashSet<Id> = repo.list_snapshots().await.unwrap().into_iter().collect();
        assert_eq!(remaining, HashSet::from([y1971, feb]));
        // Both January 1970 snapshots are dropped (older year, non-newest month).
        assert_eq!(forgotten.len(), 2);
        assert!(forgotten.contains(&jan_a) && forgotten.contains(&jan_b));
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
        prune(&mut repo, false).await.unwrap();
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

    #[tokio::test]
    async fn backup_of_non_directory_errors_clearly() {
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        // A path that does not exist.
        let missing = std::path::Path::new("/no/such/path/sluice-xyz");
        assert!(matches!(
            backup(&mut repo, missing).await,
            Err(EngineError::NotADirectory(_))
        ));
        // A file is not a directory.
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(matches!(
            backup(&mut repo, file.path()).await,
            Err(EngineError::NotADirectory(_))
        ));
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
        let would = prune(&mut repo, true).await.unwrap();
        assert!(would.deleted >= 1, "dry-run should find packs to prune");
        assert_eq!(
            repo.backend().list(FileType::Pack).await.unwrap().len(),
            before,
            "dry-run must not delete anything"
        );

        let removed = prune(&mut repo, false).await.unwrap();
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
        let report = prune(&mut repo, false).await.unwrap();
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
        let report = prune_excluding(&mut repo, true, &excluded).await.unwrap();
        assert!(
            report.reclaimed_bytes > 0,
            "should preview reclaimable bytes"
        );
        // Nothing was actually removed: both snapshots remain and verify.
        assert_eq!(repo.list_snapshots().await.unwrap().len(), 2);
        assert!(verify(&repo).await.is_ok());

        // A plain prune (excluding nothing) finds nothing dead yet.
        let none = prune(&mut repo, true).await.unwrap();
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
        assert!(prune(&mut repo, false).await.is_err());
        // A dry run takes no lock, so it still works.
        assert!(prune(&mut repo, true).await.is_ok());

        // Once released, prune proceeds and releases its own lock afterwards.
        repo.release_lock(&held).await.unwrap();
        assert!(prune(&mut repo, false).await.is_ok());
        assert!(repo.list_locks().await.unwrap().is_empty());
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
