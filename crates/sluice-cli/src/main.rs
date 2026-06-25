//! `sluice` — command-line interface for the encrypted, deduplicating backup
//! and disaster-recovery tool (see `DESIGN.md` §7).
//!
//! The passphrase comes from the stdout of `SLUICE_PASSWORD_COMMAND`, else the
//! file named by `SLUICE_PASSWORD_FILE`, else the `SLUICE_PASSWORD` environment
//! variable, else an interactive no-echo prompt when a terminal is attached. A
//! repository is a local path or an object-store URL such as `s3://bucket/prefix`.

use std::collections::HashSet;
use std::error::Error;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "fuse")]
mod mount;

use clap::{CommandFactory, Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use sluice_core::{EntryKind, Id};
use sluice_crypto::KdfParams;
use sluice_engine::{
    BackupOptions, DiffKind, EngineError, FileStatus, GroupBy, RestoreFilter, RestoreOptions,
    RestoreReport, RetentionPolicy, VerifyOptions, backup_sources_with_options, backup_stdin,
    check_only, copy_snapshots_with_progress, diff, dump, find, forget, forget_tagged,
    forget_with_policy, list_files, mirror_delete, prune, prune_excluding,
    prune_excluding_with_progress, rebuild_index, restore_filtered, retag, snapshot_stats,
    verify_with_progress,
};
use sluice_repo::{RepoError, Repository};
use sluice_store::{FileType, LocalBackend, ObjectStoreBackend, StorageBackend, StoreError};

/// Encrypted, deduplicating backup & disaster-recovery tool.
#[derive(Parser)]
#[command(name = "sluice", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new encrypted repository.
    Init {
        /// Repository path or object-store URL (e.g. s3://bucket/prefix).
        repo: String,
        /// zstd compression level for stored blobs (1 fastest .. 22 smallest).
        #[arg(long, value_name = "LEVEL", default_value_t = 3, value_parser = clap::value_parser!(i32).range(1..=22))]
        compression: i32,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Back up one or more directories into a single snapshot.
    Backup {
        /// Repository path or object-store URL.
        repo: String,
        /// Directories to back up (one or more; multiple sources land under a
        /// synthetic root named by each source's final path component).
        #[arg(required_unless_present_any = ["stdin", "files_from"], num_args = 1..)]
        sources: Vec<PathBuf>,
        /// Read backup source paths from a file, one per line (repeatable; blank
        /// lines and lines starting with '#' are ignored). Paths are literal (no
        /// glob or '~' expansion) and add to any sources given on the command line.
        #[arg(long = "files-from", value_name = "FILE", conflicts_with = "stdin")]
        files_from: Vec<PathBuf>,
        /// Back up the bytes read from standard input as a single file instead of
        /// walking source paths (for piping a stream).
        #[arg(long, conflicts_with = "sources")]
        stdin: bool,
        /// The filename recorded for --stdin input.
        #[arg(long = "stdin-filename", value_name = "NAME", default_value = "stdin")]
        stdin_filename: String,
        /// Glob of entry names to exclude (repeatable), e.g. --exclude '*.log'.
        #[arg(long = "exclude", value_name = "GLOB")]
        excludes: Vec<String>,
        /// Read exclude globs from a file, one per line (repeatable; blank lines
        /// and lines starting with '#' are ignored).
        #[arg(long = "exclude-from", value_name = "FILE")]
        exclude_from: Vec<PathBuf>,
        /// Tag to attach to the snapshot (repeatable).
        #[arg(long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// Skip files larger than this size, e.g. 100M, 2G (K/M/G/T suffixes are
        /// binary; explicitly named single-file sources are always backed up).
        #[arg(long = "exclude-larger-than", value_name = "SIZE")]
        exclude_larger_than: Option<String>,
        /// Do not cross filesystem boundaries: skip subdirectories that are on a
        /// different filesystem than their source root (e.g. mount points).
        #[arg(long)]
        one_file_system: bool,
        /// Skip any subdirectory that contains this marker file (repeatable),
        /// e.g. --exclude-if-present .nobackup.
        #[arg(long = "exclude-if-present", value_name = "FILE")]
        exclude_if_present: Vec<String>,
        /// Skip subdirectories holding a CACHEDIR.TAG with the standard cache
        /// signature (build caches, browser caches, ...).
        #[arg(long = "exclude-caches")]
        exclude_caches: bool,
        /// Path to an on-disk stat cache. Records each file's chunk ids so a later
        /// backup reuses unchanged files without re-reading them or loading the
        /// previous snapshot's trees (notably faster for object-store repos).
        #[arg(long, value_name = "PATH")]
        cache: Option<PathBuf>,
        /// Override the zstd level (1 fastest .. 22 smallest) for data stored by
        /// this run only; defaults to the repository's level set at init. Dedup is
        /// unaffected, so only newly stored chunks use the new level.
        #[arg(long, value_name = "LEVEL", value_parser = clap::value_parser!(i32).range(1..=22))]
        compression: Option<i32>,
        /// Re-read every file instead of trusting the size+mtime heuristic, to
        /// catch a content change that preserved the file's mtime. Identical
        /// content still deduplicates, so this costs I/O but not storage.
        #[arg(long)]
        force: bool,
        /// Record this Unix timestamp (seconds since the epoch, UTC) on the
        /// snapshot instead of the current time — e.g. to preserve original dates
        /// when importing history. Retention rules bucket by this time.
        #[arg(long, value_name = "EPOCH_SECONDS")]
        time: Option<i64>,
        /// Record this hostname on the snapshot instead of the local host — e.g.
        /// when a central server backs up another machine's data. Matched by
        /// `snapshots --host` and grouped by `forget --group-by host`.
        #[arg(long, value_name = "NAME")]
        host: Option<String>,
        /// Don't create a snapshot if nothing changed since the last one — avoids
        /// piling up identical snapshots from frequent no-op (e.g. hourly) backups.
        #[arg(long = "skip-if-unchanged")]
        skip_if_unchanged: bool,
        /// Report what would be backed up without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Print each new (+) and changed (M) file as it is backed up.
        #[arg(short, long)]
        verbose: bool,
        /// Emit the outcome (snapshot id and counts) as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Restore a snapshot into a target directory.
    Restore {
        /// Repository path or object-store URL.
        repo: String,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
        /// Directory to restore into.
        target: PathBuf,
        /// Restore only this path within the snapshot (repeatable; omit for all).
        #[arg(long = "path", value_name = "PATH")]
        paths: Vec<String>,
        /// Restore only entries whose path (relative to the restore root) matches
        /// this glob (repeatable); `**` spans directories, e.g. '**/*.pdf'.
        #[arg(long = "include", value_name = "GLOB")]
        include: Vec<String>,
        /// Read include globs from a file, one per line (repeatable; blank lines
        /// and lines starting with '#' are ignored).
        #[arg(long = "include-from", value_name = "FILE")]
        include_from: Vec<PathBuf>,
        /// Skip entries whose path matches this glob (repeatable); a matching
        /// directory is pruned with its subtree.
        #[arg(long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
        /// Read exclude globs from a file, one per line (repeatable; blank lines
        /// and lines starting with '#' are ignored).
        #[arg(long = "exclude-from", value_name = "FILE")]
        exclude_from: Vec<PathBuf>,
        /// Report what would be restored (file count and bytes) without writing.
        #[arg(long)]
        dry_run: bool,
        /// Leave entries already present and matching in place (resume a restore).
        #[arg(long)]
        skip_existing: bool,
        /// Don't overwrite a target file that is newer than the snapshot's version
        /// (by mtime) — keep locally-updated files when restoring an older backup.
        #[arg(long)]
        skip_newer: bool,
        /// After restoring, delete entries under the target that the snapshot does
        /// not contain, making it an exact mirror. Cannot be combined with
        /// --path/--include/--exclude. Pair with --dry-run to preview deletions.
        #[arg(long)]
        delete: bool,
        /// After writing each file, re-read it and verify it matches the snapshot.
        #[arg(long)]
        verify: bool,
        /// Print each file as it is restored.
        #[arg(short, long)]
        verbose: bool,
        /// Emit machine-readable JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Copy snapshots to another repository, re-encrypting under its keys.
    Copy {
        /// Source repository path or object-store URL.
        src: String,
        /// Destination repository path or object-store URL.
        dst: String,
        /// Snapshot id to copy (a unique hex prefix). Omit to copy every snapshot,
        /// or narrow the selection with --tag/--host/--path.
        snapshot: Option<String>,
        /// Copy only snapshots with this tag (cannot be combined with a snapshot id).
        #[arg(long, value_name = "TAG")]
        tag: Option<String>,
        /// Copy only snapshots taken on this host.
        #[arg(long, value_name = "HOST")]
        host: Option<String>,
        /// Copy only snapshots that backed up this source path.
        #[arg(long, value_name = "PATH")]
        path: Option<String>,
        /// Copy only the N most recent snapshots (applied after the other filters).
        #[arg(long, value_name = "N")]
        last: Option<usize>,
        /// Recompress data into the destination at this zstd level (1..22) instead
        /// of the destination repository's default — e.g. copy to a cold archive
        /// at level 19. Dedup within the destination is unaffected.
        #[arg(long, value_name = "LEVEL", value_parser = clap::value_parser!(i32).range(1..=22))]
        compression: Option<i32>,
        /// List the snapshots that would be copied, without writing to (or even
        /// contacting) the destination. Honors --snapshot/--tag/--host/--path.
        #[arg(long)]
        dry_run: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List the snapshots in a repository.
    Snapshots {
        /// Repository path or object-store URL.
        repo: String,
        /// Only show snapshots with this tag.
        #[arg(long)]
        tag: Option<String>,
        /// Only show snapshots taken on this host.
        #[arg(long)]
        host: Option<String>,
        /// Only show snapshots that backed up this source path.
        #[arg(long, value_name = "PATH")]
        path: Option<String>,
        /// Show only the N most recent snapshots.
        #[arg(long, value_name = "N")]
        last: Option<usize>,
        /// Group the listing by host or by source paths (each group gets a header;
        /// with --json, output becomes `[{group, snapshots}]`).
        #[arg(long = "group-by", value_enum)]
        group_by: Option<GroupByArg>,
        /// One terse line per snapshot — id, date and tags only, dropping the file
        /// count, size and source paths (human output only).
        #[arg(long)]
        compact: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Add or remove tags on a snapshot (rewrites it under a new id).
    Tag {
        /// Repository path or object-store URL.
        repo: String,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
        /// Tag to add (repeatable).
        #[arg(long = "add", value_name = "TAG")]
        add: Vec<String>,
        /// Tag to remove (repeatable).
        #[arg(long = "remove", value_name = "TAG")]
        remove: Vec<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify the integrity of all snapshots.
    Verify {
        /// Repository path or object-store URL.
        repo: String,
        /// Verify only this snapshot (a unique hex prefix); omit to verify every
        /// snapshot in the repository.
        snapshot: Option<String>,
        /// Read only this percentage (1-100) of content blobs, chosen at random,
        /// for a fast probabilistic spot-check. Trees are always fully verified.
        #[arg(long, value_name = "PERCENT")]
        sample: Option<u8>,
        /// Emit the result (counts) as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check structural integrity without reading file data (fast).
    Check {
        /// Repository path or object-store URL.
        repo: String,
        /// Check only this snapshot (a unique hex prefix); omit to check every
        /// snapshot in the repository.
        snapshot: Option<String>,
        /// Emit the result (counts and any missing blobs) as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Forget snapshots; reclaim their data later with `prune`.
    Forget {
        /// Repository path or object-store URL.
        repo: String,
        /// Snapshot id to forget (a unique hex prefix is accepted).
        snapshot: Option<String>,
        /// Keep the N most recent snapshots (combinable with the other --keep rules).
        #[arg(long, value_name = "N")]
        keep_last: Option<usize>,
        /// Keep the most recent snapshot of each of the last N hours.
        #[arg(long, value_name = "N")]
        keep_hourly: Option<usize>,
        /// Keep the most recent snapshot of each of the last N days.
        #[arg(long, value_name = "N")]
        keep_daily: Option<usize>,
        /// Keep the most recent snapshot of each of the last N (Monday-aligned) weeks.
        #[arg(long, value_name = "N")]
        keep_weekly: Option<usize>,
        /// Keep the most recent snapshot of each of the last N calendar months.
        #[arg(long, value_name = "N")]
        keep_monthly: Option<usize>,
        /// Keep the most recent snapshot of each of the last N calendar years.
        #[arg(long, value_name = "N")]
        keep_yearly: Option<usize>,
        /// Always keep snapshots with this tag, regardless of count rules (repeatable).
        #[arg(long = "keep-tag", value_name = "TAG")]
        keep_tag: Vec<String>,
        /// Always keep this snapshot (a unique hex prefix), regardless of count
        /// rules (repeatable).
        #[arg(long = "keep-id", value_name = "SNAPSHOT")]
        keep_id: Vec<String>,
        /// Keep all snapshots taken within this window, e.g. 7d, 24h, 2w.
        #[arg(long = "keep-within", value_name = "DURATION")]
        keep_within: Option<String>,
        /// Within this window, keep the most recent snapshot of each hour, e.g. 48h.
        #[arg(long = "keep-within-hourly", value_name = "DURATION")]
        keep_within_hourly: Option<String>,
        /// Within this window, keep the most recent snapshot of each day, e.g. 30d.
        #[arg(long = "keep-within-daily", value_name = "DURATION")]
        keep_within_daily: Option<String>,
        /// Within this window, keep the most recent snapshot of each week.
        #[arg(long = "keep-within-weekly", value_name = "DURATION")]
        keep_within_weekly: Option<String>,
        /// Within this window, keep the most recent snapshot of each month.
        #[arg(long = "keep-within-monthly", value_name = "DURATION")]
        keep_within_monthly: Option<String>,
        /// Within this window, keep the most recent snapshot of each year.
        #[arg(long = "keep-within-yearly", value_name = "DURATION")]
        keep_within_yearly: Option<String>,
        /// Apply the keep rules per group (host or paths) instead of globally.
        #[arg(long = "group-by", value_enum)]
        group_by: Option<GroupByArg>,
        /// Instead, forget every snapshot with this tag.
        #[arg(long, value_name = "TAG")]
        tag: Option<String>,
        /// Show which snapshots would be forgotten without removing them.
        #[arg(long)]
        dry_run: bool,
        /// After forgetting, run prune to reclaim the freed storage.
        #[arg(long)]
        prune: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Reclaim storage no longer referenced by any snapshot.
    Prune {
        /// Repository path or object-store URL.
        repo: String,
        /// Show what would be reclaimed without deleting anything.
        #[arg(long)]
        dry_run: bool,
        /// Tolerate up to this percent dead data per pack: don't repack packs at
        /// or below the threshold (0 = repack every partially-dead pack).
        #[arg(long = "max-unused", value_name = "PERCENT", default_value_t = 0)]
        max_unused: u8,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List the contents of a snapshot without restoring.
    Ls {
        /// Repository path or object-store URL.
        repo: String,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
        /// List only this path within the snapshot (a file or directory subtree).
        path: Option<String>,
        /// Long format: mode, owner, size (or device numbers), mtime, and symlink targets.
        #[arg(short, long)]
        long: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Find entries matching a glob across all snapshots.
    Find {
        /// Repository path or object-store URL.
        repo: String,
        /// Glob matched against full paths (use ** to cross directories).
        pattern: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show the changes between two snapshots.
    Diff {
        /// Repository path or object-store URL.
        repo: String,
        /// The older snapshot id (a unique hex prefix is accepted).
        from: String,
        /// The newer snapshot id (a unique hex prefix is accepted).
        to: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write a single file from a snapshot to stdout.
    Dump {
        /// Repository path or object-store URL.
        repo: String,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
        /// Path of the file within the snapshot.
        path: String,
    },
    /// Show repository metadata.
    Info {
        /// Repository path or object-store URL.
        repo: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show repository storage statistics.
    Stats {
        /// Repository path or object-store URL.
        repo: String,
        /// A snapshot id (or unique prefix) to report on. Without it, the whole
        /// repository is summarized; with it, that one snapshot's restore size,
        /// entry counts, and deduplicated raw footprint are shown.
        snapshot: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove advisory locks left behind by an interrupted operation.
    Unlock {
        /// Repository path or object-store URL.
        repo: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Rebuild index segments by rescanning packs (repairs a damaged index).
    RebuildIndex {
        /// Repository path or object-store URL.
        repo: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Manage the passphrases (keys) that unlock the repository.
    Key {
        #[command(subcommand)]
        action: KeyCmd,
    },
    /// Print a decrypted repository object as JSON (inspection/debugging).
    Cat {
        #[command(subcommand)]
        object: CatObject,
    },
    /// Mount snapshots as a read-only filesystem (needs the `fuse` build feature).
    Mount {
        /// Repository path or object-store URL.
        repo: String,
        /// An existing empty directory to mount at.
        mountpoint: PathBuf,
        /// Mount only this snapshot at the root (a unique hex prefix); omit to
        /// mount every snapshot, each under a directory named by its short id.
        #[arg(long)]
        snapshot: Option<String>,
    },
    /// Print a shell completion script to stdout (bash, zsh, fish, ...).
    Completions {
        /// Shell to generate completions for.
        shell: clap_complete::Shell,
    },
    /// Write troff man pages (sluice.1 and one per subcommand) into a directory.
    Man {
        /// Directory to write the man pages into (created if absent).
        dir: PathBuf,
    },
}

/// How `forget` partitions snapshots before applying retention.
#[derive(Clone, Copy, clap::ValueEnum)]
enum GroupByArg {
    /// Group by source hostname.
    Host,
    /// Group by the set of source paths.
    Paths,
}

/// Sub-commands of `cat`.
#[derive(Subcommand)]
enum CatObject {
    /// The repository configuration.
    Config {
        /// Repository path or object-store URL.
        repo: String,
    },
    /// A snapshot's full metadata.
    Snapshot {
        /// Repository path or object-store URL.
        repo: String,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
    },
    /// A tree object's nodes.
    Tree {
        /// Repository path or object-store URL.
        repo: String,
        /// Tree object id (full hex, as shown by `cat snapshot`).
        id: String,
    },
    /// A data blob's raw decrypted bytes (written to stdout, not JSON).
    Blob {
        /// Repository path or object-store URL.
        repo: String,
        /// Blob (chunk) id (full hex, as shown by `cat tree` under `content`).
        id: String,
    },
}

/// Sub-commands of `key`.
#[derive(Subcommand)]
enum KeyCmd {
    /// List the repository's keys (the active one is marked).
    List {
        /// Repository path or object-store URL.
        repo: String,
        /// Emit the key list as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Add a passphrase (read from SLUICE_NEW_PASSWORD or prompted).
    Add {
        /// Repository path or object-store URL.
        repo: String,
        /// Emit the new key id as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove a key by id (refused if it is the last key).
    Remove {
        /// Repository path or object-store URL.
        repo: String,
        /// The key id to remove (as shown by `key list`).
        id: String,
        /// Emit the result as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Change the current passphrase, rotating out its key.
    Passwd {
        /// Repository path or object-store URL.
        repo: String,
        /// Emit the new key id as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    // Windows' default main-thread stack is 1 MiB, far below the 8 MiB on
    // Linux/macOS. The command future built by `#[tokio::main]` is driven by
    // `block_on` on whichever thread calls `run()`, and the backup/restore
    // pipeline holds large I/O buffers across `.await` points, so that future
    // overflows a 1 MiB stack on every invocation. Drive it on a worker thread
    // with a generous stack so behaviour is uniform across platforms.
    let worker = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| match run() {
            Ok(code) => code,
            Err(error) => {
                eprintln!("error: {error}");
                exit_code(error.as_ref())
            }
        })
        .expect("spawn worker thread");
    let code = worker.join().expect("worker thread panicked");
    std::process::exit(code);
}

/// Map an error to a stable, documented exit code (`DESIGN.md` §7): 10 repo not
/// found, 11 wrong passphrase, 12 lock held, 13 corruption detected, else 1.
fn exit_code(error: &(dyn Error + 'static)) -> i32 {
    fn repo_code(e: &RepoError) -> i32 {
        match e {
            RepoError::NotFound => 10,
            RepoError::Key(_) => 11,
            RepoError::Locked => 12,
            RepoError::Blob | RepoError::BlobNotFound(_) => 13,
            _ => 1,
        }
    }
    // A repository error may be the error itself, wrapped in an EngineError, or
    // further down the source chain.
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(err) = current {
        if let Some(e) = err.downcast_ref::<RepoError>() {
            return repo_code(e);
        }
        if let Some(EngineError::Repo(e)) = err.downcast_ref::<EngineError>() {
            return repo_code(e);
        }
        current = err.source();
    }
    1
}

#[tokio::main]
async fn run() -> Result<i32, Box<dyn Error>> {
    let cli = Cli::parse();
    // Generating completions or man pages needs neither a repository nor a passphrase.
    if let Command::Completions { shell } = &cli.command {
        clap_complete::generate(
            *shell,
            &mut Cli::command(),
            "sluice",
            &mut std::io::stdout(),
        );
        return Ok(0);
    }
    if let Command::Man { dir } = &cli.command {
        write_man_pages(dir)?;
        return Ok(0);
    }
    let confirm = matches!(cli.command, Command::Init { .. });
    let passphrase = read_passphrase(confirm)?;
    let pw = passphrase.as_bytes();

    // 0 = success; set to 3 when a restore completes with best-effort warnings.
    let mut exit = 0;
    match cli.command {
        Command::Init {
            repo,
            compression,
            json,
        } => {
            let be = backend(&repo, true).await?;
            let repository =
                match Repository::init_with_compression(be, pw, kdf_params(), compression).await {
                    Ok(r) => r,
                    // The config object is written first with create semantics, so an
                    // existing repository is never clobbered; report that clearly
                    // instead of leaking the internal "object already exists" error.
                    Err(RepoError::Store(StoreError::AlreadyExists { .. })) => {
                        return Err(format!(
                            "a repository already exists at {repo}; refusing to overwrite it \
                         (its data and keys are untouched)"
                        )
                        .into());
                    }
                    Err(e) => return Err(e.into()),
                };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "repo_id": repository.id().to_string(),
                        "location": repo,
                    }))?
                );
            } else {
                println!("initialized repository {} at {repo}", repository.id());
            }
        }
        Command::Backup {
            repo,
            mut sources,
            files_from,
            stdin,
            stdin_filename,
            mut excludes,
            exclude_from,
            tags,
            exclude_larger_than,
            one_file_system,
            exclude_if_present,
            exclude_caches,
            cache,
            compression,
            force,
            time,
            host,
            skip_if_unchanged,
            dry_run,
            verbose,
            json,
        } => {
            // Append patterns read from each --exclude-from file.
            for file in &exclude_from {
                let contents = std::fs::read_to_string(file)
                    .map_err(|e| format!("reading {}: {e}", file.display()))?;
                for line in contents.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        excludes.push(line.to_string());
                    }
                }
            }
            // Append source paths read from each --files-from file.
            for file in &files_from {
                let contents = std::fs::read_to_string(file)
                    .map_err(|e| format!("reading {}: {e}", file.display()))?;
                for line in contents.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        sources.push(PathBuf::from(line));
                    }
                }
            }
            // A --files-from file may resolve to nothing (all comments/blank); that
            // is not a backup of the whole filesystem, it is an error.
            if !stdin && sources.is_empty() {
                return Err(
                    "no backup sources: pass paths on the command line or a non-empty \
                     --files-from file"
                        .into(),
                );
            }
            let max_size = exclude_larger_than.as_deref().map(parse_size).transpose()?;
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
            // Apply a per-run compression override (None keeps the repo default).
            repository.set_data_compression(compression);
            // Optionally stamp the snapshot with an explicit time (epoch seconds).
            repository.set_snapshot_time(time.map(|s| s * 1_000_000_000));
            // Optionally record an explicit hostname on the snapshot.
            repository.set_snapshot_host(host);
            // With --verbose, print each new/changed file as it is processed.
            let report = |path: &std::path::Path, status: FileStatus| match status {
                FileStatus::New => eprintln!("+ {}", path.display()),
                FileStatus::Changed => eprintln!("M {}", path.display()),
                FileStatus::Unmodified => {}
            };
            // Otherwise, on an interactive terminal, show a live spinner with the
            // running file count and current path. It hides itself when stderr is
            // not a TTY (a pipe or cron job), so scripts stay quiet.
            let spinner = (!verbose
                && !json
                && !dry_run
                && !stdin
                && std::io::stderr().is_terminal())
            .then(|| {
                let pb = ProgressBar::new_spinner();
                pb.set_style(
                    ProgressStyle::with_template("{spinner:.green} {pos} files  {wide_msg}")
                        .unwrap(),
                );
                pb.enable_steady_tick(std::time::Duration::from_millis(120));
                pb
            });
            let tick = |path: &std::path::Path, _status: FileStatus| {
                if let Some(pb) = &spinner {
                    pb.inc(1);
                    pb.set_message(path.display().to_string());
                }
            };
            let progress: Option<sluice_engine::ProgressFn> = if verbose {
                Some(&report)
            } else if spinner.is_some() {
                Some(&tick)
            } else {
                None
            };
            let outcome = if stdin {
                let reader = std::io::stdin().lock();
                backup_stdin(&mut repository, reader, stdin_filename.as_bytes(), &tags).await?
            } else {
                let options = BackupOptions {
                    exclude_globs: excludes,
                    max_file_size: max_size,
                    one_file_system,
                    exclude_if_present,
                    exclude_caches,
                    force,
                    cache_path: cache,
                    dry_run,
                    skip_if_unchanged,
                };
                backup_sources_with_options(&mut repository, &sources, &tags, &options, progress)
                    .await?
            };
            if let Some(pb) = &spinner {
                pb.finish_and_clear();
            }
            let s = outcome.summary;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "snapshot": outcome.snapshot.map(|id| id.to_string()),
                        "dry_run": dry_run,
                        "skipped": outcome.snapshot.is_none() && !dry_run,
                        "files_new": s.files_new,
                        "files_changed": s.files_changed,
                        "files_unmodified": s.files_unmodified,
                        "dirs": s.dirs,
                        "bytes": s.bytes_processed,
                        "bytes_added": s.bytes_added,
                    }))?
                );
            } else {
                match outcome.snapshot {
                    Some(id) => {
                        println!("{id}");
                        eprintln!(
                            "  {} new, {} changed, {} unmodified, {} dirs, {} bytes ({} stored)",
                            s.files_new,
                            s.files_changed,
                            s.files_unmodified,
                            s.dirs,
                            s.bytes_processed,
                            format_bytes(s.bytes_added),
                        );
                    }
                    None if dry_run => {
                        println!(
                            "dry run: {} new, {} changed, {} unmodified, {} dirs, {} bytes (nothing written)",
                            s.files_new,
                            s.files_changed,
                            s.files_unmodified,
                            s.dirs,
                            s.bytes_processed
                        );
                    }
                    None => {
                        println!(
                            "no changes since the last snapshot; skipped ({} files unchanged)",
                            s.files_unmodified
                        );
                    }
                }
            }
        }
        Command::Restore {
            repo,
            snapshot,
            target,
            paths,
            mut include,
            include_from,
            mut exclude,
            exclude_from,
            dry_run,
            skip_existing,
            skip_newer,
            delete,
            verify,
            verbose,
            json,
        } => {
            // Append include/exclude globs read from their respective files.
            for (files, dest) in [(&include_from, &mut include), (&exclude_from, &mut exclude)] {
                for file in files {
                    let contents = std::fs::read_to_string(file)
                        .map_err(|e| format!("reading {}: {e}", file.display()))?;
                    for line in contents.lines() {
                        let line = line.trim();
                        if !line.is_empty() && !line.starts_with('#') {
                            dest.push(line.to_string());
                        }
                    }
                }
            }
            // Mirror deletion considers the whole snapshot, so a partial restore
            // would delete everything outside the selected subset; refuse it.
            if delete && (!paths.is_empty() || !include.is_empty() || !exclude.is_empty()) {
                return Err(
                    "--delete cannot be combined with --path/--include/--exclude; it mirrors \
                     the entire snapshot"
                        .into(),
                );
            }
            let filter = RestoreFilter::new(&include, &exclude)?;
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let id = resolve_snapshot(&repository, &snapshot).await?;
            if dry_run {
                let mut entries = list_files(&repository, &id).await?;
                if !paths.is_empty() {
                    // Keep entries under any of the requested paths.
                    let bounds: Vec<(String, String)> = paths
                        .iter()
                        .map(|p| {
                            let p = p.trim_matches('/').to_string();
                            let prefix = format!("{p}/");
                            (p, prefix)
                        })
                        .collect();
                    entries.retain(|e| {
                        bounds
                            .iter()
                            .any(|(p, prefix)| e.path == *p || e.path.starts_with(prefix))
                    });
                }
                // Honor the include/exclude globs in the preview, too.
                entries.retain(|e| filter.allows_path(std::path::Path::new(&e.path)));
                let files = entries.iter().filter(|e| e.kind == EntryKind::File);
                let count = files.clone().count();
                let bytes: u64 = files.map(|e| e.size).sum();
                let extras = if delete {
                    mirror_delete(&repository, &id, &target, true).await?
                } else {
                    Vec::new()
                };
                if json {
                    let mut obj = serde_json::json!({
                        "dry_run": true,
                        "snapshot": id.to_string(),
                        "target": target.display().to_string(),
                        "files": count,
                        "bytes": bytes,
                    });
                    if delete {
                        obj["would_delete"] = serde_json::json!(extras.len());
                        obj["delete_paths"] = serde_json::json!(
                            extras
                                .iter()
                                .map(|p| p.display().to_string())
                                .collect::<Vec<_>>()
                        );
                    }
                    println!("{}", serde_json::to_string_pretty(&obj)?);
                } else {
                    // With -v, list every file the (possibly filtered) restore
                    // would write, to stderr — leaving stdout for the summary.
                    if verbose {
                        for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
                            eprintln!("{}", e.path);
                        }
                    }
                    println!(
                        "would restore {count} files ({bytes} bytes) into {} (nothing written)",
                        target.display()
                    );
                    if delete {
                        println!("would delete {} extra entr(ies):", extras.len());
                        for p in extras.iter().take(20) {
                            println!("  {}", p.display());
                        }
                        if extras.len() > 20 {
                            println!("  ... and {} more", extras.len() - 20);
                        }
                    }
                }
            } else {
                let options = RestoreOptions {
                    skip_existing,
                    skip_newer,
                    verify,
                };
                // With --verbose, print each file as it is restored (to stderr,
                // like `backup -v`, leaving stdout for the completion line).
                let report_file = |path: &std::path::Path| eprintln!("{}", path.display());
                // Otherwise show a live spinner on a terminal (hidden when piped or
                // emitting JSON).
                let spinner = (!verbose && !json && std::io::stderr().is_terminal()).then(|| {
                    let pb = ProgressBar::new_spinner();
                    pb.set_style(
                        ProgressStyle::with_template("{spinner:.green} {pos} files  {wide_msg}")
                            .unwrap(),
                    );
                    pb.enable_steady_tick(std::time::Duration::from_millis(120));
                    pb
                });
                let tick = |path: &std::path::Path| {
                    if let Some(pb) = &spinner {
                        pb.inc(1);
                        pb.set_message(path.display().to_string());
                    }
                };
                let progress: Option<sluice_engine::RestoreProgressFn> = if verbose {
                    Some(&report_file)
                } else if spinner.is_some() {
                    Some(&tick)
                } else {
                    None
                };
                let mut report = RestoreReport::default();
                if paths.is_empty() {
                    report = restore_filtered(
                        &repository,
                        &id,
                        None,
                        &target,
                        options,
                        &filter,
                        progress,
                    )
                    .await?;
                } else {
                    for p in &paths {
                        let r = restore_filtered(
                            &repository,
                            &id,
                            Some(p),
                            &target,
                            options,
                            &filter,
                            progress,
                        )
                        .await?;
                        report.warnings += r.warnings;
                        report.messages.extend(r.messages);
                    }
                }
                if let Some(pb) = &spinner {
                    pb.finish_and_clear();
                }
                // Mirror mode: after writing the snapshot, remove anything under
                // the target the snapshot does not contain.
                let deleted = if delete {
                    let removed = mirror_delete(&repository, &id, &target, false).await?;
                    if verbose {
                        for p in &removed {
                            eprintln!("- {}", p.display());
                        }
                    }
                    Some(removed.len())
                } else {
                    None
                };
                if json {
                    let mut obj = serde_json::json!({
                        "dry_run": false,
                        "snapshot": id.to_string(),
                        "target": target.display().to_string(),
                        "warnings": report.warnings,
                        "messages": report.messages,
                    });
                    if let Some(n) = deleted {
                        obj["deleted"] = serde_json::json!(n);
                    }
                    println!("{}", serde_json::to_string_pretty(&obj)?);
                } else {
                    if let Some(n) = deleted {
                        println!("deleted {n} extra entr(ies)");
                    }
                    println!("restored {id} into {}", target.display());
                    if report.warnings > 0 {
                        eprintln!(
                            "warning: {} metadata operation(s) could not be applied:",
                            report.warnings
                        );
                        for m in report.messages.iter().take(20) {
                            eprintln!("  {m}");
                        }
                        let shown = report.messages.len().min(20) as u64;
                        if report.warnings > shown {
                            eprintln!("  ... and {} more", report.warnings - shown);
                        }
                    }
                }
                // The exit code reflects warnings regardless of output format.
                if report.warnings > 0 {
                    exit = 3;
                }
            }
        }
        Command::Copy {
            src,
            dst,
            snapshot,
            tag,
            host,
            path,
            last,
            compression,
            dry_run,
            json,
        } => {
            let source = Repository::open(backend(&src, false).await?, pw).await?;
            // Select the source snapshots to copy: a single id, a tag/host/path
            // filtered subset, or — with no selector — every snapshot.
            if snapshot.is_some()
                && (tag.is_some() || host.is_some() || path.is_some() || last.is_some())
            {
                return Err(
                    "a snapshot id cannot be combined with --tag/--host/--path/--last".into(),
                );
            }
            let single = snapshot.is_some();
            let mut matched: Vec<(Id, sluice_core::Snapshot)> = match &snapshot {
                Some(s) => {
                    let id = resolve_snapshot(&source, s).await?;
                    let snap = source.load_snapshot(&id).await?;
                    vec![(id, snap)]
                }
                None => {
                    let mut hits = Vec::new();
                    for id in source.list_snapshots().await? {
                        let snap = source.load_snapshot(&id).await?;
                        if snapshot_matches(&snap, tag.as_deref(), host.as_deref(), path.as_deref())
                        {
                            hits.push((id, snap));
                        }
                    }
                    hits
                }
            };
            // Order oldest-first; --last keeps the most recent N (after filtering).
            matched.sort_by_key(|s| s.1.time_ns);
            if let Some(n) = last {
                let drop = matched.len().saturating_sub(n);
                matched.drain(..drop);
            }

            // --dry-run previews the source-side selection without contacting or
            // writing the destination. It can't show the new destination ids:
            // copy re-keys each snapshot, so those only exist once the data has
            // actually been re-sealed under the destination's keys.
            if dry_run {
                if json {
                    let ids: Vec<String> = matched.iter().map(|(id, _)| id.to_string()).collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "would_copy": ids.len(),
                            "snapshots": ids,
                        }))?
                    );
                } else {
                    println!("would copy {} snapshot(s)", matched.len());
                    for (id, snap) in &matched {
                        let tags = if snap.tags.is_empty() {
                            String::new()
                        } else {
                            format!("  [{}]", snap.tags.join(","))
                        };
                        println!(
                            "  {}  {}{tags}",
                            &id.to_string()[..16],
                            format_utc(snap.time_ns)
                        );
                    }
                }
                return Ok(0);
            }

            // The destination may use a different passphrase, from the
            // SLUICE_DEST_PASSWORD{_COMMAND,_FILE,} sources; otherwise the
            // source's. Mirrors the SLUICE_PASSWORD precedence.
            let dest_pass = match passphrase_from_sources("SLUICE_DEST_PASSWORD") {
                Some(result) => result?,
                None => passphrase.clone(),
            };
            let mut dest =
                Repository::open(backend(&dst, false).await?, dest_pass.as_bytes()).await?;
            // Optionally recompress data into the destination at a chosen level.
            dest.set_data_compression(compression);
            let to_copy: Vec<Id> = matched.into_iter().map(|(id, _)| id).collect();
            // A live spinner on a terminal (offsite copies can move a lot of
            // data); hidden when piped or emitting JSON.
            let spinner = (!json && std::io::stderr().is_terminal()).then(|| {
                let pb = ProgressBar::new_spinner();
                pb.set_style(
                    ProgressStyle::with_template("{spinner:.green} {pos} blobs copied").unwrap(),
                );
                pb.enable_steady_tick(std::time::Duration::from_millis(120));
                pb
            });
            let tick = || {
                if let Some(pb) = &spinner {
                    pb.inc(1);
                }
            };
            let progress: Option<sluice_engine::CopyProgressFn> =
                if spinner.is_some() { Some(&tick) } else { None };
            // Each new id is the snapshot's re-encrypted id in the destination,
            // which differs from the source id (copy re-seals under dest keys).
            let new_ids: Vec<String> =
                copy_snapshots_with_progress(&source, &mut dest, &to_copy, progress)
                    .await?
                    .iter()
                    .map(|i| i.to_string())
                    .collect();
            if let Some(pb) = &spinner {
                pb.finish_and_clear();
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "copied": new_ids.len(),
                        "snapshots": new_ids,
                    }))?
                );
            } else if single {
                // A single-snapshot copy prints the new destination id.
                println!("{}", new_ids[0]);
            } else {
                println!("copied {} snapshot(s)", new_ids.len());
            }
        }
        Command::Snapshots {
            repo,
            tag,
            host,
            path,
            last,
            group_by,
            compact,
            json,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let mut snaps = Vec::new();
            for id in repository.list_snapshots().await? {
                let snap = repository.load_snapshot(&id).await?;
                if !snapshot_matches(&snap, tag.as_deref(), host.as_deref(), path.as_deref()) {
                    continue;
                }
                snaps.push((id, snap));
            }
            // List chronologically (oldest first); --last keeps the most recent N.
            snaps.sort_by_key(|s| s.1.time_ns);
            if let Some(n) = last {
                let drop = snaps.len().saturating_sub(n);
                snaps.drain(..drop);
            }

            // One snapshot as a JSON object / a human-readable line.
            let snap_json = |id: &Id, snap: &sluice_core::Snapshot| -> serde_json::Value {
                let files = snap.summary.files_new
                    + snap.summary.files_changed
                    + snap.summary.files_unmodified;
                let paths: Vec<String> = snap
                    .paths
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect();
                serde_json::json!({
                    "id": id.to_string(),
                    "time_ns": snap.time_ns,
                    "hostname": snap.hostname,
                    "username": snap.username,
                    "tags": snap.tags,
                    "paths": paths,
                    "files": files,
                    "bytes": snap.summary.bytes_processed,
                })
            };
            let snap_line = |id: &Id, snap: &sluice_core::Snapshot| -> String {
                let files = snap.summary.files_new
                    + snap.summary.files_changed
                    + snap.summary.files_unmodified;
                let paths: Vec<String> = snap
                    .paths
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect();
                let hex = id.to_string();
                let tags = if snap.tags.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", snap.tags.join(","))
                };
                if compact {
                    return format!("{}  {}{tags}", &hex[..16], format_utc(snap.time_ns));
                }
                format!(
                    "{}  {}  {files} files, {}  {}{tags}",
                    &hex[..16],
                    format_utc(snap.time_ns),
                    format_bytes(snap.summary.bytes_processed),
                    paths.join(", ")
                )
            };

            // The group label for a snapshot, or None when not grouping.
            let label_of = |snap: &sluice_core::Snapshot| -> Option<String> {
                match group_by {
                    Some(GroupByArg::Host) => Some(snap.hostname.clone()),
                    Some(GroupByArg::Paths) => Some(
                        snap.paths
                            .iter()
                            .map(|p| String::from_utf8_lossy(p).into_owned())
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                    None => None,
                }
            };

            if group_by.is_some() {
                // Partition into groups (sorted by label), each keeping the
                // chronological order from above.
                let mut groups: std::collections::BTreeMap<String, Vec<usize>> =
                    std::collections::BTreeMap::new();
                for (i, (_, snap)) in snaps.iter().enumerate() {
                    groups
                        .entry(label_of(snap).unwrap_or_default())
                        .or_default()
                        .push(i);
                }
                if json {
                    let arr: Vec<serde_json::Value> = groups
                        .iter()
                        .map(|(label, idxs)| {
                            serde_json::json!({
                                "group": label,
                                "snapshots": idxs
                                    .iter()
                                    .map(|&i| snap_json(&snaps[i].0, &snaps[i].1))
                                    .collect::<Vec<_>>(),
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&arr)?);
                } else {
                    let kind = match group_by {
                        Some(GroupByArg::Host) => "host",
                        _ => "paths",
                    };
                    for (label, idxs) in &groups {
                        println!("{kind} {label}");
                        for &i in idxs {
                            println!("  {}", snap_line(&snaps[i].0, &snaps[i].1));
                        }
                    }
                }
            } else if json {
                let arr: Vec<serde_json::Value> =
                    snaps.iter().map(|(id, snap)| snap_json(id, snap)).collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
            } else {
                for (id, snap) in &snaps {
                    println!("{}", snap_line(id, snap));
                }
            }
        }
        Command::Tag {
            repo,
            snapshot,
            add,
            remove,
            json,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let id = resolve_snapshot(&repository, &snapshot).await?;
            let new_id = retag(&repository, &id, &add, &remove).await?;
            let changed = new_id != id;
            if json {
                // Report the resulting snapshot's id and its tags after the edit.
                let tags = repository.load_snapshot(&new_id).await?.tags;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "snapshot": new_id.to_string(),
                        "changed": changed,
                        "tags": tags,
                    }))?
                );
            } else if changed {
                println!("{new_id}");
            } else {
                println!("no change");
            }
        }
        Command::Verify {
            repo,
            snapshot,
            sample,
            json,
        } => {
            let sample_percent = match sample {
                Some(p) if (1..=100).contains(&p) => p,
                Some(p) => return Err(format!("--sample must be 1-100, got {p}").into()),
                None => VerifyOptions::default().sample_percent,
            };
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            // Resolve an optional snapshot prefix to verify just that one.
            let only = match &snapshot {
                Some(s) => Some(resolve_snapshot(&repository, s).await?),
                None => None,
            };
            let options = VerifyOptions {
                sample_percent,
                only,
            };
            // A live spinner on a terminal (verify can read a lot of data); hidden
            // when piped or with --json.
            let spinner = (!json && std::io::stderr().is_terminal()).then(|| {
                let pb = ProgressBar::new_spinner();
                pb.set_style(
                    ProgressStyle::with_template("{spinner:.green} {pos} blobs verified").unwrap(),
                );
                pb.enable_steady_tick(std::time::Duration::from_millis(120));
                pb
            });
            let tick = || {
                if let Some(pb) = &spinner {
                    pb.inc(1);
                }
            };
            let progress: Option<sluice_engine::VerifyProgressFn> =
                if spinner.is_some() { Some(&tick) } else { None };
            let report = verify_with_progress(&repository, options, progress).await?;
            if let Some(pb) = &spinner {
                pb.finish_and_clear();
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "snapshots": report.snapshots,
                        "trees": report.trees,
                        "blobs": report.blobs,
                        "total_blobs": report.total_blobs,
                        "sampled": report.blobs != report.total_blobs,
                    }))?
                );
            } else if report.blobs == report.total_blobs {
                println!(
                    "ok: {} snapshots, {} trees, {} blobs verified",
                    report.snapshots, report.trees, report.blobs
                );
            } else {
                println!(
                    "ok: {} snapshots, {} trees, sampled {} of {} blobs verified",
                    report.snapshots, report.trees, report.blobs, report.total_blobs
                );
            }
        }
        Command::Check {
            repo,
            snapshot,
            json,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            // Resolve an optional snapshot prefix to check just that one.
            let only = match &snapshot {
                Some(s) => Some(resolve_snapshot(&repository, s).await?),
                None => None,
            };
            let report = check_only(&repository, only).await?;
            if json {
                let missing: Vec<String> = report.missing.iter().map(|id| id.to_string()).collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": report.missing.is_empty(),
                        "snapshots": report.snapshots,
                        "trees": report.trees,
                        "blobs": report.blobs,
                        "missing": missing,
                    }))?
                );
                if !report.missing.is_empty() {
                    // A missing referenced blob is data corruption (DESIGN.md §7).
                    return Ok(13);
                }
            } else if report.missing.is_empty() {
                println!(
                    "ok: {} snapshots, {} trees, {} blobs referenced",
                    report.snapshots, report.trees, report.blobs
                );
            } else {
                eprintln!(
                    "FAILED: {} of {} referenced blobs missing",
                    report.missing.len(),
                    report.blobs
                );
                for id in &report.missing {
                    eprintln!("  missing {id}");
                }
                // A missing referenced blob is data corruption (DESIGN.md §7).
                return Ok(13);
            }
        }
        Command::Forget {
            repo,
            snapshot,
            keep_last,
            keep_hourly,
            keep_daily,
            keep_weekly,
            keep_monthly,
            keep_yearly,
            keep_tag,
            keep_id,
            keep_within,
            keep_within_hourly,
            keep_within_daily,
            keep_within_weekly,
            keep_within_monthly,
            keep_within_yearly,
            group_by,
            tag,
            dry_run,
            prune: do_prune,
            json,
        } => {
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
            // Parse an optional duration string (e.g. 7d, 24h, 2w) to nanoseconds.
            let within = |s: &Option<String>| -> Result<i64, Box<dyn Error>> {
                match s {
                    Some(s) => parse_within(s),
                    None => Ok(0),
                }
            };
            let keep_within_ns = within(&keep_within)?;
            // Resolve each --keep-id prefix to a full snapshot id.
            let mut keep_ids = Vec::with_capacity(keep_id.len());
            for prefix in &keep_id {
                keep_ids.push(resolve_snapshot(&repository, prefix).await?);
            }
            let policy = RetentionPolicy {
                last: keep_last.unwrap_or(0),
                hourly: keep_hourly.unwrap_or(0),
                daily: keep_daily.unwrap_or(0),
                weekly: keep_weekly.unwrap_or(0),
                monthly: keep_monthly.unwrap_or(0),
                yearly: keep_yearly.unwrap_or(0),
                keep_tags: keep_tag,
                keep_within_ns,
                within_hourly_ns: within(&keep_within_hourly)?,
                within_daily_ns: within(&keep_within_daily)?,
                within_weekly_ns: within(&keep_within_weekly)?,
                within_monthly_ns: within(&keep_within_monthly)?,
                within_yearly_ns: within(&keep_within_yearly)?,
                keep_ids,
            };
            let group = match group_by {
                None => GroupBy::None,
                Some(GroupByArg::Host) => GroupBy::Host,
                Some(GroupByArg::Paths) => GroupBy::Paths,
            };
            let verb = if dry_run { "would forget" } else { "forgot" };
            // The single-id form already prints the id; the tag/policy forms print
            // only a count, so a dry run lists which snapshots they would remove.
            let mut single_by_id = false;
            let forgotten: Vec<Id> = match (snapshot, tag, policy.is_empty()) {
                (Some(snapshot), None, true) => {
                    single_by_id = true;
                    let id = resolve_snapshot(&repository, &snapshot).await?;
                    if !dry_run {
                        forget(&repository, &id).await?;
                    }
                    if !json {
                        println!("{verb} {id}");
                    }
                    vec![id]
                }
                (None, Some(tag), true) => {
                    let forgotten = forget_tagged(&repository, &tag, dry_run).await?;
                    if !json {
                        println!("{verb} {} snapshot(s)", forgotten.len());
                    }
                    forgotten
                }
                (None, None, false) => {
                    let forgotten =
                        forget_with_policy(&repository, &policy, group, dry_run).await?;
                    if !json {
                        println!("{verb} {} snapshot(s)", forgotten.len());
                    }
                    forgotten
                }
                _ => {
                    return Err(
                        "specify exactly one of: <snapshot>, --tag T, or one or more \
                         --keep-last/-hourly/-daily/-weekly/-monthly/-yearly rules"
                            .into(),
                    );
                }
            };
            // On a dry run, list the snapshots a tag/policy would remove (id + date)
            // so retention can be reviewed before pruning.
            if dry_run && !json && !single_by_id && !forgotten.is_empty() {
                for id in forgotten.iter().take(50) {
                    let when = repository
                        .load_snapshot(id)
                        .await
                        .map(|s| format_utc(s.time_ns))
                        .unwrap_or_default();
                    println!("  {}  {when}", &id.to_string()[..16]);
                }
                if forgotten.len() > 50 {
                    println!("  ... and {} more", forgotten.len() - 50);
                }
            }
            let pruned = if do_prune {
                // Under --dry-run the snapshots are still present, so treat the
                // would-be-forgotten ones as excluded to preview the reclamation.
                let report = if dry_run {
                    let excluded: HashSet<Id> = forgotten.iter().copied().collect();
                    prune_excluding(&mut repository, true, &excluded, 0).await?
                } else {
                    prune(&mut repository, false, 0).await?
                };
                if !json {
                    let pverb = if dry_run {
                        "would reclaim"
                    } else {
                        "reclaimed"
                    };
                    println!(
                        "{pverb} {} bytes ({} packs deleted, {} repacked)",
                        report.reclaimed_bytes, report.deleted, report.repacked
                    );
                }
                Some(report)
            } else {
                None
            };
            if json {
                let mut obj = serde_json::json!({
                    "dry_run": dry_run,
                    "count": forgotten.len(),
                    "forgotten": forgotten.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                });
                if let Some(report) = pruned {
                    obj["pruned"] = serde_json::json!({
                        "deleted": report.deleted,
                        "repacked": report.repacked,
                        "reclaimed_bytes": report.reclaimed_bytes,
                    });
                }
                println!("{}", serde_json::to_string_pretty(&obj)?);
            }
        }
        Command::Prune {
            repo,
            dry_run,
            max_unused,
            json,
        } => {
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
            // A live spinner on a terminal (repacking can rewrite a lot of data);
            // hidden when piped, with --json, or on a dry run.
            let spinner = (!json && !dry_run && std::io::stderr().is_terminal()).then(|| {
                let pb = ProgressBar::new_spinner();
                pb.set_style(
                    ProgressStyle::with_template("{spinner:.green} {pos} packs swept").unwrap(),
                );
                pb.enable_steady_tick(std::time::Duration::from_millis(120));
                pb
            });
            let tick = || {
                if let Some(pb) = &spinner {
                    pb.inc(1);
                }
            };
            let progress: Option<sluice_engine::PruneProgressFn> =
                if spinner.is_some() { Some(&tick) } else { None };
            let report = prune_excluding_with_progress(
                &mut repository,
                dry_run,
                &std::collections::HashSet::new(),
                max_unused,
                progress,
            )
            .await?;
            if let Some(pb) = &spinner {
                pb.finish_and_clear();
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "dry_run": dry_run,
                        "deleted": report.deleted,
                        "repacked": report.repacked,
                        "reclaimed_bytes": report.reclaimed_bytes,
                    }))?
                );
            } else {
                let verb = if dry_run { "would prune" } else { "pruned" };
                println!(
                    "{verb} {} packs, {} repacked ({} bytes reclaimed)",
                    report.deleted, report.repacked, report.reclaimed_bytes
                );
            }
        }
        Command::Ls {
            repo,
            snapshot,
            path,
            long,
            json,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let id = resolve_snapshot(&repository, &snapshot).await?;
            let mut entries = list_files(&repository, &id).await?;
            // Restrict to a subpath (the entry itself plus everything under it).
            if let Some(p) = &path {
                let p = p.trim_matches('/');
                let prefix = format!("{p}/");
                entries.retain(|e| e.path == p || e.path.starts_with(&prefix));
            }
            if json {
                let arr: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "path": e.path,
                            "kind": kind_str(e.kind),
                            "size": e.size,
                            "mode": e.mode,
                            "uid": e.uid,
                            "gid": e.gid,
                            "mtime_ns": e.mtime_ns,
                            "rdev": e.rdev,
                            "link_target": e.link_target.as_ref().map(|b| String::from_utf8_lossy(b).into_owned()),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
            } else if long {
                for e in &entries {
                    // Devices report major,minor where a file reports its size.
                    let size_col = match e.kind {
                        EntryKind::CharDevice | EntryKind::BlockDevice => {
                            let (major, minor) = major_minor(e.rdev);
                            format!("{major}, {minor}")
                        }
                        _ => e.size.to_string(),
                    };
                    let mut line = format!(
                        "{} {:>6} {:>6} {:>12} {} {}",
                        mode_string(e.kind, e.mode),
                        e.uid,
                        e.gid,
                        size_col,
                        format_utc(e.mtime_ns),
                        e.path,
                    );
                    if e.kind == EntryKind::Symlink {
                        if let Some(target) = &e.link_target {
                            line.push_str(&format!(" -> {}", String::from_utf8_lossy(target)));
                        }
                    }
                    println!("{line}");
                }
            } else {
                for entry in &entries {
                    let tag = match entry.kind {
                        EntryKind::Dir => "d",
                        EntryKind::Symlink => "l",
                        _ => "-",
                    };
                    println!("{tag} {:>12} {}", entry.size, entry.path);
                }
            }
        }
        Command::Find {
            repo,
            pattern,
            json,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let matches = find(&repository, &pattern).await?;
            if json {
                let arr: Vec<serde_json::Value> = matches
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "snapshot": m.snapshot.to_string(),
                            "path": m.path,
                            "kind": kind_str(m.kind),
                            "size": m.size,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
            } else {
                for m in &matches {
                    let tag = match m.kind {
                        EntryKind::Dir => "d",
                        EntryKind::Symlink => "l",
                        _ => "-",
                    };
                    println!(
                        "{}  {tag} {:>12} {}",
                        &m.snapshot.to_string()[..16],
                        m.size,
                        m.path
                    );
                }
            }
        }
        Command::Diff {
            repo,
            from,
            to,
            json,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let a = resolve_snapshot(&repository, &from).await?;
            let b = resolve_snapshot(&repository, &to).await?;
            let changes = diff(&repository, &a, &b).await?;
            if json {
                let arr: Vec<serde_json::Value> = changes
                    .iter()
                    .map(|c| {
                        let kind = match c.change {
                            DiffKind::Added => "added",
                            DiffKind::Removed => "removed",
                            DiffKind::Modified => "modified",
                        };
                        serde_json::json!({ "change": kind, "path": c.path, "changed": c.detail.labels() })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
            } else {
                let (mut added, mut removed, mut modified) = (0u64, 0u64, 0u64);
                for change in &changes {
                    match change.change {
                        DiffKind::Added => {
                            added += 1;
                            println!("+ {}", change.path);
                        }
                        DiffKind::Removed => {
                            removed += 1;
                            println!("- {}", change.path);
                        }
                        DiffKind::Modified => {
                            modified += 1;
                            println!("M {} ({})", change.path, change.detail.labels().join(", "))
                        }
                    }
                }
                println!("{added} added, {removed} removed, {modified} modified");
            }
        }
        Command::Dump {
            repo,
            snapshot,
            path,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let id = resolve_snapshot(&repository, &snapshot).await?;
            let data = dump(&repository, &id, &path).await?;
            use std::io::Write;
            std::io::stdout().write_all(&data)?;
        }
        Command::Info { repo, json } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let config = repository.config();
            let snapshots = repository.list_snapshots().await?.len();
            let keys = repository.list_keys().await?.len();
            let pack_ids = repository.backend().list(FileType::Pack).await?;
            let mut stored = 0u64;
            for pid in &pack_ids {
                stored += repository.backend().size(FileType::Pack, pid).await?;
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "repository": repository.id().to_string(),
                        "created_ns": config.created_ns,
                        "cipher": format!("{:?}", config.cipher),
                        "chunker": {
                            "min": config.chunker.min,
                            "avg": config.chunker.avg,
                            "max": config.chunker.max,
                        },
                        "pack_target": config.pack_target,
                        "compression": config.compression,
                        "snapshots": snapshots,
                        "packs": pack_ids.len(),
                        "keys": keys,
                        "stored_bytes": stored,
                    }))?
                );
            } else {
                println!("repository:  {}", repository.id());
                println!("created:     {}", format_utc(config.created_ns));
                println!("cipher:      {:?}", config.cipher);
                println!(
                    "chunker:     min {} / avg {} / max {} bytes",
                    config.chunker.min, config.chunker.avg, config.chunker.max
                );
                println!("pack target: {} bytes", config.pack_target);
                println!("compression: zstd level {}", config.compression);
                println!("snapshots:   {snapshots}");
                println!("packs:       {}", pack_ids.len());
                println!("keys:        {keys}");
                println!("stored:      {}", format_bytes(stored));
            }
        }
        Command::Stats {
            repo,
            snapshot,
            json,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;

            // With a snapshot selector, report on that one snapshot instead of
            // the whole repository.
            if let Some(prefix) = snapshot {
                let id = resolve_snapshot(&repository, &prefix).await?;
                let s = snapshot_stats(&repository, &id).await?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "snapshot": id.to_string(),
                            "files": s.files,
                            "dirs": s.dirs,
                            "other": s.other,
                            "restore_bytes": s.restore_bytes,
                            "blobs": s.blobs,
                            "raw_bytes": s.raw_bytes,
                        }))?
                    );
                } else {
                    println!("snapshot:      {id}");
                    println!("files:         {}", s.files);
                    println!("dirs:          {}", s.dirs);
                    if s.other > 0 {
                        println!("other:         {}", s.other);
                    }
                    println!("restore size:  {}", format_bytes(s.restore_bytes));
                    println!("unique blobs:  {}", s.blobs);
                    println!("raw size:      {}", format_bytes(s.raw_bytes));
                }
                return Ok(0);
            }

            let pack_ids = repository.backend().list(FileType::Pack).await?;
            let mut stored = 0u64;
            for pid in &pack_ids {
                stored += repository.backend().size(FileType::Pack, pid).await?;
            }
            let snapshots = repository.list_snapshots().await?;
            let mut logical = 0u64;
            for id in &snapshots {
                logical += repository.load_snapshot(id).await?.summary.bytes_processed;
            }
            // Saving %: 0 when nothing is stored beyond the logical size, or the
            // repository is empty (checked_div guards the divide-by-zero).
            let saved = (logical.saturating_sub(stored) * 100)
                .checked_div(logical)
                .unwrap_or(0);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "snapshots": snapshots.len(),
                        "packs": pack_ids.len(),
                        "logical_bytes": logical,
                        "stored_bytes": stored,
                        "saved_percent": saved,
                    }))?
                );
            } else {
                println!("snapshots:     {}", snapshots.len());
                println!("packs:         {}", pack_ids.len());
                println!("logical bytes: {}", format_bytes(logical));
                println!("stored bytes:  {}", format_bytes(stored));
                println!("saved:         {saved}% (dedup + compression)");
            }
        }
        Command::Unlock { repo, json } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let locks = repository.list_locks().await?;
            for (id, _) in &locks {
                repository.release_lock(id).await?;
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "removed": locks.len(),
                    }))?
                );
            } else {
                println!("removed {} lock(s)", locks.len());
            }
        }
        Command::RebuildIndex { repo, json } => {
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let n = rebuild_index(&mut repository).await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "packs": n }))?
                );
            } else {
                println!("rebuilt index for {n} pack(s)");
            }
        }
        Command::Key { action } => match action {
            KeyCmd::List { repo, json } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let keys = repository.list_keys().await?;
                let active = repository.active_key_id();
                if json {
                    let arr: Vec<serde_json::Value> = keys
                        .iter()
                        .map(|id| {
                            serde_json::json!({
                                "id": id.to_string(),
                                "active": *id == active,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&arr)?);
                } else {
                    println!("{} key(s):", keys.len());
                    for id in &keys {
                        let marker = if *id == active { " (active)" } else { "" };
                        println!("  {id}{marker}");
                    }
                }
            }
            KeyCmd::Add { repo, json } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let new_pass = read_new_passphrase()?;
                let id = repository
                    .add_key(new_pass.as_bytes(), kdf_params())
                    .await?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({ "key_id": id.to_string() })
                        )?
                    );
                } else {
                    println!("added key {id}");
                }
            }
            KeyCmd::Remove { repo, id, json } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let key_id: Id = id.parse().map_err(|_| "invalid key id")?;
                repository.remove_key(&key_id).await?;
                if json {
                    let remaining = repository.list_keys().await?.len();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "removed": key_id.to_string(),
                            "keys": remaining,
                        }))?
                    );
                } else {
                    println!("removed key {key_id}");
                }
            }
            KeyCmd::Passwd { repo, json } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let new_pass = read_new_passphrase()?;
                let id = repository
                    .change_passphrase(new_pass.as_bytes(), kdf_params())
                    .await?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({ "key_id": id.to_string() })
                        )?
                    );
                } else {
                    println!("changed passphrase; new key {id}");
                }
            }
        },
        Command::Cat { object } => {
            let value = match object {
                CatObject::Config { repo } => {
                    let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                    let c = repository.config();
                    serde_json::json!({
                        "repo_id": c.repo_id.to_string(),
                        "version": c.version,
                        "cipher": format!("{:?}", c.cipher),
                        "chunker": { "min": c.chunker.min, "avg": c.chunker.avg, "max": c.chunker.max },
                        "pack_target": c.pack_target,
                        "created_ns": c.created_ns,
                    })
                }
                CatObject::Snapshot { repo, snapshot } => {
                    let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                    let id = resolve_snapshot(&repository, &snapshot).await?;
                    let s = repository.load_snapshot(&id).await?;
                    serde_json::json!({
                        "id": id.to_string(),
                        "time_ns": s.time_ns,
                        "tree": s.tree.to_string(),
                        "paths": s.paths.iter().map(|p| String::from_utf8_lossy(p).into_owned()).collect::<Vec<_>>(),
                        "hostname": s.hostname,
                        "username": s.username,
                        "uid": s.uid,
                        "gid": s.gid,
                        "tags": s.tags,
                        "parent": s.parent.map(|p| p.to_string()),
                        "program_version": s.program_version,
                        "summary": {
                            "files_new": s.summary.files_new,
                            "files_changed": s.summary.files_changed,
                            "files_unmodified": s.summary.files_unmodified,
                            "dirs": s.summary.dirs,
                            "bytes_processed": s.summary.bytes_processed,
                            "bytes_added": s.summary.bytes_added,
                        },
                    })
                }
                CatObject::Tree { repo, id } => {
                    let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                    let tid: Id = id.parse().map_err(|_| "invalid tree id")?;
                    let tree = repository.load_tree(&tid).await?;
                    let nodes: Vec<serde_json::Value> = tree
                        .nodes
                        .iter()
                        .map(|n| {
                            serde_json::json!({
                                "name": String::from_utf8_lossy(&n.name).into_owned(),
                                "kind": kind_str(n.kind),
                                "mode": n.mode,
                                "uid": n.uid,
                                "gid": n.gid,
                                "mtime_ns": n.mtime_ns,
                                "size": n.size,
                                "content": n.content.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                                "subtree": n.subtree.map(|i| i.to_string()),
                                "link_target": n.link_target.as_ref().map(|b| String::from_utf8_lossy(b).into_owned()),
                                "dev": n.dev,
                                "ino": n.ino,
                                "rdev": n.rdev,
                                "sparse": n.sparse,
                                "xattrs": n.xattrs.iter().map(|(k, _)| String::from_utf8_lossy(k).into_owned()).collect::<Vec<_>>(),
                            })
                        })
                        .collect();
                    serde_json::json!({ "nodes": nodes })
                }
                CatObject::Blob { repo, id } => {
                    // A blob is arbitrary bytes, not JSON: decrypt and stream the
                    // raw contents to stdout, then return.
                    let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                    let bid: Id = id.parse().map_err(|_| "invalid blob id")?;
                    let bytes = repository.load_blob(&bid).await?;
                    use std::io::Write;
                    std::io::stdout().write_all(&bytes)?;
                    return Ok(0);
                }
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Command::Mount {
            repo,
            mountpoint,
            snapshot,
        } => {
            #[cfg(feature = "fuse")]
            {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let target = match &snapshot {
                    Some(s) => {
                        mount::MountTarget::Snapshot(resolve_snapshot(&repository, s).await?)
                    }
                    None => mount::MountTarget::All,
                };
                eprintln!(
                    "mounting {} at {} — unmount with `fusermount -u {}` or Ctrl-C",
                    snapshot
                        .as_deref()
                        .map_or_else(|| "all snapshots".to_string(), |s| format!("snapshot {s}")),
                    mountpoint.display(),
                    mountpoint.display()
                );
                // The FUSE session blocks and builds its own runtime, so run it on
                // a thread with no ambient Tokio runtime; wait for unmount off the
                // async worker via spawn_blocking.
                let session =
                    std::thread::spawn(move || mount::run_mount(repository, target, &mountpoint));
                tokio::task::spawn_blocking(move || session.join())
                    .await
                    .map_err(|e| format!("mount supervisor failed: {e}"))?
                    .map_err(|_| "mount thread panicked")??;
            }
            #[cfg(not(feature = "fuse"))]
            {
                let _ = (&repo, &snapshot, &mountpoint);
                return Err(
                    "this build has no FUSE support; rebuild with `--features fuse`".into(),
                );
            }
        }
        // Handled before the passphrase prompt above.
        Command::Completions { .. } | Command::Man { .. } => unreachable!(),
    }
    Ok(exit)
}

/// Write a troff man page for the top-level command and one for each subcommand
/// into `dir` (creating it if absent). Used by `sluice man`.
fn write_man_pages(dir: &std::path::Path) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(dir)?;
    let render = |cmd: clap::Command, file: PathBuf| -> Result<(), Box<dyn Error>> {
        let mut buf = Vec::new();
        clap_mangen::Man::new(cmd).render(&mut buf)?;
        std::fs::write(file, &buf)?;
        Ok(())
    };
    let cmd = Cli::command();
    render(cmd.clone(), dir.join("sluice.1"))?;
    let mut count = 1usize;
    for sub in cmd.get_subcommands() {
        render(
            sub.clone(),
            dir.join(format!("sluice-{}.1", sub.get_name())),
        )?;
        count += 1;
    }
    eprintln!("wrote {count} man pages to {}", dir.display());
    Ok(())
}

/// Open (or, when `create`, create) the storage backend for `repo` — a local
/// path or an object-store URL such as `s3://bucket/prefix`.
async fn backend(repo: &str, create: bool) -> Result<Arc<dyn StorageBackend>, Box<dyn Error>> {
    if repo.contains("://") {
        let url = url::Url::parse(repo)?;
        let (store, prefix) = object_store::parse_url(&url)?;
        Ok(Arc::new(ObjectStoreBackend::with_prefix(
            Arc::from(store),
            prefix,
        )))
    } else if create {
        Ok(Arc::new(LocalBackend::create(repo).await?))
    } else {
        Ok(Arc::new(LocalBackend::open(repo)))
    }
}

/// True if `snap` passes the optional tag/host/path filters; a `None` filter
/// matches everything. Shared by the `snapshots` and `copy` selectors.
fn snapshot_matches(
    snap: &sluice_core::Snapshot,
    tag: Option<&str>,
    host: Option<&str>,
    path: Option<&str>,
) -> bool {
    if let Some(tag) = tag {
        if !snap.tags.iter().any(|t| t == tag) {
            return false;
        }
    }
    if let Some(host) = host {
        if snap.hostname != host {
            return false;
        }
    }
    if let Some(path) = path {
        if !snap
            .paths
            .iter()
            .any(|p| String::from_utf8_lossy(p) == path)
        {
            return false;
        }
    }
    true
}

/// Resolve a full id or a unique hex prefix to a snapshot id.
async fn resolve_snapshot<B: StorageBackend>(
    repo: &Repository<B>,
    needle: &str,
) -> Result<Id, Box<dyn Error>> {
    let snapshots = repo.list_snapshots().await?;
    // A full id must still name a real snapshot — otherwise it gets the same clear
    // "no snapshot matches" as a bad prefix, not a cryptic downstream error.
    if let Ok(id) = needle.parse::<Id>() {
        return if snapshots.contains(&id) {
            Ok(id)
        } else {
            Err(format!("no snapshot matches '{needle}'").into())
        };
    }
    let matches: Vec<Id> = snapshots
        .into_iter()
        .filter(|id| id.to_string().starts_with(needle))
        .collect();
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => Err(format!("no snapshot matches '{needle}'").into()),
        _ => {
            // List the candidates so the user can pick a longer, unique prefix.
            let mut list: Vec<String> = matches
                .iter()
                .map(|id| id.to_string()[..16].into())
                .collect();
            list.sort();
            let shown = if list.len() > 8 {
                format!("{}, ... and {} more", list[..8].join(", "), list.len() - 8)
            } else {
                list.join(", ")
            };
            Err(format!(
                "ambiguous snapshot prefix '{needle}': matches {} snapshots ({shown})",
                matches.len()
            )
            .into())
        }
    }
}

/// Argon2id parameters for `init`, tunable via the environment for power users
/// and tests (`SLUICE_KDF_MEMORY_KIB`, `SLUICE_KDF_PASSES`); defaults otherwise.
fn kdf_params() -> KdfParams {
    let mut params = KdfParams::DEFAULT;
    if let Some(memory) = std::env::var("SLUICE_KDF_MEMORY_KIB")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        params.m_cost_kib = memory;
    }
    if let Some(passes) = std::env::var("SLUICE_KDF_PASSES")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        params.t_cost = passes;
    }
    params
}

/// The passphrase is the first line of the file, with the trailing newline
/// removed — so the secret need not live in the environment (visible via
/// `/proc/<pid>/environ`) or be typed interactively in a script.
fn passphrase_from_file(path: &str) -> Result<String, Box<dyn Error>> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("reading password file {path}: {e}"))?;
    Ok(contents.lines().next().unwrap_or("").to_string())
}

/// Run `command` via `sh -c` and take the first line of its stdout as the
/// passphrase, so it can come from a secret manager (`pass`, a vault, the OS
/// keychain) without ever touching a file or the environment.
fn passphrase_from_command(command: &str) -> Result<String, Box<dyn Error>> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|e| format!("running password command: {e}"))?;
    if !output.status.success() {
        return Err(format!("password command exited with {}", output.status).into());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string())
}

/// Resolve a passphrase from `{prefix}_COMMAND`, then `{prefix}_FILE`, then the
/// `{prefix}` variable itself (in that order), or `None` if none is set — so the
/// caller can fall back to a prompt, or (for a copy) the source passphrase. Used
/// with the `SLUICE_PASSWORD` and `SLUICE_DEST_PASSWORD` prefixes.
fn passphrase_from_sources(prefix: &str) -> Option<Result<String, Box<dyn Error>>> {
    if let Ok(cmd) = std::env::var(format!("{prefix}_COMMAND")) {
        return Some(passphrase_from_command(&cmd));
    }
    if let Ok(path) = std::env::var(format!("{prefix}_FILE")) {
        return Some(passphrase_from_file(&path));
    }
    std::env::var(prefix).ok().map(Ok)
}

/// Read the passphrase from the `SLUICE_PASSWORD{_COMMAND,_FILE,}` sources, else
/// prompt with no echo when a terminal is attached. With `confirm` set (for
/// `init` at a prompt), it is entered twice.
fn read_passphrase(confirm: bool) -> Result<String, Box<dyn Error>> {
    use std::io::IsTerminal;
    if let Some(result) = passphrase_from_sources("SLUICE_PASSWORD") {
        return result;
    }
    if !std::io::stdin().is_terminal() {
        return Err(
            "no passphrase: set SLUICE_PASSWORD, SLUICE_PASSWORD_FILE or \
                    SLUICE_PASSWORD_COMMAND, or run in a terminal"
                .into(),
        );
    }
    let passphrase = rpassword::prompt_password("Passphrase: ")?;
    if confirm && passphrase != rpassword::prompt_password("Confirm passphrase: ")? {
        return Err("passphrases do not match".into());
    }
    Ok(passphrase)
}

/// Read the *new* passphrase for `key add` from `SLUICE_NEW_PASSWORD` or, on a
/// terminal, a confirmed prompt.
fn read_new_passphrase() -> Result<String, Box<dyn Error>> {
    use std::io::IsTerminal;
    if let Ok(passphrase) = std::env::var("SLUICE_NEW_PASSWORD") {
        return Ok(passphrase);
    }
    if !std::io::stdin().is_terminal() {
        return Err("no new passphrase: set SLUICE_NEW_PASSWORD or run in a terminal".into());
    }
    let passphrase = rpassword::prompt_password("New passphrase: ")?;
    if passphrase != rpassword::prompt_password("Confirm new passphrase: ")? {
        return Err("passphrases do not match".into());
    }
    Ok(passphrase)
}

/// Format epoch-nanoseconds as `YYYY-MM-DD HH:MM:SS UTC` (no dependencies).
/// Parse a retention window like `7d`, `24h`, or `2w` into nanoseconds. Units:
/// s (seconds), m (minutes), h (hours), d (days), w (weeks).
fn parse_within(s: &str) -> Result<i64, Box<dyn Error>> {
    let s = s.trim();
    let unit = s.chars().last().ok_or("empty duration")?;
    let factor: i64 = match unit {
        's' => 1_000_000_000,
        'm' => 60_000_000_000,
        'h' => 3_600_000_000_000,
        'd' => 86_400_000_000_000,
        'w' => 604_800_000_000_000,
        _ => return Err(format!("invalid duration unit '{unit}' (use s/m/h/d/w)").into()),
    };
    let n: i64 = s[..s.len() - unit.len_utf8()]
        .parse()
        .map_err(|_| format!("invalid duration: {s}"))?;
    n.checked_mul(factor)
        .ok_or_else(|| "duration overflow".into())
}

/// Parse a byte size like `1024`, `100K`, `2M`, `4G`, `1T` (binary multipliers,
/// case-insensitive suffix; a bare number is bytes).
fn parse_size(s: &str) -> Result<u64, Box<dyn Error>> {
    let s = s.trim();
    let (digits, factor) = match s.chars().last() {
        Some(c) if c.is_ascii_digit() => (s, 1u64),
        Some(c) => {
            let factor = match c.to_ascii_uppercase() {
                'K' => 1024,
                'M' => 1024 * 1024,
                'G' => 1024 * 1024 * 1024,
                'T' => 1024u64.pow(4),
                _ => return Err(format!("invalid size unit '{c}' (use K/M/G/T)").into()),
            };
            (&s[..s.len() - c.len_utf8()], factor)
        }
        None => return Err("empty size".into()),
    };
    let n: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("invalid size: {s}"))?;
    n.checked_mul(factor).ok_or_else(|| "size overflow".into())
}

/// Stable lowercase name for an entry kind, used in JSON output.
fn kind_str(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Dir => "dir",
        EntryKind::File => "file",
        EntryKind::Symlink => "symlink",
        EntryKind::Fifo => "fifo",
        EntryKind::Socket => "socket",
        EntryKind::CharDevice => "chardev",
        EntryKind::BlockDevice => "blockdev",
    }
}

/// Render Unix mode bits as a 10-character `ls -l` string, e.g. `drwxr-xr-x`,
/// including setuid/setgid (`s`/`S`) and sticky (`t`/`T`) overlays.
fn mode_string(kind: EntryKind, mode: u32) -> String {
    let type_char = match kind {
        EntryKind::Dir => 'd',
        EntryKind::Symlink => 'l',
        EntryKind::Fifo => 'p',
        EntryKind::Socket => 's',
        EntryKind::CharDevice => 'c',
        EntryKind::BlockDevice => 'b',
        EntryKind::File => '-',
    };
    // One rwx triplet; `special` is the setuid/setgid/sticky bit, whose presence
    // turns the execute slot into `s`/`t` (lowercase if also executable).
    let triplet = |r: u32, w: u32, x: u32, special: u32, hi: char, lo: char| -> [char; 3] {
        [
            if mode & r != 0 { 'r' } else { '-' },
            if mode & w != 0 { 'w' } else { '-' },
            match (mode & x != 0, mode & special != 0) {
                (true, true) => lo,
                (false, true) => hi,
                (true, false) => 'x',
                (false, false) => '-',
            },
        ]
    };
    let o = triplet(0o400, 0o200, 0o100, 0o4000, 'S', 's');
    let g = triplet(0o040, 0o020, 0o010, 0o2000, 'S', 's');
    let p = triplet(0o004, 0o002, 0o001, 0o1000, 'T', 't');
    format!(
        "{type_char}{}{}{}{}{}{}{}{}{}",
        o[0], o[1], o[2], g[0], g[1], g[2], p[0], p[1], p[2]
    )
}

/// Split a `st_rdev` device number into `(major, minor)` using the C library's
/// encoding (which `mknod` round-trips), matching what `ls` prints.
fn major_minor(rdev: u64) -> (u64, u64) {
    let major = ((rdev >> 32) & 0xffff_f000) | ((rdev >> 8) & 0x0000_0fff);
    let minor = ((rdev >> 12) & 0xffff_ff00) | (rdev & 0x0000_00ff);
    (major, minor)
}

/// Render a byte count with a binary unit for human-readable output (`1.5 GiB`).
/// JSON output keeps raw byte counts; this is for the text listings only.
fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn format_utc(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hour, minute, second) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // civil_from_days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::{EntryKind, format_bytes, format_utc, major_minor, mode_string, parse_size};

    #[test]
    fn parses_byte_sizes_with_binary_suffixes() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("100K").unwrap(), 100 * 1024);
        assert_eq!(parse_size("2M").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size("4g").unwrap(), 4 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1T").unwrap(), 1024u64.pow(4));
        assert!(parse_size("10X").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn formats_byte_counts_with_binary_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(format_bytes(3 * 1024_u64.pow(4)), "3.0 TiB");
    }

    #[test]
    fn formats_epoch_in_utc() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            format_utc(1_700_000_000 * 1_000_000_000),
            "2023-11-14 22:13:20 UTC"
        );
    }

    #[test]
    fn renders_ls_style_mode_strings() {
        assert_eq!(mode_string(EntryKind::File, 0o644), "-rw-r--r--");
        assert_eq!(mode_string(EntryKind::Dir, 0o755), "drwxr-xr-x");
        assert_eq!(mode_string(EntryKind::Symlink, 0o777), "lrwxrwxrwx");
        assert_eq!(mode_string(EntryKind::Fifo, 0o644), "prw-r--r--");
        assert_eq!(mode_string(EntryKind::CharDevice, 0o600), "crw-------");
        assert_eq!(mode_string(EntryKind::BlockDevice, 0o660), "brw-rw----");
        // setuid + setgid + sticky overlays (executable -> lowercase).
        assert_eq!(mode_string(EntryKind::File, 0o4755), "-rwsr-xr-x");
        assert_eq!(mode_string(EntryKind::File, 0o2755), "-rwxr-sr-x");
        assert_eq!(mode_string(EntryKind::Dir, 0o1777), "drwxrwxrwt");
        // setuid without execute -> uppercase S.
        assert_eq!(mode_string(EntryKind::File, 0o4644), "-rwSr--r--");
    }

    #[test]
    fn splits_device_numbers() {
        // Small major/minor pack into the low 16 bits (major << 8 | minor).
        assert_eq!(major_minor(0x105), (1, 5)); // /dev/zero, char 1:5
        assert_eq!(major_minor(0x103), (1, 3)); // /dev/null, char 1:3
        assert_eq!(major_minor(0x801), (8, 1)); // sda1, block 8:1
        // A major beyond 12 bits uses the bits above 32, not the low word.
        assert_eq!(major_minor(0x1000_0000_0000), (0x1000, 0));
    }
}
