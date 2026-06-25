//! `sluice` — command-line interface for the encrypted, deduplicating backup
//! and disaster-recovery tool (see `DESIGN.md` §7).
//!
//! The passphrase comes from the `SLUICE_PASSWORD` environment variable, or an
//! interactive no-echo prompt when a terminal is attached. A repository is a
//! local path or an object-store URL such as `s3://bucket/prefix`.

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
    check, copy_all_with_progress, copy_snapshot_with_progress, diff, dump, find, forget,
    forget_tagged, forget_with_policy, list_files, prune, prune_excluding, rebuild_index,
    restore_filtered, retag, verify_with_progress,
};
use sluice_repo::{RepoError, Repository};
use sluice_store::{FileType, LocalBackend, ObjectStoreBackend, StorageBackend};

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
    },
    /// Back up one or more directories into a single snapshot.
    Backup {
        /// Repository path or object-store URL.
        repo: String,
        /// Directories to back up (one or more; multiple sources land under a
        /// synthetic root named by each source's final path component).
        #[arg(required_unless_present = "stdin", num_args = 1..)]
        sources: Vec<PathBuf>,
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
        /// Skip entries whose path matches this glob (repeatable); a matching
        /// directory is pruned with its subtree.
        #[arg(long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
        /// Report what would be restored (file count and bytes) without writing.
        #[arg(long)]
        dry_run: bool,
        /// Leave entries already present and matching in place (resume a restore).
        #[arg(long)]
        skip_existing: bool,
        /// After writing each file, re-read it and verify it matches the snapshot.
        #[arg(long)]
        verify: bool,
        /// Print each file as it is restored.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Copy snapshots to another repository, re-encrypting under its keys.
    Copy {
        /// Source repository path or object-store URL.
        src: String,
        /// Destination repository path or object-store URL.
        dst: String,
        /// Snapshot id to copy (a unique hex prefix); omit to copy every snapshot.
        snapshot: Option<String>,
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
    },
    /// Verify the integrity of all snapshots.
    Verify {
        /// Repository path or object-store URL.
        repo: String,
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
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove advisory locks left behind by an interrupted operation.
    Unlock {
        /// Repository path or object-store URL.
        repo: String,
    },
    /// Rebuild index segments by rescanning packs (repairs a damaged index).
    RebuildIndex {
        /// Repository path or object-store URL.
        repo: String,
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
    },
    /// Remove a key by id (refused if it is the last key).
    Remove {
        /// Repository path or object-store URL.
        repo: String,
        /// The key id to remove (as shown by `key list`).
        id: String,
    },
    /// Change the current passphrase, rotating out its key.
    Passwd {
        /// Repository path or object-store URL.
        repo: String,
    },
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(exit_code(error.as_ref()));
        }
    }
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
        Command::Init { repo, compression } => {
            let repository = Repository::init_with_compression(
                backend(&repo, true).await?,
                pw,
                kdf_params(),
                compression,
            )
            .await?;
            println!("initialized repository {} at {repo}", repository.id());
        }
        Command::Backup {
            repo,
            sources,
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
            let max_size = exclude_larger_than.as_deref().map(parse_size).transpose()?;
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
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
                    cache_path: cache,
                    dry_run,
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
                        "dry_run": outcome.snapshot.is_none(),
                        "files_new": s.files_new,
                        "files_changed": s.files_changed,
                        "files_unmodified": s.files_unmodified,
                        "dirs": s.dirs,
                        "bytes": s.bytes_processed,
                    }))?
                );
            } else {
                match outcome.snapshot {
                    Some(id) => {
                        println!("{id}");
                        eprintln!(
                            "  {} new, {} changed, {} unmodified, {} dirs, {} bytes",
                            s.files_new,
                            s.files_changed,
                            s.files_unmodified,
                            s.dirs,
                            s.bytes_processed
                        );
                    }
                    None => {
                        println!(
                            "dry run: {} new, {} changed, {} unmodified, {} dirs, {} bytes (nothing written)",
                            s.files_new,
                            s.files_changed,
                            s.files_unmodified,
                            s.dirs,
                            s.bytes_processed
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
            include,
            exclude,
            dry_run,
            skip_existing,
            verify,
            verbose,
        } => {
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
                println!(
                    "would restore {count} files ({bytes} bytes) into {} (nothing written)",
                    target.display()
                );
            } else {
                let options = RestoreOptions {
                    skip_existing,
                    verify,
                };
                // With --verbose, print each file as it is restored (to stderr,
                // like `backup -v`, leaving stdout for the completion line).
                let report_file = |path: &std::path::Path| eprintln!("{}", path.display());
                // Otherwise show a live spinner on a terminal (hidden when piped).
                let spinner = (!verbose && std::io::stderr().is_terminal()).then(|| {
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
                    exit = 3;
                }
            }
        }
        Command::Copy { src, dst, snapshot } => {
            let source = Repository::open(backend(&src, false).await?, pw).await?;
            // The destination may use a different passphrase.
            let dest_pass =
                std::env::var("SLUICE_DEST_PASSWORD").unwrap_or_else(|_| passphrase.clone());
            let mut dest =
                Repository::open(backend(&dst, false).await?, dest_pass.as_bytes()).await?;
            let target_id = match &snapshot {
                Some(s) => Some(resolve_snapshot(&source, s).await?),
                None => None,
            };
            // A live spinner on a terminal (offsite copies can move a lot of
            // data); hidden when piped.
            let spinner = std::io::stderr().is_terminal().then(|| {
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
            let outcome = match target_id {
                Some(id) => copy_snapshot_with_progress(&source, &mut dest, &id, progress)
                    .await
                    .map(|new_id| new_id.to_string()),
                None => copy_all_with_progress(&source, &mut dest, progress)
                    .await
                    .map(|ids| format!("copied {} snapshot(s)", ids.len())),
            };
            if let Some(pb) = &spinner {
                pb.finish_and_clear();
            }
            println!("{}", outcome?);
        }
        Command::Snapshots {
            repo,
            tag,
            host,
            path,
            last,
            json,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let mut snaps = Vec::new();
            for id in repository.list_snapshots().await? {
                let snap = repository.load_snapshot(&id).await?;
                if let Some(tag) = &tag {
                    if !snap.tags.iter().any(|t| t == tag) {
                        continue;
                    }
                }
                if let Some(host) = &host {
                    if &snap.hostname != host {
                        continue;
                    }
                }
                if let Some(path) = &path {
                    if !snap
                        .paths
                        .iter()
                        .any(|p| String::from_utf8_lossy(p) == *path)
                    {
                        continue;
                    }
                }
                snaps.push((id, snap));
            }
            // List chronologically (oldest first); --last keeps the most recent N.
            snaps.sort_by(|a, b| a.1.time_ns.cmp(&b.1.time_ns));
            if let Some(n) = last {
                let drop = snaps.len().saturating_sub(n);
                snaps.drain(..drop);
            }
            if json {
                let arr: Vec<serde_json::Value> = snaps
                    .iter()
                    .map(|(id, snap)| {
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
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
            } else {
                for (id, snap) in &snaps {
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
                    println!(
                        "{}  {}  {files} files, {}  {}{tags}",
                        &hex[..16],
                        format_utc(snap.time_ns),
                        format_bytes(snap.summary.bytes_processed),
                        paths.join(", ")
                    );
                }
            }
        }
        Command::Tag {
            repo,
            snapshot,
            add,
            remove,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let id = resolve_snapshot(&repository, &snapshot).await?;
            let new_id = retag(&repository, &id, &add, &remove).await?;
            if new_id == id {
                println!("no change");
            } else {
                println!("{new_id}");
            }
        }
        Command::Verify { repo, sample, json } => {
            let options = match sample {
                Some(p) if (1..=100).contains(&p) => VerifyOptions { sample_percent: p },
                Some(p) => return Err(format!("--sample must be 1-100, got {p}").into()),
                None => VerifyOptions::default(),
            };
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
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
        Command::Check { repo, json } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let report = check(&repository).await?;
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
            keep_daily,
            keep_weekly,
            keep_monthly,
            keep_yearly,
            keep_tag,
            keep_id,
            keep_within,
            group_by,
            tag,
            dry_run,
            prune: do_prune,
            json,
        } => {
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let keep_within_ns = match &keep_within {
                Some(s) => parse_within(s)?,
                None => 0,
            };
            // Resolve each --keep-id prefix to a full snapshot id.
            let mut keep_ids = Vec::with_capacity(keep_id.len());
            for prefix in &keep_id {
                keep_ids.push(resolve_snapshot(&repository, prefix).await?);
            }
            let policy = RetentionPolicy {
                last: keep_last.unwrap_or(0),
                daily: keep_daily.unwrap_or(0),
                weekly: keep_weekly.unwrap_or(0),
                monthly: keep_monthly.unwrap_or(0),
                yearly: keep_yearly.unwrap_or(0),
                keep_tags: keep_tag,
                keep_within_ns,
                keep_ids,
            };
            let group = match group_by {
                None => GroupBy::None,
                Some(GroupByArg::Host) => GroupBy::Host,
                Some(GroupByArg::Paths) => GroupBy::Paths,
            };
            let verb = if dry_run { "would forget" } else { "forgot" };
            let forgotten: Vec<Id> = match (snapshot, tag, policy.is_empty()) {
                (Some(snapshot), None, true) => {
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
                         --keep-last/-daily/-weekly/-monthly/-yearly rules"
                            .into(),
                    );
                }
            };
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
            let report = prune(&mut repository, dry_run, max_unused).await?;
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
                for change in &changes {
                    match change.change {
                        DiffKind::Added => println!("+ {}", change.path),
                        DiffKind::Removed => println!("- {}", change.path),
                        DiffKind::Modified => {
                            println!("M {} ({})", change.path, change.detail.labels().join(", "))
                        }
                    }
                }
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
        Command::Stats { repo, json } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
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
            let saved = if logical > 0 && stored < logical {
                (logical - stored) * 100 / logical
            } else {
                0
            };
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
        Command::Unlock { repo } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let locks = repository.list_locks().await?;
            for (id, _) in &locks {
                repository.release_lock(id).await?;
            }
            println!("removed {} lock(s)", locks.len());
        }
        Command::RebuildIndex { repo } => {
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let n = rebuild_index(&mut repository).await?;
            println!("rebuilt index for {n} pack(s)");
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
            KeyCmd::Add { repo } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let new_pass = read_new_passphrase()?;
                let id = repository
                    .add_key(new_pass.as_bytes(), kdf_params())
                    .await?;
                println!("added key {id}");
            }
            KeyCmd::Remove { repo, id } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let key_id: Id = id.parse().map_err(|_| "invalid key id")?;
                repository.remove_key(&key_id).await?;
                println!("removed key {key_id}");
            }
            KeyCmd::Passwd { repo } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let new_pass = read_new_passphrase()?;
                let id = repository
                    .change_passphrase(new_pass.as_bytes(), kdf_params())
                    .await?;
                println!("changed passphrase; new key {id}");
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

/// Resolve a full id or a unique hex prefix to a snapshot id.
async fn resolve_snapshot<B: StorageBackend>(
    repo: &Repository<B>,
    needle: &str,
) -> Result<Id, Box<dyn Error>> {
    if let Ok(id) = needle.parse::<Id>() {
        return Ok(id);
    }
    let matches: Vec<Id> = repo
        .list_snapshots()
        .await?
        .into_iter()
        .filter(|id| id.to_string().starts_with(needle))
        .collect();
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => Err(format!("no snapshot matches '{needle}'").into()),
        _ => Err(format!("ambiguous snapshot prefix '{needle}'").into()),
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

/// Read the passphrase from `SLUICE_PASSWORD`, or prompt with no echo when a
/// terminal is attached. With `confirm` set (for `init`), it is entered twice.
fn read_passphrase(confirm: bool) -> Result<String, Box<dyn Error>> {
    use std::io::IsTerminal;
    if let Ok(passphrase) = std::env::var("SLUICE_PASSWORD") {
        return Ok(passphrase);
    }
    if !std::io::stdin().is_terminal() {
        return Err("no passphrase: set SLUICE_PASSWORD or run in a terminal".into());
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
