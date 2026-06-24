//! `sluice` — command-line interface for the encrypted, deduplicating backup
//! and disaster-recovery tool (see `DESIGN.md` §7).
//!
//! The passphrase is read from the `SLUICE_PASSWORD` environment variable; an
//! interactive prompt and the wider command surface are follow-up work.

use std::error::Error;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sluice_core::Id;
use sluice_crypto::KdfParams;
use sluice_engine::{backup, restore};
use sluice_repo::Repository;
use sluice_store::{LocalBackend, StorageBackend};

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
        /// Path of the repository to create.
        repo: PathBuf,
    },
    /// Back up a directory into the repository.
    Backup {
        /// Path of the repository.
        repo: PathBuf,
        /// Directory to back up.
        source: PathBuf,
    },
    /// Restore a snapshot into a target directory.
    Restore {
        /// Path of the repository.
        repo: PathBuf,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
        /// Directory to restore into.
        target: PathBuf,
    },
    /// List the snapshots in a repository.
    Snapshots {
        /// Path of the repository.
        repo: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let passphrase = std::env::var("SLUICE_PASSWORD")
        .map_err(|_| "set the SLUICE_PASSWORD environment variable")?;
    let pw = passphrase.as_bytes();

    match cli.command {
        Command::Init { repo } => {
            let backend = LocalBackend::create(&repo).await?;
            let repository = Repository::init(backend, pw, KdfParams::DEFAULT).await?;
            println!(
                "initialized repository {} at {}",
                repository.id(),
                repo.display()
            );
        }
        Command::Backup { repo, source } => {
            let mut repository = Repository::open(LocalBackend::open(&repo), pw).await?;
            let snapshot = backup(&mut repository, &source).await?;
            println!("{snapshot}");
        }
        Command::Restore {
            repo,
            snapshot,
            target,
        } => {
            let repository = Repository::open(LocalBackend::open(&repo), pw).await?;
            let id = resolve_snapshot(&repository, &snapshot).await?;
            restore(&repository, &id, &target).await?;
            println!("restored {id} into {}", target.display());
        }
        Command::Snapshots { repo } => {
            let repository = Repository::open(LocalBackend::open(&repo), pw).await?;
            for id in repository.list_snapshots().await? {
                println!("{id}");
            }
        }
    }
    Ok(())
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
