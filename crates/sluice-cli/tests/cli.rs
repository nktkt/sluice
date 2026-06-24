//! End-to-end integration tests driving the built `sluice` binary.

use assert_cmd::Command;
use predicates::prelude::*;

/// A `sluice` command pre-seeded with a passphrase.
fn sluice() -> Command {
    let mut cmd = Command::cargo_bin("sluice").unwrap();
    cmd.env("SLUICE_PASSWORD", "integration-pw")
        .env("SLUICE_KDF_MEMORY_KIB", "16")
        .env("SLUICE_KDF_PASSES", "1");
    cmd
}

#[test]
fn init_backup_snapshots_verify_restore_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    let out = dir.path().join("out");
    std::fs::create_dir_all(src.join("nested")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha content").unwrap();
    std::fs::write(src.join("nested/b.bin"), vec![3u8; 4096]).unwrap();

    sluice().arg("init").arg(&repo).assert().success();

    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snapshot = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(snapshot.len(), 64, "expected a 64-hex snapshot id");

    sluice()
        .arg("snapshots")
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains(&snapshot));

    sluice()
        .arg("verify")
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains("blobs verified"));

    // Restore by a unique hex prefix.
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snapshot[..12])
        .arg(&out)
        .assert()
        .success();

    assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"alpha content");
    assert_eq!(
        std::fs::read(out.join("nested/b.bin")).unwrap(),
        vec![3u8; 4096]
    );
}

#[test]
fn wrong_password_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    sluice().arg("init").arg(&repo).assert().success();

    let mut cmd = Command::cargo_bin("sluice").unwrap();
    cmd.env("SLUICE_PASSWORD", "the-wrong-password");
    cmd.arg("snapshots").arg(&repo).assert().failure();
}

#[test]
fn missing_password_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("sluice").unwrap();
    cmd.env_remove("SLUICE_PASSWORD");
    cmd.arg("init")
        .arg(dir.path().join("repo"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("SLUICE_PASSWORD"));
}
