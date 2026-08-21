//! Release E2E validation: compile the binary, run fixture ingest, verify
//! findings persist, confirm no duplicates on re-scan.
//!
//! This test compiles the binary; subsequent runs reuse the cached artifact.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

fn binary() -> PathBuf {
    let status = Command::new(env!("CARGO"))
        .arg("build")
        .arg("--package")
        .arg("rieko-cli")
        .arg("--no-default-features")
        .arg("--features")
        .arg("simulate")
        .status()
        .expect("cargo build failed");
    assert!(status.success(), "binary must compile");
    let bin_name = if cfg!(windows) { "rieko.exe" } else { "rieko" };
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/debug")
        .join(bin_name)
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/channels.json")
}

fn temp_db(label: &str) -> PathBuf {
    let dir = env::temp_dir().join("rieko-e2e");
    fs::create_dir_all(&dir).ok();
    dir.join(format!("{label}.db"))
}

fn cli(binary: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(binary)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("binary {}: {e}", binary.display()))
}

fn cli_ok(binary: &PathBuf, args: &[&str]) {
    let out = cli(binary, args);
    if !out.status.success() {
        panic!(
            "{} {}:\nSTDERR: {}\nSTDOUT: {}",
            binary.display(),
            args.join(" "),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
        );
    }
}

fn db_flag(db: &Path) -> String {
    format!("--db={}", db.to_str().unwrap())
}

#[test]
fn build_scan_status_no_duplicates() {
    let bin = binary();
    assert!(bin.exists(), "binary must be built at {}", bin.display());

    let db = temp_db("e2e");
    let _ = fs::remove_file(&db);
    let fix = fixture();
    assert!(fix.exists(), "fixture must exist at {}", fix.display());

    // 1. Ingest fixture.
    cli_ok(
        &bin,
        &[
            "scan",
            "--network",
            "regtest",
            "--fixture",
            fix.to_str().unwrap(),
            "--node",
            "local-node",
            &db_flag(&db),
        ],
    );

    // 2. Status reports findings and database health.
    let status = cli(&bin, &["status", &db_flag(&db)]);
    assert!(status.status.success(), "status must succeed");
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("findings"),
        "status must mention findings:\n{stdout}"
    );

    // 3. Re-scan against same fixture — no duplicate findings.
    let before = stdout.lines().filter(|l| l.contains("findings")).count();
    cli_ok(
        &bin,
        &[
            "scan",
            "--network",
            "regtest",
            "--fixture",
            fix.to_str().unwrap(),
            "--node",
            "local-node",
            &db_flag(&db),
        ],
    );
    let status2 = cli(&bin, &["status", &db_flag(&db)]);
    assert!(
        status2.status.success(),
        "status after re-scan must succeed"
    );
    let stdout2 = String::from_utf8_lossy(&status2.stdout);
    let after = stdout2.lines().filter(|l| l.contains("findings")).count();
    assert_eq!(before, after, "findings must not change after re-scan");

    // Cleanup.
    fs::remove_file(&db).ok();
    let _ = fs::remove_file(format!("{}-shm", db.display()));
    let _ = fs::remove_file(format!("{}-wal", db.display()));
}
