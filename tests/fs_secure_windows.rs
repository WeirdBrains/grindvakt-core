#![cfg(target_os = "windows")]
use grindvakt_core::Error;
use grindvakt_core::fs::{
    Privacy, atomic_write_private, ensure_private_dir, ensure_private_dir_with,
};
use tempfile::TempDir;

#[test]
fn service_policy_rejects_user_owned_dir() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("bad");
    // Ownership will be the current (unelevated) user; the service policy refuses it.
    std::fs::create_dir_all(&p).unwrap();
    let bad = ensure_private_dir_with(&p, Privacy::Service);
    assert!(matches!(bad, Err(Error::InsecurePath(_))), "{bad:?}");
}

#[test]
fn current_user_policy_works_unprivileged() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("profile").join("grindvakt");
    ensure_private_dir(&p).unwrap();
    // Idempotent on the directory it created.
    ensure_private_dir(&p).unwrap();
    atomic_write_private(&p.join("config.toml"), b"zone = \"example.net\"\n").unwrap();
    atomic_write_private(&p.join("config.toml"), b"zone = \"example.org\"\n").unwrap();
    assert_eq!(
        std::fs::read(p.join("config.toml")).unwrap(),
        b"zone = \"example.org\"\n"
    );
}

#[test]
fn current_user_policy_tightens_own_existing_dir() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("plain");
    std::fs::create_dir_all(&p).unwrap();
    ensure_private_dir(&p).unwrap();
}
