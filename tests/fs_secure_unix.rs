#![cfg(unix)]
use grindvakt_core::fs::ensure_private_dir;
use std::fs;
use tempfile::TempDir;

#[test]
fn ensure_dir_creates_secure_dir_unix() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("secure");
    ensure_private_dir(&p).unwrap();
    assert!(p.is_dir());
    let md = fs::metadata(&p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(md.permissions().mode() & 0o777, 0o700);
    }
}

use assert_fs::prelude::*;
use std::path::Path;

#[test]
fn ensure_dir_refuses_symlink() {
    let td = assert_fs::TempDir::new().unwrap();
    let real = td.child("real");
    real.create_dir_all().unwrap();
    let link = td.child("link");
    std::os::unix::fs::symlink(real.path(), link.path()).unwrap();
    let res = grindvakt_core::fs::ensure_private_dir(Path::new(link.path()));
    assert!(res.is_err());
}

#[test]
fn atomic_write_refuses_symlink_dest() {
    let td = assert_fs::TempDir::new().unwrap();
    let real = td.child("real-file");
    real.write_str("x").unwrap();
    let link = td.child("link-file");
    std::os::unix::fs::symlink(real.path(), link.path()).unwrap();
    let res = grindvakt_core::fs::atomic_write_private(Path::new(link.path()), b"data");
    assert!(res.is_err());
}

#[test]
fn atomic_write_refuses_parent_symlink() {
    let td = assert_fs::TempDir::new().unwrap();
    let real_dir = td.child("real");
    real_dir.create_dir_all().unwrap();
    let link_dir = td.child("linkdir");
    std::os::unix::fs::symlink(real_dir.path(), link_dir.path()).unwrap();
    let dest = link_dir.child("file.txt");
    let res = grindvakt_core::fs::atomic_write_private(Path::new(dest.path()), b"data");
    assert!(res.is_err());
}
