#![cfg(target_os = "windows")]
use tempfile::TempDir;

#[test]
fn insecure_acl_rejected() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("bad");
    // This test intentionally avoids trying to create a directory with invalid SDDL using raw pointers.
    // Instead, verify that ensure_dir_0700 rejects a user-owned precreated directory.
    std::fs::create_dir_all(&p).unwrap();
    // Ownership will be the current user; ensure_dir_0700 should reject non-admin/system owner.
    let bad = grindvakt_core::fs::ensure_private_dir(&p);
    assert!(bad.is_err());
}
