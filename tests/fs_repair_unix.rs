#![cfg(unix)]
use grindvakt_core::fs::{Privacy, repair_private_tree, service_sid};
use std::os::unix::fs::PermissionsExt;

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn repair_tightens_every_entry_and_skips_a_missing_dir() {
    let t = tempfile::TempDir::new().unwrap();
    let d = t.path().join("data");
    assert_eq!(
        repair_private_tree(&d, Privacy::ServiceAccount("Grindvakt")).unwrap(),
        0
    );
    std::fs::create_dir_all(d.join("credentials")).unwrap();
    std::fs::write(d.join("config.toml"), "x").unwrap();
    std::fs::write(d.join("credentials/blob"), "y").unwrap();
    for p in [&d, &d.join("credentials")] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::set_permissions(
        d.join("config.toml"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let n = repair_private_tree(&d, Privacy::ServiceAccount("Grindvakt")).unwrap();
    assert_eq!(n, 4);
    assert_eq!(mode(&d), 0o700);
    assert_eq!(mode(&d.join("credentials")), 0o700);
    assert_eq!(mode(&d.join("config.toml")), 0o600);
    assert_eq!(mode(&d.join("credentials/blob")), 0o600);
}

#[test]
fn repair_refuses_symlinks_inside_the_tree() {
    let t = tempfile::TempDir::new().unwrap();
    let d = t.path().join("data");
    std::fs::create_dir_all(&d).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", d.join("link")).unwrap();
    let e = repair_private_tree(&d, Privacy::CurrentUser).unwrap_err();
    assert!(matches!(e, grindvakt_core::Error::InsecurePath(_)), "{e:?}");
}

#[test]
fn service_sid_is_public_and_stable() {
    assert!(service_sid("Grindvakt").starts_with("S-1-5-80-"));
    assert_eq!(service_sid("Grindvakt"), service_sid("GRINDVAKT"));
}
