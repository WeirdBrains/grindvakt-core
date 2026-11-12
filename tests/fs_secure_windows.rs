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

#[test]
fn service_account_dir_names_only_system_admins_and_the_account() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("svc");
    // An elevated test run owns new directories as Administrators, which the policy accepts.
    std::fs::create_dir_all(&p).unwrap();
    let pol = Privacy::ServiceAccount("GrindvaktTest");
    match ensure_private_dir_with(&p, pol) {
        Ok(()) => {}
        // Unelevated: the directory belongs to the user, which a service policy never trusts.
        Err(Error::InsecurePath(_)) => return,
        Err(e) => panic!("{e:?}"),
    }
    grindvakt_core::fs::atomic_write_private_with(&p.join("vault.json"), b"{}", pol).unwrap();
    let sid = grindvakt_core::fs::service_sid("GrindvaktTest");
    let out = std::process::Command::new("icacls")
        .arg(&p)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("LOCAL SERVICE"), "{text}");
    assert!(
        text.contains(&sid) || text.contains("GrindvaktTest"),
        "{text}"
    );
}

#[test]
fn repair_moves_a_local_service_tree_to_the_service_account() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("old");
    std::fs::create_dir_all(&p).unwrap();
    match ensure_private_dir_with(&p, Privacy::Service) {
        Ok(()) => {}
        Err(Error::InsecurePath(_)) => return, // unelevated run
        Err(e) => panic!("{e:?}"),
    }
    grindvakt_core::fs::atomic_write_private_with(&p.join("config.toml"), b"x", Privacy::Service)
        .unwrap();
    grindvakt_core::fs::atomic_write_private_with(
        &p.join("credentials").join("blob"),
        b"y",
        Privacy::Service,
    )
    .unwrap();
    let pol = Privacy::ServiceAccount("GrindvaktTest");
    let n = grindvakt_core::fs::repair_private_tree(&p, pol).unwrap();
    assert_eq!(n, 4);
    for f in [
        p.clone(),
        p.join("config.toml"),
        p.join("credentials"),
        p.join("credentials").join("blob"),
    ] {
        let out = std::process::Command::new("icacls")
            .arg(&f)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("LOCAL SERVICE"), "{}: {text}", f.display());
    }
    // Idempotent, and the policy now verifies.
    ensure_private_dir_with(&p, pol).unwrap();
    assert_eq!(grindvakt_core::fs::repair_private_tree(&p, pol).unwrap(), 4);
}
