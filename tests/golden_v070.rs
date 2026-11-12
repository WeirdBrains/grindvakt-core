//! Compatibility with files written by Grindvakt v0.7.0 (before this crate existed).
//!
//! `tests/fixtures/v0.7.0` was produced by the v0.7.0 code itself (test-only secrets).
//! Setting `GV_CORE_WRITE_DIR` makes `write_vault_for_v070_check` leave a core-written vault
//! there so the v0.7.0 code can be pointed at it (the reverse direction).

use grindvakt_core::config::{AppConfig, Provider};
use grindvakt_core::vault::{KdfParams, RecoveryPhrase, Tokens, Vault};
use grindvakt_core::{Error, ExposeSecret, SecretString};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v0.7.0")
}

fn read(name: &str) -> String {
    std::fs::read_to_string(fixtures().join(name)).unwrap()
}

fn password() -> SecretString {
    SecretString::from(read("password.txt"))
}

#[test]
fn opens_v070_vault_with_password_and_recovery() {
    let v = Vault::load(&fixtures().join("vault.json")).unwrap();
    assert_eq!(v.file().kdf, KdfParams::default());
    let dek = v.unlock_with_password(&password()).unwrap();
    assert_eq!(
        v.token(&dek, Provider::Dnsimple).unwrap().expose_secret(),
        "tok_golden_dnsimple"
    );
    assert_eq!(
        v.token(&dek, Provider::Digitalocean)
            .unwrap()
            .expose_secret(),
        "tok_golden_digitalocean"
    );

    let phrase = RecoveryPhrase::parse(&read("recovery.txt")).unwrap();
    let dek2 = v.unlock_with_recovery(&phrase).unwrap();
    assert_eq!(dek.as_bytes(), dek2.as_bytes());

    assert!(matches!(
        v.unlock_with_password(&SecretString::from("nope".to_string())),
        Err(Error::WrongSecret)
    ));
}

#[test]
fn rewrites_v070_vault_without_changing_untouched_fields() {
    let original = read("vault.json");
    let mut v = Vault::from_json(&original).unwrap();
    // Re-serialising an untouched vault is byte-identical.
    assert_eq!(v.to_json(), original);
    let dek = v.unlock_with_password(&password()).unwrap();
    let before = v.file().clone();
    v.set_token(
        &dek,
        Provider::Dnsimple,
        SecretString::from("tok_new".to_string()),
    )
    .unwrap();
    let after = v.file().clone();
    assert_eq!(before.salt_password, after.salt_password);
    assert_eq!(
        before.dek_wrapped_by_password,
        after.dek_wrapped_by_password
    );
    assert_eq!(
        before.dek_wrapped_by_recovery,
        after.dek_wrapped_by_recovery
    );
    assert_ne!(before.secrets_aead_nonce, after.secrets_aead_nonce);
    assert_eq!(
        v.token(&dek, Provider::Digitalocean)
            .unwrap()
            .expose_secret(),
        "tok_golden_digitalocean"
    );
}

#[test]
fn v070_config_files_round_trip_byte_identical() {
    for name in ["config.toml", "config-digitalocean.toml"] {
        let text = read(name);
        let cfg = AppConfig::from_toml_str(&text).unwrap();
        assert_eq!(cfg.to_toml_string().unwrap(), text, "{name}");
    }
    let cfg = AppConfig::load(&fixtures().join("config.toml")).unwrap();
    assert_eq!(cfg.record_fqdn(), "home.example.net");
    assert_eq!(cfg.account_id, Some(1234));
}

/// Writes a core-made vault (same password and phrase as the fixtures) for the v0.7.0
/// cross-check. Runs as a normal test; only writes when `GV_CORE_WRITE_DIR` is set.
#[test]
fn write_vault_for_v070_check() {
    let phrase = RecoveryPhrase::parse(&read("recovery.txt")).unwrap();
    let mut tokens = Tokens::default();
    tokens.set(
        Provider::Dnsimple,
        SecretString::from("tok_core_dnsimple".to_string()),
    );
    let v = Vault::create_with_phrase(&password(), &phrase, &tokens, KdfParams::default()).unwrap();
    // Self-check either way.
    let dek = v.unlock_with_password(&password()).unwrap();
    assert!(matches!(
        v.token(&dek, Provider::Digitalocean),
        Err(Error::TokenMissing(_))
    ));
    if let Ok(dir) = std::env::var("GV_CORE_WRITE_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        v.save(&dir.join("vault.json")).unwrap();
        AppConfig::load(&fixtures().join("config.toml"))
            .unwrap()
            .save(&dir.join("config.toml"))
            .unwrap();
        std::fs::write(dir.join("password.txt"), read("password.txt")).unwrap();
        std::fs::write(dir.join("recovery.txt"), read("recovery.txt")).unwrap();
        std::fs::write(dir.join("want_dnsimple.txt"), "tok_core_dnsimple").unwrap();
    }
}
