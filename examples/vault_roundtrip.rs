//! Create a vault, unlock it with the password and with the 24 recovery words, change the
//! password, add a token and save it.
//!
//! `cargo run --example vault_roundtrip`

use grindvakt_core::config::Provider;
use grindvakt_core::vault::{RecoveryPhrase, Tokens, Vault};
use grindvakt_core::{Error, ExposeSecret, SecretString};

fn secret(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn main() -> grindvakt_core::Result<()> {
    let password = secret("example password, use your own UI");
    let mut tokens = Tokens::default();
    tokens.set(Provider::Dnsimple, secret("dnsimple-example-token"));

    // Default KDF: Argon2id 64 MiB, 3 passes (about a second).
    let (mut vault, recovery) = Vault::create(&password, &tokens)?;
    println!(
        "recovery words (show once, never store): {} words",
        recovery.expose_words().split(' ').count()
    );

    let dek = vault.unlock_with_password(&password)?;
    println!("token status: {:?}", vault.token_status(&dek)?);

    // The words alone also unlock it, in any case or spacing.
    let typed = recovery.expose_words().to_uppercase();
    let again = RecoveryPhrase::parse(&typed)?;
    assert_eq!(
        vault.unlock_with_recovery(&again)?.as_bytes(),
        dek.as_bytes()
    );

    // Forgotten password: reset with the words.
    let new_password = secret("a new password");
    vault.reset_password_with_recovery(&again, &new_password)?;
    assert!(matches!(
        vault.unlock_with_password(&password),
        Err(Error::WrongSecret)
    ));

    let dek = vault.unlock_with_password(&new_password)?;
    vault.set_token(&dek, Provider::Digitalocean, secret("do-example-token"))?;
    assert_eq!(
        vault.token(&dek, Provider::Digitalocean)?.expose_secret(),
        "do-example-token"
    );

    let dir = std::env::temp_dir().join(format!("grindvakt-core-vault-{}", std::process::id()));
    let path = dir.join("vault.json");
    vault.save(&path)?;
    let reloaded = Vault::load(&path)?;
    assert_eq!(reloaded, vault);
    println!(
        "saved and reloaded {} ({} bytes)",
        path.display(),
        std::fs::metadata(&path).unwrap().len()
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
