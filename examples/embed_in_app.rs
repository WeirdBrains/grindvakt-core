//! Embedding grindvakt-core in a larger application (for example a browser such as Morph).
//!
//! The host app owns everything machine-specific:
//! * its own profile directory (no `~/.grindvakt`),
//! * where the password comes from (its own UI or keystore),
//! * when sync runs (a background task on its own runtime),
//! * how results are shown (here: a channel the UI would read).
//!
//! This runs offline against a local DigitalOcean API mock, two quick cycles.
//! `cargo run --example embed_in_app`

use grindvakt_core::config::{AppConfig, Provider, Schedule};
use grindvakt_core::lock::SingleInstanceLock;
use grindvakt_core::provider;
use grindvakt_core::sync::{SyncMode, SyncOutcome, sync_once};
use grindvakt_core::vault::{KdfParams, Tokens, Vault};
use grindvakt_core::{ExposeSecret, SecretString};
use serde_json::json;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// What the host UI receives.
#[derive(Debug)]
enum DdnsEvent {
    Synced(SyncOutcome),
    Failed(String),
}

/// The host's own settings store, in its own profile directory.
struct Profile {
    dir: PathBuf,
}

impl Profile {
    fn config_path(&self) -> PathBuf {
        self.dir.join("ddns").join("config.toml")
    }
    fn vault_path(&self) -> PathBuf {
        self.dir.join("ddns").join("vault.json")
    }

    /// First-run setup from the host's settings page.
    fn set_up(
        &self,
        cfg: &AppConfig,
        password: &SecretString,
        token: SecretString,
    ) -> grindvakt_core::Result<String> {
        cfg.validate()?;
        let mut tokens = Tokens::default();
        tokens.set(cfg.provider, token);
        // KdfParams::testing() keeps the example fast; a real host keeps the default.
        let (vault, recovery) = Vault::create_with_kdf(password, &tokens, KdfParams::testing())?;
        cfg.save(&self.config_path())?;
        vault.save(&self.vault_path())?;
        Ok(recovery.expose_words().to_string()) // the host shows this once
    }
}

/// The address source the host prefers. Here a fixed value; a real host would call
/// `PublicIpConsensus::default().resolve()` or its own network stack.
async fn current_ip() -> grindvakt_core::Result<Ipv4Addr> {
    Ok("93.184.216.34".parse().unwrap())
}

/// The background task: one sync per cycle until the channel closes.
async fn ddns_task(
    profile_dir: PathBuf,
    password: SecretString,
    tx: tokio::sync::mpsc::Sender<DdnsEvent>,
    cycles: usize,
) {
    for _ in 0..cycles {
        let ev = match run_once(&profile_dir, &password).await {
            Ok(o) => DdnsEvent::Synced(o),
            Err(e) => DdnsEvent::Failed(e.to_string()), // never contains secrets
        };
        if tx.send(ev).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await; // real hosts: schedule::next_wait
    }
}

async fn run_once(dir: &Path, password: &SecretString) -> grindvakt_core::Result<SyncOutcome> {
    let profile = Profile {
        dir: dir.to_path_buf(),
    };
    let _guard = SingleInstanceLock::acquire_at(&dir.join("ddns").join("sync.lock"))?;
    let cfg = AppConfig::load(&profile.config_path())?;
    let vault = Vault::load(&profile.vault_path())?;
    let dek = vault.unlock_with_password(password)?;
    let token = vault.token(&dek, cfg.provider)?;
    let dns = provider::build(&cfg, &token)?;
    let ip = current_ip().await?;
    // Ambiguous records come back as Error::Ambiguous and nothing is changed.
    sync_once(&cfg, &dns, ip, SyncMode::Apply).await
}

#[tokio::main]
async fn main() -> grindvakt_core::Result<()> {
    // A DigitalOcean look-alike: no record at first, then the created one.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/v2/domains/example.org/records"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"domain_records": [], "links": {}})),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex("/v2/domains/example.org/records$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("/v2/domains/example.org/records"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "domain_records": [{"id": 1, "type": "A", "name": "@", "data": "93.184.216.34", "ttl": 300}],
            "links": {}
        })))
        .mount(&server)
        .await;

    let profile_dir =
        std::env::temp_dir().join(format!("morph-like-profile-{}", std::process::id()));
    let profile = Profile {
        dir: profile_dir.clone(),
    };
    let cfg = AppConfig {
        provider: Provider::Digitalocean,
        zone: "example.org".into(),
        name: "@".into(),
        api_base_url: Some(server.uri()),
        schedule: Schedule {
            calendar: None,
            interval_secs: Some(300),
        },
        ..AppConfig::default()
    };
    let password = SecretString::from("from the host's keystore".to_string());
    let words = profile.set_up(
        &cfg,
        &password,
        SecretString::from("do-mock-token".to_string()),
    )?;
    println!(
        "set up; recovery phrase has {} words",
        words.split(' ').count()
    );

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let task = tokio::spawn(ddns_task(
        profile_dir.clone(),
        SecretString::from(password.expose_secret().to_string()),
        tx,
        2,
    ));
    while let Some(ev) = rx.recv().await {
        match ev {
            DdnsEvent::Synced(o) => println!("ui: {o}"),
            DdnsEvent::Failed(e) => println!("ui: sync failed: {e}"),
        }
    }
    task.await.expect("task");
    let _ = std::fs::remove_dir_all(&profile_dir);
    Ok(())
}
