# grindvakt-core

[![crates.io](https://img.shields.io/crates/v/grindvakt-core.svg)](https://crates.io/crates/grindvakt-core)
[![docs.rs](https://docs.rs/grindvakt-core/badge.svg)](https://docs.rs/grindvakt-core)
[![CI](https://github.com/WeirdBrains/grindvakt-core/actions/workflows/ci.yml/badge.svg)](https://github.com/WeirdBrains/grindvakt-core/actions/workflows/ci.yml)

**The engine of [Grindvakt](https://grindvakt.weirdbrains.com/) — a dynamic DNS updater —
as a library.** It keeps one A record on **DNSimple** or **DigitalOcean** pointed at your
public IPv4 address, and stores the API tokens it needs in an encrypted vault. Use it to
add "keep my home name pointed at me" to your own program, such as a browser, a home
server dashboard, or a CLI of your own, without running the Grindvakt service.

```toml
[dependencies]
grindvakt-core = "1.0.0"
```

## What it does

1. **Finds your public IPv4.** `ip::PublicIpConsensus` asks four independent HTTPS echo
   services at once and accepts an address only when at least two, and a strict majority of
   those that answered, agree, and the address is globally routable (no private, CGNAT,
   loopback, documentation or reserved ranges).
2. **Plans the change.** A `provider::DnsProvider` lists the A records for the name and returns
   a `DnsAction`: `Noop`, `Create`, `Update`, or `Ambiguous` when more than one record matches.
   Sync never guesses between duplicates.
3. **Applies it.** `sync::sync_once` creates or updates the record, or in `SyncMode::DryRun`
   reports exactly what it would do. DNSimple creates re-check before posting so retries
   never duplicate a record.

Around that loop it gives you the pieces Grindvakt uses to run unattended and safely:

| module | what it gives you |
|---|---|
| `vault` | Encrypted token store (`vault.json` v1): a password **and** a 24-word recovery phrase each unlock it; change or reset the password; read and set per-provider tokens |
| `config` | The `config.toml` model (`AppConfig`, `Provider`, `Schedule`), validation, FQDN helpers, atomic save |
| `schedule` | Checks for systemd/launchd schedules, plus portable "how long until the next run" for `hourly`, `daily`, `*:0/10` and intervals |
| `fs` | Owner-only directories and atomic, fsynced, symlink-refusing file writes (Unix `0700/0600`; Windows protected DACL) |
| `lock` | A single-instance file lock so two syncs never race |
| `paths` | (feature `default-paths`) Grindvakt's own `~/.grindvakt` / `%PROGRAMDATA%\Grindvakt` layout |

## What it does not do

Everything that ties Grindvakt to one machine stays in the
[Grindvakt app](https://grindvakt.weirdbrains.com/), which is built on this crate:

* the command line, TTY prompts and logging setup;
* systemd user units and timers, the macOS launchd agent, the Windows service;
* unattended unlock through OS credential stores (systemd-creds with TPM2, macOS Keychain,
  Windows DPAPI). The library accepts the resulting key through `vault::Dek::from_bytes`;
* installers and packages.

The library never prompts, never spawns processes, never installs anything, and never puts
a secret in an error message or `Debug` output. **Your program decides** where files live,
where the password comes from, and when sync runs.

## Quick start

```rust,no_run
use grindvakt_core::config::AppConfig;
use grindvakt_core::ip::PublicIpConsensus;
use grindvakt_core::sync::{sync_once, SyncMode};
use grindvakt_core::vault::Vault;
use grindvakt_core::{provider, SecretString};
use std::path::Path;

#[tokio::main]
async fn main() -> grindvakt_core::Result<()> {
    let cfg = AppConfig::load(Path::new("/path/to/config.toml"))?;
    let vault = Vault::load(Path::new("/path/to/vault.json"))?;

    let password = SecretString::from(String::from("ask your user"));
    let dek = vault.unlock_with_password(&password)?;
    let token = vault.token(&dek, cfg.provider)?;

    let dns = provider::build(&cfg, &token)?;
    let ip = PublicIpConsensus::default().resolve().await?;
    let outcome = sync_once(&cfg, &dns, ip, SyncMode::DryRun).await?;
    println!("{outcome}"); // e.g. "DRY RUN: would update A home.example.net: 198.51.100.20 -> 93.184.216.34 (ttl=300) [record_id=7]"
    Ok(())
}
```

### Config

```toml
provider = "dnsimple"      # or "digitalocean"
account_id = 1234          # DNSimple only; optional (whoami is used otherwise)
zone = "example.net"
name = "home"              # "@" for the apex, a label, or a full name
ttl = 300                  # >= 60

[schedule]
interval_secs = 300        # or: calendar = "hourly"
```

`AppConfig::from_toml_str`, `load`, `validate`, `to_toml_string` and `save` read and write
exactly what the Grindvakt app does, so both can share one file.

### Vault

```rust
use grindvakt_core::config::Provider;
use grindvakt_core::vault::{KdfParams, RecoveryPhrase, Tokens, Vault};
use grindvakt_core::{ExposeSecret, SecretString};

# fn main() -> grindvakt_core::Result<()> {
let password = SecretString::from("correct horse battery staple".to_string());
let mut tokens = Tokens::default();
tokens.set(Provider::Digitalocean, SecretString::from("do-token".to_string()));

// Use Vault::create (default Argon2id cost) in real code; testing() just keeps this fast.
let (mut vault, words) = Vault::create_with_kdf(&password, &tokens, KdfParams::testing())?;
// Show `words.expose_words()` to the user once. It is never stored.

let dek = vault.unlock_with_password(&password)?;
assert_eq!(vault.token(&dek, Provider::Digitalocean)?.expose_secret(), "do-token");

// Forgot the password? The 24 words reset it.
let typed = RecoveryPhrase::parse(words.expose_words())?;
vault.reset_password_with_recovery(&typed, &SecretString::from("new password".to_string()))?;
# Ok(()) }
```

Format: a random 256-bit data key encrypts the token JSON with XChaCha20-Poly1305. That key is
wrapped twice, under Argon2id(password) (64 MiB, 3 passes, 1 lane by default; bounds are
enforced when loading so a hostile file can't demand unbounded work) and under
HKDF-SHA256(recovery-phrase entropy). Every AEAD call binds `grindvakt-vault-v1`. All
primitives come from [`weirdnet-keys`](https://crates.io/crates/weirdnet-keys). The file is
byte-compatible with every Grindvakt 0.x release in both directions, and the test suite proves
it against fixtures written by Grindvakt v0.7.0.

### Your own provider

`DnsProvider` is three async methods (`plan`, `create_a`, `update_a`), and their futures
are `Send`. Implement it to drive another DNS host or a fake for tests; `sync_once` works
with any implementation.

### Scheduling

```rust
use grindvakt_core::config::Schedule;
use grindvakt_core::schedule::next_wait;
use std::time::SystemTime;

let s = Schedule { calendar: Some("*:0/10".into()), interval_secs: None };
let wait = next_wait(SystemTime::now(), &s).unwrap(); // until the next 10-minute mark
assert!(wait.as_secs() <= 600);
```

## Examples

All of these run offline; the provider examples start a local mock API.

| example | shows |
|---|---|
| `config_load` | load, validate, edit and atomically save `config.toml` |
| `vault_roundtrip` | create a vault, unlock by password and by recovery words, reset the password, add a token |
| `ip_consensus` | the agreement rules on canned answers (`-- --live` queries the real sources) |
| `dns_sync_dry_run` | plan, dry-run, then apply a DNSimple update against a mock |
| `schedule_next` | validation and next-run timing for each schedule shape |
| `embed_in_app` | a host app (for example a browser) with its own profile dir, settings flow, background sync task and UI events |

```sh
cargo run --example embed_in_app
```

## Features

| feature | default | adds |
|---|---|---|
| `dnsimple` | yes | `provider::DnsimpleProvider` (official `dnsimple` crate) |
| `digitalocean` | yes | `provider::DigitalOceanProvider` (reqwest + rustls) |
| `public-ip` | yes | `ip::PublicIpConsensus::resolve` (reqwest + rustls) |
| `default-paths` | no | `paths`, `lock::SingleInstanceLock::acquire(name)` |

`default-features = false` gives a crate with **no network code**: config, vault, schedule,
fs, lock, the IP agreement rules and the `DnsProvider` trait. The network features need a
Tokio runtime, because reqwest does.

## Security notes

* Secrets are `secrecy::SecretString` (re-exported) and are wiped on drop; `Dek`,
  `RecoveryPhrase` and `Tokens` print as `<redacted>`.
* Wrong passwords, wrong recovery words and tampering all give the same
  `Error::WrongSecret`.
* Files are written to a temp file, fsynced, renamed, and the directory fsynced; symlinks and
  reparse points are refused; on Unix the data directory must be owned by the current user.
* The Windows `fs` rules match the Grindvakt service (SYSTEM, Administrators, LocalService
  only) and reject directories owned by an ordinary user. An unprivileged Windows app should
  keep its own directory and use the in-memory `Vault` APIs (`from_json`/`to_json`) with its
  own storage.
* This crate has not had an independent security audit.

## Platforms and MSRV

Linux, macOS and Windows. Rust **1.99** or newer, edition 2024.

## Versioning

`grindvakt-core` is versioned **in lockstep with the Grindvakt app**: crate X.Y.Z is
exactly the library inside Grindvakt vX.Y.Z. Every Grindvakt release publishes
`grindvakt-core` X.Y.Z to crates.io first, and the app's release script refuses to tag
vX.Y.Z until that version is live on crates.io and the app depends on `=X.Y.Z`. Semver
applies to this crate's public API. Because of the lockstep, a minor or patch version may
contain no library changes at all. The vault and config formats are stable; changing them
would take a major version and a migration path.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
