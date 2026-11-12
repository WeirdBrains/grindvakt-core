# grindvakt-core

[![crates.io](https://img.shields.io/crates/v/grindvakt-core.svg)](https://crates.io/crates/grindvakt-core)
[![docs.rs](https://docs.rs/grindvakt-core/badge.svg)](https://docs.rs/grindvakt-core)
[![CI](https://github.com/WeirdBrains/grindvakt-core/actions/workflows/ci.yml/badge.svg)](https://github.com/WeirdBrains/grindvakt-core/actions/workflows/ci.yml)

**The engine of [Grindvakt](https://grindvakt.weirdbrains.com/), the dynamic DNS updater,
as a library.** It keeps **A, AAAA and TXT** records on **DNSimple** or **DigitalOcean**
pointed at where your machine is, including the libp2p `_dnsaddr` TXT record a
peer-to-peer node publishes. Use it to add "keep my name pointed at me" to your own
program (a browser, a home server dashboard, a node) without running the Grindvakt service.

```toml
[dependencies]
grindvakt-core = "1.0.0"
```

## What it does

1. **Finds your public addresses, IPv4 and IPv6 separately.** `ip::discover` asks several
   independent HTTPS echo services per family (each request forced onto that family) and
   accepts an address only when at least two, and a strict majority of those that answered,
   agree. When there is nothing worth publishing (CGNAT, private-only, no IPv6) it returns
   `Error::NoGlobalAddress`, so a peer-to-peer app knows to use relays. Addresses you already
   know (for example from libp2p AutoNAT) need no lookup; `ip::require_global` checks them.
2. **Plans.** `plan(&provider, zone, &records)` reads the zone and returns a `Plan`: for each
   wanted record `Noop`, `Create`, `Update`, or `Ambiguous` when it will not guess (two A
   records where one is wanted). The plan is the dry run; print it.
3. **Applies.** `apply(&provider, &plan)` writes it, and refuses the whole plan if anything
   is ambiguous. Running it again changes nothing.

TXT records are matched by their key (the text up to `=`, such as `dnsaddr=`), so your
`_dnsaddr` records never touch an SPF or site-verification record at the same name.
Nothing is ever deleted.

## What the caller owns

* **Secrets:** tokens come in as `SecretString`. Keep them in your own keyring, or use the
  optional `vault`.
* **Paths:** every file path is an argument. Nothing defaults to `~/.grindvakt` unless you
  turn on `standalone`.
* **Timing:** there is no scheduler. Call `plan`/`apply` when your app wants to (on start,
  on a network change, every few minutes while open).
* **UI:** errors are typed so you can explain them: `Error::Auth`, `Error::RateLimited`
  (with `retry_after`), `Error::Ambiguous`, `Error::NoGlobalAddress`, `Error::Network`,
  `Error::Provider`, `Error::InvalidRecord`. Messages never contain tokens or request URLs.

No CLI, no prompts, no global state, no spawned processes.

## Quick start

```rust,no_run
use grindvakt_core::{apply, ip, plan, provider, record::Record, Error, SecretString};

#[tokio::main]
async fn main() -> grindvakt_core::Result<()> {
    let token = SecretString::from(String::from("from your keyring"));
    let dns = provider::digitalocean(&token)?; // or provider::dnsimple(&token, None)?

    let addrs = match ip::discover(ip::Family::Both, &ip::Sources::default()).await {
        Ok(a) => a,
        Err(Error::NoGlobalAddress(why)) => {
            println!("nothing to publish ({why}); using relays");
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    let peer = "12D3KooW...";
    let mut want = Vec::new();
    if let Some(v4) = addrs.v4 {
        want.push(Record::a("home", v4));
        want.push(Record::txt("_dnsaddr.home", format!("dnsaddr=/dns4/home.example.com/tcp/4747/p2p/{peer}")));
    }
    if let Some(v6) = addrs.v6 {
        want.push(Record::aaaa("home", v6));
        want.push(Record::txt("_dnsaddr.home", format!("dnsaddr=/dns6/home.example.com/tcp/4747/p2p/{peer}")));
    }

    let p = plan(&dns, "example.com", &want).await?;
    println!("{p}"); // e.g. "create AAAA home.example.com = 2606:4700::7 (ttl=300)"
    apply(&dns, &p).await?;
    Ok(())
}
```

### Your own provider

`provider::DnsProvider` has a name and three async methods (`list`, `create`, `update`), with
`Send` futures. Implement it to drive another DNS host or a fake for tests; `plan` and
`apply` work with any implementation:

```rust
use grindvakt_core::provider::DnsProvider;
use grindvakt_core::record::{ExistingRecord, RecordKind, RecordValue};

struct MyHost;
impl DnsProvider for MyHost {
    fn name(&self) -> &str { "myhost" }
    async fn list(&self, zone: &str, name: &str, kind: RecordKind) -> grindvakt_core::Result<Vec<ExistingRecord>> {
        Ok(vec![]) // call your API; names are zone-relative, "" for the apex
    }
    async fn create(&self, zone: &str, name: &str, value: &RecordValue, ttl: u32) -> grindvakt_core::Result<()> {
        Ok(())
    }
    async fn update(&self, zone: &str, id: u64, value: &RecordValue, ttl: u32) -> grindvakt_core::Result<()> {
        Ok(())
    }
}
```

### Vault (feature `vault`)

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

A random 256-bit data key encrypts the token JSON with XChaCha20-Poly1305. That key is wrapped
twice, under Argon2id(password) (64 MiB, 3 passes, 1 lane by default; bounds are enforced when
loading so a hostile file can't demand unbounded work) and under HKDF-SHA256(recovery-phrase
entropy). Every AEAD call binds `grindvakt-vault-v1`. All primitives come from
[`weirdnet-keys`](https://crates.io/crates/weirdnet-keys). The file is byte-compatible with
every Grindvakt 0.x release in both directions; the tests prove it against fixtures written by
Grindvakt v0.7.0.

### Next to a standalone Grindvakt (feature `standalone`)

An app that manages `home.example.com` must not fight a standalone Grindvakt that manages the
same name. `standalone::find_conflicts(&["home.example.com"])` reads the standalone app's
config from its default location and reports installs that would conflict. The same feature
holds the standalone app's own `config.toml` model (`config::AppConfig`), default paths, and
its single-A-record `sync::sync_once`.

## Examples

All of these run offline; the provider examples start a local mock API.

| example | shows |
|---|---|
| `embed_in_app` | a browser-like host: token from its keyring, addresses from its network stack, a dry-run preview, apply, typed errors for the UI, falling back to relays on CGNAT |
| `dns_plan_dry_run` | A, AAAA and `_dnsaddr` TXT planned against a DNSimple mock, leaving an SPF record alone |
| `ip_discovery` | IPv4/IPv6 discovery, majority voting, `NoGlobalAddress` (`-- --live` asks the real sources) |
| `vault_roundtrip` | create a vault, unlock by password and by recovery words, reset the password, add a token |
| `config_load` | load, validate, edit and atomically save the standalone `config.toml` |

```sh
cargo run --example embed_in_app
```

## Features

| feature | default | adds |
|---|---|---|
| `dnsimple` | yes | `provider::DnsimpleProvider` (official `dnsimple` crate, rustls) |
| `digitalocean` | yes | `provider::DigitalOceanProvider` (reqwest, rustls) |
| `public-ip` | yes | `ip::discover` (reqwest, rustls) |
| `vault` | no | `vault`: encrypted token file with password and recovery phrase |
| `standalone` | no | `config::AppConfig`, `paths`, `sync`, `standalone::find_conflicts`, `lock::SingleInstanceLock::acquire` |

`default-features = false` has **no network code**: records, the planner, the provider trait,
the address rules, private file writes and the lock. The network features need a Tokio
runtime.

## Mobile

Every feature builds for Android and iOS (CI checks `aarch64-linux-android` and
`aarch64-apple-ios`). TLS is rustls only, no OpenSSL. On Android, initialize
`rustls-platform-verifier` from your app before the first HTTPS call, as that crate
documents. Phones usually sit behind carrier NAT, so expect `NoGlobalAddress` there and use
relays.

## Security notes

* Secrets are `secrecy::SecretString` (re-exported) and are wiped on drop; vault keys,
  recovery phrases and token sets print as `<redacted>`.
* Wrong passwords, wrong recovery words and tampering all give the same `Error::WrongSecret`.
* Files are written to a temp file, fsynced, renamed, and the directory fsynced; symlinks and
  reparse points are refused.
* Private means `fs::Privacy::CurrentUser` by default (Unix `0700/0600`; Windows a protected
  DACL for you and SYSTEM), so an ordinary app can keep files in its own profile directory.
  `Privacy::Service` applies the Grindvakt service rules (SYSTEM, Administrators and
  LocalService only) and refuses directories an ordinary user owns.
* This crate has not had an independent security audit.

## Platforms and MSRV

Linux, macOS, Windows, Android and iOS. Rust **1.99** or newer, edition 2024.

## Versioning

`grindvakt-core` is versioned **in lockstep with the Grindvakt app**: crate X.Y.Z is exactly
the library inside Grindvakt vX.Y.Z. Every Grindvakt release publishes `grindvakt-core` X.Y.Z
to crates.io first, and the app's release script refuses to tag vX.Y.Z until that version is
live on crates.io and the app depends on `=X.Y.Z`. Semver applies to this crate's public API;
because of the lockstep, a minor or patch version may contain no library changes. The vault
and config formats are stable; changing them would take a major version and a migration path.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
