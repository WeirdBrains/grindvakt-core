//! # grindvakt-core
//!
//! The engine of [Grindvakt](https://grindvakt.weirdbrains.com/), the user-mode dynamic DNS
//! updater, as a library you can embed. It keeps one A record on **DNSimple** or
//! **DigitalOcean** pointed at your public IPv4 address:
//!
//! 1. [`ip::PublicIpConsensus`] asks several HTTPS echo services for your address and only
//!    accepts one that a strict majority agree on and that is globally routable.
//! 2. A [`provider::DnsProvider`] looks up the record and plans a
//!    [`provider::DnsAction`]: nothing, create, update, or refuse because it is ambiguous.
//! 3. [`sync::sync_once`] applies the plan, or reports it in dry-run mode.
//!
//! Around that core it gives you the pieces Grindvakt uses to run unattended and safely:
//! an encrypted token [`vault`] (Argon2id password and 24-word recovery phrase wrapping a
//! random key; XChaCha20-Poly1305; primitives from [`weirdnet_keys`]), the TOML
//! [`config`], [`schedule`] checks and timing, owner-only atomic file writes in [`fs`], and
//! a single-instance [`lock`].
//!
//! ## What is not here
//!
//! Everything that ties Grindvakt to a particular machine stays in the Grindvakt app:
//! the command line and prompts, systemd user units and timers, the macOS launchd agent,
//! the Windows service, the unattended credential stores (systemd-creds with TPM2, the
//! macOS Keychain, Windows DPAPI), installers and logging setup. The library never prompts,
//! never spawns processes, never installs anything and never logs secrets. Your
//! application decides where files live, where secrets come from and when sync runs.
//!
//! ## Example
//!
//! A complete dry-run pass against an in-memory provider (no network):
//!
//! ```
//! use grindvakt_core::config::AppConfig;
//! use grindvakt_core::provider::{DnsAction, DnsProvider};
//! use grindvakt_core::sync::{sync_once, SyncMode};
//! use std::net::Ipv4Addr;
//!
//! /// A provider whose record currently points at 203.0.113.7 … er, a stale address.
//! struct Stale;
//! impl DnsProvider for Stale {
//!     async fn plan(&self, cfg: &AppConfig, ip: Ipv4Addr) -> grindvakt_core::Result<DnsAction> {
//!         let prev: Ipv4Addr = "198.51.100.20".parse().unwrap();
//!         Ok(if prev == ip { DnsAction::Noop(ip) } else {
//!             DnsAction::Update { record_id: 42, ttl: cfg.ttl, prev }
//!         })
//!     }
//!     async fn create_a(&self, _: &AppConfig, _: &str, _: Ipv4Addr, _: u32) -> grindvakt_core::Result<()> { Ok(()) }
//!     async fn update_a(&self, _: &AppConfig, _: u64, _: Ipv4Addr, _: u32) -> grindvakt_core::Result<()> { Ok(()) }
//! }
//!
//! let cfg = AppConfig::from_toml_str(r#"
//!     provider = "dnsimple"
//!     zone = "example.net"
//!     name = "home"
//!     ttl = 300
//!     [schedule]
//!     interval_secs = 300
//! "#)?;
//!
//! let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();
//! let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
//! let outcome = rt.block_on(sync_once(&cfg, &Stale, ip, SyncMode::DryRun))?;
//! assert_eq!(
//!     outcome.to_string(),
//!     "DRY RUN: would update A home.example.net: 198.51.100.20 -> 93.184.216.34 (ttl=300) [record_id=42]"
//! );
//! # Ok::<(), grindvakt_core::Error>(())
//! ```
//!
//! With the default features the real thing is:
//!
//! ```no_run
//! # fn main() {}
//! # #[cfg(all(feature = "public-ip", any(feature = "dnsimple", feature = "digitalocean")))]
//! # async fn run() -> grindvakt_core::Result<()> {
//! use grindvakt_core::{config::AppConfig, ip::PublicIpConsensus, provider, sync, vault::Vault};
//! use grindvakt_core::SecretString;
//! use std::path::Path;
//!
//! let cfg = AppConfig::load(Path::new("/path/to/config.toml"))?;
//! let vault = Vault::load(Path::new("/path/to/vault.json"))?;
//! let password = SecretString::from(String::from("from your own UI"));
//! let dek = vault.unlock_with_password(&password)?;
//! let token = vault.token(&dek, cfg.provider)?;
//!
//! let dns = provider::build(&cfg, &token)?;
//! let ip = PublicIpConsensus::default().resolve().await?;
//! let outcome = sync::sync_once(&cfg, &dns, ip, sync::SyncMode::Apply).await?;
//! println!("{outcome}");
//! # Ok(()) }
//! ```
//!
//! ## Features
//!
//! | feature | default | adds |
//! |---|---|---|
//! | `dnsimple` | yes | [`provider::DnsimpleProvider`] (official `dnsimple` crate) |
//! | `digitalocean` | yes | [`provider::DigitalOceanProvider`] (reqwest + rustls) |
//! | `public-ip` | yes | [`ip::PublicIpConsensus::resolve`] (reqwest + rustls) |
//! | `default-paths` | no | [`paths`]: Grindvakt's own `~/.grindvakt` / `%PROGRAMDATA%\Grindvakt` layout |
//!
//! With `default-features = false` the crate makes no network calls at all; plug in your
//! own [`provider::DnsProvider`] and address source.
//!
//! ## Platforms and MSRV
//!
//! Linux, macOS and Windows; Rust 1.99 or newer (edition 2024). The network features need
//! a Tokio runtime (reqwest's requirement).
//!
//! ## Versioning
//!
//! `grindvakt-core` is released in lockstep with the Grindvakt app: crate version X.Y.Z is
//! the library inside Grindvakt vX.Y.Z, and is published to crates.io before that app
//! release is tagged. Semver applies to the public API. The vault and config formats are
//! stable; a format change would come with a major version and a migration path.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod config;
mod error;
pub mod fs;
pub mod ip;
pub mod lock;
#[cfg(feature = "default-paths")]
#[cfg_attr(docsrs, doc(cfg(feature = "default-paths")))]
pub mod paths;
pub mod provider;
pub mod schedule;
pub mod sync;
pub mod vault;

pub use error::{Error, Result};
/// Re-exported so callers use the same secret type as the vault and providers.
pub use secrecy::{ExposeSecret, SecretString};
/// Re-exported so callers can match the crypto crate in use.
pub use weirdnet_keys;

/// Compiles and runs the README's examples as doctests.
#[cfg(all(
    doctest,
    feature = "dnsimple",
    feature = "digitalocean",
    feature = "public-ip"
))]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
