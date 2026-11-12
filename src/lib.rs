//! # grindvakt-core
//!
//! The engine of [Grindvakt](https://grindvakt.weirdbrains.com/), the dynamic DNS updater,
//! as a library you embed. It keeps **A, AAAA, TXT and CNAME** records on **DNSimple** or
//! **DigitalOcean** pointed at where your machine is, including the libp2p
//! `_dnsaddr` TXT record a peer-to-peer node publishes and aliases such as `www`
//! ([`record::Record::cname`]):
//!
//! 1. [`ip::discover`] finds your public IPv4 and IPv6 addresses separately, from several
//!    HTTPS sources that must agree, and says [`Error::NoGlobalAddress`] when there is
//!    nothing worth publishing (CGNAT, private-only, no IPv6). Or pass addresses you
//!    already know.
//! 2. [`plan()`] compares the [`record::Record`]s you want with the zone, through a
//!    [`provider::DnsProvider`], and returns a [`plan::Plan`]: no change, create, update,
//!    or refuse because it is ambiguous. The plan is the dry run.
//! 3. [`apply()`] writes it. Running it again changes nothing.
//!
//! The caller owns everything around that: tokens arrive as [`SecretString`]s, every file
//! path is an argument, and *when* to sync is up to you; there is no scheduler, CLI, prompt
//! or global state in the crate. Errors are typed ([`Error::Auth`],
//! [`Error::RateLimited`], [`Error::Ambiguous`], [`Error::NoGlobalAddress`],
//! [`Error::Network`], [`Error::Provider`]) so a UI can explain them.
//!
//! ## Example
//!
//! ```no_run
//! # #[cfg(all(feature = "digitalocean", feature = "public-ip"))]
//! # async fn run(token: grindvakt_core::SecretString, peer: &str) -> grindvakt_core::Result<()> {
//! use grindvakt_core::{apply, ip, plan, provider, record::Record};
//!
//! let dns = provider::digitalocean(&token)?; // or provider::dnsimple(&token, None)?
//! let addrs = ip::discover(ip::Family::Both, &ip::Sources::default()).await?;
//!
//! let mut want = vec![Record::txt(
//!     "_dnsaddr.home",
//!     format!("dnsaddr=/dns4/home.example.com/tcp/4747/p2p/{peer}"),
//! )];
//! if let Some(v4) = addrs.v4 { want.push(Record::a("home", v4)); }
//! if let Some(v6) = addrs.v6 { want.push(Record::aaaa("home", v6)); }
//!
//! let p = plan(&dns, "example.com", &want).await?;
//! println!("{p}");       // show the dry run
//! apply(&dns, &p).await?; // then write it
//! # Ok(()) }
//! ```
//!
//! A complete offline run against an in-memory provider is in the [`plan`](mod@plan) module docs and
//! in `examples/`.
//!
//! ## Features
//!
//! | feature | default | adds |
//! |---|---|---|
//! | `dnsimple` | yes | [`provider::DnsimpleProvider`] (official `dnsimple` crate, rustls) |
//! | `digitalocean` | yes | [`provider::DigitalOceanProvider`] (reqwest, rustls) |
//! | `public-ip` | yes | [`ip::discover`] (reqwest, rustls) |
//! | `vault` | no | [`vault`]: encrypted token file (Argon2id password and 24-word recovery phrase, XChaCha20-Poly1305 via [`weirdnet_keys`]) |
//! | `standalone` | no | The standalone Grindvakt app's [`config::AppConfig`], [`paths`], single-record [`sync`], and [`standalone::find_conflicts`] |
//!
//! With `default-features = false` the crate makes no network calls at all; plug in your
//! own [`provider::DnsProvider`] and addresses. Every feature builds for Android and iOS
//! (rustls only, no OpenSSL). On Android, initialize `rustls-platform-verifier` from your
//! app before the first HTTPS call, as that crate documents.
//!
//! ## What is not here
//!
//! Everything that ties Grindvakt to a machine stays in the Grindvakt app: the command
//! line and prompts, schedules and timers, the systemd/launchd/Windows services, the
//! unattended credential stores (systemd-creds, Keychain, DPAPI), installers and logging.
//!
//! ## Platforms and MSRV
//!
//! Linux, macOS, Windows, Android and iOS; Rust 1.99 or newer (edition 2024). The network
//! features need a Tokio runtime.
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
#[cfg(feature = "standalone")]
#[cfg_attr(docsrs, doc(cfg(feature = "standalone")))]
pub mod paths;
pub mod plan;
pub mod provider;
pub mod record;
#[cfg(feature = "standalone")]
#[cfg_attr(docsrs, doc(cfg(feature = "standalone")))]
pub mod standalone;
#[cfg(feature = "standalone")]
#[cfg_attr(docsrs, doc(cfg(feature = "standalone")))]
pub mod sync;
#[cfg(feature = "vault")]
#[cfg_attr(docsrs, doc(cfg(feature = "vault")))]
pub mod vault;

pub use error::{Error, Result};
pub use plan::{apply, plan};
/// Re-exported so callers use the same secret type as the providers and vault.
pub use secrecy::{ExposeSecret, SecretString};
/// Re-exported so callers can match the crypto crate in use.
#[cfg(feature = "vault")]
#[cfg_attr(docsrs, doc(cfg(feature = "vault")))]
pub use weirdnet_keys;

/// Compiles and runs the README's examples as doctests.
#[cfg(all(
    doctest,
    feature = "dnsimple",
    feature = "digitalocean",
    feature = "public-ip",
    feature = "vault",
    feature = "standalone"
))]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
