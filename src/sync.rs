//! One sync pass: plan against the provider, then create, update or leave the record.

use crate::config::AppConfig;
use crate::error::{Error, Result};
use crate::provider::{DnsAction, DnsProvider};
use std::fmt;
use std::net::Ipv4Addr;

/// Whether to change DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Plan only; report what would change.
    DryRun,
    /// Create or update the record.
    Apply,
}

/// What a sync pass did (or, in dry-run mode, would do).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncOutcome {
    /// Already correct.
    Noop {
        /// Record name.
        fqdn: String,
        /// Current address.
        ip: Ipv4Addr,
    },
    /// The record was created.
    Created {
        /// Record name.
        fqdn: String,
        /// New address.
        ip: Ipv4Addr,
        /// TTL set.
        ttl: u32,
    },
    /// The record was updated.
    Updated {
        /// Record name.
        fqdn: String,
        /// Old address.
        prev: Ipv4Addr,
        /// New address.
        ip: Ipv4Addr,
        /// TTL set.
        ttl: u32,
        /// Provider record id.
        record_id: u64,
    },
    /// Dry run: the record would be created.
    WouldCreate {
        /// Record name.
        fqdn: String,
        /// Address it would get.
        ip: Ipv4Addr,
        /// TTL it would get.
        ttl: u32,
    },
    /// Dry run: the record would be updated.
    WouldUpdate {
        /// Record name.
        fqdn: String,
        /// Current address.
        prev: Ipv4Addr,
        /// Address it would get.
        ip: Ipv4Addr,
        /// TTL it would get.
        ttl: u32,
        /// Provider record id.
        record_id: u64,
    },
}

impl SyncOutcome {
    /// Whether DNS was (or in a dry run, would be) changed.
    pub fn changes_dns(&self) -> bool {
        !matches!(self, SyncOutcome::Noop { .. })
    }
}

impl fmt::Display for SyncOutcome {
    /// The log lines Grindvakt prints.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncOutcome::Noop { fqdn, ip } => write!(f, "No change needed: {fqdn} -> {ip}"),
            SyncOutcome::Created { fqdn, ip, ttl } => {
                write!(f, "Created A {fqdn} = {ip} (ttl={ttl})")
            }
            SyncOutcome::Updated {
                fqdn,
                prev,
                ip,
                ttl,
                ..
            } => write!(f, "Updated A {fqdn}: {prev} -> {ip} (ttl={ttl})"),
            SyncOutcome::WouldCreate { fqdn, ip, ttl } => {
                write!(f, "DRY RUN: would create A {fqdn} = {ip} (ttl={ttl})")
            }
            SyncOutcome::WouldUpdate {
                fqdn,
                prev,
                ip,
                ttl,
                record_id,
            } => {
                write!(
                    f,
                    "DRY RUN: would update A {fqdn}: {prev} -> {ip} (ttl={ttl}) [record_id={record_id}]"
                )
            }
        }
    }
}

/// Plans against `provider` for `ip` and applies the result unless `mode` is
/// [`SyncMode::DryRun`]. Ambiguous records give [`Error::Ambiguous`] and nothing changes.
///
/// ```
/// use grindvakt_core::config::AppConfig;
/// use grindvakt_core::provider::{DnsAction, DnsProvider};
/// use grindvakt_core::sync::{sync_once, SyncMode, SyncOutcome};
/// use std::net::Ipv4Addr;
///
/// struct Empty;
/// impl DnsProvider for Empty {
///     async fn plan(&self, cfg: &AppConfig, _ip: Ipv4Addr) -> grindvakt_core::Result<DnsAction> {
///         Ok(DnsAction::Create { name: "home".into(), ttl: cfg.ttl })
///     }
///     async fn create_a(&self, _: &AppConfig, _: &str, _: Ipv4Addr, _: u32) -> grindvakt_core::Result<()> {
///         unreachable!("dry run")
///     }
///     async fn update_a(&self, _: &AppConfig, _: u64, _: Ipv4Addr, _: u32) -> grindvakt_core::Result<()> {
///         unreachable!("dry run")
///     }
/// }
///
/// # fn block_on<F: std::future::Future>(f: F) -> F::Output {
/// #     tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
/// # }
/// let cfg = AppConfig { zone: "example.net".into(), name: "home".into(), ..AppConfig::default() };
/// let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();
/// let out = block_on(sync_once(&cfg, &Empty, ip, SyncMode::DryRun)).unwrap();
/// assert!(matches!(out, SyncOutcome::WouldCreate { .. }));
/// assert_eq!(out.to_string(), "DRY RUN: would create A home.example.net = 93.184.216.34 (ttl=300)");
/// ```
pub async fn sync_once<P: DnsProvider + ?Sized>(
    cfg: &AppConfig,
    provider: &P,
    ip: Ipv4Addr,
    mode: SyncMode,
) -> Result<SyncOutcome> {
    let fqdn = cfg.record_fqdn();
    match provider.plan(cfg, ip).await? {
        DnsAction::Noop(current) => Ok(SyncOutcome::Noop { fqdn, ip: current }),
        DnsAction::Create { name, ttl } => {
            if mode == SyncMode::DryRun {
                return Ok(SyncOutcome::WouldCreate { fqdn, ip, ttl });
            }
            provider.create_a(cfg, &name, ip, ttl).await?;
            Ok(SyncOutcome::Created { fqdn, ip, ttl })
        }
        DnsAction::Update {
            record_id,
            ttl,
            prev,
        } => {
            if mode == SyncMode::DryRun {
                return Ok(SyncOutcome::WouldUpdate {
                    fqdn,
                    prev,
                    ip,
                    ttl,
                    record_id,
                });
            }
            provider.update_a(cfg, record_id, ip, ttl).await?;
            Ok(SyncOutcome::Updated {
                fqdn,
                prev,
                ip,
                ttl,
                record_id,
            })
        }
        DnsAction::Ambiguous { reason } => Err(Error::Ambiguous(reason)),
    }
}
