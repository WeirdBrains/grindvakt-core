//! The standalone Grindvakt app's sync pass (feature `standalone`): one `A` record from an
//! [`AppConfig`], with the app's log lines. It is a thin wrapper over [`crate::plan()`] and
//! [`crate::apply()`]; embedding apps usually call those directly.

use crate::config::AppConfig;
use crate::error::{Error, Result};
use crate::plan::{Change, apply, plan};
use crate::provider::DnsProvider;
use crate::record::{Record, RecordValue};
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

/// Plans the config's `A` record for `ip` and applies it unless `mode` is
/// [`SyncMode::DryRun`]. Ambiguous records give [`Error::Ambiguous`] and nothing changes.
pub async fn sync_once<P: DnsProvider + ?Sized>(
    cfg: &AppConfig,
    provider: &P,
    ip: Ipv4Addr,
    mode: SyncMode,
) -> Result<SyncOutcome> {
    let fqdn = cfg.record_fqdn();
    let want = [Record::a(cfg.name.clone(), ip).with_ttl(cfg.ttl)];
    let p = plan(provider, &cfg.zone, &want).await?;
    let action = &p.actions[0];
    let ttl = cfg.ttl;
    let outcome = match &action.change {
        Change::Noop => return Ok(SyncOutcome::Noop { fqdn, ip }),
        Change::Ambiguous { reason } => return Err(Error::Ambiguous(reason.clone())),
        Change::Create if mode == SyncMode::DryRun => SyncOutcome::WouldCreate { fqdn, ip, ttl },
        Change::Create => SyncOutcome::Created { fqdn, ip, ttl },
        Change::Update { id, prev, .. } => {
            let prev = match prev {
                RecordValue::A(p) => *p,
                _ => unreachable!("A records plan against A records"),
            };
            if mode == SyncMode::DryRun {
                SyncOutcome::WouldUpdate {
                    fqdn,
                    prev,
                    ip,
                    ttl,
                    record_id: *id,
                }
            } else {
                SyncOutcome::Updated {
                    fqdn,
                    prev,
                    ip,
                    ttl,
                    record_id: *id,
                }
            }
        }
        #[allow(unreachable_patterns)]
        _ => return Err(Error::Ambiguous("unknown plan change".into())),
    };
    if mode == SyncMode::Apply {
        apply(provider, &p).await?;
    }
    Ok(outcome)
}
