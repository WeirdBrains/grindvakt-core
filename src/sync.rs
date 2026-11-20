//! The standalone Grindvakt app's sync pass (feature `standalone`): one `A` record (or, with
//! `record = "cname"`, one `CNAME`) from an [`AppConfig`], with the app's log lines. It is a thin wrapper over [`crate::plan()`] and
//! [`crate::apply()`]; embedding apps usually call those directly.

use crate::config::{AppConfig, RecordType};
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

/// What a CNAME sync pass did (or, in dry-run mode, would do).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CnameOutcome {
    /// Already correct.
    Noop {
        /// Record name.
        fqdn: String,
        /// Current target.
        target: String,
    },
    /// The record was created.
    Created {
        /// Record name.
        fqdn: String,
        /// New target.
        target: String,
        /// TTL set.
        ttl: u32,
    },
    /// The record was retargeted.
    Updated {
        /// Record name.
        fqdn: String,
        /// Old target.
        prev: String,
        /// New target.
        target: String,
        /// TTL set.
        ttl: u32,
        /// Provider record id.
        record_id: u64,
    },
    /// Dry run: the record would be created.
    WouldCreate {
        /// Record name.
        fqdn: String,
        /// Target it would get.
        target: String,
        /// TTL it would get.
        ttl: u32,
    },
    /// Dry run: the record would be retargeted.
    WouldUpdate {
        /// Record name.
        fqdn: String,
        /// Current target.
        prev: String,
        /// Target it would get.
        target: String,
        /// TTL it would get.
        ttl: u32,
        /// Provider record id.
        record_id: u64,
    },
}

impl CnameOutcome {
    /// Whether DNS was (or in a dry run, would be) changed.
    pub fn changes_dns(&self) -> bool {
        !matches!(self, CnameOutcome::Noop { .. })
    }
}

impl fmt::Display for CnameOutcome {
    /// The log lines Grindvakt prints.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CnameOutcome::Noop { fqdn, target } => {
                write!(f, "No change: CNAME {fqdn} -> {target}")
            }
            CnameOutcome::Created { fqdn, target, ttl } => {
                write!(f, "Created CNAME {fqdn} -> {target} (ttl={ttl})")
            }
            CnameOutcome::Updated {
                fqdn,
                prev,
                target,
                ttl,
                record_id,
            } => write!(
                f,
                "Updated CNAME {fqdn}: {prev} -> {target} (ttl={ttl}) [record_id={record_id}]"
            ),
            CnameOutcome::WouldCreate { fqdn, target, ttl } => {
                write!(
                    f,
                    "DRY RUN: would create CNAME {fqdn} -> {target} (ttl={ttl})"
                )
            }
            CnameOutcome::WouldUpdate {
                fqdn,
                prev,
                target,
                ttl,
                record_id,
            } => write!(
                f,
                "DRY RUN: would update CNAME {fqdn}: {prev} -> {target} (ttl={ttl}) [record_id={record_id}]"
            ),
        }
    }
}

/// Plans the config's `CNAME` record and applies it unless `mode` is [`SyncMode::DryRun`].
///
/// The target comes from the config's `[cname]` table (a host name, or with feature
/// `weirdnet` a Weirdnet resource link), so a changed link gives a new target on the next pass.
/// A target that cannot be resolved is an error and nothing is written. Ambiguous records
/// (anything else at the name) give [`Error::Ambiguous`] and nothing changes. Fails with
/// [`Error::Config`] unless the config says `record = "cname"`.
pub async fn sync_cname_once<P: DnsProvider + ?Sized>(
    cfg: &AppConfig,
    provider: &P,
    mode: SyncMode,
) -> Result<CnameOutcome> {
    if cfg.record != RecordType::Cname {
        return Err(Error::Config("config is not record = \"cname\"".into()));
    }
    let content = cfg
        .cname
        .as_ref()
        .ok_or_else(|| Error::Config("record = \"cname\" needs a [cname] table".into()))?;
    let target = content.source()?.target()?;
    let fqdn = cfg.record_fqdn();
    let ttl = cfg.ttl;
    let want = [Record::cname(cfg.name.clone(), target.clone()).with_ttl(ttl)];
    let p = plan(provider, &cfg.zone, &want).await?;
    let outcome = match &p.actions[0].change {
        Change::Noop => return Ok(CnameOutcome::Noop { fqdn, target }),
        Change::Ambiguous { reason } => return Err(Error::Ambiguous(reason.clone())),
        Change::Create if mode == SyncMode::DryRun => {
            CnameOutcome::WouldCreate { fqdn, target, ttl }
        }
        Change::Create => CnameOutcome::Created { fqdn, target, ttl },
        Change::Update { id, prev, .. } => {
            let prev = match prev {
                RecordValue::Cname(p) => p.clone(),
                _ => unreachable!("CNAME records plan against CNAME records"),
            };
            if mode == SyncMode::DryRun {
                CnameOutcome::WouldUpdate {
                    fqdn,
                    prev,
                    target,
                    ttl,
                    record_id: *id,
                }
            } else {
                CnameOutcome::Updated {
                    fqdn,
                    prev,
                    target,
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
