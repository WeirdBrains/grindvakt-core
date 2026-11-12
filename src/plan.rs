//! Plan, then apply: decide what to change for a set of wanted records, show it, write it.
//!
//! [`plan()`] reads the zone through a [`DnsProvider`] and returns a [`Plan`]: one
//! [`Action`] per wanted record, each a [`Change::Noop`], [`Change::Create`],
//! [`Change::Update`] or [`Change::Ambiguous`]. A plan *is* the dry run; nothing is
//! written until you pass it to [`apply()`], which refuses the whole plan if any action is
//! ambiguous. Applying the same wanted records twice changes nothing the second time.
//!
//! ## How records are matched
//!
//! Wanted records are grouped by name and type (and, for TXT, by [`Record::txt_key`], so
//! `dnsaddr=` records never touch an SPF or verification record at the same name):
//!
//! 1. An existing record with the same data is kept ([`Change::Noop`]), or gets its TTL
//!    fixed ([`Change::Update`]).
//! 2. The rest are paired with the group's remaining existing records and updated, and any
//!    wanted record left over is created.
//! 3. `A`/`AAAA`: more existing records than wanted ones is ambiguous (Grindvakt never
//!    deletes, and will not guess which to keep). TXT: leftover existing records of the same
//!    key are ambiguous only when a wanted record still needs a slot; otherwise they are left
//!    alone.
//! 4. `CNAME`: a name has at most one, so the group is that name's CNAME: kept, retargeted
//!    or created. A CNAME must be the only record at its name, so the plan is ambiguous when
//!    a wanted CNAME's name already has records of any other type (as reported by
//!    [`DnsProvider::types_at`]), when a wanted `A`/`AAAA`/`TXT` record's name already has a
//!    CNAME, or when the same plan wants a CNAME and another record at one name.
//!
//! ```
//! use grindvakt_core::plan::{plan, apply, Change};
//! use grindvakt_core::provider::DnsProvider;
//! use grindvakt_core::record::{ExistingRecord, Record, RecordKind, RecordValue};
//! use std::net::Ipv4Addr;
//! use std::sync::Mutex;
//!
//! /// An in-memory zone.
//! #[derive(Default)]
//! struct Memory(Mutex<Vec<ExistingRecord>>);
//! impl DnsProvider for Memory {
//!     fn name(&self) -> &str { "memory" }
//!     async fn list(&self, _z: &str, name: &str, kind: RecordKind) -> grindvakt_core::Result<Vec<ExistingRecord>> {
//!         Ok(self.0.lock().unwrap().iter().filter(|r| r.name == name && r.value.kind() == kind).cloned().collect())
//!     }
//!     async fn create(&self, _z: &str, name: &str, value: &RecordValue, ttl: u32) -> grindvakt_core::Result<()> {
//!         let mut z = self.0.lock().unwrap();
//!         let id = z.len() as u64 + 1;
//!         z.push(ExistingRecord { id, name: name.into(), value: value.clone(), ttl: Some(ttl) });
//!         Ok(())
//!     }
//!     async fn update(&self, _z: &str, id: u64, value: &RecordValue, ttl: u32) -> grindvakt_core::Result<()> {
//!         for r in self.0.lock().unwrap().iter_mut().filter(|r| r.id == id) {
//!             r.value = value.clone();
//!             r.ttl = Some(ttl);
//!         }
//!         Ok(())
//!     }
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//! let zone = Memory::default();
//! let want = [
//!     Record::a("home", Ipv4Addr::new(203, 0, 113, 7)),
//!     Record::txt("_dnsaddr.home", "dnsaddr=/dns4/home.example.com/tcp/4747/p2p/12D3KooW"),
//! ];
//! let p = plan(&zone, "example.com", &want).await?;
//! assert!(p.actions.iter().all(|a| a.change == Change::Create));
//! println!("{p}"); // the dry run
//! apply(&zone, &p).await?;
//! assert!(plan(&zone, "example.com", &want).await?.is_noop());
//! # Ok::<(), grindvakt_core::Error>(()) }).unwrap();
//! ```

use crate::config::{normalize_fqdn, relative_name};
use crate::error::{Error, Result};
use crate::provider::DnsProvider;
use crate::record::{ExistingRecord, Record, RecordKind, RecordValue, txt_key};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

/// What will happen to one wanted record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// Already correct.
    Noop,
    /// No matching record; one will be created.
    Create,
    /// Record `id` will be changed from `prev` (and `prev_ttl`).
    Update {
        /// Provider record id.
        id: u64,
        /// Its current data.
        prev: RecordValue,
        /// Its current TTL, when known.
        prev_ttl: Option<u32>,
    },
    /// The zone's records don't allow a safe decision; [`apply()`] refuses the plan.
    Ambiguous {
        /// Why.
        reason: String,
    },
}

/// One wanted record and its [`Change`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// The wanted record, with `name` made relative to the zone (`""` for the apex).
    pub record: Record,
    /// The record's full name, without a trailing dot.
    pub fqdn: String,
    /// What will happen.
    pub change: Change,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, fqdn, value, ttl) = (
            self.record.kind(),
            &self.fqdn,
            &self.record.value,
            self.record.ttl,
        );
        match &self.change {
            Change::Noop => write!(f, "no change: {kind} {fqdn} = {value}"),
            Change::Create => write!(f, "create {kind} {fqdn} = {value} (ttl={ttl})"),
            Change::Update { id, prev, .. } => {
                write!(
                    f,
                    "update {kind} {fqdn}: {prev} -> {value} (ttl={ttl}) [record_id={id}]"
                )
            }
            Change::Ambiguous { reason } => write!(f, "ambiguous {kind} {fqdn}: {reason}"),
        }
    }
}

/// The result of [`plan()`]: what [`apply()`] would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The zone, without a trailing dot.
    pub zone: String,
    /// One action per wanted record, in the order given.
    pub actions: Vec<Action>,
}

impl Plan {
    /// Whether nothing would change.
    pub fn is_noop(&self) -> bool {
        self.actions.iter().all(|a| a.change == Change::Noop)
    }
    /// Actions that would create or update a record.
    pub fn changes(&self) -> impl Iterator<Item = &Action> {
        self.actions
            .iter()
            .filter(|a| matches!(a.change, Change::Create | Change::Update { .. }))
    }
    /// Ambiguous actions.
    pub fn ambiguous(&self) -> impl Iterator<Item = &Action> {
        self.actions
            .iter()
            .filter(|a| matches!(a.change, Change::Ambiguous { .. }))
    }
}

impl fmt::Display for Plan {
    /// One line per action.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, a) in self.actions.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{a}")?;
        }
        Ok(())
    }
}

/// Reads the current records for every name and type in `want` and decides what to change.
/// Writes nothing. Fails with [`Error::InvalidRecord`] for a bad name, TTL, TXT value or
/// CNAME target, two identical wanted records, or two wanted CNAMEs at one name.
pub async fn plan<P: DnsProvider + ?Sized>(
    provider: &P,
    zone: &str,
    want: &[Record],
) -> Result<Plan> {
    let zone = zone.trim().trim_end_matches('.').to_string();
    if zone.is_empty() {
        return Err(Error::InvalidRecord("zone must be set".into()));
    }
    // Normalize names and validate.
    let mut wanted = Vec::with_capacity(want.len());
    for r in want {
        r.validate(&zone)?;
        let mut r = r.clone();
        r.name = relative_name(&zone, &r.name).to_ascii_lowercase();
        if wanted
            .iter()
            .any(|w: &Record| w.name == r.name && w.value.same_data(&r.value))
        {
            return Err(Error::InvalidRecord(format!(
                "{} {} is listed twice",
                r.kind(),
                normalize_fqdn(&zone, &r.name)
            )));
        }
        if r.kind() == RecordKind::Cname
            && wanted
                .iter()
                .any(|w: &Record| w.name == r.name && w.kind() == RecordKind::Cname)
        {
            return Err(Error::InvalidRecord(format!(
                "CNAME {} is listed twice with different targets; a name has one CNAME",
                normalize_fqdn(&zone, &r.name)
            )));
        }
        wanted.push(r);
    }

    // One list call per (name, kind).
    let mut existing: HashMap<(String, RecordKind), Vec<ExistingRecord>> = HashMap::new();
    for r in &wanted {
        let key = (r.name.clone(), r.kind());
        if let std::collections::hash_map::Entry::Vacant(slot) = existing.entry(key) {
            let mut recs = provider.list(&zone, &r.name, r.kind()).await?;
            recs.sort_by_key(|e| e.id);
            slot.insert(recs);
        }
    }

    // Group wanted records: (name, kind, txt key).
    let group_of = |r: &Record| (r.name.clone(), r.kind(), r.txt_key().map(str::to_string));
    let mut changes: Vec<Option<Change>> = vec![None; wanted.len()];
    let mut seen_groups: Vec<(String, RecordKind, Option<String>)> = Vec::new();
    for (i, r) in wanted.iter().enumerate() {
        let g = group_of(r);
        if seen_groups.contains(&g) {
            continue;
        }
        seen_groups.push(g.clone());
        let members: Vec<usize> = (i..wanted.len())
            .filter(|&j| group_of(&wanted[j]) == g)
            .collect();
        let pool_all = &existing[&(g.0.clone(), g.1)];
        let mut pool: Vec<&ExistingRecord> = pool_all
            .iter()
            .filter(|e| match (&g.2, &e.value) {
                (Some(key), RecordValue::Txt(t)) => txt_key(t) == key,
                _ => true,
            })
            .collect();
        let fqdn = normalize_fqdn(&zone, &g.0);

        if g.1 != RecordKind::Txt && pool.len() > members.len() {
            let reason = format!(
                "found {} {} records for {fqdn}, expected at most {}",
                pool.len(),
                g.1,
                members.len()
            );
            for &j in &members {
                changes[j] = Some(Change::Ambiguous {
                    reason: reason.clone(),
                });
            }
            continue;
        }

        // 1. exact data matches
        let mut rest = Vec::new();
        for &j in &members {
            let w = &wanted[j];
            if let Some(pos) = pool.iter().position(|e| e.value.same_data(&w.value)) {
                let e = pool.remove(pos);
                changes[j] = Some(if e.ttl.is_none_or(|t| t == w.ttl) {
                    Change::Noop
                } else {
                    Change::Update {
                        id: e.id,
                        prev: e.value.clone(),
                        prev_ttl: e.ttl,
                    }
                });
            } else {
                rest.push(j);
            }
        }
        // 2./3. pair the rest
        if !rest.is_empty() && pool.len() > rest.len() {
            let reason = format!(
                "found {} other {} records{} for {fqdn}; not sure which to replace",
                pool.len(),
                g.1,
                g.2.as_deref()
                    .map(|k| format!(" starting {k:?}"))
                    .unwrap_or_default()
            );
            for &j in &rest {
                changes[j] = Some(Change::Ambiguous {
                    reason: reason.clone(),
                });
            }
            continue;
        }
        for (n, &j) in rest.iter().enumerate() {
            changes[j] = Some(match pool.get(n) {
                Some(e) => Change::Update {
                    id: e.id,
                    prev: e.value.clone(),
                    prev_ttl: e.ttl,
                },
                None => Change::Create,
            });
        }
    }

    // CNAME exclusivity, in both directions. Never resolved by deleting: the plan is refused.
    let mut cname_names = BTreeSet::new();
    let mut other_names: BTreeMap<String, BTreeSet<RecordKind>> = BTreeMap::new();
    for r in &wanted {
        if r.kind() == RecordKind::Cname {
            cname_names.insert(r.name.clone());
        } else {
            other_names
                .entry(r.name.clone())
                .or_default()
                .insert(r.kind());
        }
    }
    let mut conflicts: HashMap<String, String> = HashMap::new();
    for name in &cname_names {
        let fqdn = normalize_fqdn(&zone, name);
        if let Some(kinds) = other_names.get(name) {
            let kinds: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
            conflicts.insert(
                name.clone(),
                format!(
                    "a CNAME and {} records are both wanted at {fqdn}; a CNAME must be alone at its name",
                    kinds.join("/")
                ),
            );
            continue;
        }
        let others: BTreeSet<String> = provider
            .types_at(&zone, name)
            .await?
            .into_iter()
            .map(|t| t.to_ascii_uppercase())
            .filter(|t| t != RecordKind::Cname.as_str())
            .collect();
        if !others.is_empty() {
            let others: Vec<String> = others.into_iter().collect();
            conflicts.insert(
                name.clone(),
                format!(
                    "{fqdn} already has {} records; a CNAME must be alone at its name (nothing is deleted)",
                    others.join("/")
                ),
            );
        }
    }
    for name in other_names.keys() {
        if cname_names.contains(name) {
            continue;
        }
        let cnames = provider.list(&zone, name, RecordKind::Cname).await?;
        if let Some(c) = cnames.first() {
            let fqdn = normalize_fqdn(&zone, name);
            conflicts.insert(
                name.clone(),
                format!(
                    "{fqdn} is a CNAME to {}; it cannot also have other records (nothing is deleted)",
                    c.value.content()
                ),
            );
        }
    }
    for (r, c) in wanted.iter().zip(changes.iter_mut()) {
        if let Some(reason) = conflicts.get(&r.name) {
            *c = Some(Change::Ambiguous {
                reason: reason.clone(),
            });
        }
    }

    let actions = wanted
        .into_iter()
        .zip(changes)
        .map(|(record, change)| Action {
            fqdn: normalize_fqdn(&zone, &record.name),
            record,
            change: change.expect("every wanted record is planned"),
        })
        .collect();
    Ok(Plan { zone, actions })
}

/// Writes a plan: creates and updates in order and returns the actions it performed.
///
/// Refuses the whole plan with [`Error::Ambiguous`] before writing anything if any action is
/// ambiguous. Stops at the first failed write; planning again shows what is left.
pub async fn apply<P: DnsProvider + ?Sized>(provider: &P, plan: &Plan) -> Result<Vec<Action>> {
    let reasons: Vec<String> = plan.ambiguous().map(|a| a.to_string()).collect();
    if !reasons.is_empty() {
        return Err(Error::Ambiguous(reasons.join("; ")));
    }
    let mut done = Vec::new();
    for a in plan.changes() {
        match &a.change {
            Change::Create => {
                provider
                    .create(&plan.zone, &a.record.name, &a.record.value, a.record.ttl)
                    .await?
            }
            Change::Update { id, .. } => {
                provider
                    .update(&plan.zone, *id, &a.record.value, a.record.ttl)
                    .await?
            }
            _ => continue,
        }
        done.push(a.clone());
    }
    Ok(done)
}
