//! DNS records: what you want published ([`Record`]) and what a provider has ([`ExistingRecord`]).
//!
//! ```
//! use grindvakt_core::record::{Record, RecordKind};
//! use std::net::{Ipv4Addr, Ipv6Addr};
//!
//! let peer = "12D3KooWExamplePeerId";
//! let want = [
//!     Record::a("home", Ipv4Addr::new(203, 0, 113, 7)),
//!     Record::aaaa("home", "2001:db8::7".parse::<Ipv6Addr>().unwrap()).with_ttl(120),
//!     Record::txt("_dnsaddr.home", format!("dnsaddr=/dns4/home.example.com/tcp/4747/p2p/{peer}")),
//!     Record::cname("www", "home.example.com"),
//! ];
//! assert_eq!(want[1].kind(), RecordKind::Aaaa);
//! assert_eq!(want[2].txt_key(), Some("dnsaddr="));
//! assert_eq!(want[3].kind(), RecordKind::Cname);
//! ```

use crate::error::{Error, Result};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Smallest TTL accepted, in seconds.
pub const MIN_TTL: u32 = 60;
/// TTL a [`Record`] gets unless you call [`Record::with_ttl`], in seconds.
pub const DEFAULT_TTL: u32 = 300;
/// Longest TXT value accepted, in bytes (one DNS character-string is 255; providers split
/// longer values, but `_dnsaddr` values are far shorter).
pub const MAX_TXT_LEN: usize = 2048;

/// The record types this crate manages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RecordKind {
    /// IPv4 address.
    A,
    /// IPv6 address.
    Aaaa,
    /// Text.
    Txt,
    /// Canonical name (an alias for another name).
    Cname,
}

impl RecordKind {
    /// Every kind, in a stable order.
    pub const ALL: [RecordKind; 4] = [
        RecordKind::A,
        RecordKind::Aaaa,
        RecordKind::Txt,
        RecordKind::Cname,
    ];

    /// The DNS type name: `A`, `AAAA`, `TXT` or `CNAME`.
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::A => "A",
            RecordKind::Aaaa => "AAAA",
            RecordKind::Txt => "TXT",
            RecordKind::Cname => "CNAME",
        }
    }
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A record's data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordValue {
    /// An `A` record.
    A(Ipv4Addr),
    /// An `AAAA` record.
    Aaaa(Ipv6Addr),
    /// A `TXT` record, unquoted (see [`normalize_txt`]).
    Txt(String),
    /// A `CNAME` record: the full target name, compared case-insensitively and without a
    /// trailing dot (see [`normalize_target`]).
    Cname(String),
}

impl RecordValue {
    /// The record type.
    pub fn kind(&self) -> RecordKind {
        match self {
            RecordValue::A(_) => RecordKind::A,
            RecordValue::Aaaa(_) => RecordKind::Aaaa,
            RecordValue::Txt(_) => RecordKind::Txt,
            RecordValue::Cname(_) => RecordKind::Cname,
        }
    }

    /// The value as providers store it (`content` / `data`). A CNAME target is lowercase,
    /// without a trailing dot; providers that want one (DigitalOcean) add it.
    pub fn content(&self) -> String {
        match self {
            RecordValue::A(ip) => ip.to_string(),
            RecordValue::Aaaa(ip) => ip.to_string(),
            RecordValue::Txt(t) => t.clone(),
            RecordValue::Cname(t) => normalize_target(t),
        }
    }

    /// Parses provider `content` for `kind`. TXT content is normalized with [`normalize_txt`];
    /// a CNAME target with [`normalize_target`] (it must be a full name).
    pub fn parse(kind: RecordKind, content: &str) -> Result<Self> {
        let c = content.trim();
        match kind {
            RecordKind::A => c.parse().map(RecordValue::A).map_err(|_| {
                Error::InvalidRecord(format!("not an IPv4 address in A record: {c:?}"))
            }),
            RecordKind::Aaaa => c.parse().map(RecordValue::Aaaa).map_err(|_| {
                Error::InvalidRecord(format!("not an IPv6 address in AAAA record: {c:?}"))
            }),
            RecordKind::Txt => Ok(RecordValue::Txt(normalize_txt(c))),
            RecordKind::Cname => {
                let t = normalize_target(c);
                if is_valid_target(&t) {
                    Ok(RecordValue::Cname(t))
                } else {
                    Err(Error::InvalidRecord(format!(
                        "not a host name in CNAME record: {c:?}"
                    )))
                }
            }
        }
    }

    /// Same data, comparing TXT values after [`normalize_txt`] and CNAME targets after
    /// [`normalize_target`].
    pub fn same_data(&self, other: &RecordValue) -> bool {
        match (self, other) {
            (RecordValue::Txt(a), RecordValue::Txt(b)) => normalize_txt(a) == normalize_txt(b),
            (RecordValue::Cname(a), RecordValue::Cname(b)) => {
                normalize_target(a) == normalize_target(b)
            }
            (a, b) => a == b,
        }
    }
}

impl fmt::Display for RecordValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordValue::Txt(t) => write!(f, "{t:?}"),
            other => f.write_str(&other.content()),
        }
    }
}

/// A record you want to exist.
///
/// `name` is relative to the zone (`home`, `_dnsaddr.home`), `@` or empty for the apex, or a
/// full name inside the zone (`home.example.com`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record {
    /// Name, as described above.
    pub name: String,
    /// Data.
    pub value: RecordValue,
    /// TTL in seconds (at least [`MIN_TTL`]).
    pub ttl: u32,
}

impl Record {
    /// An `A` record with [`DEFAULT_TTL`].
    pub fn a(name: impl Into<String>, ip: Ipv4Addr) -> Self {
        Self::new(name, RecordValue::A(ip))
    }
    /// An `AAAA` record with [`DEFAULT_TTL`].
    pub fn aaaa(name: impl Into<String>, ip: Ipv6Addr) -> Self {
        Self::new(name, RecordValue::Aaaa(ip))
    }
    /// A `TXT` record with [`DEFAULT_TTL`]. Pass the text without surrounding quotes.
    pub fn txt(name: impl Into<String>, text: impl Into<String>) -> Self {
        Self::new(name, RecordValue::Txt(text.into()))
    }
    /// A `CNAME` record with [`DEFAULT_TTL`]: `name` becomes an alias for `target`, a full
    /// host name (a trailing dot is optional, case is ignored). A CNAME must be the only record
    /// at its name and cannot sit at the zone apex; [`crate::plan()`] refuses plans that
    /// would break either rule.
    ///
    /// ```
    /// use grindvakt_core::record::{Record, RecordValue};
    ///
    /// let r = Record::cname("www", "Home.Example.com.");
    /// assert!(r.validate("example.com").is_ok());
    /// assert_eq!(r.value.content(), "home.example.com");
    /// assert!(r.value.same_data(&RecordValue::Cname("home.example.com".into())));
    ///
    /// assert!(Record::cname("@", "home.example.com").validate("example.com").is_err()); // apex
    /// assert!(Record::cname("www", "not a name").validate("example.com").is_err());
    /// assert!(Record::cname("www", "www.example.com").validate("example.com").is_err()); // itself
    /// ```
    pub fn cname(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self::new(name, RecordValue::Cname(target.into()))
    }
    /// A record with [`DEFAULT_TTL`].
    pub fn new(name: impl Into<String>, value: RecordValue) -> Self {
        Self {
            name: name.into(),
            value,
            ttl: DEFAULT_TTL,
        }
    }
    /// Sets the TTL.
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }
    /// The record type.
    pub fn kind(&self) -> RecordKind {
        self.value.kind()
    }
    /// For TXT records, the part that identifies "the same kind of TXT": everything up to and
    /// including the first `=` (`dnsaddr=`, `google-site-verification=`), extended to the first
    /// space for `v=` tags (`v=spf1`), or the whole text when there is no `=`. See [`crate::plan()`] for how it is used.
    pub fn txt_key(&self) -> Option<&str> {
        match &self.value {
            RecordValue::Txt(t) => Some(txt_key(t)),
            _ => None,
        }
    }

    /// Checks the name against `zone`, the TTL, the TXT length and, for a CNAME, that the
    /// target is a full host name other than the record itself and that the name is not the
    /// zone apex.
    pub fn validate(&self, zone: &str) -> Result<()> {
        if self.ttl < MIN_TTL {
            return Err(Error::InvalidRecord(format!(
                "{} {}: ttl {} is below {MIN_TTL}",
                self.kind(),
                self.name,
                self.ttl
            )));
        }
        if !is_valid_name(zone, &self.name) {
            return Err(Error::InvalidRecord(format!(
                "{:?} is not a valid record name in zone {zone}",
                self.name
            )));
        }
        if let RecordValue::Txt(t) = &self.value {
            if t.is_empty() || t.len() > MAX_TXT_LEN {
                return Err(Error::InvalidRecord(format!(
                    "TXT {}: value must be 1..={MAX_TXT_LEN} bytes",
                    self.name
                )));
            }
            if t.contains('"') || t.contains('\n') {
                return Err(Error::InvalidRecord(format!(
                    "TXT {}: value must not contain quotes or newlines",
                    self.name
                )));
            }
        }
        if let RecordValue::Cname(t) = &self.value {
            let fqdn = crate::config::normalize_fqdn(zone, &self.name).to_ascii_lowercase();
            let zone_l = zone.trim().trim_end_matches('.').to_ascii_lowercase();
            if fqdn == zone_l {
                return Err(Error::InvalidRecord(format!(
                    "CNAME {fqdn}: a CNAME cannot be at the zone apex"
                )));
            }
            let target = normalize_target(t);
            if !is_valid_target(&target) {
                return Err(Error::InvalidRecord(format!(
                    "CNAME {fqdn}: target {t:?} is not a full host name"
                )));
            }
            if target == fqdn {
                return Err(Error::InvalidRecord(format!(
                    "CNAME {fqdn}: a CNAME cannot point at itself"
                )));
            }
        }
        Ok(())
    }
}

/// A record as a provider reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingRecord {
    /// Provider record id.
    pub id: u64,
    /// Name relative to the zone, `""` for the apex.
    pub name: String,
    /// Data.
    pub value: RecordValue,
    /// TTL in seconds, when the provider reports one.
    pub ttl: Option<u32>,
}

/// Removes one pair of surrounding quotes and joins `"a" "b"` character-strings, as some
/// providers return TXT content quoted.
///
/// ```
/// use grindvakt_core::record::normalize_txt;
/// assert_eq!(normalize_txt("\"dnsaddr=/dns4/x\""), "dnsaddr=/dns4/x");
/// assert_eq!(normalize_txt("\"abc\" \"def\""), "abcdef");
/// assert_eq!(normalize_txt("plain"), "plain");
/// ```
pub fn normalize_txt(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        let inner = &t[1..t.len() - 1];
        if inner.contains("\" \"") {
            return inner.split("\" \"").collect();
        }
        return inner.replace("\\\"", "\"");
    }
    t.to_string()
}

/// Lowercases a host name and drops surrounding space and one trailing dot.
///
/// ```
/// use grindvakt_core::record::normalize_target;
/// assert_eq!(normalize_target(" Home.Example.COM. "), "home.example.com");
/// ```
pub fn normalize_target(s: &str) -> String {
    let t = s.trim();
    t.strip_suffix('.').unwrap_or(t).to_ascii_lowercase()
}

/// Whether `target` (already normalized) is a full host name: at least two labels of 1–63
/// letters, digits, `-` or `_`, not starting or ending with `-`, at most 253 bytes.
pub(crate) fn is_valid_target(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= 253
        && target.contains('.')
        && target.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

pub(crate) fn txt_key(t: &str) -> &str {
    match t.find('=') {
        Some(1) if t.starts_with('v') => t.split_whitespace().next().unwrap_or(t),
        Some(i) => &t[..=i],
        None => t,
    }
}

/// Whether `name` is a usable record name in `zone`: `@` or empty (apex), labels of 1–63
/// letters, digits, `-` or `_` (so `_dnsaddr.home` works), or a full name ending in the zone.
/// A dotted name that does not end in the zone is taken as relative to it, the way DNS
/// providers treat it (`home.office` in `example.com` is `home.office.example.com`).
///
/// ```
/// use grindvakt_core::record::is_valid_name;
/// assert!(is_valid_name("example.com", "@"));
/// assert!(is_valid_name("example.com", "_dnsaddr.home"));
/// assert!(is_valid_name("example.com", "a"));
/// assert!(is_valid_name("example.com", "home.example.com."));
/// assert!(!is_valid_name("example.com", "bad..name"));
/// assert!(!is_valid_name("example.com", "-x"));
/// ```
pub fn is_valid_name(zone: &str, name: &str) -> bool {
    let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() || n == "@" || n == zone {
        return true;
    }
    if n.len() > 253 {
        return false;
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    n.split('.').all(label_ok)
}
