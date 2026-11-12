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
//! ];
//! assert_eq!(want[1].kind(), RecordKind::Aaaa);
//! assert_eq!(want[2].txt_key(), Some("dnsaddr="));
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
}

impl RecordKind {
    /// The DNS type name: `A`, `AAAA` or `TXT`.
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::A => "A",
            RecordKind::Aaaa => "AAAA",
            RecordKind::Txt => "TXT",
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
}

impl RecordValue {
    /// The record type.
    pub fn kind(&self) -> RecordKind {
        match self {
            RecordValue::A(_) => RecordKind::A,
            RecordValue::Aaaa(_) => RecordKind::Aaaa,
            RecordValue::Txt(_) => RecordKind::Txt,
        }
    }

    /// The value as providers store it (`content` / `data`).
    pub fn content(&self) -> String {
        match self {
            RecordValue::A(ip) => ip.to_string(),
            RecordValue::Aaaa(ip) => ip.to_string(),
            RecordValue::Txt(t) => t.clone(),
        }
    }

    /// Parses provider `content` for `kind`. TXT content is normalized with [`normalize_txt`].
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
        }
    }

    /// Same data, comparing TXT values after [`normalize_txt`].
    pub fn same_data(&self, other: &RecordValue) -> bool {
        match (self, other) {
            (RecordValue::Txt(a), RecordValue::Txt(b)) => normalize_txt(a) == normalize_txt(b),
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

    /// Checks the name against `zone`, the TTL and the TXT length.
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
