//! Public address discovery, IPv4 and IPv6 separately, by strict-majority agreement between
//! independent HTTPS echo sources.
//!
//! * [`discover`] (feature `public-ip`) asks the sources for the families you choose and
//!   returns the [`Discovered`] addresses. Requests for one family are forced onto that
//!   family (only A or only AAAA answers are dialled), so dual-stack hosts get both right.
//! * You can skip discovery and pass addresses you already know (for example from libp2p
//!   AutoNAT); [`require_global`] checks them the same way.
//! * When there is nothing worth publishing (private, CGNAT, loopback, documentation
//!   addresses, or no IPv6 connectivity) you get [`Error::NoGlobalAddress`], so a
//!   peer-to-peer app can fall back to relays.
//!
//! The decision logic is pure and always available ([`decide`], [`is_global_ipv4`],
//! [`is_global_ipv6`], [`extract`]):
//!
//! ```
//! use grindvakt_core::ip::{decide, Answer, Verdict};
//! use std::net::IpAddr;
//!
//! let a: IpAddr = "93.184.216.34".parse().unwrap();
//! let b: IpAddr = "93.184.216.35".parse().unwrap();
//! // Three of four sources agree: accepted.
//! assert_eq!(decide(&[Answer::Address(a), Answer::Address(a), Answer::Address(a), Answer::Address(b)]), Verdict::Found(a));
//! // Two against two: refused.
//! assert!(matches!(decide(&[Answer::Address(a), Answer::Address(a), Answer::Address(b), Answer::Address(b)]), Verdict::Disagree(_)));
//! // Sources agree on a CGNAT address: nothing to publish.
//! let cgnat: IpAddr = "100.64.1.2".parse().unwrap();
//! assert_eq!(decide(&[Answer::Address(cgnat), Answer::Address(cgnat)]), Verdict::NotGlobal(cgnat));
//! ```

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Which address families to discover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
    /// Both; succeeds if either is found.
    Both,
}

impl Family {
    /// Whether IPv4 is asked for.
    pub fn includes_v4(self) -> bool {
        matches!(self, Family::V4 | Family::Both)
    }
    /// Whether IPv6 is asked for.
    pub fn includes_v6(self) -> bool {
        matches!(self, Family::V6 | Family::Both)
    }
}

/// IPv4 sources Grindvakt queries by default.
pub const DEFAULT_V4_SOURCES: [&str; 4] = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://ipv4.icanhazip.com",
    "https://checkip.amazonaws.com",
];

/// IPv6 sources Grindvakt queries by default.
pub const DEFAULT_V6_SOURCES: [&str; 3] = [
    "https://api6.ipify.org",
    "https://ipv6.icanhazip.com",
    "https://v6.ident.me",
];

/// Where and how to look up addresses. Every field is yours to replace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sources {
    /// HTTPS URLs that answer with the caller's IPv4 address in the body.
    pub v4: Vec<String>,
    /// HTTPS URLs that answer with the caller's IPv6 address in the body.
    pub v6: Vec<String>,
    /// Per-request timeout.
    pub timeout: Duration,
    /// `User-Agent` header sent to the sources.
    pub user_agent: String,
}

impl Default for Sources {
    fn default() -> Self {
        Self {
            v4: DEFAULT_V4_SOURCES.iter().map(|s| s.to_string()).collect(),
            v6: DEFAULT_V6_SOURCES.iter().map(|s| s.to_string()).collect(),
            timeout: Duration::from_secs(4),
            user_agent: concat!(
                "grindvakt-core/",
                env!("CARGO_PKG_VERSION"),
                " (+https://grindvakt.weirdbrains.com)"
            )
            .to_string(),
        }
    }
}

/// Addresses found by [`discover`]. A family you did not ask for, or that has no global
/// address, is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Discovered {
    /// Public IPv4 address.
    pub v4: Option<Ipv4Addr>,
    /// Public IPv6 address.
    pub v6: Option<Ipv6Addr>,
}

/// One source's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The request failed (DNS, connect, TLS, timeout, HTTP error).
    Failed,
    /// The body held no address of the requested family.
    NoAddress,
    /// The address in the body (global or not).
    Address(IpAddr),
}

/// The verdict for one family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A strict majority agree on this global address.
    Found(IpAddr),
    /// A strict majority agree on this address, but it is not globally routable.
    NotGlobal(IpAddr),
    /// Every source failed.
    Unreachable,
    /// Sources answered but no address has a strict majority (why).
    Disagree(String),
}

/// Applies Grindvakt's rule: an address needs at least two votes and more than half of
/// the sources that answered with an address.
pub fn decide(answers: &[Answer]) -> Verdict {
    let mut votes: HashMap<IpAddr, usize> = HashMap::new();
    let mut answered = 0usize;
    for a in answers {
        if let Answer::Address(ip) = a {
            *votes.entry(*ip).or_insert(0) += 1;
            answered += 1;
        }
    }
    if answered == 0 {
        return if answers.iter().all(|a| *a == Answer::Failed) {
            Verdict::Unreachable
        } else {
            Verdict::Disagree("no source returned an address".into())
        };
    }
    match votes.iter().find(|(_, c)| **c >= 2 && **c > answered / 2) {
        Some((ip, _)) if is_global(*ip) => Verdict::Found(*ip),
        Some((ip, _)) => Verdict::NotGlobal(*ip),
        None => Verdict::Disagree(format!(
            "{answered} source(s) answered with {} different address(es); a strict majority of at least 2 is required",
            votes.len()
        )),
    }
}

/// Combines per-family verdicts into the [`discover`] result.
///
/// * Any family found: `Ok` with what was found.
/// * Otherwise, sources that disagree: [`Error::AddressLookup`].
/// * Otherwise, every requested family unreachable and IPv4 among them: [`Error::Network`]
///   (probably offline).
/// * Otherwise: [`Error::NoGlobalAddress`] (non-global answers, or no IPv6 route).
pub fn combine(v4: Option<Verdict>, v6: Option<Verdict>) -> Result<Discovered> {
    let mut out = Discovered::default();
    if let Some(Verdict::Found(IpAddr::V4(ip))) = v4 {
        out.v4 = Some(ip);
    }
    if let Some(Verdict::Found(IpAddr::V6(ip))) = v6 {
        out.v6 = Some(ip);
    }
    if out.v4.is_some() || out.v6.is_some() {
        return Ok(out);
    }
    let verdicts: Vec<(&str, &Verdict)> = [("IPv4", v4.as_ref()), ("IPv6", v6.as_ref())]
        .into_iter()
        .filter_map(|(n, v)| v.map(|v| (n, v)))
        .collect();
    if let Some((n, Verdict::Disagree(why))) = verdicts
        .iter()
        .find(|(_, v)| matches!(v, Verdict::Disagree(_)))
    {
        return Err(Error::AddressLookup(format!("{n}: {why}")));
    }
    let v4_unreachable = matches!(v4, Some(Verdict::Unreachable));
    if v4_unreachable && verdicts.iter().all(|(_, v)| **v == Verdict::Unreachable) {
        return Err(Error::Network("no address source could be reached".into()));
    }
    let detail: Vec<String> = verdicts
        .iter()
        .map(|(n, v)| match v {
            Verdict::NotGlobal(ip) => {
                format!("{n} sources see {ip}, which is not globally routable")
            }
            Verdict::Unreachable => format!("no {n} connectivity"),
            other => format!("{n}: {other:?}"),
        })
        .collect();
    Err(Error::NoGlobalAddress(detail.join("; ")))
}

/// Discovers public addresses for `family` from `sources`, querying every source of each
/// family concurrently. See [`combine`] for the errors.
#[cfg(feature = "public-ip")]
#[cfg_attr(docsrs, doc(cfg(feature = "public-ip")))]
pub async fn discover(family: Family, sources: &Sources) -> Result<Discovered> {
    let (v4, v6) = futures_util::future::join(
        async {
            if family.includes_v4() {
                Some(query_family(false, &sources.v4, sources).await)
            } else {
                None
            }
        },
        async {
            if family.includes_v6() {
                Some(query_family(true, &sources.v6, sources).await)
            } else {
                None
            }
        },
    )
    .await;
    combine(v4, v6)
}

#[cfg(feature = "public-ip")]
async fn query_family(v6: bool, urls: &[String], sources: &Sources) -> Verdict {
    let client = match reqwest::Client::builder()
        .user_agent(sources.user_agent.clone())
        .timeout(sources.timeout)
        .dns_resolver(std::sync::Arc::new(FamilyResolver { v6 }))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Verdict::Unreachable,
    };
    let futs = urls.iter().map(|url| {
        let c = client.clone();
        async move {
            match c.get(url).send().await.and_then(|r| r.error_for_status()) {
                Ok(r) => match r.text().await {
                    Ok(t) => match extract(&t, v6) {
                        Some(ip) => Answer::Address(ip),
                        None => Answer::NoAddress,
                    },
                    Err(_) => Answer::Failed,
                },
                Err(_) => Answer::Failed,
            }
        }
    });
    decide(&futures_util::future::join_all(futs).await)
}

/// Resolves host names to addresses of one family only, so a request goes out over IPv4 or
/// IPv6 as asked.
#[cfg(feature = "public-ip")]
struct FamilyResolver {
    v6: bool,
}

#[cfg(feature = "public-ip")]
impl reqwest::dns::Resolve for FamilyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let v6 = self.v6;
        let host = format!("{}:0", name.as_str());
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(host)
                .await?
                .filter(|a| a.is_ipv6() == v6)
                .collect();
            if addrs.is_empty() {
                return Err(Box::new(std::io::Error::other(if v6 {
                    "host has no IPv6 address"
                } else {
                    "host has no IPv4 address"
                }))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The first address of the requested family in `body` (IPv6 when `v6`), global or not.
///
/// ```
/// use grindvakt_core::ip::extract;
/// assert_eq!(extract("ip=93.184.216.34\n", false), Some("93.184.216.34".parse().unwrap()));
/// assert_eq!(extract("2606:4700:4700::1111\n", true), Some("2606:4700:4700::1111".parse().unwrap()));
/// assert_eq!(extract("2606:4700:4700::1111\n", false), None);
/// ```
pub fn extract(body: &str, v6: bool) -> Option<IpAddr> {
    body.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .filter(|t| !t.is_empty())
        .find_map(|t| {
            let ip: IpAddr = t.parse().or_else(|_| t.trim_matches(':').parse()).ok()?;
            (ip.is_ipv6() == v6).then_some(ip)
        })
}

/// Returns `ip` if it is globally routable, else [`Error::NoGlobalAddress`]. Use it for
/// addresses you supply yourself.
pub fn require_global(ip: IpAddr) -> Result<IpAddr> {
    if is_global(ip) {
        Ok(ip)
    } else {
        Err(Error::NoGlobalAddress(format!(
            "{ip} is not globally routable"
        )))
    }
}

/// [`is_global_ipv4`] or [`is_global_ipv6`].
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_ipv4(v4),
        IpAddr::V6(v6) => is_global_ipv6(v6),
    }
}

/// False for private, loopback, link-local, multicast, broadcast/reserved (240/4),
/// documentation, `0/8`, CGNAT (`100.64/10`) and benchmarking (`198.18/15`) addresses.
pub fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    let oct = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || oct[0] >= 240
        || ip.is_documentation()
        || oct[0] == 0
        || (oct[0] == 100 && (oct[1] & 0b1100_0000) == 0b0100_0000)
        || (oct[0] == 198 && (oct[1] == 18 || oct[1] == 19)))
}

/// True only for global unicast (`2000::/3`), excluding documentation (`2001:db8::/32`),
/// Teredo (`2001::/32`), benchmarking (`2001:2::/48`) and 6to4 (`2002::/16`) addresses.
pub fn is_global_ipv6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] == 0x0db8)
        && !(s[0] == 0x2001 && s[1] == 0x0000)
        && !(s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0)
        && s[0] != 0x2002
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtering_v4() {
        for bad in [
            "10.0.0.1",
            "192.168.0.1",
            "127.0.0.1",
            "169.254.1.10",
            "100.64.0.1",
            "198.18.0.1",
            "0.1.2.3",
            "240.0.0.1",
            "192.0.2.5",
        ] {
            assert!(!is_global_ipv4(bad.parse().unwrap()), "{bad}");
        }
        assert!(is_global_ipv4("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn filtering_v6() {
        for bad in [
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "2001::1",
            "2002:c000:0204::1",
            "ff02::1",
            "::ffff:1.2.3.4",
        ] {
            assert!(!is_global_ipv6(bad.parse().unwrap()), "{bad}");
        }
        assert!(is_global_ipv6("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn majority() {
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        let a = Answer::Address(ip);
        assert!(
            matches!(
                decide(&[a, Answer::Failed, Answer::Failed]),
                Verdict::Disagree(_)
            ),
            "one vote is never enough"
        );
        assert_eq!(
            decide(&[a, a, Answer::Failed, Answer::NoAddress]),
            Verdict::Found(ip)
        );
        assert_eq!(
            decide(&[Answer::Failed, Answer::Failed]),
            Verdict::Unreachable
        );
    }

    #[test]
    fn combining() {
        let v4: IpAddr = "93.184.216.34".parse().unwrap();
        let v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        let both = combine(Some(Verdict::Found(v4)), Some(Verdict::Found(v6))).unwrap();
        assert_eq!(both.v4, Some("93.184.216.34".parse().unwrap()));
        assert_eq!(both.v6, Some("2606:4700:4700::1111".parse().unwrap()));
        // IPv4 only, no IPv6 route: fine.
        let d = combine(Some(Verdict::Found(v4)), Some(Verdict::Unreachable)).unwrap();
        assert_eq!(d.v6, None);
        // CGNAT-looking and no IPv6: nothing to publish.
        let e = combine(
            Some(Verdict::NotGlobal("100.64.0.9".parse().unwrap())),
            Some(Verdict::Unreachable),
        )
        .unwrap_err();
        assert!(matches!(e, Error::NoGlobalAddress(_)), "{e}");
        // Offline.
        let e = combine(Some(Verdict::Unreachable), Some(Verdict::Unreachable)).unwrap_err();
        assert!(matches!(e, Error::Network(_)), "{e}");
        // IPv6 asked alone, no route: no global address.
        let e = combine(None, Some(Verdict::Unreachable)).unwrap_err();
        assert!(matches!(e, Error::NoGlobalAddress(_)), "{e}");
        // Disagreement.
        let e = combine(Some(Verdict::Disagree("x".into())), None).unwrap_err();
        assert!(matches!(e, Error::AddressLookup(_)), "{e}");
        assert!(matches!(
            require_global("10.1.1.1".parse().unwrap()),
            Err(Error::NoGlobalAddress(_))
        ));
    }
}
