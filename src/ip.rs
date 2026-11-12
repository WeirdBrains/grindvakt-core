//! Public IPv4 discovery by strict-majority agreement between independent HTTPS sources.
//!
//! The pure parts ([`is_global_ipv4`], [`extract_ipv4`], [`consensus`]) are always
//! available. [`PublicIpConsensus::resolve`] makes the HTTPS requests and needs the
//! `public-ip` feature.
//!
//! ```
//! use grindvakt_core::ip::consensus;
//! use std::net::Ipv4Addr;
//!
//! let a: Ipv4Addr = "93.184.216.34".parse().unwrap();
//! let b: Ipv4Addr = "93.184.216.35".parse().unwrap();
//! // Three of four sources agree: accepted.
//! assert_eq!(consensus(&[Some(a), Some(a), Some(a), Some(b)]).unwrap(), a);
//! // Two against two: refused.
//! assert!(consensus(&[Some(a), Some(a), Some(b), Some(b)]).is_err());
//! ```

use crate::error::{Error, Result};
use regex::Regex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::LazyLock;
use std::time::Duration;

/// The sources Grindvakt queries by default.
pub const DEFAULT_SOURCES: [&str; 4] = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://ipv4.icanhazip.com",
    "https://checkip.amazonaws.com",
];

static IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)\b(\d{1,3}(?:\.\d{1,3}){3})\b").expect("static regex"));

/// How to look up the public IPv4 address.
#[derive(Debug, Clone)]
pub struct PublicIpConsensus {
    /// HTTPS URLs that answer with the caller's address in the body.
    pub sources: Vec<String>,
    /// Per-request timeout.
    pub timeout: Duration,
    /// `User-Agent` header sent to the sources.
    pub user_agent: String,
}

impl Default for PublicIpConsensus {
    fn default() -> Self {
        Self {
            sources: DEFAULT_SOURCES.iter().map(|s| s.to_string()).collect(),
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

impl PublicIpConsensus {
    /// Queries every source concurrently and applies [`consensus`].
    #[cfg(feature = "public-ip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "public-ip")))]
    pub async fn resolve(&self) -> Result<Ipv4Addr> {
        let client = reqwest::Client::builder()
            .user_agent(self.user_agent.clone())
            .timeout(self.timeout)
            .use_rustls_tls()
            .build()
            .map_err(|e| Error::PublicIp(format!("http client: {e}")))?;
        let futs = self.sources.iter().map(|url| {
            let c = client.clone();
            async move {
                match c.get(url).send().await {
                    Ok(r) => r.text().await.ok().and_then(|t| extract_ipv4(&t)),
                    Err(_) => None,
                }
            }
        });
        let results = futures_util::future::join_all(futs).await;
        consensus(&results)
    }
}

/// Picks the address that at least two sources and a strict majority of the answering
/// sources agree on, and checks it is globally routable. `None` entries are sources that
/// failed or gave no usable address.
pub fn consensus(results: &[Option<Ipv4Addr>]) -> Result<Ipv4Addr> {
    let mut seen: HashMap<Ipv4Addr, usize> = HashMap::new();
    let mut success = 0usize;
    for ip in results.iter().flatten() {
        *seen.entry(*ip).or_insert(0) += 1;
        success += 1;
    }
    if seen.is_empty() {
        return Err(Error::PublicIp("no public IPv4 sources succeeded".into()));
    }
    let ip = choose_strict_majority(&seen, success).ok_or_else(|| {
        Error::PublicIp("no consensus on public IPv4 (strict majority required)".into())
    })?;
    if !is_global_ipv4(ip) {
        return Err(Error::PublicIp(format!(
            "resolved IPv4 not global routable: {ip}"
        )));
    }
    Ok(ip)
}

/// The address with at least two votes and more than half of `success_count`, if any.
pub fn choose_strict_majority(
    counts: &HashMap<Ipv4Addr, usize>,
    success_count: usize,
) -> Option<Ipv4Addr> {
    counts
        .iter()
        .find(|(_, c)| **c >= 2 && **c > success_count / 2)
        .map(|(ip, _)| *ip)
}

/// The first dotted-quad in `body`, if it is a global address.
pub fn extract_ipv4(body: &str) -> Option<Ipv4Addr> {
    let caps = IPV4.captures(body)?;
    let ip: Ipv4Addr = caps.get(1)?.as_str().parse().ok()?;
    is_global_ipv4(ip).then_some(ip)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtering() {
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
        assert_eq!(
            extract_ipv4("ip=93.184.216.34\n"),
            Some("93.184.216.34".parse().unwrap())
        );
        assert_eq!(extract_ipv4("10.0.0.1"), None);
    }

    #[test]
    fn majority() {
        let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();
        let a = Some(ip);
        assert!(
            consensus(&[a, None, None, None]).is_err(),
            "one vote is never enough"
        );
        assert_eq!(consensus(&[a, a, None, None]).unwrap(), ip);
        assert!(consensus(&[None, None]).is_err());
    }
}
