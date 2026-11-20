//! Where a `CNAME` record's content comes from: a fixed target name, or a Weirdnet resource
//! link whose authority is the target (feature `weirdnet`).
//!
//! ```
//! use grindvakt_core::cname::CnameSource;
//! let s = CnameSource::Target("Home.Example.com.".into());
//! assert_eq!(s.target().unwrap(), "home.example.com");
//! ```
//!
//! With feature `weirdnet`, `weirdnet-morph://home.example.com/notes/a.md` gives the target
//! `home.example.com`. Parsing the link is [`weirdnet_schemes::Link::parse`]; this module only
//! decides which links Grindvakt accepts as CNAME content:
//!
//! * a resource link (`<scheme>://<authority>/<path>`) on a first-party `weirdnet-<app>`
//!   scheme;
//! * whose authority is a full DNS host name (two or more labels, not an IP address).
//!
//! Invitation links (`join/`, `answer/`), user ids and other names without a dot, ports,
//! credentials, the bare `weirdnet://` scheme and other apps' schemes are refused. An error
//! never repeats a join or answer link, because its code is a secret.

use crate::error::{Error, Result};
use crate::record::{is_valid_target, normalize_target};

/// The scheme prefix of first-party Weirdnet apps (`weirdnet-morph`, `weirdnet-muninn`).
#[cfg(feature = "weirdnet")]
const FIRST_PARTY_PREFIX: &str = "weirdnet-";

/// The content of a `CNAME` record before it is resolved to a target name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CnameSource {
    /// A full host name, such as `home.example.com` (a trailing dot is optional).
    Target(String),
    /// A Weirdnet resource link, such as `weirdnet-morph://home.example.com/notes`. Resolving
    /// needs feature `weirdnet`; without it [`CnameSource::target`] fails with
    /// [`Error::Config`].
    WeirdnetLink(String),
}

impl CnameSource {
    /// The normalized target name (lowercase, no trailing dot) this source stands for.
    ///
    /// Nothing is looked up: the name comes from the text alone, so the same input always
    /// gives the same target.
    pub fn target(&self) -> Result<String> {
        match self {
            CnameSource::Target(t) => {
                let n = normalize_target(t);
                if is_valid_target(&n) {
                    Ok(n)
                } else {
                    Err(Error::InvalidRecord(format!(
                        "CNAME target {t:?} is not a full host name"
                    )))
                }
            }
            CnameSource::WeirdnetLink(link) => weirdnet_link_target(link),
        }
    }
}

/// The CNAME target named by a Weirdnet resource link: its authority, as a full host name.
///
/// Needs feature `weirdnet`. See the [module docs](self) for what is accepted.
#[cfg(feature = "weirdnet")]
#[cfg_attr(docsrs, doc(cfg(feature = "weirdnet")))]
pub fn weirdnet_link_target(link: &str) -> Result<String> {
    use weirdnet_schemes::{Action, Link};

    let bad = |why: &str| {
        Error::InvalidRecord(format!(
            "Weirdnet link is not usable as CNAME content: {why}"
        ))
    };
    let parsed = Link::parse(link.trim())
        .map_err(|e| Error::InvalidRecord(format!("not a valid Weirdnet link: {e}")))?;
    if !parsed.scheme.starts_with(FIRST_PARTY_PREFIX) {
        return Err(bad(
            "the scheme must be a first-party weirdnet-<app> scheme",
        ));
    }
    let authority = match parsed.action {
        Action::Resource { authority, .. } => authority,
        Action::Join(_) | Action::Answer(_) => {
            return Err(bad(
                "an invitation (join or answer) link names no host; use a resource link such as weirdnet-<app>://home.example.com/path",
            ));
        }
    };
    if authority.contains(['@', ':', '[', ']']) {
        return Err(bad(
            "the authority must be a bare host name (no user, port or IP literal)",
        ));
    }
    let target = normalize_target(&authority);
    let numeric_tld = target
        .rsplit('.')
        .next()
        .is_some_and(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()));
    if !is_valid_target(&target) || numeric_tld {
        return Err(bad(
            "the authority must be a full DNS host name (two or more labels, not an IP address or a user id)",
        ));
    }
    Ok(target)
}

/// Without feature `weirdnet` a link cannot be resolved.
#[cfg(not(feature = "weirdnet"))]
fn weirdnet_link_target(_link: &str) -> Result<String> {
    Err(Error::Config(
        "Weirdnet links need grindvakt-core's `weirdnet` feature".into(),
    ))
}

#[cfg(all(test, feature = "weirdnet"))]
mod tests {
    use super::*;

    fn ok(l: &str) -> String {
        weirdnet_link_target(l).unwrap()
    }
    fn err(l: &str) -> String {
        weirdnet_link_target(l).unwrap_err().to_string()
    }

    #[test]
    fn resource_links_give_their_authority() {
        assert_eq!(
            ok("weirdnet-morph://home.example.com/notes/a.md"),
            "home.example.com"
        );
        assert_eq!(ok("weirdnet-morph://home.example.com"), "home.example.com");
        assert_eq!(ok("weirdnet-morph://home.example.com/"), "home.example.com");
        assert_eq!(
            ok("WEIRDNET-MUNINN://Home.Example.COM/x?y=1#z"),
            "home.example.com"
        );
        assert_eq!(
            ok("  weirdnet-morph://a.b.example.org./p  "),
            "a.b.example.org"
        );
        assert_eq!(
            ok("weirdnet-morph://my_host.example.com/p"),
            "my_host.example.com"
        );
    }

    #[test]
    fn invitations_are_refused_without_echoing_the_code() {
        for l in [
            "weirdnet-morph://join/SECRETCODE",
            "weirdnet-morph://answer/SECRETCODE",
        ] {
            let e = err(l);
            assert!(e.contains("invitation"), "{e}");
            assert!(!e.contains("SECRETCODE"), "{e}");
        }
    }

    #[test]
    fn bad_authorities_are_refused() {
        // a user id or peer id: no dot
        assert!(
            err("weirdnet-morph://12D3KooWHp56KezbVCubjuznJGqyn9xTe8PWePfuwv4YQUGxaRBB/x")
                .contains("full DNS host name")
        );
        assert!(err("weirdnet-morph://localhost/x").contains("full DNS host name"));
        // IP addresses
        assert!(err("weirdnet-morph://192.0.2.1/x").contains("full DNS host name"));
        assert!(err("weirdnet-morph://[2001:db8::1]/x").contains("bare host name"));
        // port and credentials
        assert!(err("weirdnet-morph://home.example.com:443/x").contains("bare host name"));
        assert!(err("weirdnet-morph://me@home.example.com/x").contains("bare host name"));
        // labels
        assert!(err("weirdnet-morph://-a.example.com/x").contains("full DNS host name"));
        assert!(err("weirdnet-morph://a..example.com/x").contains("full DNS host name"));
        assert!(err("weirdnet-morph://exa%6dple.com/x").contains("full DNS host name"));
    }

    #[test]
    fn schemes_and_shapes_are_refused() {
        assert!(err("weirdnet://home.example.com/x").contains("not a valid Weirdnet link"));
        assert!(err("https://home.example.com/x").contains("not a valid Weirdnet link"));
        assert!(err("home.example.com").contains("not a valid Weirdnet link"));
        assert!(err("").contains("not a valid Weirdnet link"));
        assert!(err("weirdnet-morph://").contains("not a valid Weirdnet link"));
        assert!(err("weirdnet-morph://home.example.com/a b").contains("not a valid Weirdnet link"));
        assert!(err("someapp://home.example.com/x").contains("first-party"));
    }

    #[test]
    fn source_resolves_either_way() {
        let t = CnameSource::Target("Home.Example.com".into());
        let l = CnameSource::WeirdnetLink("weirdnet-morph://home.example.com/x".into());
        assert_eq!(t.target().unwrap(), l.target().unwrap());
        assert!(CnameSource::Target("nodots".into()).target().is_err());
    }
}
