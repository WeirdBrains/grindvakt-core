//! Configuration: which provider, which record, which TTL and how often.
//!
//! The on-disk form is the TOML that the Grindvakt app writes to `config.toml`:
//!
//! ```toml
//! provider = "dnsimple"
//! account_id = 1234
//! zone = "example.net"
//! name = "home"
//! ttl = 300
//! sandbox = false
//!
//! [schedule]
//! interval_secs = 300
//! ```

use crate::error::{Error, IoContext, Result};
use crate::fs::{Privacy, atomic_write_private_with};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

/// File name the Grindvakt app uses for the config inside its data directory.
pub const CONFIG_FILE_NAME: &str = "config.toml";
/// Smallest TTL accepted, in seconds.
pub const MIN_TTL: u32 = 60;
/// TTL used when the config does not set one, in seconds.
pub const DEFAULT_TTL: u32 = 300;

/// A supported DNS provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// DNSimple (<https://dnsimple.com>).
    #[default]
    Dnsimple,
    /// DigitalOcean DNS (<https://www.digitalocean.com>).
    Digitalocean,
}

impl Provider {
    /// Every provider, in a stable order.
    pub const ALL: [Provider; 2] = [Provider::Dnsimple, Provider::Digitalocean];

    /// The lowercase name used in config files and on the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Dnsimple => "dnsimple",
            Provider::Digitalocean => "digitalocean",
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Provider {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dnsimple" => Ok(Provider::Dnsimple),
            "digitalocean" => Ok(Provider::Digitalocean),
            other => Err(Error::Config(format!(
                "unsupported provider {other:?}; choose dnsimple or digitalocean"
            ))),
        }
    }
}

/// When the updater runs: a calendar expression or a fixed interval (exactly one).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    /// A systemd `OnCalendar` expression. Portable timing ([`crate::schedule::next_wait`])
    /// understands `hourly`, `daily` and `*:0/10`.
    #[serde(default)]
    pub calendar: Option<String>,
    /// Polling interval in seconds (at least 60).
    #[serde(default)]
    pub interval_secs: Option<u64>,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            calendar: None,
            interval_secs: Some(300),
        }
    }
}

/// The updater's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    /// Active DNS provider.
    #[serde(default)]
    pub provider: Provider,
    /// DNSimple account id. When unset, DNSimple's `whoami` supplies it.
    #[serde(default)]
    pub account_id: Option<u64>,
    /// DNS zone, for example `example.com`.
    pub zone: String,
    /// Record name: `@` for the apex, a relative label such as `www`, or a full name.
    pub name: String,
    /// TTL in seconds (at least [`MIN_TTL`]).
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Use the DNSimple sandbox API.
    #[serde(default)]
    pub sandbox: bool,
    /// Override the provider API base URL (tests and mocks).
    #[serde(default)]
    pub api_base_url: Option<String>,
    /// When to run.
    #[serde(default)]
    pub schedule: Schedule,
}

fn default_ttl() -> u32 {
    DEFAULT_TTL
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            provider: Provider::default(),
            account_id: None,
            zone: "example.com".to_string(),
            name: "@".to_string(),
            ttl: DEFAULT_TTL,
            sandbox: false,
            api_base_url: None,
            schedule: Schedule::default(),
        }
    }
}

impl AppConfig {
    /// Checks TTL, zone, name and that a schedule is set.
    pub fn validate(&self) -> Result<()> {
        if self.ttl < MIN_TTL {
            return Err(Error::Config(format!("ttl must be >= {MIN_TTL}")));
        }
        if self.zone.trim().is_empty() {
            return Err(Error::Config("zone must be set".into()));
        }
        if self.name.trim().is_empty() {
            return Err(Error::Config("name must be set".into()));
        }
        if self.schedule.calendar.is_none() && self.schedule.interval_secs.is_none() {
            return Err(Error::Config(
                "schedule must set either calendar or interval_secs".into(),
            ));
        }
        Ok(())
    }

    /// The record's fully qualified name, without a trailing dot.
    pub fn record_fqdn(&self) -> String {
        normalize_fqdn(&self.zone, &self.name)
    }

    /// Parses and validates TOML.
    pub fn from_toml_str(text: &str) -> Result<Self> {
        let cfg: AppConfig = toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Serializes to the same pretty TOML the Grindvakt app writes.
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))
    }

    /// Reads, parses and validates a config file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).ctx(|| format!("reading {}", path.display()))?;
        Self::from_toml_str(&text)
            .map_err(|e| Error::Config(format!("parsing {}: {e}", path.display())))
    }

    /// Writes the config atomically, private to the current user
    /// (see [`crate::fs::atomic_write_private`]).
    pub fn save(&self, path: &Path) -> Result<()> {
        self.save_with(path, Privacy::CurrentUser)
    }

    /// [`AppConfig::save`] under an explicit [`Privacy`] policy, such as
    /// [`Privacy::Service`] for data a system service reads.
    pub fn save_with(&self, path: &Path, privacy: Privacy) -> Result<()> {
        let text = self.to_toml_string()?;
        atomic_write_private_with(path, text.as_bytes(), privacy)
    }
}

/// Joins a zone and a record name into one name without a trailing dot.
///
/// ```
/// use grindvakt_core::config::normalize_fqdn;
/// assert_eq!(normalize_fqdn("example.com", "@"), "example.com");
/// assert_eq!(normalize_fqdn("example.com.", "www"), "www.example.com");
/// assert_eq!(normalize_fqdn("example.com", "api.example.com."), "api.example.com");
/// ```
pub fn normalize_fqdn(zone: &str, name: &str) -> String {
    let z = zone.trim_end_matches('.').to_string();
    let n = name.trim().trim_end_matches('.');
    if n == "@" || n.is_empty() {
        z
    } else if n.ends_with(&z) {
        n.to_string()
    } else {
        format!("{}.", n) + &z
    }
}

/// The record name relative to its zone: `""` for the apex (DNSimple's convention).
///
/// ```
/// use grindvakt_core::config::relative_name;
/// assert_eq!(relative_name("example.com", "@"), "");
/// assert_eq!(relative_name("example.com", "home.example.com"), "home");
/// assert_eq!(relative_name("example.com", "www"), "www");
/// ```
pub fn relative_name(zone: &str, name: &str) -> String {
    let zone = zone.trim_end_matches('.').to_string();
    let name = name.trim().trim_end_matches('.');
    if name == "@" || name.is_empty() || name == zone {
        String::new()
    } else if name.ends_with(&zone) {
        name.trim_end_matches('.')
            .trim_end_matches(&zone)
            .trim_end_matches('.')
            .to_string()
    } else {
        name.to_string()
    }
}

/// Input checks used when collecting a config interactively.
pub mod validate {
    use regex::Regex;
    use std::sync::LazyLock;

    static FQDN: LazyLock<Regex> = LazyLock::new(|| {
        let label = r"(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])";
        Regex::new(&format!("^({label}\\.)+[a-z{{2,}}A-Z{{2,}}]+$")).expect("static regex")
    });
    static LABEL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$").expect("static regex")
    });

    /// A domain such as `example.com` (labels of letters, digits and hyphens; a dot needed).
    ///
    /// ```
    /// use grindvakt_core::config::validate::is_valid_fqdn;
    /// assert!(is_valid_fqdn("api.example.co.uk"));
    /// assert!(!is_valid_fqdn("bad_underscore.example.com"));
    /// ```
    pub fn is_valid_fqdn(s: &str) -> bool {
        FQDN.is_match(s.trim_end_matches('.'))
    }

    /// One DNS label of two or more characters.
    pub fn is_valid_label(label: &str) -> bool {
        LABEL.is_match(label)
    }

    /// `@`, relative labels such as `www` or `home.office`, or a full name inside `zone`.
    pub fn is_valid_record_name(zone: &str, name: &str) -> bool {
        let n = name.trim();
        if n == "@" {
            return true;
        }
        if n.split('.')
            .all(|lbl| !lbl.is_empty() && is_valid_label(lbl))
        {
            return true;
        }
        is_valid_fqdn(n) && n.ends_with(zone.trim_end_matches('.'))
    }

    /// The cheap calendar check used when `systemd-analyze` is not available: not empty,
    /// no newline, no `%`, at most 256 bytes.
    pub fn calendar_is_plausible(expr: &str) -> bool {
        let t = expr.trim();
        !t.is_empty() && !t.contains('\n') && !t.contains('%') && t.len() <= 256
    }
}
