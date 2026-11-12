//! The crate's error type.

use crate::config::Provider;
use std::time::Duration;

/// Everything that can go wrong in `grindvakt-core`.
///
/// The variants are meant to be matched by a UI: [`Error::Auth`], [`Error::RateLimited`],
/// [`Error::Ambiguous`], [`Error::NoGlobalAddress`], [`Error::Network`] and
/// [`Error::Provider`] each call for a different message. Messages never contain secrets
/// (tokens, passwords, recovery words or keys) or request URLs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The provider rejected the token (HTTP 401/403, or an account that is not in good
    /// standing).
    #[error("{provider}: authentication failed: {message}")]
    Auth {
        /// Provider name, such as `dnsimple`.
        provider: String,
        /// What the provider said.
        message: String,
    },
    /// The provider is throttling requests (HTTP 429).
    #[error("{provider}: rate limited{}", .retry_after.map(|d| format!(", retry after {}s", d.as_secs())).unwrap_or_default())]
    RateLimited {
        /// Provider name.
        provider: String,
        /// How long the provider asked us to wait, when it said.
        retry_after: Option<Duration>,
    },
    /// The provider or address sources could not be reached (DNS, connect, TLS, timeout).
    #[error("network: {0}")]
    Network(String),
    /// A provider API call failed or returned something unexpected.
    #[error("{provider} API: {message}")]
    Provider {
        /// Provider name.
        provider: String,
        /// What went wrong (status code or error text; never the token).
        message: String,
    },
    /// Planning found records it will not guess about (for example two `A` records where
    /// one is wanted); nothing was changed.
    #[error("refusing to modify records: {0}")]
    Ambiguous(String),
    /// There is no globally routable address to publish: the sources agree on a private,
    /// CGNAT or otherwise non-global address, or (for IPv6) there is no IPv6 connectivity.
    /// A peer-to-peer app should fall back to relays.
    #[error("no global address: {0}")]
    NoGlobalAddress(String),
    /// Address sources answered but did not agree (no strict majority).
    #[error("address lookup: {0}")]
    AddressLookup(String),
    /// A record you asked for is invalid (name, TTL or TXT value).
    #[error("invalid record: {0}")]
    InvalidRecord(String),
    /// A configuration value is missing or out of range.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// Reading, writing or locking a file failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done, including the path.
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A path was refused for safety (symlink, reparse point, wrong owner or insecure ACL).
    #[error("insecure path: {0}")]
    InsecurePath(String),
    /// Another process holds the single-instance lock.
    #[error("already running: {0}")]
    Locked(String),
    /// The password or recovery phrase is wrong, or the vault was tampered with.
    #[error("wrong password or recovery phrase, or the vault was tampered with")]
    WrongSecret,
    /// The recovery phrase is not 24 valid BIP39 English words.
    #[error("invalid recovery phrase: {0}")]
    InvalidRecoveryPhrase(String),
    /// The vault file has an unsupported version or out-of-bounds KDF parameters.
    #[error("unsupported vault: {0}")]
    UnsupportedVault(String),
    /// The vault file could not be parsed or decoded.
    #[error("corrupt vault: {0}")]
    CorruptVault(String),
    /// The vault has no token stored for this provider.
    #[error("no {0} token is stored in the vault")]
    TokenMissing(Provider),
    /// A cryptographic primitive failed (for example, no system randomness).
    #[error("crypto failure: {0}")]
    Crypto(String),
}

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    /// A [`Error::Provider`] error, for your own [`crate::provider::DnsProvider`]s.
    pub fn provider(provider: impl Into<String>, message: impl std::fmt::Display) -> Self {
        Error::Provider {
            provider: provider.into(),
            message: message.to_string(),
        }
    }

    /// Whether retrying later could help (network trouble, throttling, provider 5xx-type
    /// failures). Auth, ambiguity, bad input and missing addresses are not retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Network(_)
                | Error::RateLimited { .. }
                | Error::Provider { .. }
                | Error::AddressLookup(_)
        )
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Error::Io {
            context: "I/O".into(),
            source,
        }
    }
}

#[cfg(feature = "vault")]
impl From<weirdnet_keys::KeysError> for Error {
    fn from(e: weirdnet_keys::KeysError) -> Self {
        match e {
            weirdnet_keys::KeysError::Unlock(_) => Error::WrongSecret,
            other => Error::Crypto(other.to_string()),
        }
    }
}

/// Attach context to `std::io::Result`.
#[allow(dead_code)]
pub(crate) trait IoContext<T> {
    fn ctx(self, f: impl FnOnce() -> String) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn ctx(self, f: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::io(f(), e))
    }
}
