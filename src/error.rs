//! The crate's error type.

use crate::config::Provider;

/// Everything that can go wrong in `grindvakt-core`.
///
/// Messages never contain secrets (tokens, passwords, recovery words or keys).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A configuration value is missing or out of range.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// A schedule cannot be used (bad calendar, interval too small, both or neither set).
    #[error("invalid schedule: {0}")]
    Schedule(String),
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
    /// A DNS provider API call failed or returned something unexpected.
    #[error("{provider} API: {message}")]
    Provider {
        /// The provider that failed.
        provider: Provider,
        /// What went wrong (status code or error text; never the token).
        message: String,
    },
    /// Sync refused to touch DNS because the current records are ambiguous.
    #[error("refusing to modify records: {0}")]
    Ambiguous(String),
    /// Public IPv4 lookup failed or the sources disagreed.
    #[error("public IPv4 lookup: {0}")]
    PublicIp(String),
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
    #[allow(dead_code)]
    pub(crate) fn provider(provider: Provider, message: impl std::fmt::Display) -> Self {
        Error::Provider {
            provider,
            message: message.to_string(),
        }
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

impl From<weirdnet_keys::KeysError> for Error {
    fn from(e: weirdnet_keys::KeysError) -> Self {
        match e {
            weirdnet_keys::KeysError::Unlock(_) => Error::WrongSecret,
            other => Error::Crypto(other.to_string()),
        }
    }
}

/// Attach context to `std::io::Result`.
pub(crate) trait IoContext<T> {
    fn ctx(self, f: impl FnOnce() -> String) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn ctx(self, f: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::io(f(), e))
    }
}
