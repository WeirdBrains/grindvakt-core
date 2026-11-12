//! The encrypted token vault (`vault.json`, format version 1).
//!
//! Provider tokens are encrypted with a random 256-bit data key (the DEK) using
//! XChaCha20-Poly1305. The DEK is wrapped twice: by a key derived from the password with
//! Argon2id (64 MiB, 3 passes, 1 lane by default), and by a key derived from a 24-word BIP39
//! recovery phrase with HKDF-SHA256. Either one unlocks the vault; the recovery phrase can
//! reset a forgotten password. All primitives come from [`weirdnet_keys`].
//!
//! The file layout is byte-for-byte the one Grindvakt 0.x wrote, so existing vaults open
//! unchanged and vaults written here open in older Grindvakt releases:
//!
//! | field | content |
//! |---|---|
//! | `salt_password`, `salt_recovery` | base64, 16 random bytes each |
//! | `dek_wrapped_by_password`, `dek_wrapped_by_recovery` | base64(nonce(24) ‖ ciphertext+tag) |
//! | `secrets_aead_nonce` / `secrets_aead_ciphertext` | base64 nonce / base64 ciphertext+tag of the token JSON |
//!
//! Every AEAD call uses the associated data `grindvakt-vault-v1`.
//!
//! ```
//! use grindvakt_core::config::Provider;
//! use grindvakt_core::vault::{KdfParams, Tokens, Vault};
//! use grindvakt_core::{ExposeSecret, SecretString};
//!
//! # fn main() -> grindvakt_core::Result<()> {
//! let password = SecretString::from("correct horse battery staple".to_string());
//! let mut tokens = Tokens::default();
//! tokens.set(Provider::Dnsimple, SecretString::from("dnsimple-token".to_string()));
//!
//! // Small KDF settings keep the doctest quick; real vaults use `KdfParams::default()`.
//! let (vault, recovery) = Vault::create_with_kdf(&password, &tokens, KdfParams::testing())?;
//!
//! let dek = vault.unlock_with_password(&password)?;
//! assert_eq!(vault.token(&dek, Provider::Dnsimple)?.expose_secret(), "dnsimple-token");
//!
//! let dek2 = vault.unlock_with_recovery(&recovery)?;
//! assert_eq!(dek.as_bytes(), dek2.as_bytes());
//! # Ok(()) }
//! ```

use crate::config::Provider;
use crate::error::{Error, IoContext, Result};
use crate::fs::atomic_write_private;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use weirdnet_keys::{Key32, Sealed, Zeroizing, aead, kdf, words};

/// File name the Grindvakt app uses for the vault inside its data directory.
pub const VAULT_FILE_NAME: &str = "vault.json";
/// The only vault format version this crate reads and writes.
pub const VAULT_VERSION: u32 = 1;
/// Associated data bound into every AEAD operation, and the HKDF `info` for recovery keys.
pub const AAD_CONTEXT: &str = "grindvakt-vault-v1";

/// Accepted Argon2id memory, in MiB (inclusive bounds).
pub const KDF_MEMORY_MIB: std::ops::RangeInclusive<u32> = 64..=64;
/// Accepted Argon2id passes (inclusive bounds).
pub const KDF_ITERATIONS: std::ops::RangeInclusive<u32> = 1..=6;
/// Accepted Argon2id lanes (inclusive bounds).
pub const KDF_PARALLELISM: std::ops::RangeInclusive<u32> = 1..=4;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// The vault file exactly as stored on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFile {
    /// Format version; always [`VAULT_VERSION`].
    pub version: u32,
    /// Argon2id parameters for the password key.
    pub kdf: KdfParams,
    /// Base64 salt for the password key.
    pub salt_password: String,
    /// Base64 salt for the recovery key.
    pub salt_recovery: String,
    /// Base64 nonce ‖ ciphertext of the DEK under the password key.
    pub dek_wrapped_by_password: String,
    /// Base64 nonce ‖ ciphertext of the DEK under the recovery key.
    pub dek_wrapped_by_recovery: String,
    /// Base64 nonce of the token ciphertext.
    pub secrets_aead_nonce: String,
    /// Base64 ciphertext of the token JSON.
    pub secrets_aead_ciphertext: String,
    /// Creation time, seconds since the Unix epoch.
    pub created_unix: i64,
}

/// Argon2id parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in MiB.
    pub mem_mib: u32,
    /// Passes.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 1 lane: what Grindvakt has always used.
    fn default() -> Self {
        Self {
            mem_mib: 64,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfParams {
    /// The fastest parameters the bounds allow (64 MiB, 1 pass, 1 lane), for tests and examples.
    pub fn testing() -> Self {
        Self {
            mem_mib: 64,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Checks the parameters against [`KDF_MEMORY_MIB`], [`KDF_ITERATIONS`] and
    /// [`KDF_PARALLELISM`], so a hostile file cannot demand unbounded work.
    pub fn check(&self) -> Result<()> {
        if !KDF_MEMORY_MIB.contains(&self.mem_mib)
            || !KDF_ITERATIONS.contains(&self.iterations)
            || !KDF_PARALLELISM.contains(&self.parallelism)
        {
            return Err(Error::UnsupportedVault(
                "vault KDF parameters out of bounds".into(),
            ));
        }
        Ok(())
    }
}

/// The vault's data key. Wiped on drop and never printed.
#[derive(Clone)]
pub struct Dek(Key32);

impl Dek {
    /// Wraps 32 raw bytes, for example a DEK released by an OS credential store.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::Crypto(format!(
                "DEK must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Dek(Key32::from_slice(bytes)?))
    }

    /// The raw key bytes, for sealing into an OS credential store. Handle with care.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0.0
    }
}

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek(<redacted>)")
    }
}

/// A 24-word BIP39 (English) recovery phrase. Wiped on drop and never printed.
#[derive(Clone)]
pub struct RecoveryPhrase {
    words: SecretString,
    entropy: Key32,
}

impl RecoveryPhrase {
    /// A new phrase from 256 bits of operating-system randomness.
    pub fn generate() -> Result<Self> {
        let entropy = Key32::random()?;
        let words = words::to_words(&entropy)?;
        Ok(Self {
            words: SecretString::from(words.to_string()),
            entropy,
        })
    }

    /// Parses 24 words (any case and spacing; the BIP39 checksum is checked).
    pub fn parse(text: &str) -> Result<Self> {
        let entropy = words::from_words(text).map_err(|_| {
            Error::InvalidRecoveryPhrase("expected 24 valid BIP39 English words".into())
        })?;
        let words = words::to_words(&entropy)?;
        Ok(Self {
            words: SecretString::from(words.to_string()),
            entropy,
        })
    }

    /// The 24 words, lowercase and single-spaced, for showing to the user once.
    pub fn expose_words(&self) -> &str {
        self.words.expose_secret()
    }

    /// Whether `text` is the same phrase (ignoring case and spacing).
    pub fn matches(&self, text: &str) -> bool {
        RecoveryPhrase::parse(text)
            .map(|p| p.entropy == self.entropy)
            .unwrap_or(false)
    }

    fn key(&self, salt: &[u8]) -> Result<Key32> {
        Ok(kdf::hkdf(
            &self.entropy.0,
            Some(salt),
            AAD_CONTEXT.as_bytes(),
        )?)
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPhrase(<redacted>)")
    }
}

/// Provider tokens held in the vault.
#[derive(Clone, Default)]
pub struct Tokens {
    dnsimple: Option<SecretString>,
    digitalocean: Option<SecretString>,
}

impl Tokens {
    /// The token for `provider`, if stored.
    pub fn get(&self, provider: Provider) -> Option<&SecretString> {
        match provider {
            Provider::Dnsimple => self.dnsimple.as_ref(),
            Provider::Digitalocean => self.digitalocean.as_ref(),
        }
    }
    /// Stores (or replaces) the token for `provider`.
    pub fn set(&mut self, provider: Provider, token: SecretString) {
        match provider {
            Provider::Dnsimple => self.dnsimple = Some(token),
            Provider::Digitalocean => self.digitalocean = Some(token),
        }
    }
    /// Removes the token for `provider`.
    pub fn clear(&mut self, provider: Provider) {
        match provider {
            Provider::Dnsimple => self.dnsimple = None,
            Provider::Digitalocean => self.digitalocean = None,
        }
    }
    /// Which providers have a token.
    pub fn status(&self) -> TokenStatus {
        TokenStatus {
            dnsimple: self.dnsimple.is_some(),
            digitalocean: self.digitalocean.is_some(),
        }
    }

    fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        let wire = SecretsWire {
            dnsimple_token: self
                .dnsimple
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            digitalocean_token: self
                .digitalocean
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
        };
        let out = serde_json::to_vec(&wire).map_err(|e| Error::Crypto(e.to_string()));
        wire.wipe();
        Ok(Zeroizing::new(out?))
    }

    fn from_json(bytes: &[u8]) -> Result<Self> {
        let wire: SecretsWire = serde_json::from_slice(bytes)
            .map_err(|_| Error::CorruptVault("could not parse decrypted secrets".into()))?;
        let t = Tokens {
            dnsimple: wire.dnsimple_token.clone().map(SecretString::from),
            digitalocean: wire.digitalocean_token.clone().map(SecretString::from),
        };
        wire.wipe();
        Ok(t)
    }
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tokens")
            .field("status", &self.status())
            .finish()
    }
}

/// Which providers have a token in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenStatus {
    /// A DNSimple token is stored.
    pub dnsimple: bool,
    /// A DigitalOcean token is stored.
    pub digitalocean: bool,
}

/// The JSON inside the vault (same field order and `null`s as Grindvakt 0.x).
#[derive(Serialize, Deserialize, Default)]
struct SecretsWire {
    #[serde(default)]
    dnsimple_token: Option<String>,
    #[serde(default)]
    digitalocean_token: Option<String>,
}

impl SecretsWire {
    fn wipe(mut self) {
        use zeroize::Zeroize;
        if let Some(s) = self.dnsimple_token.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.digitalocean_token.as_mut() {
            s.zeroize();
        }
    }
}

/// A loaded, version-checked vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    file: VaultFile,
}

impl Vault {
    /// Creates a vault with the default KDF and a fresh recovery phrase.
    /// Show the phrase to the user once; it is not stored anywhere.
    pub fn create(password: &SecretString, tokens: &Tokens) -> Result<(Vault, RecoveryPhrase)> {
        Self::create_with_kdf(password, tokens, KdfParams::default())
    }

    /// [`Vault::create`] with explicit KDF parameters (still bounds-checked).
    pub fn create_with_kdf(
        password: &SecretString,
        tokens: &Tokens,
        kdf: KdfParams,
    ) -> Result<(Vault, RecoveryPhrase)> {
        let phrase = RecoveryPhrase::generate()?;
        let v = Self::create_with_phrase(password, &phrase, tokens, kdf)?;
        Ok((v, phrase))
    }

    /// Creates a vault for a phrase the caller already has.
    pub fn create_with_phrase(
        password: &SecretString,
        phrase: &RecoveryPhrase,
        tokens: &Tokens,
        kdf: KdfParams,
    ) -> Result<Vault> {
        kdf.check()?;
        let salt_password: [u8; 16] = weirdnet_keys::random_bytes()?;
        let salt_recovery: [u8; 16] = weirdnet_keys::random_bytes()?;
        let dek = Dek(Key32::random()?);
        let pwd_key = password_key(password, &salt_password, &kdf)?;
        let wrapped_pwd = seal_blob(&pwd_key, dek.as_bytes())?;
        let rec_key = phrase.key(&salt_recovery)?;
        let wrapped_rec = seal_blob(&rec_key, dek.as_bytes())?;
        let created_unix = chrono::Utc::now().timestamp();
        let mut file = VaultFile {
            version: VAULT_VERSION,
            kdf,
            salt_password: B64.encode(salt_password),
            salt_recovery: B64.encode(salt_recovery),
            dek_wrapped_by_password: B64.encode(wrapped_pwd),
            dek_wrapped_by_recovery: B64.encode(wrapped_rec),
            secrets_aead_nonce: String::new(),
            secrets_aead_ciphertext: String::new(),
            created_unix,
        };
        write_tokens(&mut file, &dek, tokens)?;
        Ok(Vault { file })
    }

    /// Wraps an already parsed file after checking its version and KDF bounds.
    pub fn from_file(file: VaultFile) -> Result<Vault> {
        if file.version != VAULT_VERSION {
            return Err(Error::UnsupportedVault(format!(
                "unsupported vault version {}",
                file.version
            )));
        }
        file.kdf.check()?;
        Ok(Vault { file })
    }

    /// Parses vault JSON.
    pub fn from_json(text: &str) -> Result<Vault> {
        let file: VaultFile = serde_json::from_str(text)
            .map_err(|e| Error::CorruptVault(format!("parse vault: {e}")))?;
        Self::from_file(file)
    }

    /// The pretty JSON Grindvakt writes.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.file).expect("vault file serializes")
    }

    /// Reads a vault file.
    pub fn load(path: &Path) -> Result<Vault> {
        let text =
            std::fs::read_to_string(path).ctx(|| format!("read vault {}", path.display()))?;
        Self::from_json(&text)
    }

    /// Writes the vault atomically with owner-only permissions.
    pub fn save(&self, path: &Path) -> Result<()> {
        atomic_write_private(path, self.to_json().as_bytes())
    }

    /// The on-disk structure.
    pub fn file(&self) -> &VaultFile {
        &self.file
    }

    /// Unwraps the DEK with the password.
    pub fn unlock_with_password(&self, password: &SecretString) -> Result<Dek> {
        let salt = b64(&self.file.salt_password, "salt_password")?;
        let key = password_key(password, &salt, &self.file.kdf)?;
        open_dek(&key, &self.file.dek_wrapped_by_password)
    }

    /// Unwraps the DEK with the recovery phrase.
    pub fn unlock_with_recovery(&self, phrase: &RecoveryPhrase) -> Result<Dek> {
        let salt = b64(&self.file.salt_recovery, "salt_recovery")?;
        let key = phrase.key(&salt)?;
        open_dek(&key, &self.file.dek_wrapped_by_recovery)
    }

    /// Checks that `dek` belongs to this vault by decrypting the tokens.
    pub fn verify_dek(&self, dek: &Dek) -> Result<()> {
        self.tokens(dek).map(|_| ())
    }

    /// Decrypts all tokens.
    pub fn tokens(&self, dek: &Dek) -> Result<Tokens> {
        let nonce = b64(&self.file.secrets_aead_nonce, "secrets_aead_nonce")?;
        let ct = b64(
            &self.file.secrets_aead_ciphertext,
            "secrets_aead_ciphertext",
        )?;
        if nonce.len() != NONCE_LEN {
            return Err(Error::CorruptVault("secrets nonce must be 24 bytes".into()));
        }
        let sealed = Sealed {
            nonce: hex(&nonce),
            ct: hex(&ct),
        };
        let pt = aead::open(&dek.0, &sealed, AAD_CONTEXT.as_bytes())?;
        Tokens::from_json(&pt)
    }

    /// The token for one provider, or [`Error::TokenMissing`].
    pub fn token(&self, dek: &Dek, provider: Provider) -> Result<SecretString> {
        self.tokens(dek)?
            .get(provider)
            .cloned()
            .ok_or(Error::TokenMissing(provider))
    }

    /// Which providers have a token.
    pub fn token_status(&self, dek: &Dek) -> Result<TokenStatus> {
        Ok(self.tokens(dek)?.status())
    }

    /// Stores (or replaces) one provider's token, keeping the others.
    pub fn set_token(&mut self, dek: &Dek, provider: Provider, token: SecretString) -> Result<()> {
        let mut t = self.tokens(dek)?;
        t.set(provider, token);
        self.set_tokens(dek, &t)
    }

    /// Replaces all tokens (fresh nonce).
    pub fn set_tokens(&mut self, dek: &Dek, tokens: &Tokens) -> Result<()> {
        self.verify_dek(dek)?;
        write_tokens(&mut self.file, dek, tokens)
    }

    /// Re-wraps the DEK under a new password (same salt and KDF, as Grindvakt always has).
    pub fn set_password(&mut self, dek: &Dek, new_password: &SecretString) -> Result<()> {
        self.verify_dek(dek)?;
        let salt = b64(&self.file.salt_password, "salt_password")?;
        let key = password_key(new_password, &salt, &self.file.kdf)?;
        self.file.dek_wrapped_by_password = B64.encode(seal_blob(&key, dek.as_bytes())?);
        Ok(())
    }

    /// Changes the password after checking the current one.
    pub fn change_password(
        &mut self,
        current: &SecretString,
        new_password: &SecretString,
    ) -> Result<()> {
        let dek = self.unlock_with_password(current)?;
        self.set_password(&dek, new_password)
    }

    /// Sets a new password using the recovery phrase.
    pub fn reset_password_with_recovery(
        &mut self,
        phrase: &RecoveryPhrase,
        new_password: &SecretString,
    ) -> Result<()> {
        let dek = self.unlock_with_recovery(phrase)?;
        self.set_password(&dek, new_password)
    }
}

fn write_tokens(file: &mut VaultFile, dek: &Dek, tokens: &Tokens) -> Result<()> {
    let json = tokens.to_json()?;
    let s = aead::seal(&dek.0, &json, AAD_CONTEXT.as_bytes())?;
    file.secrets_aead_nonce = B64.encode(unhex(&s.nonce)?);
    file.secrets_aead_ciphertext = B64.encode(unhex(&s.ct)?);
    Ok(())
}

fn password_key(password: &SecretString, salt: &[u8], p: &KdfParams) -> Result<Key32> {
    p.check()?;
    Ok(kdf::argon2id(
        password,
        salt,
        p.mem_mib.saturating_mul(1024),
        p.iterations,
        p.parallelism,
    )?)
}

/// nonce ‖ ciphertext, the layout Grindvakt 0.x uses for wrapped DEKs.
fn seal_blob(key: &Key32, plaintext: &[u8]) -> Result<Vec<u8>> {
    let s = aead::seal(key, plaintext, AAD_CONTEXT.as_bytes())?;
    let mut out = unhex(&s.nonce)?;
    out.extend_from_slice(&unhex(&s.ct)?);
    Ok(out)
}

fn open_dek(key: &Key32, wrapped_b64: &str) -> Result<Dek> {
    let blob = b64(wrapped_b64, "wrapped DEK")?;
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::CorruptVault("wrapped DEK too short".into()));
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let pt = aead::open(
        key,
        &Sealed {
            nonce: hex(nonce),
            ct: hex(ct),
        },
        AAD_CONTEXT.as_bytes(),
    )?;
    Dek::from_bytes(&pt).map_err(|_| Error::CorruptVault("wrapped DEK has the wrong length".into()))
}

fn b64(s: &str, what: &str) -> Result<Vec<u8>> {
    B64.decode(s)
        .map_err(|_| Error::CorruptVault(format!("{what} is not valid base64")))
}

fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    let v = |c: u8| -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(Error::Crypto("bad hex".into())),
        }
    };
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err(Error::Crypto("bad hex".into()));
    }
    b.chunks(2).map(|p| Ok(v(p[0])? << 4 | v(p[1])?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn hex_roundtrip() {
        let b: Vec<u8> = (0..=255).collect();
        assert_eq!(unhex(&hex(&b)).unwrap(), b);
    }

    #[test]
    fn wrong_password_and_phrase_fail() {
        let mut t = Tokens::default();
        t.set(Provider::Dnsimple, pw("tok"));
        let (v, _p) = Vault::create_with_kdf(&pw("a"), &t, KdfParams::testing()).unwrap();
        assert!(matches!(
            v.unlock_with_password(&pw("b")),
            Err(Error::WrongSecret)
        ));
        let other = RecoveryPhrase::generate().unwrap();
        assert!(matches!(
            v.unlock_with_recovery(&other),
            Err(Error::WrongSecret)
        ));
    }

    #[test]
    fn tamper_detected() {
        let (v, _) =
            Vault::create_with_kdf(&pw("a"), &Tokens::default(), KdfParams::testing()).unwrap();
        let mut f = v.file().clone();
        let mut ct = B64.decode(&f.secrets_aead_ciphertext).unwrap();
        ct[0] ^= 1;
        f.secrets_aead_ciphertext = B64.encode(ct);
        let v2 = Vault::from_file(f).unwrap();
        let dek = v2.unlock_with_password(&pw("a")).unwrap();
        assert!(matches!(v2.tokens(&dek), Err(Error::WrongSecret)));
    }

    #[test]
    fn kdf_bounds_enforced() {
        let (v, _) =
            Vault::create_with_kdf(&pw("a"), &Tokens::default(), KdfParams::testing()).unwrap();
        for bad in [
            KdfParams {
                mem_mib: 128,
                iterations: 3,
                parallelism: 1,
            },
            KdfParams {
                mem_mib: 64,
                iterations: 0,
                parallelism: 1,
            },
            KdfParams {
                mem_mib: 64,
                iterations: 7,
                parallelism: 1,
            },
            KdfParams {
                mem_mib: 64,
                iterations: 3,
                parallelism: 5,
            },
        ] {
            let mut f = v.file().clone();
            f.kdf = bad;
            assert!(matches!(
                Vault::from_file(f),
                Err(Error::UnsupportedVault(_))
            ));
        }
        let mut f = v.file().clone();
        f.version = 2;
        assert!(matches!(
            Vault::from_file(f),
            Err(Error::UnsupportedVault(_))
        ));
    }

    #[test]
    fn change_and_reset_password() {
        let mut t = Tokens::default();
        t.set(Provider::Digitalocean, pw("do"));
        let (mut v, phrase) = Vault::create_with_kdf(&pw("one"), &t, KdfParams::testing()).unwrap();
        v.change_password(&pw("one"), &pw("two")).unwrap();
        assert!(v.unlock_with_password(&pw("one")).is_err());
        v.reset_password_with_recovery(&phrase, &pw("three"))
            .unwrap();
        let dek = v.unlock_with_password(&pw("three")).unwrap();
        assert_eq!(
            v.token(&dek, Provider::Digitalocean)
                .unwrap()
                .expose_secret(),
            "do"
        );
        assert!(matches!(
            v.token(&dek, Provider::Dnsimple),
            Err(Error::TokenMissing(Provider::Dnsimple))
        ));
        v.set_token(&dek, Provider::Dnsimple, pw("dns")).unwrap();
        assert_eq!(
            v.token_status(&dek).unwrap(),
            TokenStatus {
                dnsimple: true,
                digitalocean: true
            }
        );
    }

    #[test]
    fn phrase_parse_is_lenient_about_case_and_space() {
        let p = RecoveryPhrase::generate().unwrap();
        let messy = format!(
            "  {}  ",
            p.expose_words().to_uppercase().replace(' ', "   ")
        );
        assert!(p.matches(&messy));
        assert!(RecoveryPhrase::parse("abandon abandon").is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let p = RecoveryPhrase::generate().unwrap();
        let first = p.expose_words().split(' ').next().unwrap().to_string();
        let mut t = Tokens::default();
        t.set(Provider::Dnsimple, pw("super-secret-token"));
        let (v, _) = Vault::create_with_kdf(&pw("a"), &t, KdfParams::testing()).unwrap();
        let dek = v.unlock_with_password(&pw("a")).unwrap();
        let all = format!("{p:?} {t:?} {dek:?}");
        assert!(!all.contains("super-secret-token"));
        assert!(!all.contains(&first) || first.len() < 3);
        assert!(all.contains("redacted"));
    }

    #[test]
    fn secrets_json_shape_matches_v0() {
        let mut t = Tokens::default();
        t.set(Provider::Dnsimple, pw("x"));
        assert_eq!(
            &*t.to_json().unwrap(),
            br#"{"dnsimple_token":"x","digitalocean_token":null}"#
        );
    }
}
