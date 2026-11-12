//! DNS providers: a small trait plus DNSimple and DigitalOcean implementations.
//!
//! A [`DnsProvider`] only lists, creates and updates records. Deciding *what* to change is
//! done once, for every provider, by [`crate::plan()`]. Implement the trait yourself to drive
//! another DNS host, an in-memory fake for tests, or a recorder. The built-in providers sit
//! behind the `dnsimple` and `digitalocean` features.
//!
//! Names passed to and returned from a provider are relative to the zone, with `""` for the
//! apex; providers translate to their own convention (DigitalOcean's `@`).

#[cfg(any(feature = "dnsimple", feature = "digitalocean"))]
use crate::config::Provider;
#[cfg(any(feature = "dnsimple", feature = "digitalocean"))]
use crate::error::Error;
use crate::error::Result;
use crate::record::{ExistingRecord, RecordKind, RecordValue};
#[cfg(any(feature = "dnsimple", feature = "digitalocean"))]
use secrecy::{ExposeSecret, SecretString};
use std::future::Future;

/// A DNS host that can list, create and update records in a zone.
///
/// The futures are `Send`, so providers work inside `tokio::spawn` and other multi-threaded
/// executors. Return the typed errors ([`crate::Error::Auth`], [`crate::Error::RateLimited`],
/// [`crate::Error::Network`], [`crate::Error::Provider`]) so callers can explain failures.
pub trait DnsProvider {
    /// Short provider name used in messages, such as `dnsimple`.
    fn name(&self) -> &str;

    /// Every record of `kind` named `name` (relative, `""` for the apex) in `zone`.
    fn list(
        &self,
        zone: &str,
        name: &str,
        kind: RecordKind,
    ) -> impl Future<Output = Result<Vec<ExistingRecord>>> + Send;

    /// Creates a record named `name` (relative, `""` for the apex).
    fn create(
        &self,
        zone: &str,
        name: &str,
        value: &RecordValue,
        ttl: u32,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Sets record `id` to `value` with `ttl`.
    fn update(
        &self,
        zone: &str,
        id: u64,
        value: &RecordValue,
        ttl: u32,
    ) -> impl Future<Output = Result<()>> + Send;

    /// The DNS types of every record named `name` (relative, `""` for the apex), one entry per
    /// record, including types this crate does not manage (`MX`, `SRV`, ...). [`crate::plan()`]
    /// uses it to keep a CNAME the only record at its name.
    ///
    /// The default asks [`DnsProvider::list`] for each [`RecordKind`], so it sees only the
    /// managed types; the built-in providers override it to report every type.
    fn types_at(&self, zone: &str, name: &str) -> impl Future<Output = Result<Vec<String>>> + Send {
        let lists = RecordKind::ALL.map(|k| (k, self.list(zone, name, k)));
        async move {
            let mut out = Vec::new();
            for (kind, list) in lists {
                for _ in list.await? {
                    out.push(kind.as_str().to_string());
                }
            }
            Ok(out)
        }
    }
}

/// Options for the built-in providers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderOptions {
    /// DNSimple: use the sandbox API.
    pub sandbox: bool,
    /// Override the API endpoint (tests and mocks).
    pub base_url: Option<String>,
    /// DNSimple account id. When unset, DNSimple's `whoami` supplies it.
    pub account_id: Option<u64>,
}

/// One of the built-in providers, chosen at run time.
#[derive(Debug)]
#[non_exhaustive]
pub enum AnyProvider {
    /// DNSimple.
    #[cfg(feature = "dnsimple")]
    Dnsimple(DnsimpleProvider),
    /// DigitalOcean.
    #[cfg(feature = "digitalocean")]
    Digitalocean(DigitalOceanProvider),
}

#[cfg(any(feature = "dnsimple", feature = "digitalocean"))]
impl AnyProvider {
    /// Builds provider `kind` with `token`. Fails with [`Error::Config`] when the crate was
    /// built without that provider's feature.
    #[allow(unused_variables)]
    pub fn new(kind: Provider, token: &SecretString, opts: &ProviderOptions) -> Result<Self> {
        match kind {
            #[cfg(feature = "dnsimple")]
            Provider::Dnsimple => Ok(AnyProvider::Dnsimple(DnsimpleProvider::new(
                token,
                opts.sandbox,
                opts.base_url.as_deref(),
                opts.account_id,
            )?)),
            #[cfg(feature = "digitalocean")]
            Provider::Digitalocean => Ok(AnyProvider::Digitalocean(DigitalOceanProvider::new(
                token,
                opts.base_url.as_deref(),
            )?)),
            #[allow(unreachable_patterns)]
            other => Err(Error::Config(format!(
                "grindvakt-core was built without the {other} feature"
            ))),
        }
    }
}

/// DNSimple with `token` (production API). `account_id` skips the `whoami` lookup.
#[cfg(feature = "dnsimple")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnsimple")))]
pub fn dnsimple(token: &SecretString, account_id: Option<u64>) -> Result<DnsimpleProvider> {
    DnsimpleProvider::new(token, false, None, account_id)
}

/// DigitalOcean with `token` (public API).
#[cfg(feature = "digitalocean")]
#[cfg_attr(docsrs, doc(cfg(feature = "digitalocean")))]
pub fn digitalocean(token: &SecretString) -> Result<DigitalOceanProvider> {
    DigitalOceanProvider::new(token, None)
}

/// Builds the provider named in a standalone Grindvakt config.
#[cfg(all(
    feature = "standalone",
    any(feature = "dnsimple", feature = "digitalocean")
))]
#[cfg_attr(docsrs, doc(cfg(feature = "standalone")))]
pub fn build(cfg: &crate::config::AppConfig, token: &SecretString) -> Result<AnyProvider> {
    AnyProvider::new(
        cfg.provider,
        token,
        &ProviderOptions {
            sandbox: cfg.sandbox,
            base_url: cfg.api_base_url.clone(),
            account_id: cfg.account_id,
        },
    )
}

macro_rules! dispatch {
    ($self:ident, $p:ident => $e:expr) => {
        match $self {
            #[cfg(feature = "dnsimple")]
            AnyProvider::Dnsimple($p) => $e,
            #[cfg(feature = "digitalocean")]
            AnyProvider::Digitalocean($p) => $e,
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyProvider has no variants without provider features"),
        }
    };
}

impl DnsProvider for AnyProvider {
    fn name(&self) -> &str {
        #[allow(unused_variables)]
        let n = dispatch!(self, p => p.name());
        #[allow(unreachable_code)]
        n
    }
    #[allow(unused_variables)]
    async fn list(&self, zone: &str, name: &str, kind: RecordKind) -> Result<Vec<ExistingRecord>> {
        dispatch!(self, p => p.list(zone, name, kind).await)
    }
    #[allow(unused_variables)]
    async fn create(&self, zone: &str, name: &str, value: &RecordValue, ttl: u32) -> Result<()> {
        dispatch!(self, p => p.create(zone, name, value, ttl).await)
    }
    #[allow(unused_variables)]
    async fn update(&self, zone: &str, id: u64, value: &RecordValue, ttl: u32) -> Result<()> {
        dispatch!(self, p => p.update(zone, id, value, ttl).await)
    }
    #[allow(unused_variables)]
    async fn types_at(&self, zone: &str, name: &str) -> Result<Vec<String>> {
        dispatch!(self, p => p.types_at(zone, name).await)
    }
}

#[cfg(feature = "dnsimple")]
pub use self::dnsimple_impl::DnsimpleProvider;

#[cfg(feature = "dnsimple")]
mod dnsimple_impl {
    use super::*;
    use ::dnsimple::dnsimple::zones_records::{
        ZoneRecord, ZoneRecordPayload, ZoneRecordUpdatePayload,
    };
    use ::dnsimple::dnsimple::{Client, Filters, Paginate, RequestOptions, new_client};
    use ::dnsimple::errors::DNSimpleError;
    use std::collections::HashMap;
    use std::time::Duration;

    const NAME: &str = "dnsimple";

    fn err(m: impl std::fmt::Display) -> Error {
        Error::provider(NAME, m)
    }

    /// Maps the `dnsimple` crate's errors onto the typed [`Error`] variants.
    pub(crate) fn map_err(what: &str, e: DNSimpleError) -> Error {
        match e {
            DNSimpleError::Unauthorized => Error::Auth {
                provider: NAME.into(),
                message: format!("{what}: token rejected"),
            },
            DNSimpleError::Forbidden(m) => Error::Auth {
                provider: NAME.into(),
                message: format!("{what}: {m}"),
            },
            DNSimpleError::PaymentRequired => Error::Auth {
                provider: NAME.into(),
                message: format!("{what}: account not subscribed or not in good standing"),
            },
            DNSimpleError::TooManyRequests => Error::RateLimited {
                provider: NAME.into(),
                retry_after: None,
            },
            DNSimpleError::Network(m) => Error::Network(format!("{NAME} {what}: {m}")),
            other => err(format!("{what}: {other}")),
        }
    }

    /// DNSimple through the official `dnsimple` crate. Retries 5xx and network errors up to
    /// three times; fails fast on 401, 402, 403 and 429.
    #[cfg_attr(docsrs, doc(cfg(feature = "dnsimple")))]
    pub struct DnsimpleProvider {
        client: Client,
        account_id: Option<u64>,
    }

    impl std::fmt::Debug for DnsimpleProvider {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DnsimpleProvider")
                .field("account_id", &self.account_id)
                .finish_non_exhaustive()
        }
    }

    impl DnsimpleProvider {
        /// A client for the production or sandbox API, or `base_url` if given. Without an
        /// `account_id`, each call asks DNSimple's `whoami` for it.
        pub fn new(
            token: &SecretString,
            sandbox: bool,
            base_url: Option<&str>,
            account_id: Option<u64>,
        ) -> Result<Self> {
            let mut client = new_client(sandbox, token.expose_secret().to_string())
                .map_err(|e| err(format!("create client: {e}")))?;
            if let Some(base) = base_url {
                client.set_base_url(base);
            }
            Ok(Self { client, account_id })
        }

        async fn account(&self) -> Result<u64> {
            if let Some(id) = self.account_id {
                return Ok(id);
            }
            let resp = with_retries(|| async { self.client.identity().whoami().await })
                .await
                .map_err(|e| map_err("whoami", e))?;
            let data = resp.data.ok_or_else(|| err("whoami returned no data"))?;
            data.account.map(|a| a.id).ok_or_else(|| {
                Error::Config(
                    "DNSimple whoami did not include an account id; set account_id".into(),
                )
            })
        }

        /// Every record named exactly `name`, of `kind` or of any type.
        async fn raw_list(
            &self,
            zone: &str,
            name: &str,
            kind: Option<RecordKind>,
        ) -> Result<Vec<ZoneRecord>> {
            let account = self.account().await?;
            let mut page: u32 = 1;
            let mut out = Vec::new();
            loop {
                let resp = with_retries(|| async {
                    let mut fmap = HashMap::new();
                    if let Some(kind) = kind {
                        fmap.insert("type".to_string(), kind.as_str().to_string());
                    }
                    if !name.is_empty() {
                        fmap.insert("name".to_string(), name.to_string());
                    }
                    let opts = RequestOptions {
                        filters: Some(Filters::new(fmap)),
                        sort: None,
                        paginate: Some(Paginate {
                            per_page: 100,
                            page,
                        }),
                    };
                    self.client
                        .zones()
                        .list_zone_records(account, zone, Some(opts))
                        .await
                })
                .await
                .map_err(|e| map_err(&format!("list_zone_records page {page}"), e))?;
                for r in resp.data.unwrap_or_default() {
                    if r.name == name && kind.is_none_or(|k| r.record_type == k.as_str()) {
                        out.push(r);
                    }
                }
                let pagination = resp.pagination.ok_or_else(|| err("missing pagination"))?;
                if u64::from(page) >= pagination.total_pages {
                    break;
                }
                page += 1;
            }
            Ok(out)
        }
    }

    impl DnsProvider for DnsimpleProvider {
        fn name(&self) -> &str {
            NAME
        }

        async fn list(
            &self,
            zone: &str,
            name: &str,
            kind: RecordKind,
        ) -> Result<Vec<ExistingRecord>> {
            let mut out = Vec::new();
            for r in self.raw_list(zone, name, Some(kind)).await? {
                out.push(ExistingRecord {
                    id: r.id,
                    name: r.name.clone(),
                    value: RecordValue::parse(kind, &r.content)?,
                    ttl: u32::try_from(r.ttl).ok(),
                });
            }
            Ok(out)
        }

        async fn types_at(&self, zone: &str, name: &str) -> Result<Vec<String>> {
            Ok(self
                .raw_list(zone, name, None)
                .await?
                .into_iter()
                .map(|r| r.record_type)
                .collect())
        }

        async fn create(
            &self,
            zone: &str,
            name: &str,
            value: &RecordValue,
            ttl: u32,
        ) -> Result<()> {
            let account = self.account().await?;
            let payload = ZoneRecordPayload {
                name: name.to_string(),
                record_type: value.kind().as_str().to_string(),
                content: value.content(),
                ttl: Some(u64::from(ttl)),
                priority: None,
                regions: None,
            };
            self.client
                .zones()
                .create_zone_record(account, zone, payload)
                .await
                .map_err(|e| map_err(&format!("create {} {name:?}", value.kind()), e))?;
            Ok(())
        }

        async fn update(&self, zone: &str, id: u64, value: &RecordValue, ttl: u32) -> Result<()> {
            let account = self.account().await?;
            let payload = ZoneRecordUpdatePayload {
                name: None,
                content: Some(value.content()),
                ttl: Some(u64::from(ttl)),
                priority: None,
                regions: None,
            };
            self.client
                .zones()
                .update_zone_record(account, zone, id, payload)
                .await
                .map_err(|e| map_err(&format!("update record id={id}"), e))?;
            Ok(())
        }
    }

    async fn with_retries<F, Fut, T>(mut f: F) -> std::result::Result<T, DNSimpleError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = std::result::Result<T, DNSimpleError>>,
    {
        let mut attempt = 0u64;
        loop {
            match f().await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    let retry = matches!(
                        &e,
                        DNSimpleError::BadGateway
                            | DNSimpleError::GatewayTimeout(_)
                            | DNSimpleError::ServiceUnavailable
                            | DNSimpleError::Network(_)
                    ) || matches!(&e, DNSimpleError::UnexpectedStatus(c) if (500..=599).contains(c));
                    attempt += 1;
                    if !retry || attempt >= 3 {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(200 * attempt)).await;
                }
            }
        }
    }
}

#[cfg(feature = "digitalocean")]
pub use self::digitalocean_impl::DigitalOceanProvider;

#[cfg(feature = "digitalocean")]
mod digitalocean_impl {
    use super::*;
    use reqwest::{Response, StatusCode};
    use serde::Deserialize;
    use std::time::Duration;

    /// Default DigitalOcean API endpoint.
    pub const API_BASE: &str = "https://api.digitalocean.com";
    const NAME: &str = "digitalocean";
    /// Pages of 200 records read at most when listing (10 000 records).
    const MAX_PAGES: u32 = 50;

    fn err(m: impl std::fmt::Display) -> Error {
        Error::provider(NAME, m)
    }

    fn net(what: &str, e: reqwest::Error) -> Error {
        let e = e.without_url();
        if e.is_decode() {
            err(format!("{what}: {e}"))
        } else {
            Error::Network(format!("{NAME} {what}: {e}"))
        }
    }

    /// Turns a non-success response into the typed error.
    fn status_err(what: &str, resp: &Response) -> Error {
        let status = resp.status();
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Error::Auth {
                provider: NAME.into(),
                message: format!("{what}: {status}"),
            },
            StatusCode::TOO_MANY_REQUESTS => {
                let h = resp.headers();
                let secs = h
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .or_else(|| {
                        let reset = h
                            .get("ratelimit-reset")?
                            .to_str()
                            .ok()?
                            .trim()
                            .parse::<u64>()
                            .ok()?;
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .ok()?
                            .as_secs();
                        Some(reset.saturating_sub(now))
                    });
                Error::RateLimited {
                    provider: NAME.into(),
                    retry_after: secs.map(Duration::from_secs),
                }
            }
            s => err(format!("{what}: unexpected status {s}")),
        }
    }

    /// DigitalOcean DNS over its REST API (`/v2/domains/{zone}/records`).
    #[cfg_attr(docsrs, doc(cfg(feature = "digitalocean")))]
    pub struct DigitalOceanProvider {
        client: reqwest::Client,
        api_base: String,
        token: SecretString,
    }

    impl std::fmt::Debug for DigitalOceanProvider {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DigitalOceanProvider")
                .field("api_base", &self.api_base)
                .finish_non_exhaustive()
        }
    }

    #[derive(Deserialize)]
    struct ListResp {
        domain_records: Vec<DoRecord>,
        #[serde(default)]
        links: Option<Links>,
    }
    #[derive(Deserialize)]
    struct Links {
        #[serde(default)]
        pages: Option<Pages>,
    }
    #[derive(Deserialize)]
    struct Pages {
        #[serde(default)]
        next: Option<String>,
    }
    #[derive(Deserialize, Clone)]
    struct DoRecord {
        id: i64,
        #[serde(rename = "type")]
        r#type: String,
        name: String,
        data: String,
        #[serde(default)]
        ttl: Option<i64>,
    }

    fn to_do_name(name: &str) -> &str {
        if name.is_empty() { "@" } else { name }
    }

    /// DigitalOcean wants a CNAME target as a fully qualified name with a trailing dot.
    fn to_do_data(value: &RecordValue) -> String {
        match value {
            RecordValue::Cname(_) => format!("{}.", value.content()),
            _ => value.content(),
        }
    }

    /// DigitalOcean reports CNAME data as `target.` (absolute), `@` (the apex) or, for names
    /// created without a dot, relative to the zone.
    fn from_do_data(zone: &str, kind: RecordKind, data: &str) -> Result<RecordValue> {
        if kind != RecordKind::Cname {
            return RecordValue::parse(kind, data);
        }
        let d = data.trim();
        let zone = zone.trim_end_matches('.');
        let full = if d == "@" {
            zone.to_string()
        } else if d.ends_with('.') {
            d.to_string()
        } else {
            format!("{d}.{zone}")
        };
        RecordValue::parse(kind, &full)
    }

    impl DigitalOceanProvider {
        /// Every record named exactly `name`, of `kind` or of any type.
        async fn raw_list(
            &self,
            zone: &str,
            name: &str,
            kind: Option<RecordKind>,
        ) -> Result<Vec<DoRecord>> {
            let want = to_do_name(name);
            let mut page: u32 = 1;
            let mut out = Vec::new();
            loop {
                if page > MAX_PAGES {
                    return Err(err("list: pagination exceeded safety cap"));
                }
                let mut url = format!(
                    "{}/v2/domains/{}/records?page={}&per_page=200",
                    self.api_base, zone, page
                );
                if let Some(kind) = kind {
                    url.push_str("&type=");
                    url.push_str(kind.as_str());
                }
                let resp = self
                    .client
                    .get(&url)
                    .bearer_auth(self.token.expose_secret())
                    .send()
                    .await
                    .map_err(|e| net("list", e))?;
                if !resp.status().is_success() {
                    return Err(status_err("list", &resp));
                }
                let body: ListResp = resp.json().await.map_err(|e| net("parse list", e))?;
                for r in body.domain_records {
                    if r.name == want && kind.is_none_or(|k| r.r#type == k.as_str()) {
                        out.push(r);
                    }
                }
                if body
                    .links
                    .and_then(|l| l.pages)
                    .and_then(|p| p.next)
                    .is_some()
                {
                    page += 1;
                } else {
                    break;
                }
            }
            Ok(out)
        }

        /// A client for `base_url`, or the public API when `None`.
        pub fn new(token: &SecretString, base_url: Option<&str>) -> Result<Self> {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| err(format!("http client: {e}")))?;
            Ok(Self {
                client,
                api_base: base_url
                    .unwrap_or(API_BASE)
                    .trim_end_matches('/')
                    .to_string(),
                token: SecretString::from(token.expose_secret().to_string()),
            })
        }
    }

    impl DnsProvider for DigitalOceanProvider {
        fn name(&self) -> &str {
            NAME
        }

        /// Lists by type and filters the name locally (DigitalOcean's `name` filter wants a
        /// fully qualified name, and an empty match must never look like "no record").
        async fn list(
            &self,
            zone: &str,
            name: &str,
            kind: RecordKind,
        ) -> Result<Vec<ExistingRecord>> {
            let mut out = Vec::new();
            for r in self.raw_list(zone, name, Some(kind)).await? {
                out.push(ExistingRecord {
                    id: u64::try_from(r.id).map_err(|_| err("negative record id"))?,
                    name: name.to_string(),
                    value: from_do_data(zone, kind, &r.data)?,
                    ttl: r.ttl.and_then(|t| u32::try_from(t).ok()),
                });
            }
            Ok(out)
        }

        async fn types_at(&self, zone: &str, name: &str) -> Result<Vec<String>> {
            Ok(self
                .raw_list(zone, name, None)
                .await?
                .into_iter()
                .map(|r| r.r#type)
                .collect())
        }

        async fn create(
            &self,
            zone: &str,
            name: &str,
            value: &RecordValue,
            ttl: u32,
        ) -> Result<()> {
            let url = format!("{}/v2/domains/{}/records", self.api_base, zone);
            let body = serde_json::json!({
                "type": value.kind().as_str(),
                "name": to_do_name(name),
                "data": to_do_data(value),
                "ttl": ttl,
            });
            let resp = self
                .client
                .post(&url)
                .bearer_auth(self.token.expose_secret())
                .json(&body)
                .send()
                .await
                .map_err(|e| net("create", e))?;
            if !resp.status().is_success() {
                return Err(status_err("create", &resp));
            }
            Ok(())
        }

        async fn update(&self, zone: &str, id: u64, value: &RecordValue, ttl: u32) -> Result<()> {
            let url = format!("{}/v2/domains/{}/records/{}", self.api_base, zone, id);
            let body = serde_json::json!({ "data": to_do_data(value), "ttl": ttl });
            let resp = self
                .client
                .patch(&url)
                .bearer_auth(self.token.expose_secret())
                .json(&body)
                .send()
                .await
                .map_err(|e| net("update", e))?;
            if !resp.status().is_success() {
                return Err(status_err("update", &resp));
            }
            Ok(())
        }
    }
}
