//! DNS providers: a small trait plus DNSimple and DigitalOcean implementations.
//!
//! Implement [`DnsProvider`] yourself to drive another DNS host, an in-memory fake for
//! tests, or a dry-run recorder. The built-in providers sit behind the `dnsimple` and
//! `digitalocean` features; [`AnyProvider`] and [`build`] pick one from an [`AppConfig`].

use crate::config::AppConfig;
#[cfg(any(feature = "dnsimple", feature = "digitalocean"))]
use crate::config::Provider;
#[cfg(any(feature = "dnsimple", feature = "digitalocean"))]
use crate::error::Error;
use crate::error::Result;
#[cfg(any(feature = "dnsimple", feature = "digitalocean"))]
use secrecy::{ExposeSecret, SecretString};
use std::future::Future;
use std::net::Ipv4Addr;

/// What sync would do to the A record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAction {
    /// The record already points at this address with the configured TTL.
    Noop(Ipv4Addr),
    /// No A record exists; create one with this (provider-relative) name.
    Create {
        /// Name relative to the zone in the provider's convention.
        name: String,
        /// TTL to set.
        ttl: u32,
    },
    /// One A record exists with a different address or TTL.
    Update {
        /// Provider record id.
        record_id: u64,
        /// TTL to set.
        ttl: u32,
        /// The address it points at now.
        prev: Ipv4Addr,
    },
    /// Several A records match; sync refuses to guess.
    Ambiguous {
        /// Why.
        reason: String,
    },
}

/// A DNS host that can list, create and update one A record.
///
/// The futures are `Send`, so providers work inside `tokio::spawn` and other
/// multi-threaded executors.
pub trait DnsProvider {
    /// Looks up the current record and decides what to do for `ip`.
    fn plan(&self, cfg: &AppConfig, ip: Ipv4Addr)
    -> impl Future<Output = Result<DnsAction>> + Send;
    /// Creates the A record (`name` as returned in [`DnsAction::Create`]).
    fn create_a(
        &self,
        cfg: &AppConfig,
        name: &str,
        ip: Ipv4Addr,
        ttl: u32,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Points record `record_id` at `ip` with `ttl`.
    fn update_a(
        &self,
        cfg: &AppConfig,
        record_id: u64,
        ip: Ipv4Addr,
        ttl: u32,
    ) -> impl Future<Output = Result<()>> + Send;
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

/// Builds the provider named in `cfg.provider` with its token.
///
/// `cfg.api_base_url` overrides the API endpoint (useful with a mock server).
#[cfg(any(feature = "dnsimple", feature = "digitalocean"))]
pub fn build(cfg: &AppConfig, token: &SecretString) -> Result<AnyProvider> {
    match cfg.provider {
        #[cfg(feature = "dnsimple")]
        Provider::Dnsimple => Ok(AnyProvider::Dnsimple(DnsimpleProvider::new(
            token,
            cfg.sandbox,
            cfg.api_base_url.as_deref(),
            cfg.account_id,
        )?)),
        #[cfg(feature = "digitalocean")]
        Provider::Digitalocean => Ok(AnyProvider::Digitalocean(DigitalOceanProvider::new(
            token,
            cfg.api_base_url.as_deref(),
        )?)),
        #[allow(unreachable_patterns)]
        other => Err(Error::Config(format!(
            "grindvakt-core was built without the {other} feature"
        ))),
    }
}

impl DnsProvider for AnyProvider {
    #[allow(unused_variables)]
    async fn plan(&self, cfg: &AppConfig, ip: Ipv4Addr) -> Result<DnsAction> {
        match self {
            #[cfg(feature = "dnsimple")]
            AnyProvider::Dnsimple(p) => p.plan(cfg, ip).await,
            #[cfg(feature = "digitalocean")]
            AnyProvider::Digitalocean(p) => p.plan(cfg, ip).await,
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyProvider has no variants without provider features"),
        }
    }
    #[allow(unused_variables)]
    async fn create_a(&self, cfg: &AppConfig, name: &str, ip: Ipv4Addr, ttl: u32) -> Result<()> {
        match self {
            #[cfg(feature = "dnsimple")]
            AnyProvider::Dnsimple(p) => p.create_a(cfg, name, ip, ttl).await,
            #[cfg(feature = "digitalocean")]
            AnyProvider::Digitalocean(p) => p.create_a(cfg, name, ip, ttl).await,
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyProvider has no variants without provider features"),
        }
    }
    #[allow(unused_variables)]
    async fn update_a(
        &self,
        cfg: &AppConfig,
        record_id: u64,
        ip: Ipv4Addr,
        ttl: u32,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "dnsimple")]
            AnyProvider::Dnsimple(p) => p.update_a(cfg, record_id, ip, ttl).await,
            #[cfg(feature = "digitalocean")]
            AnyProvider::Digitalocean(p) => p.update_a(cfg, record_id, ip, ttl).await,
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyProvider has no variants without provider features"),
        }
    }
}

#[cfg(feature = "dnsimple")]
pub use self::dnsimple_impl::DnsimpleProvider;

#[cfg(feature = "dnsimple")]
mod dnsimple_impl {
    use super::*;
    use crate::config::relative_name;
    use ::dnsimple::dnsimple::zones_records::{
        ZoneRecord, ZoneRecordPayload, ZoneRecordUpdatePayload,
    };
    use ::dnsimple::dnsimple::{Client, Filters, Paginate, RequestOptions, new_client};
    use ::dnsimple::errors::DNSimpleError;
    use std::collections::HashMap;
    use std::time::Duration;

    fn err(m: impl std::fmt::Display) -> Error {
        Error::provider(Provider::Dnsimple, m)
    }

    /// DNSimple through the official `dnsimple` crate. Retries 5xx and network errors up to
    /// three times; fails fast on 401, 403 and 429.
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
                .map_err(|e| err(format!("create dnsimple client: {e}")))?;
            if let Some(base) = base_url {
                client.set_base_url(base);
            }
            Ok(Self { client, account_id })
        }

        async fn account(&self) -> Result<u64> {
            if let Some(id) = self.account_id {
                return Ok(id);
            }
            let resp = self
                .client
                .identity()
                .whoami()
                .await
                .map_err(|e| err(format!("whoami: {e}")))?;
            let data = resp.data.ok_or_else(|| err("whoami returned no data"))?;
            data.account.map(|a| a.id).ok_or_else(|| {
                err("whoami did not include account id; provide account_id in config")
            })
        }

        async fn list(&self, account: u64, zone: &str, name: &str) -> Result<Vec<ZoneRecord>> {
            let mut page: u32 = 1;
            let mut out = Vec::new();
            loop {
                let resp = with_retries(|| async {
                    let mut fmap = HashMap::new();
                    fmap.insert("type".to_string(), "A".to_string());
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
                .map_err(|e| err(format!("list_zone_records page {page}: {e}")))?;
                if let Some(records) = resp.data {
                    out.extend(
                        records
                            .into_iter()
                            .filter(|r| r.record_type == "A" && r.name == name),
                    );
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
        async fn plan(&self, cfg: &AppConfig, ip: Ipv4Addr) -> Result<DnsAction> {
            let account = self.account().await?;
            let name = relative_name(&cfg.zone, &cfg.name);
            let mut matches = self.list(account, &cfg.zone, &name).await?;
            if matches.is_empty() {
                return Ok(DnsAction::Create { name, ttl: cfg.ttl });
            }
            if matches.len() > 1 {
                return Ok(DnsAction::Ambiguous {
                    reason: format!(
                        "found {} A records for name {:?} in zone {}; specify record_id manually or clean up duplicates",
                        matches.len(),
                        name,
                        cfg.zone
                    ),
                });
            }
            let rec = matches.remove(0);
            let current: Ipv4Addr = rec.content.parse().map_err(|_| {
                err(format!(
                    "unexpected non-IPv4 content in existing A record: {}",
                    rec.content
                ))
            })?;
            if current == ip && rec.ttl == u64::from(cfg.ttl) {
                return Ok(DnsAction::Noop(current));
            }
            Ok(DnsAction::Update {
                record_id: rec.id,
                ttl: cfg.ttl,
                prev: current,
            })
        }

        async fn create_a(
            &self,
            cfg: &AppConfig,
            name: &str,
            ip: Ipv4Addr,
            ttl: u32,
        ) -> Result<()> {
            let account = self.account().await?;
            // Re-check first so a retried POST never makes a duplicate.
            if !self.list(account, &cfg.zone, name).await?.is_empty() {
                return Err(err("refusing to create: record now exists; re-run sync"));
            }
            let payload = ZoneRecordPayload {
                name: name.to_string(),
                record_type: "A".to_string(),
                content: ip.to_string(),
                ttl: Some(u64::from(ttl)),
                priority: None,
                regions: None,
            };
            self.client
                .zones()
                .create_zone_record(account, &cfg.zone, payload)
                .await
                .map_err(|e| err(format!("create_zone_record {}/{}: {e}", cfg.zone, cfg.name)))?;
            Ok(())
        }

        async fn update_a(
            &self,
            cfg: &AppConfig,
            record_id: u64,
            ip: Ipv4Addr,
            ttl: u32,
        ) -> Result<()> {
            let account = self.account().await?;
            let payload = ZoneRecordUpdatePayload {
                name: None,
                content: Some(ip.to_string()),
                ttl: Some(u64::from(ttl)),
                priority: None,
                regions: None,
            };
            self.client
                .zones()
                .update_zone_record(account, &cfg.zone, record_id, payload)
                .await
                .map_err(|e| err(format!("update_zone_record id={record_id}: {e}")))?;
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
                    if matches!(
                        e,
                        DNSimpleError::Unauthorized
                            | DNSimpleError::TooManyRequests
                            | DNSimpleError::Forbidden(_)
                    ) {
                        return Err(e);
                    }
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
    use reqwest::StatusCode;
    use serde::Deserialize;

    /// Default DigitalOcean API endpoint.
    pub const API_BASE: &str = "https://api.digitalocean.com";

    fn err(m: impl std::fmt::Display) -> Error {
        Error::provider(Provider::Digitalocean, m)
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
        domain_records: Vec<Record>,
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
    struct Record {
        id: i64,
        #[serde(rename = "type")]
        r#type: String,
        name: String,
        data: String,
        #[serde(default)]
        ttl: Option<i64>,
    }

    /// The record name in DigitalOcean's convention: `@` for the apex.
    pub(crate) fn relative_name_do(cfg: &AppConfig) -> String {
        let n = crate::config::relative_name(&cfg.zone, &cfg.name);
        if n.is_empty() { "@".to_string() } else { n }
    }

    impl DigitalOceanProvider {
        /// A client for `base_url`, or the public API when `None`.
        pub fn new(token: &SecretString, base_url: Option<&str>) -> Result<Self> {
            let client = reqwest::Client::builder()
                .build()
                .map_err(|e| err(format!("http client: {e}")))?;
            Ok(Self {
                client,
                api_base: base_url.unwrap_or(API_BASE).to_string(),
                token: SecretString::from(token.expose_secret().to_string()),
            })
        }

        async fn list(&self, domain: &str, name: &str) -> Result<Vec<Record>> {
            let mut page: u32 = 1;
            let mut out = Vec::new();
            loop {
                if page > 50 {
                    return Err(err("pagination exceeded safety cap"));
                }
                let url = format!(
                    "{}/v2/domains/{}/records?page={}&per_page=200&type=A&name={}",
                    self.api_base, domain, page, name
                );
                let resp = self
                    .client
                    .get(&url)
                    .bearer_auth(self.token.expose_secret())
                    .send()
                    .await
                    .map_err(|e| err(format!("list request: {}", e.without_url())))?;
                let status = resp.status();
                if status == StatusCode::UNAUTHORIZED
                    || status == StatusCode::FORBIDDEN
                    || status == StatusCode::TOO_MANY_REQUESTS
                {
                    return Err(err(format!("list error: {status}")));
                }
                if !status.is_success() {
                    return Err(err(format!("list unexpected status: {status}")));
                }
                let body: ListResp = resp
                    .json()
                    .await
                    .map_err(|e| err(format!("parse list: {}", e.without_url())))?;
                out.extend(
                    body.domain_records
                        .into_iter()
                        .filter(|r| r.r#type == "A" && r.name == name),
                );
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
    }

    impl DnsProvider for DigitalOceanProvider {
        async fn plan(&self, cfg: &AppConfig, ip: Ipv4Addr) -> Result<DnsAction> {
            let name = relative_name_do(cfg);
            let records = self.list(&cfg.zone, &name).await?;
            if records.is_empty() {
                return Ok(DnsAction::Create { name, ttl: cfg.ttl });
            }
            if records.len() > 1 {
                return Ok(DnsAction::Ambiguous {
                    reason: format!(
                        "found {} A records for {:?} in {}",
                        records.len(),
                        name,
                        cfg.zone
                    ),
                });
            }
            let rec = &records[0];
            let current: Ipv4Addr = rec
                .data
                .parse()
                .map_err(|_| err(format!("unexpected non-IPv4 in A record: {}", rec.data)))?;
            let rec_ttl = rec.ttl.unwrap_or(i64::from(cfg.ttl)) as u32;
            if current == ip && rec_ttl == cfg.ttl {
                Ok(DnsAction::Noop(current))
            } else {
                Ok(DnsAction::Update {
                    record_id: rec.id as u64,
                    ttl: cfg.ttl,
                    prev: current,
                })
            }
        }

        async fn create_a(
            &self,
            cfg: &AppConfig,
            name: &str,
            ip: Ipv4Addr,
            ttl: u32,
        ) -> Result<()> {
            let url = format!("{}/v2/domains/{}/records", self.api_base, cfg.zone);
            let body = serde_json::json!({ "type": "A", "name": name, "data": ip.to_string(), "ttl": ttl });
            let resp = self
                .client
                .post(&url)
                .bearer_auth(self.token.expose_secret())
                .json(&body)
                .send()
                .await
                .map_err(|e| err(format!("create request: {}", e.without_url())))?;
            if !resp.status().is_success() {
                return Err(err(format!("create unexpected status: {}", resp.status())));
            }
            Ok(())
        }

        async fn update_a(
            &self,
            cfg: &AppConfig,
            record_id: u64,
            ip: Ipv4Addr,
            ttl: u32,
        ) -> Result<()> {
            let url = format!(
                "{}/v2/domains/{}/records/{}",
                self.api_base, cfg.zone, record_id
            );
            let body = serde_json::json!({ "data": ip.to_string(), "ttl": ttl });
            let resp = self
                .client
                .patch(&url)
                .bearer_auth(self.token.expose_secret())
                .json(&body)
                .send()
                .await
                .map_err(|e| err(format!("update request: {}", e.without_url())))?;
            if !resp.status().is_success() {
                return Err(err(format!("update unexpected status: {}", resp.status())));
            }
            Ok(())
        }
    }
}
