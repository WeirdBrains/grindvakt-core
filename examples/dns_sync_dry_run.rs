//! Plan and dry-run a sync against a local mock of the DNSimple API (no real DNS touched),
//! then apply it against the same mock.
//!
//! `cargo run --example dns_sync_dry_run`

use grindvakt_core::SecretString;
use grindvakt_core::config::AppConfig;
use grindvakt_core::provider::{self, DnsProvider};
use grindvakt_core::sync::{SyncMode, sync_once};
use serde_json::json;
use std::net::Ipv4Addr;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// DNSimple always sends rate-limit headers; the client expects them.
fn dnsimple_response(body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("X-RateLimit-Limit", "4000")
        .insert_header("X-RateLimit-Remaining", "3999")
        .insert_header("X-RateLimit-Reset", "1700000000")
        .set_body_json(body)
}

#[tokio::main]
async fn main() -> grindvakt_core::Result<()> {
    // A DNSimple look-alike with one stale A record for home.example.net.
    let server = MockServer::start().await;
    let record = json!({
        "id": 7, "zone_id": "example.net", "parent_id": null, "name": "home",
        "content": "198.51.100.20", "ttl": 300, "priority": null, "type": "A",
        "regions": null, "system_record": false,
        "created_at": "2020-01-01T00:00:00Z", "updated_at": "2020-01-01T00:00:00Z"
    });
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/.*/records$"))
        .respond_with(dnsimple_response(json!({
            "data": [record.clone()],
            "pagination": {"current_page": 1, "per_page": 100, "total_entries": 1, "total_pages": 1}
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path_regex(".*/zones/.*/records/7$"))
        .respond_with(dnsimple_response(json!({ "data": record })))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = AppConfig {
        zone: "example.net".into(),
        name: "home".into(),
        account_id: Some(1234), // skips the whoami call
        api_base_url: Some(server.uri()),
        ..AppConfig::default()
    };
    let token = SecretString::from("mock-token".to_string());
    let dns = provider::build(&cfg, &token)?;
    let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();

    println!("plan: {:?}", dns.plan(&cfg, ip).await?);
    println!("{}", sync_once(&cfg, &dns, ip, SyncMode::DryRun).await?);
    println!("{}", sync_once(&cfg, &dns, ip, SyncMode::Apply).await?);
    Ok(())
}
