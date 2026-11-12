//! Plan A, AAAA, `_dnsaddr` TXT and CNAME records against DNSimple and print the dry run,
//! without writing anything. Runs offline against a local mock of the DNSimple API.
//!
//! `cargo run --example dns_plan_dry_run`

use grindvakt_core::provider::DnsimpleProvider;
use grindvakt_core::record::Record;
use grindvakt_core::{SecretString, plan};
use serde_json::json;
use wiremock::matchers::{method, path_regex, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn rec(id: u64, name: &str, kind: &str, content: &str) -> serde_json::Value {
    json!({"id": id, "zone_id": "example.com", "parent_id": null, "name": name, "content": content,
        "ttl": 300, "priority": null, "type": kind, "regions": null, "system_record": false,
        "created_at": "2020-01-01T00:00:00Z", "updated_at": "2020-01-01T00:00:00Z"})
}

fn page(records: serde_json::Value) -> ResponseTemplate {
    let n = records.as_array().map(|a| a.len()).unwrap_or(0);
    ResponseTemplate::new(200)
        .insert_header("X-RateLimit-Limit", "4000")
        .insert_header("X-RateLimit-Remaining", "3999")
        .insert_header("X-RateLimit-Reset", "1700000000")
        .set_body_json(json!({"data": records, "pagination":
            {"current_page": 1, "per_page": 100, "total_entries": n, "total_pages": 1}}))
}

/// Records of every type at `name` (what the CNAME exclusivity check asks for).
async fn name_has(server: &MockServer, name: &str, records: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/example.com/records$"))
        .and(query_param_is_missing("type"))
        .and(query_param("name", name))
        .respond_with(page(records))
        .mount(server)
        .await;
}

async fn zone_has(server: &MockServer, kind: &str, records: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/example.com/records$"))
        .and(query_param("type", kind))
        .respond_with(page(records))
        .mount(server)
        .await;
}

#[tokio::main]
async fn main() -> grindvakt_core::Result<()> {
    let server = MockServer::start().await;
    // The zone today: a stale A record, an SPF record and an old dnsaddr record.
    zone_has(&server, "A", json!([rec(1, "home", "A", "198.51.100.20")])).await;
    zone_has(&server, "AAAA", json!([])).await;
    // No CNAMEs yet; "mail" has an MX record, "www" has nothing.
    zone_has(&server, "CNAME", json!([])).await;
    name_has(&server, "www", json!([])).await;
    name_has(
        &server,
        "mail",
        json!([rec(4, "mail", "MX", "mx.example.net")]),
    )
    .await;
    zone_has(
        &server,
        "TXT",
        json!([
            rec(2, "_dnsaddr.home", "TXT", "\"v=spf1 -all\""),
            rec(
                3,
                "_dnsaddr.home",
                "TXT",
                "\"dnsaddr=/dns4/home.example.com/tcp/4001/p2p/12D3KooWOld\""
            ),
        ]),
    )
    .await;

    let token = SecretString::from("dnsimple-example-token".to_string());
    let dns = DnsimpleProvider::new(&token, false, Some(&server.uri()), Some(1234))?;
    let peer = "12D3KooWNew";
    let want = [
        Record::a("home", "203.0.113.7".parse().unwrap()),
        Record::aaaa("home", "2606:4700::7".parse().unwrap()),
        Record::txt(
            "_dnsaddr.home",
            format!("dnsaddr=/dns4/home.example.com/tcp/4747/p2p/{peer}"),
        ),
        Record::cname("www", "home.example.com"),
    ];
    let p = plan(&dns, "example.com", &want).await?;
    println!("DRY RUN for zone {}:\n{p}", p.zone);
    println!("{} change(s); nothing was written.", p.changes().count());

    // A CNAME must be alone at its name, so this plan is refused rather than deleting the MX.
    let p = plan(
        &dns,
        "example.com",
        &[Record::cname("mail", "home.example.com")],
    )
    .await?;
    println!("\n{p}");
    assert_eq!(p.ambiguous().count(), 1);
    Ok(())
}
