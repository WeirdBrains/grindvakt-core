//! Plan A, AAAA and `_dnsaddr` TXT records against DNSimple and print the dry run, without
//! writing anything. Runs offline against a local mock of the DNSimple API.
//!
//! `cargo run --example dns_plan_dry_run`

use grindvakt_core::provider::DnsimpleProvider;
use grindvakt_core::record::Record;
use grindvakt_core::{SecretString, plan};
use serde_json::json;
use wiremock::matchers::{method, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn rec(id: u64, name: &str, kind: &str, content: &str) -> serde_json::Value {
    json!({"id": id, "zone_id": "example.com", "parent_id": null, "name": name, "content": content,
        "ttl": 300, "priority": null, "type": kind, "regions": null, "system_record": false,
        "created_at": "2020-01-01T00:00:00Z", "updated_at": "2020-01-01T00:00:00Z"})
}

async fn zone_has(server: &MockServer, kind: &str, records: serde_json::Value) {
    let n = records.as_array().map(|a| a.len()).unwrap_or(0);
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/example.com/records$"))
        .and(query_param("type", kind))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-RateLimit-Limit", "4000")
                .insert_header("X-RateLimit-Remaining", "3999")
                .insert_header("X-RateLimit-Reset", "1700000000")
                .set_body_json(json!({"data": records, "pagination":
                    {"current_page": 1, "per_page": 100, "total_entries": n, "total_pages": 1}})),
        )
        .mount(server)
        .await;
}

#[tokio::main]
async fn main() -> grindvakt_core::Result<()> {
    let server = MockServer::start().await;
    // The zone today: a stale A record, an SPF record and an old dnsaddr record.
    zone_has(&server, "A", json!([rec(1, "home", "A", "198.51.100.20")])).await;
    zone_has(&server, "AAAA", json!([])).await;
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
    ];
    let p = plan(&dns, "example.com", &want).await?;
    println!("DRY RUN for zone {}:\n{p}", p.zone);
    println!("{} change(s); nothing was written.", p.changes().count());
    Ok(())
}
