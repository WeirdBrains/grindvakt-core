#![cfg(feature = "dnsimple")]
use grindvakt_core::SecretString;
use grindvakt_core::config::{AppConfig, Provider};
use grindvakt_core::provider::{DnsAction, DnsProvider, DnsimpleProvider};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn with_rl_headers(t: ResponseTemplate) -> ResponseTemplate {
    t.insert_header("X-RateLimit-Limit", "4000")
        .insert_header("X-RateLimit-Remaining", "3999")
        .insert_header("X-RateLimit-Reset", "1700000000")
}

fn record_json(id: u64, name: &str, content: &str, ttl: u64) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "zone_id": "example.com",
        "parent_id": null,
        "name": name,
        "content": content,
        "ttl": ttl,
        "priority": null,
        "type": "A",
        "regions": null,
        "system_record": false,
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2020-01-01T00:00:00Z"
    })
}

fn page_json(data: serde_json::Value, page: u64, total_pages: u64) -> serde_json::Value {
    serde_json::json!({
        "data": data,
        "pagination": {
            "current_page": page,
            "per_page": 100,
            "total_entries": 1,
            "total_pages": total_pages
        }
    })
}

#[tokio::test]
async fn plan_noop_when_matching_record_exists() {
    let server = MockServer::start().await;
    let resp = page_json(
        serde_json::json!([record_json(10, "", "93.184.216.34", 300)]),
        1,
        1,
    );
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/.*/records"))
        .respond_with(with_rl_headers(
            ResponseTemplate::new(200).set_body_json(resp),
        ))
        .mount(&server)
        .await;

    let cfg = AppConfig {
        provider: Provider::Dnsimple,
        account_id: Some(1234),
        zone: "example.com".into(),
        name: "@".into(),
        ttl: 300,
        sandbox: false,
        api_base_url: Some(server.uri()),
        schedule: Default::default(),
    };
    let client = DnsimpleProvider::new(
        &SecretString::from("t".to_string()),
        cfg.sandbox,
        cfg.api_base_url.as_deref(),
        cfg.account_id,
    )
    .unwrap();
    let action = client
        .plan(&cfg, "93.184.216.34".parse::<std::net::Ipv4Addr>().unwrap())
        .await
        .unwrap();
    match action {
        DnsAction::Noop(ip) => {
            assert_eq!(ip, "93.184.216.34".parse::<std::net::Ipv4Addr>().unwrap())
        }
        _ => panic!("expected Noop"),
    }
}

#[tokio::test]
async fn plan_create_when_none_exists() {
    let server = MockServer::start().await;
    let resp = page_json(serde_json::json!([]), 1, 1);
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/.*/records"))
        .respond_with(with_rl_headers(
            ResponseTemplate::new(200).set_body_json(resp),
        ))
        .mount(&server)
        .await;
    let cfg = AppConfig {
        provider: Provider::Dnsimple,
        account_id: Some(1234),
        zone: "example.com".into(),
        name: "www".into(),
        ttl: 300,
        sandbox: false,
        api_base_url: Some(server.uri()),
        schedule: Default::default(),
    };
    let client = DnsimpleProvider::new(
        &SecretString::from("t".to_string()),
        cfg.sandbox,
        cfg.api_base_url.as_deref(),
        cfg.account_id,
    )
    .unwrap();
    let action = client
        .plan(&cfg, "1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap())
        .await
        .unwrap();
    match action {
        DnsAction::Create { name, ttl } => {
            assert_eq!(name, "www");
            assert_eq!(ttl, 300);
        }
        _ => panic!("expected Create"),
    }
}

#[tokio::test]
async fn plan_ambiguous_on_duplicates() {
    let server = MockServer::start().await;
    let resp = page_json(
        serde_json::json!([
            record_json(10, "www", "1.2.3.4", 300),
            record_json(11, "www", "2.3.4.5", 300)
        ]),
        1,
        1,
    );
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/.*/records"))
        .respond_with(with_rl_headers(
            ResponseTemplate::new(200).set_body_json(resp),
        ))
        .mount(&server)
        .await;
    let cfg = AppConfig {
        provider: Provider::Dnsimple,
        account_id: Some(1234),
        zone: "example.com".into(),
        name: "www".into(),
        ttl: 300,
        sandbox: false,
        api_base_url: Some(server.uri()),
        schedule: Default::default(),
    };
    let client = DnsimpleProvider::new(
        &SecretString::from("t".to_string()),
        cfg.sandbox,
        cfg.api_base_url.as_deref(),
        cfg.account_id,
    )
    .unwrap();
    let action = client
        .plan(&cfg, "1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap())
        .await
        .unwrap();
    assert!(matches!(action, DnsAction::Ambiguous { .. }));
}
