#![cfg(feature = "dnsimple")]
use grindvakt_core::SecretString;
use grindvakt_core::config::{AppConfig, Provider};
use grindvakt_core::provider::{DnsProvider, DnsimpleProvider};
use serde_json::json;
use wiremock::matchers::{body_json, method, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn with_rl_headers(t: ResponseTemplate) -> ResponseTemplate {
    t.insert_header("X-RateLimit-Limit", "4000")
        .insert_header("X-RateLimit-Remaining", "3999")
        .insert_header("X-RateLimit-Reset", "1700000000")
}
fn page_json(data: serde_json::Value, page: u64, total_pages: u64) -> serde_json::Value {
    json!({
        "data": data,
        "pagination": {
            "current_page": page,
            "per_page": 100,
            "total_entries": data.as_array().map(|a| a.len()).unwrap_or(0),
            "total_pages": total_pages
        }
    })
}

fn record_json(id: u64, name: &str, content: &str, ttl: u64) -> serde_json::Value {
    json!({
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

#[tokio::test]
async fn create_posts_expected_body_once() {
    let server = MockServer::start().await;
    // No existing records
    let resp = page_json(json!([]), 1, 1);
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/.*/records$"))
        .and(query_param("page", "1"))
        .respond_with(with_rl_headers(
            ResponseTemplate::new(200).set_body_json(resp),
        ))
        .mount(&server)
        .await;

    // Expect POST with payload
    let expected = json!({
        "name": "www",
        "type": "A",
        "content": "1.2.3.4",
        "ttl": 300,
        "priority": null
    });
    Mock::given(method("POST"))
        .and(path_regex(".*/zones/.*/records$"))
        .and(body_json(expected))
        .respond_with(with_rl_headers(
            ResponseTemplate::new(201)
                .set_body_json(json!({"data": record_json(42,"www","1.2.3.4",300)})),
        ))
        .expect(1)
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
    client
        .create_a(
            &cfg,
            "www",
            "1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap(),
            300,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn update_patches_expected_body_once() {
    let server = MockServer::start().await;
    // Expect PATCH to id 10 (SDK uses PATCH)
    let expected = json!({"name": null, "content":"5.6.7.8","ttl":300,"priority":null});
    Mock::given(method("PATCH"))
        .and(path_regex(".*/v2/.*/zones/.*/records/10$"))
        .and(body_json(expected))
        .respond_with(with_rl_headers(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": record_json(10,"www","5.6.7.8",300)})),
        ))
        .expect(1)
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
    client
        .update_a(
            &cfg,
            10,
            "5.6.7.8".parse::<std::net::Ipv4Addr>().unwrap(),
            300,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn pagination_across_pages() {
    let server = MockServer::start().await;
    let page1 = page_json(json!([]), 1, 2);
    let page2 = page_json(json!([record_json(7, "", "9.9.9.9", 300)]), 2, 2);
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/.*/records$"))
        .and(query_param("page", "1"))
        .respond_with(with_rl_headers(
            ResponseTemplate::new(200).set_body_json(page1.clone()),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/.*/records$"))
        .and(query_param("page", "2"))
        .respond_with(with_rl_headers(
            ResponseTemplate::new(200).set_body_json(page2.clone()),
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
        .plan(&cfg, "1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap())
        .await
        .unwrap();
    match action {
        grindvakt_core::provider::DnsAction::Update { record_id, .. } => assert_eq!(record_id, 7),
        _ => panic!("expected Update"),
    }
}
