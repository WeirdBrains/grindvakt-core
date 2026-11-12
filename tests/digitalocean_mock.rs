#![cfg(feature = "digitalocean")]
use grindvakt_core::SecretString;
use grindvakt_core::config::{AppConfig, Provider, Schedule};
use grindvakt_core::provider::build;
use grindvakt_core::provider::{DnsAction, DnsProvider};
use serde_json::json;
use std::net::Ipv4Addr;
use wiremock::matchers::{method, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn do_list_resp(records: serde_json::Value, next: bool) -> serde_json::Value {
    json!({"domain_records": records, "links": if next { json!({"pages":{"next":"n"}}) } else { json!({}) }})
}

#[tokio::test]
async fn do_plan_create_when_missing() {
    let server = MockServer::start().await;
    let resp = do_list_resp(json!([]), false);
    Mock::given(method("GET"))
        .and(path_regex("/v2/domains/.*/records"))
        .and(query_param("type", "A"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resp))
        .mount(&server)
        .await;
    let cfg = AppConfig {
        provider: Provider::Digitalocean,
        account_id: None,
        zone: "example.com".into(),
        name: "www".into(),
        ttl: 300,
        sandbox: false,
        api_base_url: Some(server.uri()),
        schedule: Schedule {
            calendar: None,
            interval_secs: Some(300),
        },
    };
    let token = SecretString::from("do_test_token".to_string());
    let provider = build(&cfg, &token).unwrap();
    let action = provider
        .plan(&cfg, "1.2.3.4".parse().unwrap())
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
async fn do_plan_noop_when_matching_ip_and_ttl() {
    let server = MockServer::start().await;
    let recs = json!([ { "id": 10, "type":"A", "name":"www", "data":"1.2.3.4", "ttl": 300 } ]);
    let resp = do_list_resp(recs, false);
    Mock::given(method("GET"))
        .and(path_regex("/v2/domains/.*/records"))
        .and(query_param("type", "A"))
        .and(query_param("name", "www"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resp))
        .mount(&server)
        .await;
    let cfg = AppConfig {
        provider: Provider::Digitalocean,
        account_id: None,
        zone: "example.com".into(),
        name: "www".into(),
        ttl: 300,
        sandbox: false,
        api_base_url: Some(server.uri()),
        schedule: Schedule {
            calendar: None,
            interval_secs: Some(300),
        },
    };
    let token = SecretString::from("do_test_token".to_string());
    let provider = build(&cfg, &token).unwrap();
    let action = provider
        .plan(&cfg, "1.2.3.4".parse().unwrap())
        .await
        .unwrap();
    match action {
        DnsAction::Noop(ip) => {
            let want: Ipv4Addr = "1.2.3.4".parse::<Ipv4Addr>().unwrap();
            assert_eq!(ip, want)
        }
        _ => panic!("expected Noop"),
    }
}

#[tokio::test]
async fn do_plan_update_when_ip_or_ttl_differs() {
    let server = MockServer::start().await;
    let recs = json!([ { "id": 42, "type":"A", "name":"www", "data":"2.2.2.2", "ttl": 120 } ]);
    let resp = do_list_resp(recs, false);
    Mock::given(method("GET"))
        .and(path_regex("/v2/domains/.*/records"))
        .and(query_param("type", "A"))
        .and(query_param("name", "www"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resp))
        .mount(&server)
        .await;
    let cfg = AppConfig {
        provider: Provider::Digitalocean,
        account_id: None,
        zone: "example.com".into(),
        name: "www".into(),
        ttl: 300,
        sandbox: false,
        api_base_url: Some(server.uri()),
        schedule: Schedule {
            calendar: None,
            interval_secs: Some(300),
        },
    };
    let token = SecretString::from("do_test_token".to_string());
    let provider = build(&cfg, &token).unwrap();
    let action = provider
        .plan(&cfg, "1.2.3.4".parse().unwrap())
        .await
        .unwrap();
    match action {
        DnsAction::Update {
            record_id,
            ttl,
            prev,
        } => {
            assert_eq!(record_id, 42);
            assert_eq!(ttl, 300);
            let want: Ipv4Addr = "2.2.2.2".parse::<Ipv4Addr>().unwrap();
            assert_eq!(prev, want);
        }
        _ => panic!("expected Update"),
    }
}

#[tokio::test]
async fn do_plan_create_apex_uses_at_name() {
    let server = MockServer::start().await;
    let resp = do_list_resp(json!([]), false);
    Mock::given(method("GET"))
        .and(path_regex("/v2/domains/.*/records"))
        .and(query_param("type", "A"))
        .and(query_param("name", "@"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resp))
        .mount(&server)
        .await;
    let cfg = AppConfig {
        provider: Provider::Digitalocean,
        account_id: None,
        zone: "example.com".into(),
        name: "@".into(),
        ttl: 300,
        sandbox: false,
        api_base_url: Some(server.uri()),
        schedule: Schedule {
            calendar: None,
            interval_secs: Some(300),
        },
    };
    let token = SecretString::from("do_test_token".to_string());
    let provider = build(&cfg, &token).unwrap();
    let action = provider
        .plan(&cfg, "9.8.7.6".parse().unwrap())
        .await
        .unwrap();
    match action {
        DnsAction::Create { name, ttl } => {
            assert_eq!(name, "@");
            assert_eq!(ttl, 300);
        }
        _ => panic!("expected Create"),
    }
}

#[tokio::test]
async fn do_list_pagination_cap_exceeded() {
    let server = MockServer::start().await;
    // Pages 1..50 each return next=true and empty list
    for p in 1..=50 {
        let resp = do_list_resp(json!([]), true);
        Mock::given(method("GET"))
            .and(path_regex("/v2/domains/.*/records"))
            .and(query_param("type", "A"))
            .and(query_param("page", p.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(resp))
            .mount(&server)
            .await;
    }
    let cfg = AppConfig {
        provider: Provider::Digitalocean,
        account_id: None,
        zone: "example.com".into(),
        name: "www".into(),
        ttl: 300,
        sandbox: false,
        api_base_url: Some(server.uri()),
        schedule: Schedule {
            calendar: None,
            interval_secs: Some(300),
        },
    };
    let token = SecretString::from("do_test_token".to_string());
    let provider = build(&cfg, &token).unwrap();
    let err = provider
        .plan(&cfg, "1.1.1.1".parse().unwrap())
        .await
        .err()
        .unwrap();
    assert!(format!("{err}").contains("pagination exceeded"));
}

#[tokio::test]
async fn do_list_errors_fail_fast() {
    for status in [401, 403, 429] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/v2/domains/.*/records"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let cfg = AppConfig {
            provider: Provider::Digitalocean,
            account_id: None,
            zone: "example.com".into(),
            name: "www".into(),
            ttl: 300,
            sandbox: false,
            api_base_url: Some(server.uri()),
            schedule: Schedule {
                calendar: None,
                interval_secs: Some(300),
            },
        };
        let token = SecretString::from("do_test_token".to_string());
        let provider = build(&cfg, &token).unwrap();
        let err = provider
            .plan(&cfg, "1.2.3.4".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert!(format!("{err}").contains("digitalocean API: list error"));
    }
}

#[tokio::test]
async fn do_create_posts_expected_body_once() {
    let server = MockServer::start().await;
    // No existing records
    let resp = do_list_resp(json!([]), false);
    Mock::given(method("GET"))
        .and(path_regex("/v2/domains/.*/records"))
        .and(query_param("type", "A"))
        .and(query_param("name", "www"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resp))
        .mount(&server)
        .await;
    // Expect POST with payload
    let expected = json!({ "type":"A","name":"www","data":"1.2.3.4","ttl":300 });
    Mock::given(method("POST"))
        .and(path_regex("/v2/domains/.*/records$"))
        .and(wiremock::matchers::body_json(expected))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"domain_record": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = AppConfig {
        provider: Provider::Digitalocean,
        account_id: None,
        zone: "example.com".into(),
        name: "www".into(),
        ttl: 300,
        sandbox: false,
        api_base_url: Some(server.uri()),
        schedule: Schedule {
            calendar: None,
            interval_secs: Some(300),
        },
    };
    let token = SecretString::from("do_test_token".to_string());
    let provider = build(&cfg, &token).unwrap();
    // Act: create via provider
    provider
        .create_a(&cfg, "www", "1.2.3.4".parse().unwrap(), 300)
        .await
        .unwrap();
}

#[tokio::test]
async fn do_update_patches_expected_body_once() {
    let server = MockServer::start().await;
    let expected = json!({ "data":"5.6.7.8","ttl":300 });
    Mock::given(method("PATCH"))
        .and(path_regex("/v2/domains/.*/records/10$"))
        .and(wiremock::matchers::body_json(expected))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"domain_record": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = AppConfig {
        provider: Provider::Digitalocean,
        account_id: None,
        zone: "example.com".into(),
        name: "www".into(),
        ttl: 300,
        sandbox: false,
        api_base_url: Some(server.uri()),
        schedule: Schedule {
            calendar: None,
            interval_secs: Some(300),
        },
    };
    let token = SecretString::from("do_test_token".to_string());
    let provider = build(&cfg, &token).unwrap();
    provider
        .update_a(&cfg, 10, "5.6.7.8".parse().unwrap(), 300)
        .await
        .unwrap();
}
