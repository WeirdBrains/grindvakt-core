//! DigitalOcean provider against a mock API.
#![cfg(feature = "digitalocean")]
use grindvakt_core::plan::Change;
use grindvakt_core::provider::{DigitalOceanProvider, DnsProvider};
use grindvakt_core::record::{Record, RecordKind};
use grindvakt_core::{Error, SecretString, apply, plan};
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn list(records: serde_json::Value, next: bool) -> serde_json::Value {
    json!({"domain_records": records, "links": if next { json!({"pages": {"next": "n"}}) } else { json!({}) }})
}

fn client(server: &MockServer) -> DigitalOceanProvider {
    DigitalOceanProvider::new(
        &SecretString::from("do_test_token".to_string()),
        Some(&server.uri()),
    )
    .unwrap()
}

async fn list_mock(server: &MockServer, kind: &str, records: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/v2/domains/example.com/records"))
        .and(query_param("type", kind))
        .and(header("authorization", "Bearer do_test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list(records, false)))
        .mount(server)
        .await;
}

#[tokio::test]
async fn noop_update_and_apex() {
    let server = MockServer::start().await;
    list_mock(
        &server,
        "A",
        json!([
            {"id": 10, "type": "A", "name": "www", "data": "1.2.3.4", "ttl": 300},
            {"id": 11, "type": "A", "name": "@", "data": "1.2.3.4", "ttl": 1800},
            {"id": 12, "type": "A", "name": "other", "data": "8.8.8.8", "ttl": 300},
        ]),
    )
    .await;
    list_mock(&server, "CNAME", json!([])).await;
    let c = client(&server);
    let ip = "1.2.3.4".parse().unwrap();
    let p = plan(
        &c,
        "example.com",
        &[
            Record::a("www", ip),
            Record::a("@", ip),
            Record::a("new", ip),
        ],
    )
    .await
    .unwrap();
    assert_eq!(p.actions[0].change, Change::Noop);
    assert!(
        matches!(
            p.actions[1].change,
            Change::Update {
                id: 11,
                prev_ttl: Some(1800),
                ..
            }
        ),
        "ttl fix: {p}"
    );
    assert_eq!(p.actions[2].change, Change::Create);
}

#[tokio::test]
async fn writes_expected_bodies() {
    let server = MockServer::start().await;
    list_mock(
        &server,
        "A",
        json!([{"id": 11, "type": "A", "name": "@", "data": "9.9.9.9", "ttl": 300}]),
    )
    .await;
    list_mock(
        &server,
        "TXT",
        json!([{"id": 20, "type": "TXT", "name": "_dnsaddr", "data": "v=spf1 -all", "ttl": 300}]),
    )
    .await;
    list_mock(&server, "AAAA", json!([])).await;
    list_mock(&server, "CNAME", json!([])).await;
    let txt = "dnsaddr=/dns6/example.com/tcp/4747/p2p/12D3KooWTest";
    Mock::given(method("PATCH"))
        .and(path("/v2/domains/example.com/records/11"))
        .and(body_json(json!({"data": "1.2.3.4", "ttl": 300})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"domain_record": {}})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/domains/example.com/records"))
        .and(body_json(
            json!({"type": "TXT", "name": "_dnsaddr", "data": txt, "ttl": 300}),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"domain_record": {}})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/domains/example.com/records"))
        .and(body_json(
            json!({"type": "AAAA", "name": "@", "data": "2606:4700::1", "ttl": 300}),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"domain_record": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    let want = [
        Record::a("@", "1.2.3.4".parse().unwrap()),
        Record::txt("_dnsaddr.example.com", txt), // the SPF record at the same name is left alone
        Record::aaaa("", "2606:4700::1".parse().unwrap()),
    ];
    let p = plan(&c, "example.com.", &want).await.unwrap();
    assert_eq!(apply(&c, &p).await.unwrap().len(), 3);
}

#[tokio::test]
async fn cname_wants_a_trailing_dot_and_reads_relative_data() {
    let server = MockServer::start().await;
    list_mock(
        &server,
        "CNAME",
        json!([
            {"id": 30, "type": "CNAME", "name": "www", "data": "home.example.com.", "ttl": 300},
            {"id": 31, "type": "CNAME", "name": "blog", "data": "home", "ttl": 300},
            {"id": 32, "type": "CNAME", "name": "apex", "data": "@", "ttl": 300},
        ]),
    )
    .await;
    // Any-type listing for the exclusivity check: "mail" has an MX record.
    Mock::given(method("GET"))
        .and(path("/v2/domains/example.com/records"))
        .and(wiremock::matchers::query_param_is_missing("type"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list(
            json!([
                {"id": 30, "type": "CNAME", "name": "www", "data": "home.example.com.", "ttl": 300},
                {"id": 40, "type": "MX", "name": "mail", "data": "mx.example.net.", "ttl": 300},
            ]),
            false,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/domains/example.com/records"))
        .and(body_json(
            json!({"type": "CNAME", "name": "docs", "data": "pages.example.net.", "ttl": 300}),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"domain_record": {}})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/v2/domains/example.com/records/32"))
        .and(body_json(json!({"data": "home.example.com.", "ttl": 300})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"domain_record": {}})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    let p = plan(
        &c,
        "example.com",
        &[
            Record::cname("www", "home.example.com"),
            Record::cname("blog", "home.example.com."),
            Record::cname("docs", "Pages.Example.net"),
            Record::cname("apex", "home.example.com"),
        ],
    )
    .await
    .unwrap();
    assert_eq!(p.actions[0].change, Change::Noop, "{p}");
    assert_eq!(p.actions[1].change, Change::Noop, "relative data: {p}");
    assert_eq!(p.actions[2].change, Change::Create, "{p}");
    assert!(
        matches!(p.actions[3].change, Change::Update { id: 32, .. }),
        "{p}"
    );
    assert_eq!(apply(&c, &p).await.unwrap().len(), 2);

    let p = plan(
        &c,
        "example.com",
        &[Record::cname("mail", "home.example.com")],
    )
    .await
    .unwrap();
    assert!(
        matches!(&p.actions[0].change, Change::Ambiguous { reason } if reason.contains("MX")),
        "{p}"
    );
    let types = c.types_at("example.com", "mail").await.unwrap();
    assert_eq!(types, ["MX"]);
}

#[tokio::test]
async fn typed_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(query_param("type", "A"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(query_param("type", "AAAA"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "30"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(query_param("type", "TXT"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let c = client(&server);
    let e = c
        .list("example.com", "home", RecordKind::A)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Auth { .. }), "{e:?}");
    let e = c
        .list("example.com", "home", RecordKind::Aaaa)
        .await
        .unwrap_err();
    assert!(
        matches!(e, Error::RateLimited { retry_after: Some(d), .. } if d == Duration::from_secs(30)),
        "{e:?}"
    );
    let e = c
        .list("example.com", "home", RecordKind::Txt)
        .await
        .unwrap_err();
    assert!(
        matches!(e, Error::Provider { .. }) && e.is_retryable(),
        "{e:?}"
    );
    assert!(!format!("{e} {e:?}").contains("do_test_token"));

    let dead = DigitalOceanProvider::new(
        &SecretString::from("x".to_string()),
        Some("http://127.0.0.1:9"),
    )
    .unwrap();
    let e = dead
        .list("example.com", "home", RecordKind::A)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Network(_)), "{e:?}");
    assert!(
        !e.to_string().contains("127.0.0.1:9/v2"),
        "no URL in message: {e}"
    );
}

#[tokio::test]
async fn pagination_cap() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list(json!([]), true)))
        .mount(&server)
        .await;
    let e = client(&server)
        .list("example.com", "www", RecordKind::A)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("pagination exceeded"), "{e}");
}
