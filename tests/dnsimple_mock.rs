//! DNSimple provider against a mock API.
#![cfg(feature = "dnsimple")]
use grindvakt_core::plan::Change;
use grindvakt_core::provider::{DnsProvider, DnsimpleProvider};
use grindvakt_core::record::{Record, RecordKind, RecordValue};
use grindvakt_core::{Error, SecretString, apply, plan};
use serde_json::json;
use std::net::{Ipv4Addr, Ipv6Addr};
use wiremock::matchers::{body_json, method, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn rl(t: ResponseTemplate) -> ResponseTemplate {
    t.insert_header("X-RateLimit-Limit", "4000")
        .insert_header("X-RateLimit-Remaining", "3999")
        .insert_header("X-RateLimit-Reset", "1700000000")
}

fn rec(id: u64, name: &str, kind: &str, content: &str, ttl: u64) -> serde_json::Value {
    json!({
        "id": id, "zone_id": "example.com", "parent_id": null, "name": name,
        "content": content, "ttl": ttl, "priority": null, "type": kind,
        "regions": null, "system_record": false,
        "created_at": "2020-01-01T00:00:00Z", "updated_at": "2020-01-01T00:00:00Z"
    })
}

fn page(data: serde_json::Value, page: u64, total: u64) -> serde_json::Value {
    json!({"data": data, "pagination": {"current_page": page, "per_page": 100,
        "total_entries": data.as_array().map(|a| a.len()).unwrap_or(0), "total_pages": total}})
}

async fn list_mock(server: &MockServer, kind: &str, data: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/example.com/records$"))
        .and(query_param("type", kind))
        .respond_with(rl(
            ResponseTemplate::new(200).set_body_json(page(data, 1, 1))
        ))
        .mount(server)
        .await;
}

fn client(server: &MockServer) -> DnsimpleProvider {
    DnsimpleProvider::new(
        &SecretString::from("t".to_string()),
        false,
        Some(&server.uri()),
        Some(1234),
    )
    .unwrap()
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

#[tokio::test]
async fn plans_noop_create_and_ambiguous() {
    let server = MockServer::start().await;
    list_mock(
        &server,
        "A",
        json!([
            rec(10, "", "A", "93.184.216.34", 300),
            rec(11, "dup", "A", "1.1.1.1", 300),
            rec(12, "dup", "A", "1.1.1.2", 300)
        ]),
    )
    .await;
    let c = client(&server);
    let p = plan(
        &c,
        "example.com",
        &[
            Record::a("@", v4("93.184.216.34")),
            Record::a("www", v4("93.184.216.34")),
            Record::a("dup", v4("93.184.216.34")),
        ],
    )
    .await
    .unwrap();
    assert_eq!(p.actions[0].change, Change::Noop);
    assert_eq!(p.actions[1].change, Change::Create);
    assert!(matches!(p.actions[2].change, Change::Ambiguous { .. }));
    assert!(matches!(apply(&c, &p).await, Err(Error::Ambiguous(_))));
}

#[tokio::test]
async fn creates_a_aaaa_and_txt_with_expected_bodies() {
    let server = MockServer::start().await;
    for k in ["A", "AAAA", "TXT"] {
        list_mock(&server, k, json!([])).await;
    }
    let txt = "dnsaddr=/dns4/home.example.com/tcp/4747/p2p/12D3KooWTest";
    for (kind, content, name) in [
        ("A", "1.2.3.4", "home"),
        ("AAAA", "2606:4700::1", "home"),
        ("TXT", txt, "_dnsaddr.home"),
    ] {
        Mock::given(method("POST"))
            .and(path_regex(".*/zones/example.com/records$"))
            .and(body_json(json!({"name": name, "type": kind, "content": content, "ttl": 300, "priority": null})))
            .respond_with(rl(ResponseTemplate::new(201).set_body_json(json!({"data": rec(42, name, kind, content, 300)}))))
            .expect(1)
            .mount(&server)
            .await;
    }
    let c = client(&server);
    let want = [
        Record::a("home", v4("1.2.3.4")),
        Record::aaaa(
            "home.example.com",
            "2606:4700::1".parse::<Ipv6Addr>().unwrap(),
        ),
        Record::txt("_dnsaddr.home", txt),
    ];
    let p = plan(&c, "example.com", &want).await.unwrap();
    assert_eq!(p.changes().count(), 3);
    assert_eq!(apply(&c, &p).await.unwrap().len(), 3);
}

#[tokio::test]
async fn quoted_txt_from_dnsimple_matches() {
    let server = MockServer::start().await;
    list_mock(
        &server,
        "TXT",
        json!([
            rec(
                5,
                "_dnsaddr.home",
                "TXT",
                "\"dnsaddr=/dns4/h/tcp/1/p2p/X\"",
                300
            ),
            rec(6, "_dnsaddr.home", "TXT", "\"v=spf1 -all\"", 300)
        ]),
    )
    .await;
    let c = client(&server);
    let p = plan(
        &c,
        "example.com",
        &[Record::txt("_dnsaddr.home", "dnsaddr=/dns4/h/tcp/1/p2p/X")],
    )
    .await
    .unwrap();
    assert!(p.is_noop(), "{p}");
}

#[tokio::test]
async fn updates_with_patch_and_reads_all_pages() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/example.com/records$"))
        .and(query_param("page", "1"))
        .respond_with(rl(ResponseTemplate::new(200).set_body_json(page(
            json!([]),
            1,
            2,
        ))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(".*/zones/example.com/records$"))
        .and(query_param("page", "2"))
        .respond_with(rl(ResponseTemplate::new(200).set_body_json(page(
            json!([rec(7, "", "A", "9.9.9.9", 300)]),
            2,
            2,
        ))))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path_regex(".*/v2/1234/zones/example.com/records/7$"))
        .and(body_json(
            json!({"name": null, "content": "5.6.7.8", "ttl": 300, "priority": null}),
        ))
        .respond_with(rl(ResponseTemplate::new(200)
            .set_body_json(json!({"data": rec(7, "", "A", "5.6.7.8", 300)}))))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    let p = plan(&c, "example.com", &[Record::a("@", v4("5.6.7.8"))])
        .await
        .unwrap();
    assert!(
        matches!(&p.actions[0].change, Change::Update { id: 7, prev: RecordValue::A(prev), .. } if *prev == v4("9.9.9.9"))
    );
    apply(&c, &p).await.unwrap();
}

#[tokio::test]
async fn typed_errors() {
    for (status, check) in [
        (
            401u16,
            (|e: &Error| matches!(e, Error::Auth { .. })) as fn(&Error) -> bool,
        ),
        (403, |e| matches!(e, Error::Auth { .. })),
        (429, |e| matches!(e, Error::RateLimited { .. })),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(".*/zones/example.com/records$"))
            .respond_with(rl(
                ResponseTemplate::new(status).set_body_json(json!({"message": "nope"}))
            ))
            .mount(&server)
            .await;
        let e = client(&server)
            .list("example.com", "home", RecordKind::A)
            .await
            .unwrap_err();
        assert!(check(&e), "{status}: {e:?}");
        assert!(!e.to_string().contains("t\""), "no token in message");
    }
}
