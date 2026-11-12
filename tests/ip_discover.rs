//! Address discovery against local mock sources.
#![cfg(feature = "public-ip")]
use grindvakt_core::Error;
use grindvakt_core::ip::{Family, Sources, discover};
use std::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn source(body: &str) -> String {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&s)
        .await;
    let uri = s.uri();
    std::mem::forget(s); // keep serving for the test's lifetime
    uri
}

fn sources(v4: Vec<String>, v6: Vec<String>) -> Sources {
    Sources {
        v4,
        v6,
        timeout: Duration::from_secs(2),
        ..Sources::default()
    }
}

#[tokio::test]
async fn finds_both_families() {
    let v4 = vec![
        source("93.184.216.34\n").await,
        source("ip: 93.184.216.34").await,
        source("garbage").await,
    ];
    let v6 = vec![
        source("2606:4700:4700::1111\n").await,
        source("2606:4700:4700::1111").await,
    ];
    let d = discover(Family::Both, &sources(v4, v6)).await.unwrap();
    assert_eq!(d.v4, Some("93.184.216.34".parse().unwrap()));
    assert_eq!(d.v6, Some("2606:4700:4700::1111".parse().unwrap()));
}

#[tokio::test]
async fn cgnat_only_means_no_global_address() {
    let v4 = vec![source("100.64.3.4").await, source("100.64.3.4").await];
    let dead = vec![
        "http://127.0.0.1:9".to_string(),
        "http://127.0.0.1:9".to_string(),
    ];
    let e = discover(Family::Both, &sources(v4, dead))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::NoGlobalAddress(_)), "{e}");
}

#[tokio::test]
async fn unreachable_and_disagreeing_sources() {
    let dead = vec![
        "http://127.0.0.1:9".to_string(),
        "http://127.0.0.1:9".to_string(),
    ];
    let e = discover(Family::V4, &sources(dead.clone(), vec![]))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Network(_)), "{e}");
    let split = vec![source("93.184.216.34").await, source("93.184.216.35").await];
    let e = discover(Family::V4, &sources(split, vec![]))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::AddressLookup(_)), "{e}");
    // IPv4 found, IPv6 has no route: fine, v6 is None.
    let ok = vec![source("93.184.216.34").await, source("93.184.216.34").await];
    let d = discover(Family::Both, &sources(ok, dead)).await.unwrap();
    assert!(d.v4.is_some() && d.v6.is_none());
}
