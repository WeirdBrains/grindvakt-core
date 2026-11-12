//! Embedding grindvakt-core in a larger application, the way a browser such as Morph does.
//!
//! The host owns everything machine-specific:
//! * the token, from its own keyring (here a constant),
//! * the addresses, from its own network stack (libp2p AutoNAT) or `ip::discover`,
//! * when sync runs (a background task while the app is open; no scheduler in the crate),
//! * how results are shown (a channel the UI reads), with typed errors it can explain.
//!
//! Runs offline against a local DigitalOcean API mock.
//! `cargo run --example embed_in_app`

use grindvakt_core::plan::Plan;
use grindvakt_core::provider::DigitalOceanProvider;
use grindvakt_core::record::Record;
use grindvakt_core::{Error, SecretString, apply, ip, plan};
use serde_json::json;
use std::net::IpAddr;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// What the host UI receives.
#[derive(Debug)]
enum DdnsEvent {
    Preview(Plan),
    Applied(usize),
    UseRelays(String),
    Failed(String),
}

/// The records a peer-to-peer browser publishes for itself.
fn wanted(name: &str, zone: &str, port: u16, peer: &str, addrs: &[IpAddr]) -> Vec<Record> {
    let mut want = Vec::new();
    for a in addrs {
        match a {
            IpAddr::V4(v4) => {
                want.push(Record::a(name, *v4));
                want.push(Record::txt(
                    format!("_dnsaddr.{name}"),
                    format!("dnsaddr=/dns4/{name}.{zone}/tcp/{port}/p2p/{peer}"),
                ));
            }
            IpAddr::V6(v6) => {
                want.push(Record::aaaa(name, *v6));
                want.push(Record::txt(
                    format!("_dnsaddr.{name}"),
                    format!("dnsaddr=/dns6/{name}.{zone}/tcp/{port}/p2p/{peer}"),
                ));
            }
        }
    }
    want
}

async fn sync(dns: &DigitalOceanProvider, addrs: &[IpAddr], dry_run: bool) -> DdnsEvent {
    // Only publish global addresses; otherwise tell the UI to rely on relays.
    let global: Vec<IpAddr> = addrs
        .iter()
        .copied()
        .filter(|a| ip::is_global(*a))
        .collect();
    if global.is_empty() {
        return DdnsEvent::UseRelays(format!("no global address among {addrs:?}"));
    }
    let want = wanted("home", "example.org", 4747, "12D3KooWExample", &global);
    let result = async {
        let p = plan(dns, "example.org", &want).await?;
        if dry_run {
            return Ok(DdnsEvent::Preview(p));
        }
        Ok::<_, Error>(DdnsEvent::Applied(apply(dns, &p).await?.len()))
    }
    .await;
    match result {
        Ok(ev) => ev,
        Err(Error::Auth { .. }) => {
            DdnsEvent::Failed("the DNS token was rejected; check settings".into())
        }
        Err(Error::RateLimited { retry_after, .. }) => {
            DdnsEvent::Failed(format!("provider is throttling; retry in {retry_after:?}"))
        }
        Err(Error::Ambiguous(why)) => DdnsEvent::Failed(format!("not touching your zone: {why}")),
        Err(e) => DdnsEvent::Failed(e.to_string()), // never contains secrets
    }
}

#[tokio::main]
async fn main() -> grindvakt_core::Result<()> {
    // A DigitalOcean look-alike with an empty zone, accepting creates.
    let server = MockServer::start().await;
    for kind in ["A", "AAAA", "TXT"] {
        Mock::given(method("GET"))
            .and(path("/v2/domains/example.org/records"))
            .and(query_param("type", kind))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"domain_records": [], "links": {}})),
            )
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/v2/domains/example.org/records"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"domain_record": {}})))
        .expect(4)
        .mount(&server)
        .await;

    let token = SecretString::from("from-the-host-keyring".to_string());
    let dns = DigitalOceanProvider::new(&token, Some(&server.uri()))?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(async move {
        // What AutoNAT reported: one public IPv4 and one public IPv6 address.
        let addrs: Vec<IpAddr> = vec![
            "93.184.216.34".parse().unwrap(),
            "2606:4700::7".parse().unwrap(),
        ];
        let _ = tx.send(sync(&dns, &addrs, true).await).await; // settings page preview
        let _ = tx.send(sync(&dns, &addrs, false).await).await; // the real thing
        // Later, on a CGNAT network:
        let cgnat: Vec<IpAddr> = vec!["100.64.1.2".parse().unwrap()];
        let _ = tx.send(sync(&dns, &cgnat, false).await).await;
    });
    while let Some(ev) = rx.recv().await {
        match ev {
            DdnsEvent::Preview(p) => println!("ui: preview\n{p}"),
            DdnsEvent::Applied(n) => println!("ui: published {n} record(s)"),
            DdnsEvent::UseRelays(why) => println!("ui: will use relays ({why})"),
            DdnsEvent::Failed(e) => println!("ui: sync failed: {e}"),
        }
    }
    task.await.expect("task");
    Ok(())
}
