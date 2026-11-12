//! Find the public IPv4 and IPv6 addresses, the way a peer-to-peer app decides between
//! publishing DNS records and falling back to relays.
//!
//! `cargo run --example ip_discovery` runs offline against local mock sources.
//! `cargo run --example ip_discovery -- --live` asks the real default sources.

use grindvakt_core::Error;
use grindvakt_core::ip::{self, Family, Sources};
use std::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn mock_source(body: &'static str) -> (MockServer, String) {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&s)
        .await;
    let uri = s.uri();
    (s, uri)
}

fn report(label: &str, r: grindvakt_core::Result<ip::Discovered>) {
    match r {
        Ok(d) => println!("{label}: publish A={:?} AAAA={:?}", d.v4, d.v6),
        Err(Error::NoGlobalAddress(why)) => {
            println!("{label}: nothing to publish ({why}); use relays")
        }
        Err(Error::Network(why)) => println!("{label}: offline? {why}"),
        Err(e) => println!("{label}: {e}"),
    }
}

#[tokio::main]
async fn main() {
    if std::env::args().any(|a| a == "--live") {
        report(
            "live",
            ip::discover(Family::Both, &Sources::default()).await,
        );
        return;
    }
    // Home connection: both families global; one source returns junk and is outvoted.
    let (_a, a) = mock_source("93.184.216.34\n").await;
    let (_b, b) = mock_source("your ip is 93.184.216.34").await;
    let (_c, c) = mock_source("<html>oops</html>").await;
    let (_d, d) = mock_source("2606:4700:4700::1111").await;
    let (_e, e) = mock_source("2606:4700:4700::1111\n").await;
    let sources = Sources {
        v4: vec![a, b, c],
        v6: vec![d, e],
        timeout: Duration::from_secs(2),
        ..Sources::default()
    };
    report("home", ip::discover(Family::Both, &sources).await);

    // Carrier-grade NAT and no IPv6: the sources agree on 100.64.x.x.
    let (_f, f) = mock_source("100.64.12.34").await;
    let (_g, g) = mock_source("100.64.12.34").await;
    let cgnat = Sources {
        v4: vec![f, g],
        v6: vec!["http://127.0.0.1:9".into()],
        timeout: Duration::from_secs(2),
        ..Sources::default()
    };
    report("phone hotspot", ip::discover(Family::Both, &cgnat).await);

    // Addresses you already know (for example from libp2p AutoNAT) need no lookup.
    for known in ["93.184.216.34", "203.0.113.9", "10.0.0.5", "2606:4700::7"] {
        let ip: std::net::IpAddr = known.parse().unwrap();
        match ip::require_global(ip) {
            Ok(ip) => println!("supplied {ip}: publishable"),
            Err(e) => println!("supplied {known}: {e}"),
        }
    }
}
