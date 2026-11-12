//! The standalone app's single-record sync, names, providers and the lock.
#![cfg(feature = "standalone")]
mod common;
use common::{Memory, existing};
use grindvakt_core::Error;
use grindvakt_core::config::{AppConfig, Provider, normalize_fqdn, relative_name, validate};
use grindvakt_core::lock::SingleInstanceLock;
use grindvakt_core::record::RecordValue;
use grindvakt_core::sync::{SyncMode, SyncOutcome, sync_once};
use std::net::Ipv4Addr;

fn cfg() -> AppConfig {
    AppConfig {
        zone: "example.net".into(),
        name: "home".into(),
        ..AppConfig::default()
    }
}

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

#[tokio::test]
async fn sync_paths_keep_the_app_log_lines() {
    let zone = Memory::default();
    let new = ip("93.184.216.34");
    let out = sync_once(&cfg(), &zone, new, SyncMode::DryRun)
        .await
        .unwrap();
    assert_eq!(
        out.to_string(),
        "DRY RUN: would create A home.example.net = 93.184.216.34 (ttl=300)"
    );
    assert!(zone.writes().is_empty());
    let out = sync_once(&cfg(), &zone, new, SyncMode::Apply)
        .await
        .unwrap();
    assert_eq!(
        out.to_string(),
        "Created A home.example.net = 93.184.216.34 (ttl=300)"
    );
    assert!(out.changes_dns());

    let out = sync_once(&cfg(), &zone, new, SyncMode::Apply)
        .await
        .unwrap();
    assert_eq!(
        out.to_string(),
        "No change needed: home.example.net -> 93.184.216.34"
    );
    assert!(!out.changes_dns());

    let newer = ip("93.184.216.35");
    let out = sync_once(&cfg(), &zone, newer, SyncMode::DryRun)
        .await
        .unwrap();
    assert_eq!(
        out.to_string(),
        "DRY RUN: would update A home.example.net: 93.184.216.34 -> 93.184.216.35 (ttl=300) [record_id=1]"
    );
    let out = sync_once(&cfg(), &zone, newer, SyncMode::Apply)
        .await
        .unwrap();
    assert!(matches!(out, SyncOutcome::Updated { record_id: 1, .. }));
    assert_eq!(
        out.to_string(),
        "Updated A home.example.net: 93.184.216.34 -> 93.184.216.35 (ttl=300)"
    );
    assert_eq!(
        zone.writes(),
        vec![
            "create \"home\" 93.184.216.34 300",
            "update 1 93.184.216.35 300"
        ]
    );

    let dup = Memory::with(vec![
        existing(1, "home", RecordValue::A(new), 300),
        existing(2, "home", RecordValue::A(newer), 300),
    ]);
    assert!(matches!(
        sync_once(&cfg(), &dup, new, SyncMode::Apply).await,
        Err(Error::Ambiguous(_))
    ));
    assert!(dup.writes().is_empty());
}

#[test]
fn names_and_validation() {
    assert_eq!(normalize_fqdn("example.com", "@"), "example.com");
    assert_eq!(normalize_fqdn("example.com.", "www"), "www.example.com");
    assert_eq!(
        normalize_fqdn("example.com", "api.example.com."),
        "api.example.com"
    );
    assert_eq!(normalize_fqdn("example.com", ""), "example.com");
    assert_eq!(
        normalize_fqdn("example.com", "notexample.com"),
        "notexample.com.example.com"
    );
    assert_eq!(relative_name("example.com", "example.com"), "");
    assert_eq!(relative_name("example.com", "a.b.example.com."), "a.b");
    assert!(validate::is_valid_fqdn("example.com"));
    assert!(!validate::is_valid_fqdn("-bad.example.com"));
    assert!(!validate::is_valid_fqdn("a..b.com"));
    assert!(validate::is_valid_record_name("example.com", "@"));
    assert!(validate::is_valid_record_name("example.com", "home.office"));
    assert_eq!(Provider::Dnsimple.to_string(), "dnsimple");
    assert_eq!(
        "DigitalOcean".parse::<Provider>().unwrap(),
        Provider::Digitalocean
    );
    assert!("route53".parse::<Provider>().is_err());
    let bad = AppConfig {
        ttl: 59,
        ..AppConfig::default()
    };
    assert!(matches!(bad.validate(), Err(Error::Config(_))));
}

#[cfg(any(feature = "dnsimple", feature = "digitalocean"))]
#[test]
fn build_from_config() {
    let token = grindvakt_core::SecretString::from("t".to_string());
    for p in Provider::ALL {
        let c = AppConfig {
            provider: p,
            ..cfg()
        };
        match grindvakt_core::provider::build(&c, &token) {
            Ok(built) => assert_eq!(
                grindvakt_core::provider::DnsProvider::name(&built),
                p.as_str()
            ),
            Err(e) => assert!(matches!(e, Error::Config(_)), "{e}"),
        }
    }
}

#[test]
fn second_lock_fails() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("run").join("sync.lock");
    let a = SingleInstanceLock::acquire_at(&p).unwrap();
    assert!(matches!(
        SingleInstanceLock::acquire_at(&p),
        Err(Error::Locked(_))
    ));
    drop(a);
    SingleInstanceLock::acquire_at(&p).unwrap();
}
