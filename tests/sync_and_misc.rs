use grindvakt_core::config::{AppConfig, Provider, normalize_fqdn, relative_name, validate};
use grindvakt_core::lock::SingleInstanceLock;
use grindvakt_core::provider::{DnsAction, DnsProvider};
use grindvakt_core::sync::{SyncMode, SyncOutcome, sync_once};
use grindvakt_core::{Error, Result};
use std::net::Ipv4Addr;
use std::sync::Mutex;

#[derive(Default)]
struct Fake {
    plan: Mutex<Option<DnsAction>>,
    calls: Mutex<Vec<String>>,
}

impl DnsProvider for Fake {
    async fn plan(&self, _cfg: &AppConfig, _ip: Ipv4Addr) -> Result<DnsAction> {
        Ok(self.plan.lock().unwrap().clone().unwrap())
    }
    async fn create_a(&self, _cfg: &AppConfig, name: &str, ip: Ipv4Addr, ttl: u32) -> Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("create {name} {ip} {ttl}"));
        Ok(())
    }
    async fn update_a(&self, _cfg: &AppConfig, id: u64, ip: Ipv4Addr, ttl: u32) -> Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("update {id} {ip} {ttl}"));
        Ok(())
    }
}

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
async fn sync_paths() {
    let f = Fake::default();
    let new = ip("93.184.216.34");
    *f.plan.lock().unwrap() = Some(DnsAction::Create {
        name: "home".into(),
        ttl: 300,
    });
    assert_eq!(
        sync_once(&cfg(), &f, new, SyncMode::DryRun)
            .await
            .unwrap()
            .to_string(),
        "DRY RUN: would create A home.example.net = 93.184.216.34 (ttl=300)"
    );
    assert!(f.calls.lock().unwrap().is_empty());
    let out = sync_once(&cfg(), &f, new, SyncMode::Apply).await.unwrap();
    assert_eq!(
        out.to_string(),
        "Created A home.example.net = 93.184.216.34 (ttl=300)"
    );
    assert!(out.changes_dns());

    *f.plan.lock().unwrap() = Some(DnsAction::Update {
        record_id: 7,
        ttl: 300,
        prev: ip("198.51.100.1"),
    });
    let out = sync_once(&cfg(), &f, new, SyncMode::Apply).await.unwrap();
    assert!(matches!(out, SyncOutcome::Updated { record_id: 7, .. }));
    assert_eq!(
        out.to_string(),
        "Updated A home.example.net: 198.51.100.1 -> 93.184.216.34 (ttl=300)"
    );

    *f.plan.lock().unwrap() = Some(DnsAction::Noop(new));
    let out = sync_once(&cfg(), &f, new, SyncMode::Apply).await.unwrap();
    assert_eq!(
        out.to_string(),
        "No change needed: home.example.net -> 93.184.216.34"
    );
    assert!(!out.changes_dns());

    *f.plan.lock().unwrap() = Some(DnsAction::Ambiguous {
        reason: "two".into(),
    });
    assert!(matches!(
        sync_once(&cfg(), &f, new, SyncMode::Apply).await,
        Err(Error::Ambiguous(_))
    ));
    assert_eq!(
        f.calls.lock().unwrap().as_slice(),
        [
            "create home 93.184.216.34 300",
            "update 7 93.184.216.34 300"
        ]
    );
}

#[test]
fn spawnable_on_multithreaded_runtime() {
    // DnsProvider futures are Send: sync can run inside tokio::spawn.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let f = std::sync::Arc::new(Fake::default());
        *f.plan.lock().unwrap() = Some(DnsAction::Noop(ip("93.184.216.34")));
        let f2 = f.clone();
        let h = tokio::spawn(async move {
            sync_once(&cfg(), &*f2, ip("93.184.216.34"), SyncMode::Apply).await
        });
        assert!(h.await.unwrap().is_ok());
    });
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
    assert_eq!(relative_name("example.com", "example.com"), "");
    assert_eq!(relative_name("example.com", "a.b.example.com."), "a.b");
    assert!(validate::is_valid_fqdn("example.com"));
    assert!(!validate::is_valid_fqdn("-bad.example.com"));
    assert!(!validate::is_valid_fqdn("a..b.com"));
    assert!(validate::is_valid_record_name("example.com", "@"));
    assert!(validate::is_valid_record_name("example.com", "home.office"));
    assert!(!validate::calendar_is_plausible("bad%fmt"));
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
