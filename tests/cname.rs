//! CNAME planning rules, against an in-memory zone (no features needed).
mod common;
use common::{Memory, existing};
use grindvakt_core::plan::Change;
use grindvakt_core::provider::DnsProvider;
use grindvakt_core::record::{ExistingRecord, Record, RecordKind, RecordValue};
use grindvakt_core::{Error, Result, apply, plan};
use std::net::Ipv4Addr;

const ZONE: &str = "example.com";

fn cname(s: &str) -> RecordValue {
    RecordValue::Cname(s.into())
}
fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

#[tokio::test]
async fn create_noop_retarget_and_idempotent() {
    let zone = Memory::default();
    let want = [Record::cname("www", "home.example.com")];
    let p = plan(&zone, ZONE, &want).await.unwrap();
    assert_eq!(p.actions[0].change, Change::Create);
    assert_eq!(
        p.actions[0].to_string(),
        "create CNAME www.example.com = home.example.com (ttl=300)"
    );
    apply(&zone, &p).await.unwrap();
    // Case and trailing dot don't matter.
    let p = plan(
        &zone,
        ZONE,
        &[Record::cname("WWW.example.com.", "Home.Example.com.")],
    )
    .await
    .unwrap();
    assert!(p.is_noop(), "{p}");
    // Retargeting updates the one CNAME in place.
    let p = plan(&zone, ZONE, &[Record::cname("www", "other.example.net")])
        .await
        .unwrap();
    assert!(
        matches!(&p.actions[0].change, Change::Update { id: 1, prev, .. } if *prev == cname("home.example.com")),
        "{p}"
    );
    apply(&zone, &p).await.unwrap();
    assert_eq!(
        zone.writes(),
        [
            "create \"www\" home.example.com 300",
            "update 1 other.example.net 300"
        ]
    );
    assert_eq!(
        zone.records.lock().unwrap().len(),
        1,
        "nothing added or deleted"
    );
}

#[tokio::test]
async fn cname_where_other_records_exist_is_refused() {
    for other in [
        RecordValue::A(v4("203.0.113.7")),
        RecordValue::Aaaa("2606:4700::7".parse().unwrap()),
        RecordValue::Txt("v=spf1 -all".into()),
    ] {
        let zone = Memory::with(vec![existing(1, "www", other.clone(), 300)]);
        let p = plan(&zone, ZONE, &[Record::cname("www", "home.example.com")])
            .await
            .unwrap();
        let Change::Ambiguous { reason } = &p.actions[0].change else {
            panic!("{other:?}: {p}")
        };
        assert!(reason.contains(other.kind().as_str()), "{reason}");
        assert!(matches!(apply(&zone, &p).await, Err(Error::Ambiguous(_))));
        assert!(zone.writes().is_empty());
    }
}

#[tokio::test]
async fn records_where_a_cname_exists_are_refused() {
    let zone = Memory::with(vec![existing(
        1,
        "home",
        cname("elsewhere.example.net"),
        300,
    )]);
    for want in [
        Record::a("home", v4("203.0.113.7")),
        Record::aaaa("home", "2606:4700::7".parse().unwrap()),
        Record::txt("home", "dnsaddr=/dns4/home.example.com/tcp/4747/p2p/X"),
    ] {
        let p = plan(&zone, ZONE, std::slice::from_ref(&want))
            .await
            .unwrap();
        let Change::Ambiguous { reason } = &p.actions[0].change else {
            panic!("{want:?}: {p}")
        };
        assert!(
            reason.contains("is a CNAME to elsewhere.example.net"),
            "{reason}"
        );
        assert!(matches!(apply(&zone, &p).await, Err(Error::Ambiguous(_))));
    }
    assert!(zone.writes().is_empty());
    // Other names are unaffected.
    let p = plan(&zone, ZONE, &[Record::a("other", v4("203.0.113.7"))])
        .await
        .unwrap();
    assert_eq!(p.actions[0].change, Change::Create);
}

#[tokio::test]
async fn cname_and_other_wanted_at_one_name_is_refused() {
    let zone = Memory::default();
    let p = plan(
        &zone,
        ZONE,
        &[
            Record::cname("www", "home.example.com"),
            Record::a("www", v4("203.0.113.7")),
            Record::a("home", v4("203.0.113.7")),
        ],
    )
    .await
    .unwrap();
    assert!(
        matches!(p.actions[0].change, Change::Ambiguous { .. }),
        "{p}"
    );
    assert!(
        matches!(p.actions[1].change, Change::Ambiguous { .. }),
        "{p}"
    );
    assert_eq!(p.actions[2].change, Change::Create);
    assert!(matches!(apply(&zone, &p).await, Err(Error::Ambiguous(_))));
    assert!(zone.writes().is_empty(), "the whole plan is refused");
}

#[tokio::test]
async fn two_existing_cnames_are_ambiguous() {
    let zone = Memory::with(vec![
        existing(1, "www", cname("a.example.net"), 300),
        existing(2, "www", cname("b.example.net"), 300),
    ]);
    let p = plan(&zone, ZONE, &[Record::cname("www", "c.example.net")])
        .await
        .unwrap();
    assert!(
        matches!(p.actions[0].change, Change::Ambiguous { .. }),
        "{p}"
    );
}

/// A zone that also has records of types the crate does not manage.
struct WithMx(Memory);
impl DnsProvider for WithMx {
    fn name(&self) -> &str {
        "with-mx"
    }
    async fn list(&self, z: &str, n: &str, k: RecordKind) -> Result<Vec<ExistingRecord>> {
        self.0.list(z, n, k).await
    }
    async fn create(&self, z: &str, n: &str, v: &RecordValue, t: u32) -> Result<()> {
        self.0.create(z, n, v, t).await
    }
    async fn update(&self, z: &str, id: u64, v: &RecordValue, t: u32) -> Result<()> {
        self.0.update(z, id, v, t).await
    }
    async fn types_at(&self, _z: &str, n: &str) -> Result<Vec<String>> {
        Ok(if n == "mail" {
            vec!["MX".into()]
        } else {
            vec![]
        })
    }
}

#[tokio::test]
async fn unmanaged_types_block_a_cname() {
    let zone = WithMx(Memory::default());
    let p = plan(&zone, ZONE, &[Record::cname("mail", "home.example.com")])
        .await
        .unwrap();
    assert!(
        matches!(&p.actions[0].change, Change::Ambiguous { reason } if reason.contains("MX")),
        "{p}"
    );
    let p = plan(&zone, ZONE, &[Record::cname("www", "home.example.com")])
        .await
        .unwrap();
    assert_eq!(p.actions[0].change, Change::Create);
}

#[tokio::test]
async fn invalid_cnames_are_rejected() {
    let zone = Memory::default();
    for bad in [
        vec![Record::cname("@", "home.example.com")],
        vec![Record::cname("", "home.example.com")],
        vec![Record::cname("example.com.", "home.example.com")],
        vec![Record::cname("www", "")],
        vec![Record::cname("www", "localhost")],
        vec![Record::cname("www", "bad..name.com")],
        vec![Record::cname("www", "has space.com")],
        vec![Record::cname("www", "-x.example.com")],
        vec![Record::cname("www", "WWW.example.com.")],
        vec![
            Record::cname("www", "a.example.net"),
            Record::cname("www", "b.example.net"),
        ],
    ] {
        let e = plan(&zone, ZONE, &bad).await.unwrap_err();
        assert!(matches!(e, Error::InvalidRecord(_)), "{bad:?}: {e}");
    }
    assert!(RecordValue::parse(RecordKind::Cname, "not a name").is_err());
    assert_eq!(
        RecordValue::parse(RecordKind::Cname, "Home.Example.com.").unwrap(),
        cname("home.example.com")
    );
}
