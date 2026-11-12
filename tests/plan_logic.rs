//! Planning rules, against an in-memory zone (no features needed).
mod common;
use common::{Memory, existing};
use grindvakt_core::plan::Change;
use grindvakt_core::record::{Record, RecordValue};
use grindvakt_core::{Error, apply, plan};
use std::net::{Ipv4Addr, Ipv6Addr};

const ZONE: &str = "example.com";

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}
fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}
fn txt(s: &str) -> RecordValue {
    RecordValue::Txt(s.into())
}

#[tokio::test]
async fn morph_records_end_to_end_and_idempotent() {
    let zone = Memory::default();
    let peer = "12D3KooWExample";
    let want = vec![
        Record::a("home", v4("203.0.113.7")),
        Record::aaaa("home", v6("2606:4700::7")),
        Record::txt(
            "_dnsaddr.home",
            format!("dnsaddr=/dns4/home.example.com/tcp/4747/p2p/{peer}"),
        ),
        Record::txt(
            "_dnsaddr.home",
            format!("dnsaddr=/dns6/home.example.com/tcp/4747/p2p/{peer}"),
        ),
    ];
    let p = plan(&zone, ZONE, &want).await.unwrap();
    assert_eq!(p.changes().count(), 4);
    assert!(zone.writes().is_empty(), "planning never writes");
    assert_eq!(apply(&zone, &p).await.unwrap().len(), 4);
    let again = plan(&zone, ZONE, &want).await.unwrap();
    assert!(again.is_noop(), "{again}");
    assert!(apply(&zone, &again).await.unwrap().is_empty());
    assert_eq!(zone.writes().len(), 4);

    // The port changes: both dnsaddr records are updated in place, nothing is created.
    let moved: Vec<Record> = want
        .iter()
        .map(|r| match &r.value {
            RecordValue::Txt(t) => Record::txt(r.name.clone(), t.replace("4747", "4848")),
            _ => r.clone(),
        })
        .collect();
    let p = plan(&zone, ZONE, &moved).await.unwrap();
    assert_eq!(
        p.changes()
            .filter(|a| matches!(a.change, Change::Update { .. }))
            .count(),
        2,
        "{p}"
    );
    apply(&zone, &p).await.unwrap();
    assert!(plan(&zone, ZONE, &moved).await.unwrap().is_noop());
}

#[tokio::test]
async fn txt_keys_leave_other_txt_records_alone() {
    let zone = Memory::with(vec![
        existing(1, "", txt("v=spf1 include:_spf.example.net -all"), 300),
        existing(2, "", txt("google-site-verification=abc"), 300),
        existing(3, "", txt("dnsaddr=/dns4/old/tcp/1/p2p/X"), 300),
    ]);
    let p = plan(
        &zone,
        ZONE,
        &[Record::txt("@", "dnsaddr=/dns4/new/tcp/1/p2p/X")],
    )
    .await
    .unwrap();
    assert!(
        matches!(&p.actions[0].change, Change::Update { id: 3, .. }),
        "{p}"
    );
    apply(&zone, &p).await.unwrap();
    assert_eq!(
        zone.writes(),
        vec!["update 3 \"dnsaddr=/dns4/new/tcp/1/p2p/X\" 300"]
    );
}

#[tokio::test]
async fn ambiguity_rules() {
    // Two A records for one wanted A: refuse, and apply writes nothing.
    let zone = Memory::with(vec![
        existing(1, "home", RecordValue::A(v4("203.0.113.7")), 300),
        existing(2, "home", RecordValue::A(v4("203.0.113.8")), 300),
        existing(3, "_dnsaddr.home", txt("dnsaddr=/a"), 300),
        existing(4, "_dnsaddr.home", txt("dnsaddr=/b"), 300),
    ]);
    let p = plan(
        &zone,
        ZONE,
        &[
            Record::a("home", v4("203.0.113.7")),
            Record::txt("_dnsaddr.home", "dnsaddr=/c"),
            Record::aaaa("home", v6("2606:4700::7")),
        ],
    )
    .await
    .unwrap();
    assert!(matches!(p.actions[0].change, Change::Ambiguous { .. }));
    assert!(
        matches!(p.actions[1].change, Change::Ambiguous { .. }),
        "two dnsaddr records, one slot: {p}"
    );
    assert_eq!(p.actions[2].change, Change::Create);
    let e = apply(&zone, &p).await.unwrap_err();
    assert!(matches!(e, Error::Ambiguous(_)), "{e}");
    assert!(zone.writes().is_empty());

    // Keeping one of two dnsaddr records is fine: the other is left alone.
    let p = plan(&zone, ZONE, &[Record::txt("_dnsaddr.home", "dnsaddr=/a")])
        .await
        .unwrap();
    assert!(p.is_noop());
}

#[tokio::test]
async fn ttl_only_change_is_an_update() {
    let zone = Memory::with(vec![existing(
        9,
        "",
        RecordValue::A(v4("203.0.113.7")),
        3600,
    )]);
    let p = plan(
        &zone,
        ZONE,
        &[Record::a("example.com.", v4("203.0.113.7")).with_ttl(120)],
    )
    .await
    .unwrap();
    assert!(matches!(
        p.actions[0].change,
        Change::Update {
            id: 9,
            prev_ttl: Some(3600),
            ..
        }
    ));
    assert_eq!(p.actions[0].fqdn, "example.com");
    assert_eq!(
        p.to_string(),
        "update A example.com: 203.0.113.7 -> 203.0.113.7 (ttl=120) [record_id=9]"
    );
}

#[tokio::test]
async fn invalid_input_is_rejected() {
    let zone = Memory::default();
    for bad in [
        vec![Record::a("home", v4("203.0.113.7")).with_ttl(30)],
        vec![Record::a("bad..name", v4("203.0.113.7"))],
        vec![Record::txt("x", "has \"quotes\"")],
        vec![Record::txt("x", "")],
        vec![
            Record::a("home", v4("203.0.113.7")),
            Record::a("HOME.example.com", v4("203.0.113.7")),
        ],
    ] {
        let e = plan(&zone, ZONE, &bad).await.unwrap_err();
        assert!(matches!(e, Error::InvalidRecord(_)), "{e}");
    }
    assert!(matches!(
        plan(&zone, " ", &[]).await,
        Err(Error::InvalidRecord(_))
    ));
}

#[test]
fn plans_are_send_for_tokio_spawn() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let zone = std::sync::Arc::new(Memory::default());
        let z = zone.clone();
        let h = tokio::spawn(async move {
            let p = plan(&*z, ZONE, &[Record::a("home", v4("203.0.113.7"))]).await?;
            apply(&*z, &p).await
        });
        assert_eq!(h.await.unwrap().unwrap().len(), 1);
    });
}
