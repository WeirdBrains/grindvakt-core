#![cfg(feature = "standalone")]
//! `record = "cname"` configs and `sync_cname_once`, against an in-memory zone.
mod common;
use common::{Memory, existing};
use grindvakt_core::Error;
use grindvakt_core::config::{AppConfig, RecordType};
use grindvakt_core::record::RecordValue;
use grindvakt_core::sync::{CnameOutcome, SyncMode, sync_cname_once};

fn cfg(extra: &str) -> String {
    format!(
        "provider = \"dnsimple\"\nzone = \"example.com\"\nname = \"www\"\nttl = 300\n{extra}\n[schedule]\ninterval_secs = 300\n"
    )
}

fn parse(extra: &str) -> Result<AppConfig, Error> {
    AppConfig::from_toml_str(&cfg(extra))
}

#[test]
fn default_record_is_a_and_round_trips_unchanged() {
    let c = parse("sandbox = false").unwrap();
    assert_eq!(c.record, RecordType::A);
    assert!(c.cname.is_none());
    let text = c.to_toml_string().unwrap();
    assert!(
        !text.contains("record") && !text.contains("cname"),
        "{text}"
    );
}

#[test]
fn cname_config_with_target_round_trips() {
    let c = parse("record = \"cname\"\n[cname]\ntarget = \"home.example.org\"").unwrap();
    // `[cname]` must come before `[schedule]` in the file; reparse what we write.
    assert_eq!(c.record, RecordType::Cname);
    let again = AppConfig::from_toml_str(&c.to_toml_string().unwrap()).unwrap();
    assert_eq!(again, c);
}

#[test]
fn config_needs_exactly_one_source() {
    let both = parse(
        "record = \"cname\"\n[cname]\ntarget = \"a.example.org\"\nweirdnet_link = \"weirdnet-morph://a.example.org/x\"",
    );
    assert!(both.unwrap_err().to_string().contains("not both"));
    let none = parse("record = \"cname\"\n[cname]");
    assert!(
        none.unwrap_err()
            .to_string()
            .contains("target or weirdnet_link")
    );
    let missing = parse("record = \"cname\"");
    assert!(missing.unwrap_err().to_string().contains("[cname] table"));
    let stray = parse("[cname]\ntarget = \"a.example.org\"");
    assert!(stray.unwrap_err().to_string().contains("only used with"));
    let unknown = parse("record = \"cname\"\n[cname]\ntarget = \"a.example.org\"\nlink = \"x\"");
    assert!(unknown.is_err());
    let kind = parse("record = \"txt\"");
    assert!(kind.is_err());
}

#[test]
fn config_refuses_apex_and_bad_targets() {
    let apex = AppConfig::from_toml_str(
        "zone = \"example.com\"\nname = \"@\"\nrecord = \"cname\"\n[cname]\ntarget = \"a.example.org\"\n[schedule]\ninterval_secs = 300\n",
    );
    assert!(apex.unwrap_err().to_string().contains("apex"));
    let bad = parse("record = \"cname\"\n[cname]\ntarget = \"nodots\"");
    assert!(bad.unwrap_err().to_string().contains("full host name"));
}

#[tokio::test]
async fn static_target_create_noop_retarget() {
    let c = parse("record = \"cname\"\n[cname]\ntarget = \"Home.Example.org.\"").unwrap();
    let zone = Memory::default();

    let dry = sync_cname_once(&c, &zone, SyncMode::DryRun).await.unwrap();
    assert_eq!(
        dry.to_string(),
        "DRY RUN: would create CNAME www.example.com -> home.example.org (ttl=300)"
    );
    assert!(zone.writes().is_empty());

    let made = sync_cname_once(&c, &zone, SyncMode::Apply).await.unwrap();
    assert!(matches!(made, CnameOutcome::Created { .. }), "{made:?}");
    assert!(made.changes_dns());
    assert_eq!(zone.writes().len(), 1);

    let same = sync_cname_once(&c, &zone, SyncMode::Apply).await.unwrap();
    assert_eq!(
        same.to_string(),
        "No change: CNAME www.example.com -> home.example.org"
    );
    assert!(!same.changes_dns());
    assert_eq!(zone.writes().len(), 1);

    let moved = parse("record = \"cname\"\n[cname]\ntarget = \"other.example.org\"").unwrap();
    let dry = sync_cname_once(&moved, &zone, SyncMode::DryRun)
        .await
        .unwrap();
    assert!(matches!(dry, CnameOutcome::WouldUpdate { .. }), "{dry:?}");
    let up = sync_cname_once(&moved, &zone, SyncMode::Apply)
        .await
        .unwrap();
    assert_eq!(
        up.to_string(),
        "Updated CNAME www.example.com: home.example.org -> other.example.org (ttl=300) [record_id=1]"
    );
}

#[tokio::test]
async fn refuses_other_record_types_and_ambiguity() {
    let a = parse("sandbox = false").unwrap();
    let zone = Memory::default();
    assert!(matches!(
        sync_cname_once(&a, &zone, SyncMode::Apply).await,
        Err(Error::Config(_))
    ));

    let c = parse("record = \"cname\"\n[cname]\ntarget = \"home.example.org\"").unwrap();
    let busy = Memory::with(vec![existing(
        1,
        "www",
        RecordValue::A("192.0.2.1".parse().unwrap()),
        300,
    )]);
    assert!(matches!(
        sync_cname_once(&c, &busy, SyncMode::Apply).await,
        Err(Error::Ambiguous(_))
    ));
    assert!(busy.writes().is_empty());
}

#[cfg(feature = "weirdnet")]
mod weirdnet {
    use super::*;

    fn cname(s: &str) -> RecordValue {
        RecordValue::Cname(s.into())
    }

    const LINK: &str = "weirdnet-morph://home.example.org/site/index";

    fn linked(link: &str) -> String {
        format!("record = \"cname\"\n[cname]\nweirdnet_link = \"{link}\"")
    }

    #[tokio::test]
    async fn link_authority_becomes_the_target() {
        let c = parse(&linked(LINK)).unwrap();
        let zone = Memory::default();
        let out = sync_cname_once(&c, &zone, SyncMode::Apply).await.unwrap();
        assert_eq!(
            out.to_string(),
            "Created CNAME www.example.com -> home.example.org (ttl=300)"
        );
        assert_eq!(
            zone.records.lock().unwrap()[0].value,
            cname("home.example.org")
        );
    }

    #[tokio::test]
    async fn a_changed_link_retargets_the_record() {
        let zone = Memory::default();
        let first = parse(&linked(LINK)).unwrap();
        sync_cname_once(&first, &zone, SyncMode::Apply)
            .await
            .unwrap();
        let next = parse(&linked("weirdnet-morph://new-home.example.org/site")).unwrap();
        let out = sync_cname_once(&next, &zone, SyncMode::Apply)
            .await
            .unwrap();
        assert!(matches!(out, CnameOutcome::Updated { .. }), "{out:?}");
        assert_eq!(
            zone.records.lock().unwrap()[0].value,
            cname("new-home.example.org")
        );
    }

    #[test]
    fn bad_links_fail_config_validation_without_echoing_invites() {
        for l in [
            "weirdnet://home.example.org/x",
            "weirdnet-morph://join/SECRETCODE",
            "weirdnet-morph://answer/SECRETCODE",
            "weirdnet-morph://12D3KooWHp56KezbVCubjuznJGqyn9xTe8PWePfuwv4YQUGxaRBB/x",
            "https://home.example.org/x",
            "weirdnet-morph://192.0.2.1/x",
        ] {
            let e = parse(&linked(l)).unwrap_err().to_string();
            assert!(!e.contains("SECRETCODE"), "{e}");
        }
    }
}

#[cfg(not(feature = "weirdnet"))]
#[test]
fn links_need_the_feature() {
    let e = parse(
        "record = \"cname\"\n[cname]\nweirdnet_link = \"weirdnet-morph://home.example.org/x\"",
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("`weirdnet` feature"), "{e}");
}
