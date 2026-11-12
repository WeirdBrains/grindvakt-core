//! Portable schedule timing matches the hand-written Windows scheduler of Grindvakt v0.7.0.

use chrono::{DateTime, Duration as CDuration, FixedOffset, LocalResult, TimeZone, Timelike, Utc};
use grindvakt_core::config::Schedule;
use grindvakt_core::schedule::{next_wait_in, validate, validate_portable};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn cal(c: &str) -> Schedule {
    Schedule {
        calendar: Some(c.into()),
        interval_secs: None,
    }
}

/// The v0.7.0 `compute_wait` logic, generic over the zone.
fn reference<Z: TimeZone>(now: SystemTime, s: &Schedule, tz: &Z) -> Duration {
    if let Some(secs) = s.interval_secs {
        return Duration::from_secs(secs.max(60));
    }
    let t = s.calendar.as_ref().unwrap().trim().to_lowercase();
    let now_utc: DateTime<Utc> = now.into();
    let now_dt = now_utc.with_timezone(tz);
    match t.as_str() {
        "hourly" => {
            let next = now_dt
                .with_minute(0)
                .unwrap()
                .with_second(0)
                .unwrap()
                .with_nanosecond(0)
                .unwrap()
                + CDuration::hours(1);
            (next - now_dt.clone()).to_std().unwrap()
        }
        "daily" => {
            let midnight = now_dt
                .date_naive()
                .succ_opt()
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap();
            let next = match tz.from_local_datetime(&midnight) {
                LocalResult::Single(dt) => dt,
                LocalResult::Ambiguous(a, b) => a.min(b),
                LocalResult::None => now_dt.clone() + CDuration::hours(24),
            };
            (next - now_dt.clone()).to_std().unwrap()
        }
        "*:0/10" => {
            let add = 10 - (now_dt.minute() % 10);
            let next = now_dt.with_second(0).unwrap().with_nanosecond(0).unwrap()
                + CDuration::minutes(add as i64);
            (next - now_dt.clone()).to_std().unwrap()
        }
        other => panic!("{other}"),
    }
}

#[test]
fn matches_v070_across_a_sweep() {
    let zones = [
        FixedOffset::east_opt(0).unwrap(),
        FixedOffset::west_opt(5 * 3600).unwrap(),
        FixedOffset::east_opt(5 * 3600 + 1800).unwrap(),
    ];
    // 2026-03-01 to 2026-03-04, every 7 minutes 13.25 seconds (hits exact boundaries too).
    let start = 1_772_323_200_000u64;
    for tz in &zones {
        for c in ["hourly", "daily", "*:0/10", " HOURLY "] {
            let mut ms = start;
            while ms < start + 3 * 86_400_000 {
                let now = UNIX_EPOCH + Duration::from_millis(ms);
                let got = next_wait_in(now, &cal(c), tz).unwrap();
                let want = reference(now, &cal(c), tz);
                assert_eq!(got, want, "{c} at {ms} in {tz}");
                ms += 433_250;
            }
        }
    }
    // Exact boundaries wait a full period.
    let top = UNIX_EPOCH + Duration::from_secs(1_772_323_200);
    assert_eq!(
        next_wait_in(top, &cal("hourly"), &Utc).unwrap(),
        Duration::from_secs(3600)
    );
    assert_eq!(
        next_wait_in(top, &cal("*:0/10"), &Utc).unwrap(),
        Duration::from_secs(600)
    );
    assert_eq!(
        next_wait_in(top, &cal("daily"), &Utc).unwrap(),
        Duration::from_secs(86_400)
    );
}

#[test]
fn intervals_and_empty() {
    let now = SystemTime::now();
    let s = Schedule {
        calendar: None,
        interval_secs: Some(30),
    };
    assert_eq!(
        next_wait_in(now, &s, &Utc).unwrap(),
        Duration::from_secs(60)
    );
    let s = Schedule {
        calendar: None,
        interval_secs: None,
    };
    assert_eq!(next_wait_in(now, &s, &Utc).unwrap(), Duration::ZERO);
    assert!(next_wait_in(now, &cal("weekly"), &Utc).is_err());
}

#[test]
fn portable_validation_matches_v070_windows_rules() {
    for c in ["hourly", "daily", "*:0/10"] {
        assert!(validate_portable(&cal(c)).is_ok(), "{c}");
    }
    assert!(
        validate_portable(&Schedule {
            calendar: None,
            interval_secs: Some(60)
        })
        .is_ok()
    );
    assert!(
        validate_portable(&Schedule {
            calendar: None,
            interval_secs: Some(59)
        })
        .is_err()
    );
    assert!(validate_portable(&cal("weekly")).is_err());
    assert!(validate_portable(&cal("hourly\n")).is_err());
    assert!(validate_portable(&cal("%hourly")).is_err());
    assert!(validate_portable(&cal(&"a".repeat(257))).is_err());
    assert!(
        validate_portable(&Schedule {
            calendar: None,
            interval_secs: None
        })
        .is_err()
    );
    assert!(
        validate_portable(&Schedule {
            calendar: Some("hourly".into()),
            interval_secs: Some(300)
        })
        .is_err()
    );
}

#[test]
fn unit_validation_matches_v070_linux_rules() {
    assert!(validate(&cal("Mon *-*-* 12:00:00")).is_ok());
    assert!(validate(&cal("bad%fmt")).is_err());
    assert!(validate(&cal("a\nb")).is_err());
    assert!(
        validate(&Schedule {
            calendar: None,
            interval_secs: Some(59)
        })
        .is_err()
    );
    assert!(
        validate(&Schedule {
            calendar: None,
            interval_secs: Some(60)
        })
        .is_ok()
    );
}
