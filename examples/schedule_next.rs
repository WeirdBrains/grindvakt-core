//! When does the next run happen? Checks and timing for each schedule shape.
//!
//! `cargo run --example schedule_next`

use grindvakt_core::config::Schedule;
use grindvakt_core::schedule::{PORTABLE_CALENDARS, next_wait, validate, validate_portable};
use std::time::SystemTime;

fn main() {
    let now = SystemTime::now();
    let shapes = [
        Schedule {
            calendar: None,
            interval_secs: Some(300),
        },
        Schedule {
            calendar: Some("hourly".into()),
            interval_secs: None,
        },
        Schedule {
            calendar: Some("daily".into()),
            interval_secs: None,
        },
        Schedule {
            calendar: Some("*:0/10".into()),
            interval_secs: None,
        },
        Schedule {
            calendar: Some("Mon *-*-* 12:00:00".into()),
            interval_secs: None,
        },
        Schedule {
            calendar: None,
            interval_secs: Some(30),
        },
    ];
    println!("portable calendars: {PORTABLE_CALENDARS:?}");
    for s in &shapes {
        let unit_ok = validate(s).is_ok();
        match validate_portable(s).and_then(|_| next_wait(now, s)) {
            Ok(wait) => println!(
                "{s:?}: systemd-ok={unit_ok} next run in {}s",
                wait.as_secs()
            ),
            Err(e) => println!("{s:?}: systemd-ok={unit_ok} portable: {e}"),
        }
    }
}
