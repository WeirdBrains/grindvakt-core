//! Schedule checks and portable timing.
//!
//! On Linux and macOS the Grindvakt app hands `calendar` to systemd or launchd. Everywhere
//! else (the Windows service, or an embedding app with its own loop) [`next_wait`] works
//! out how long to sleep. It understands `interval_secs` and the calendar values
//! [`PORTABLE_CALENDARS`], evaluated as five-field cron by [`weirdnet_rules`] in local time.
//!
//! ```
//! use grindvakt_core::config::Schedule;
//! use grindvakt_core::schedule::{next_wait, validate_portable};
//! use std::time::{Duration, SystemTime};
//!
//! let every_ten = Schedule { calendar: Some("*:0/10".into()), interval_secs: None };
//! validate_portable(&every_ten).unwrap();
//! let wait = next_wait(SystemTime::now(), &every_ten).unwrap();
//! assert!(wait <= Duration::from_secs(600));
//!
//! let polling = Schedule { calendar: None, interval_secs: Some(300) };
//! assert_eq!(next_wait(SystemTime::now(), &polling).unwrap(), Duration::from_secs(300));
//! ```

use crate::config::Schedule;
use crate::error::{Error, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Smallest interval accepted, in seconds.
pub const MIN_INTERVAL_SECS: u64 = 60;

/// Calendar values [`next_wait`] understands, with the cron they map to.
pub const PORTABLE_CALENDARS: [(&str, &str); 3] = [
    ("hourly", "0 * * * *"),
    ("daily", "0 0 * * *"),
    ("*:0/10", "*/10 * * * *"),
];

/// Checks done before rendering a systemd timer or launchd agent: no newline, no `%`,
/// at most 256 bytes, interval at least [`MIN_INTERVAL_SECS`]. Calendar syntax itself is
/// left to systemd.
pub fn validate(s: &Schedule) -> Result<()> {
    if let Some(cal) = &s.calendar
        && (cal.contains('\n') || cal.contains('%') || cal.len() > 256)
    {
        return Err(Error::Schedule("invalid calendar expression".into()));
    }
    if let Some(secs) = s.interval_secs
        && secs < MIN_INTERVAL_SECS
    {
        return Err(Error::Schedule(format!(
            "interval_secs must be >= {MIN_INTERVAL_SECS}"
        )));
    }
    Ok(())
}

/// Stricter checks for portable timing: exactly one of calendar or interval, and a
/// calendar from [`PORTABLE_CALENDARS`].
pub fn validate_portable(s: &Schedule) -> Result<()> {
    match (&s.calendar, s.interval_secs) {
        (Some(_), Some(_)) => Err(Error::Schedule(
            "schedule must not set both calendar and interval_secs".into(),
        )),
        (Some(raw), None) => {
            if raw.contains('\n') || raw.contains('%') || raw.len() > 256 {
                return Err(Error::Schedule("invalid calendar expression".into()));
            }
            cron_for(raw).map(|_| ())
        }
        (None, Some(secs)) if secs < MIN_INTERVAL_SECS => Err(Error::Schedule(format!(
            "interval_secs must be >= {MIN_INTERVAL_SECS}"
        ))),
        (None, Some(_)) => Ok(()),
        (None, None) => Err(Error::Schedule(
            "schedule must set either calendar or interval_secs".into(),
        )),
    }
}

fn cron_for(raw: &str) -> Result<&'static str> {
    let t = raw.trim().to_lowercase();
    PORTABLE_CALENDARS
        .iter()
        .find(|(name, _)| *name == t)
        .map(|(_, cron)| *cron)
        .ok_or_else(|| Error::Schedule(format!("unsupported calendar expression: {t}")))
}

/// How long to wait from `now` until the next run.
///
/// An interval waits `max(interval_secs, 60)` seconds. A calendar waits until the next
/// matching local wall-clock minute (strictly after `now`). Neither set gives zero.
pub fn next_wait(now: SystemTime, s: &Schedule) -> Result<Duration> {
    next_wait_in(now, s, &chrono::Local)
}

/// [`next_wait`] in an explicit time zone.
pub fn next_wait_in<Z: chrono::TimeZone>(
    now: SystemTime,
    s: &Schedule,
    tz: &Z,
) -> Result<Duration> {
    if let Some(secs) = s.interval_secs {
        return Ok(Duration::from_secs(secs.max(MIN_INTERVAL_SECS)));
    }
    let Some(cal) = &s.calendar else {
        return Ok(Duration::ZERO);
    };
    let cron = weirdnet_rules::schedule::parse_cron(cron_for(cal)?)
        .map_err(|e| Error::Schedule(e.to_string()))?;
    let since = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Schedule("clock before 1970".into()))?;
    let now_ms = i64::try_from(since.as_millis())
        .map_err(|_| Error::Schedule("clock out of range".into()))?;
    let next_ms = cron
        .next_after_in(now_ms, tz)
        .ok_or_else(|| Error::Schedule("no upcoming run time".into()))?;
    let next = UNIX_EPOCH + Duration::from_millis(next_ms as u64);
    Ok(next.duration_since(now).unwrap_or(Duration::ZERO))
}
