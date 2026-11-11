//! UTC timestamps for log names, evidence files and snapshots, without a date crate.

use std::time::{SystemTime, UNIX_EPOCH};

const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utc {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

impl Utc {
    pub fn now() -> Utc {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        Utc::from_unix(seconds)
    }

    pub fn from_unix(seconds: i64) -> Utc {
        let days = seconds.div_euclid(SECONDS_PER_DAY);
        let rest = seconds.rem_euclid(SECONDS_PER_DAY) as u32;
        let (year, month, day) = civil_from_days(days);
        Utc {
            year,
            month,
            day,
            hour: rest / 3600,
            minute: rest % 3600 / 60,
            second: rest % 60,
        }
    }

    /// `2026-11-11T10:15:00Z`
    pub fn iso(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// `20261111T101500Z`, safe in file names on every system.
    pub fn compact(&self) -> String {
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Howard Hinnant's days-to-civil conversion for the proleptic Gregorian calendar.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants() {
        assert_eq!(Utc::from_unix(0).iso(), "1970-01-01T00:00:00Z");
        assert_eq!(Utc::from_unix(951_782_400).iso(), "2000-02-29T00:00:00Z");
        assert_eq!(Utc::from_unix(1_700_000_000).iso(), "2023-11-14T22:13:20Z");
        assert_eq!(Utc::from_unix(1_700_000_000).compact(), "20231114T221320Z");
        assert_eq!(Utc::from_unix(-1).iso(), "1969-12-31T23:59:59Z");
    }
}
