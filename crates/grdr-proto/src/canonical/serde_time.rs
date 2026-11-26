// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! ProtoJSON RFC 3339 timestamp and duration serde helpers with object compatibility.

use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::common_types::{ProtoDuration, ProtoTimestamp};

const MIN_TS_SECONDS: i64 = -62_135_596_800; // 0001-01-01T00:00:00Z
const MAX_TS_SECONDS: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
const MAX_DURATION_SECONDS: i64 = 315_576_000_000;

fn is_leap_year(year: i64) -> bool {
    let mod4 = year.rem_euclid(4) == 0;
    let mod100 = year.rem_euclid(100) == 0;
    let mod400 = year.rem_euclid(400) == 0;
    mod4 && (!mod100 || mod400)
}

fn days_in_month(year: i64, month: u32) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 30,
    }
}

fn civil_from_days(z: i64) -> Option<(i64, u32, u32)> {
    let z_shift = z.checked_add(719_468)?;
    let era = z_shift.div_euclid(146_097);
    let doe = z_shift.rem_euclid(146_097);
    let yoe = doe
        .saturating_sub(doe.div_euclid(1_460))
        .saturating_add(doe.div_euclid(36_524))
        .saturating_sub(doe.div_euclid(146_096))
        .div_euclid(365);
    let y = yoe.checked_add(era.checked_mul(400)?)?;
    let doy = doe.saturating_sub(
        365_i64
            .checked_mul(yoe)?
            .saturating_add(yoe.div_euclid(4))
            .saturating_sub(yoe.div_euclid(100)),
    );
    let mp = 5_i64.checked_mul(doy)?.saturating_add(2).div_euclid(153);
    let d = doy
        .saturating_sub(153_i64.checked_mul(mp)?.saturating_add(2).div_euclid(5))
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let year = if m <= 2 { y.checked_add(1)? } else { y };
    Some((year, u32::try_from(m).ok()?, u32::try_from(d).ok()?))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let m_i64 = i64::from(month);
    let y = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let adj_m = if m_i64 > 2 {
        m_i64.saturating_sub(3)
    } else {
        m_i64.saturating_add(9)
    };
    let doy = 153_i64
        .checked_mul(adj_m)?
        .saturating_add(2)
        .div_euclid(5)
        .checked_add(i64::from(day).saturating_sub(1))?;
    let doe = 365_i64
        .checked_mul(yoe)?
        .checked_add(yoe.div_euclid(4))?
        .saturating_sub(yoe.div_euclid(100))
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

fn is_valid_timestamp(seconds: i64, nanos: i32) -> bool {
    (MIN_TS_SECONDS..=MAX_TS_SECONDS).contains(&seconds) && (0..1_000_000_000).contains(&nanos)
}

fn is_valid_duration(seconds: i64, nanos: i32) -> bool {
    if !(-MAX_DURATION_SECONDS..=MAX_DURATION_SECONDS).contains(&seconds)
        || !(-999_999_999..=999_999_999).contains(&nanos)
    {
        return false;
    }
    if seconds > 0 && nanos < 0 {
        return false;
    }
    if seconds < 0 && nanos > 0 {
        return false;
    }
    true
}

fn parse_fixed_digits(raw: &str, len: usize, field: &str) -> Result<i64, String> {
    if raw.len() != len || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid {field}"));
    }
    raw.parse::<i64>().map_err(|_| format!("bad {field}"))
}

fn split_rfc3339_offset(time_part: &str) -> Result<(&str, i64), String> {
    if let Some(hms_frac) = time_part
        .strip_suffix('Z')
        .or_else(|| time_part.strip_suffix('z'))
    {
        return Ok((hms_frac, 0));
    }
    let idx = time_part
        .rfind(['+', '-'])
        .ok_or_else(|| "timestamp missing timezone offset".to_owned())?;
    let (hms_frac, tz) = time_part
        .split_at_checked(idx)
        .ok_or_else(|| "invalid timezone boundary".to_owned())?;
    let bytes = tz.as_bytes();
    if bytes.len() != 6 || bytes.get(3).copied() != Some(b':') {
        return Err("invalid timezone offset".to_owned());
    }
    let sign = match bytes.first().copied() {
        Some(b'+') => 1i64,
        Some(b'-') => -1i64,
        _ => return Err("invalid timezone sign".to_owned()),
    };
    let hh_str = tz
        .get(1..3)
        .ok_or_else(|| "invalid timezone hour".to_owned())?;
    let mm_str = tz
        .get(4..6)
        .ok_or_else(|| "invalid timezone minute".to_owned())?;
    let hh = parse_fixed_digits(hh_str, 2, "timezone hour")?;
    let mm = parse_fixed_digits(mm_str, 2, "timezone minute")?;
    if !(0..=23).contains(&hh) || !(0..=59).contains(&mm) {
        return Err("timezone offset out of range".to_owned());
    }
    let offset_secs = sign
        .checked_mul(
            hh.saturating_mul(3_600)
                .saturating_add(mm.saturating_mul(60)),
        )
        .ok_or_else(|| "timezone overflow".to_owned())?;
    Ok((hms_frac, offset_secs))
}

pub(crate) fn format_rfc3339(seconds: i64, nanos: i32) -> Option<String> {
    if !is_valid_timestamp(seconds, nanos) {
        return None;
    }
    let days = seconds.div_euclid(86_400);
    let secs_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days)?;
    if !(1..=9999).contains(&year) {
        return None;
    }
    let hour = secs_of_day.div_euclid(3_600);
    let rem = secs_of_day.rem_euclid(3_600);
    let min = rem.div_euclid(60);
    let sec = rem.rem_euclid(60);
    if nanos == 0 {
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z"
        ))
    } else {
        let mut frac = format!("{nanos:09}");
        while frac.ends_with('0') {
            frac.pop();
        }
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{frac}Z"
        ))
    }
}

pub(crate) fn parse_rfc3339(raw: &str) -> Result<ProtoTimestamp, String> {
    let (date_part, time_part) = raw
        .split_once('T')
        .or_else(|| raw.split_once('t'))
        .ok_or_else(|| "missing 'T' separator".to_owned())?;
    if date_part.len() != 10 {
        return Err("invalid date".to_owned());
    }
    let d_parts: Vec<&str> = date_part.split('-').collect();
    let [year_s, month_s, day_s] = d_parts.as_slice() else {
        return Err("invalid date".to_owned());
    };
    let year = parse_fixed_digits(year_s, 4, "year")?;
    let month_i = parse_fixed_digits(month_s, 2, "month")?;
    let day_i = parse_fixed_digits(day_s, 2, "day")?;
    let month = u32::try_from(month_i).map_err(|_| "bad month")?;
    let day = u32::try_from(day_i).map_err(|_| "bad day")?;
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || i64::from(day) > days_in_month(year, month)
    {
        return Err("date out of range".to_owned());
    }
    let (time_no_tz, tz_offset) = split_rfc3339_offset(time_part)?;
    let (hms, frac) = match time_no_tz.split_once('.') {
        Some((h, f)) => (h, Some(f)),
        None => (time_no_tz, None),
    };
    if hms.len() != 8 {
        return Err("invalid time".to_owned());
    }
    let t_parts: Vec<&str> = hms.split(':').collect();
    let [hour_s, min_s, sec_s] = t_parts.as_slice() else {
        return Err("invalid time".to_owned());
    };
    let hour = parse_fixed_digits(hour_s, 2, "hour")?;
    let min = parse_fixed_digits(min_s, 2, "minute")?;
    let sec = parse_fixed_digits(sec_s, 2, "second")?;
    if !(0..=23).contains(&hour) || !(0..=59).contains(&min) || !(0..=59).contains(&sec) {
        return Err("time out of range".to_owned());
    }
    let nanos = match frac {
        None => 0i32,
        Some(f) if f.is_empty() || f.len() > 9 || !f.bytes().all(|b| b.is_ascii_digit()) => {
            return Err("invalid fractional seconds".to_owned());
        }
        Some(f) => {
            let mut padded = f.to_owned();
            while padded.len() < 9 {
                padded.push('0');
            }
            padded.parse::<i32>().map_err(|_| "bad nanos")?
        }
    };
    let days = days_from_civil(year, month, day).ok_or_else(|| "date overflow".to_owned())?;
    let day_secs = hour
        .checked_mul(3_600)
        .and_then(|v| v.checked_add(min.checked_mul(60)?))
        .and_then(|v| v.checked_add(sec))
        .ok_or_else(|| "time overflow".to_owned())?;
    let total = days
        .checked_mul(86_400)
        .and_then(|v| v.checked_add(day_secs))
        .and_then(|v| v.checked_sub(tz_offset))
        .ok_or_else(|| "timestamp overflow".to_owned())?;
    if !is_valid_timestamp(total, nanos) {
        return Err("timestamp out of protobuf 0001..=9999 UTC range".to_owned());
    }
    Ok(ProtoTimestamp {
        seconds: total,
        nanos,
    })
}

pub(crate) fn format_duration(seconds: i64, nanos: i32) -> Result<String, &'static str> {
    if !is_valid_duration(seconds, nanos) {
        return Err("duration out of protobuf bounds");
    }
    if nanos == 0 {
        Ok(format!("{seconds}s"))
    } else {
        let sign = if seconds < 0 || nanos < 0 { "-" } else { "" };
        let abs_s = seconds.unsigned_abs();
        let abs_n = nanos.unsigned_abs();
        let mut frac = format!("{abs_n:09}");
        while frac.ends_with('0') {
            frac.pop();
        }
        Ok(format!("{sign}{abs_s}.{frac}s"))
    }
}

pub(crate) fn parse_duration(raw: &str) -> Result<ProtoDuration, String> {
    let body = raw
        .strip_suffix('s')
        .ok_or_else(|| "duration must end with 's'".to_owned())?;
    let (neg, unsigned) = match body.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, body),
    };
    let (sec_str, frac_str) = match unsigned.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (unsigned, None),
    };
    if sec_str.is_empty() || !sec_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid duration seconds".to_owned());
    }
    let sec_abs: i64 = sec_str.parse().map_err(|_| "invalid duration seconds")?;
    let nanos_abs = match frac_str {
        None => 0i32,
        Some(f) if f.is_empty() || f.len() > 9 || !f.bytes().all(|b| b.is_ascii_digit()) => {
            return Err("invalid duration fractional seconds".to_owned());
        }
        Some(f) => {
            let mut padded = f.to_owned();
            while padded.len() < 9 {
                padded.push('0');
            }
            padded.parse::<i32>().map_err(|_| "bad nanos")?
        }
    };
    let seconds = if neg {
        sec_abs
            .checked_neg()
            .ok_or_else(|| "duration overflow".to_owned())?
    } else {
        sec_abs
    };
    let nanos = if neg {
        nanos_abs
            .checked_neg()
            .ok_or_else(|| "nanos overflow".to_owned())?
    } else {
        nanos_abs
    };
    if !is_valid_duration(seconds, nanos) {
        return Err("duration out of protobuf bounds".to_owned());
    }
    Ok(ProtoDuration { seconds, nanos })
}

impl Serialize for ProtoTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let iso = format_rfc3339(self.seconds, self.nanos)
            .ok_or_else(|| serde::ser::Error::custom("invalid ProtoTimestamp out of range"))?;
        serializer.serialize_str(&iso)
    }
}

impl<'de> Deserialize<'de> for ProtoTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TsVisitor;
        impl<'de> Visitor<'de> for TsVisitor {
            type Value = ProtoTimestamp;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("RFC 3339 timestamp string or {seconds, nanos} object")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                parse_rfc3339(v).map_err(E::custom)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut seconds = None;
                let mut nanos = None;
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "seconds" => {
                            if seconds.is_some() {
                                return Err(de::Error::duplicate_field("seconds"));
                            }
                            seconds = Some(map.next_value()?);
                        }
                        "nanos" => {
                            if nanos.is_some() {
                                return Err(de::Error::duplicate_field("nanos"));
                            }
                            nanos = Some(map.next_value()?);
                        }
                        other => {
                            return Err(de::Error::unknown_field(other, &["seconds", "nanos"]));
                        }
                    }
                }
                let s = seconds.unwrap_or(0);
                let n = nanos.unwrap_or(0);
                if !is_valid_timestamp(s, n) {
                    return Err(de::Error::custom("timestamp out of protobuf range"));
                }
                Ok(ProtoTimestamp {
                    seconds: s,
                    nanos: n,
                })
            }
        }
        deserializer.deserialize_any(TsVisitor)
    }
}

impl Serialize for ProtoDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let formatted =
            format_duration(self.seconds, self.nanos).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&formatted)
    }
}

impl<'de> Deserialize<'de> for ProtoDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DurVisitor;
        impl<'de> Visitor<'de> for DurVisitor {
            type Value = ProtoDuration;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("ProtoJSON duration string (e.g. '10s') or {seconds, nanos} object")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                parse_duration(v).map_err(E::custom)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut seconds = None;
                let mut nanos = None;
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "seconds" => {
                            if seconds.is_some() {
                                return Err(de::Error::duplicate_field("seconds"));
                            }
                            seconds = Some(map.next_value()?);
                        }
                        "nanos" => {
                            if nanos.is_some() {
                                return Err(de::Error::duplicate_field("nanos"));
                            }
                            nanos = Some(map.next_value()?);
                        }
                        other => {
                            return Err(de::Error::unknown_field(other, &["seconds", "nanos"]));
                        }
                    }
                }
                let s = seconds.unwrap_or(0);
                let n = nanos.unwrap_or(0);
                if !is_valid_duration(s, n) {
                    return Err(de::Error::custom("duration out of protobuf bounds"));
                }
                Ok(ProtoDuration {
                    seconds: s,
                    nanos: n,
                })
            }
        }
        deserializer.deserialize_any(DurVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_roundtrip_offsets_and_bounds() {
        let ts = ProtoTimestamp {
            seconds: 1_700_000_000,
            nanos: 123_450_000,
        };
        let j = serde_json::to_string(&ts).unwrap();
        assert_eq!(j, "\"2023-11-14T22:13:20.12345Z\"");
        assert_eq!(serde_json::from_str::<ProtoTimestamp>(&j).unwrap(), ts);

        let tz = "\"2023-11-15T00:13:20.12345+02:00\"";
        assert_eq!(serde_json::from_str::<ProtoTimestamp>(tz).unwrap(), ts);

        let obj = "{\"seconds\":1700000000,\"nanos\":123450000}";
        assert_eq!(serde_json::from_str::<ProtoTimestamp>(obj).unwrap(), ts);

        assert!(
            serde_json::to_string(&ProtoTimestamp {
                seconds: 0,
                nanos: -1,
            })
            .is_err()
        );
        assert!(
            serde_json::to_string(&ProtoTimestamp {
                seconds: MAX_TS_SECONDS + 1,
                nanos: 0,
            })
            .is_err()
        );
        assert!(serde_json::from_str::<ProtoTimestamp>("\" 2023-11-14T22:13:20Z\"").is_err());
        assert!(serde_json::from_str::<ProtoTimestamp>("\"0000-01-01T00:00:00Z\"").is_err());
        assert!(serde_json::from_str::<ProtoTimestamp>("\"+202-01-01T00:00:00Z\"").is_err());
        assert!(serde_json::from_str::<ProtoTimestamp>("\"2023-11-14T22:13:20+25:00\"").is_err());
        assert!(serde_json::from_str::<ProtoTimestamp>("\"0001-01-01T00:00:00+01:00\"").is_err());
        assert!(serde_json::from_str::<ProtoTimestamp>("\"9999-12-31T23:59:59-01:00\"").is_err());
        assert!(
            serde_json::from_str::<ProtoTimestamp>("{\"seconds\":0,\"nanos\":1000000000}").is_err()
        );
        assert!(serde_json::from_str::<ProtoTimestamp>("{\"seconds\":1,\"seconds\":2}").is_err());
        assert!(serde_json::from_str::<ProtoTimestamp>("{\"seconds\":0,\"extra\":1}").is_err());
    }

    #[test]
    fn duration_roundtrip_and_rejects_mixed_sign_and_bounds() {
        let d = ProtoDuration {
            seconds: -10,
            nanos: -500_000_000,
        };
        let j = serde_json::to_string(&d).unwrap();
        assert_eq!(j, "\"-10.5s\"");
        assert_eq!(serde_json::from_str::<ProtoDuration>(&j).unwrap(), d);

        assert!(serde_json::from_str::<ProtoDuration>("\"--10.5s\"").is_err());
        assert!(serde_json::from_str::<ProtoDuration>("\"+10s\"").is_err());
        assert!(serde_json::from_str::<ProtoDuration>("\" 10s\"").is_err());
        assert!(serde_json::from_str::<ProtoDuration>("\"315576000001s\"").is_err());
        assert!(
            serde_json::to_string(&ProtoDuration {
                seconds: -1,
                nanos: 500_000_000,
            })
            .is_err()
        );
        assert!(serde_json::from_str::<ProtoDuration>("{\"seconds\":-1,\"nanos\":100}").is_err());
        assert!(serde_json::from_str::<ProtoDuration>("{\"seconds\":1,\"unknown\":2}").is_err());
    }
}
