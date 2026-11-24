// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

pub const AV_ALTITUDE_MIN: u32 = 320_000;
pub const AV_ALTITUDE_MAX: u32 = 329_999;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevDriveTrust {
    Trusted,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevDriveFilterPolicy {
    AllowAll,
    DisallowAntivirus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevDriveVolume {
    pub volume_root: String,
    pub trust: DevDriveTrust,
    pub filter_policy: DevDriveFilterPolicy,
    pub allowed_filters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "coverage", rename_all = "snake_case")]
pub enum DevDriveCoverageProbe {
    FullCoverage,
    FileFilterDetached {
        volume_root: String,
        reason: &'static str,
        detached_filters: Vec<String>,
    },
}

pub fn parse_fsutil_devdrv_output(volume_root: &str, raw: &str) -> DevDriveVolume {
    let mut trust = DevDriveTrust::Untrusted;
    let mut filter_policy = DevDriveFilterPolicy::AllowAll;
    let mut allowed_filters = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("trusted") && !lower.contains("untrusted") {
            trust = DevDriveTrust::Trusted;
        }
        if lower.contains("antivirus") && lower.contains("disallowed") {
            filter_policy = DevDriveFilterPolicy::DisallowAntivirus;
        }
        if let Some((_, rest)) = trimmed.split_once(':')
            && lower.starts_with("filters allowed")
        {
            for item in rest.split([',', ';']) {
                let name = item.trim();
                if !name.is_empty() && !name.eq_ignore_ascii_case("none") {
                    allowed_filters.push(name.to_string());
                }
            }
        }
    }

    DevDriveVolume {
        volume_root: volume_root.to_string(),
        trust,
        filter_policy,
        allowed_filters,
    }
}

pub fn probe_dev_drive_coverage(
    volume: &DevDriveVolume,
    expected_filters: &[(&str, u32)],
) -> DevDriveCoverageProbe {
    if volume.trust == DevDriveTrust::Untrusted {
        return DevDriveCoverageProbe::FullCoverage;
    }

    let mut detached = Vec::new();
    for (filter_name, altitude) in expected_filters {
        let is_av_band = (*altitude >= AV_ALTITUDE_MIN) && (*altitude <= AV_ALTITUDE_MAX);
        let explicitly_allowed = volume
            .allowed_filters
            .iter()
            .any(|f| f.eq_ignore_ascii_case(filter_name));
        let attached = if is_av_band {
            volume.filter_policy == DevDriveFilterPolicy::AllowAll || explicitly_allowed
        } else {
            explicitly_allowed
        };
        if !attached {
            detached.push((*filter_name).to_string());
        }
    }

    if detached.is_empty() {
        DevDriveCoverageProbe::FullCoverage
    } else {
        DevDriveCoverageProbe::FileFilterDetached {
            volume_root: volume.volume_root.clone(),
            reason: "file-filter-detached",
            detached_filters: detached,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_detached_filters_on_trusted_dev_drive() {
        let sample = "Volume D:\\ is a trusted developer volume.\nAntivirus filters are allowed.\nFilters allowed on this volume: None\n";
        let vol = parse_fsutil_devdrv_output(r"D:\", sample);
        assert_eq!(vol.trust, DevDriveTrust::Trusted);

        let probe = probe_dev_drive_coverage(&vol, &[("MsSecFlt", 328010), ("GrdrFilter", 370500)]);
        assert_eq!(
            probe,
            DevDriveCoverageProbe::FileFilterDetached {
                volume_root: r"D:\".into(),
                reason: "file-filter-detached",
                detached_filters: vec!["GrdrFilter".into()],
            }
        );
    }

    #[test]
    fn allowlisted_filter_reports_full_coverage() {
        let sample = "Volume D:\\ is a trusted developer volume.\nFilters allowed on this volume: GrdrFilter, MsSecFlt\n";
        let vol = parse_fsutil_devdrv_output(r"D:\", sample);
        let probe = probe_dev_drive_coverage(&vol, &[("MsSecFlt", 328010), ("GrdrFilter", 370500)]);
        assert_eq!(probe, DevDriveCoverageProbe::FullCoverage);
    }
}
