// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::UNIX_EPOCH;

use uuid::Uuid;

use grdr_ports::ProfileKind;

use crate::fs_safe;
use crate::server_preflight::probe_types::{
    ErrCodeSlot, PreflightThresholds, ProbeOutcomeKind, RawProbeResult,
};

const SECS_PER_DAY: i64 = 86_400;
const SECS_PER_HOUR: u64 = 3_600;
const SECS_PER_MINUTE: u64 = 60;
const MAX_DRILL_MARKER_BYTES: u64 = 65_536;

pub fn probe_backup_and_drill(
    profile: ProfileKind,
    backup_dir: Option<&Path>,
    data_dir: Option<&Path>,
    drill_marker: Option<&Path>,
    thresholds: &PreflightThresholds,
    now_unix_s: i64,
) -> Vec<RawProbeResult> {
    let mut out = Vec::new();
    if let Some(dir) = backup_dir {
        if let Err(err) = fs_safe::reject_symlinks_on_existing_prefixes(dir) {
            out.push(storage_res(
                "PF-10",
                "backup_recency",
                ProbeOutcomeKind::Fail,
                format!("Backup directory `{}` rejected: {err}", dir.display()),
                Some("Point --backup-dir at a real, symlink-free directory."),
            ));
            return out;
        }
        match fs::symlink_metadata(dir) {
            Ok(meta) if !meta.file_type().is_symlink() && meta.is_dir() => {
                let max_age_s = match profile {
                    ProfileKind::Embedded => thresholds
                        .sqlite_backup_max_age_minutes
                        .saturating_mul(SECS_PER_MINUTE),
                    ProfileKind::Ha | ProfileKind::Distributed => thresholds
                        .backup_max_age_hours
                        .saturating_mul(SECS_PER_HOUR),
                };
                match newest_backup_age_s(dir, now_unix_s) {
                    Some(age_s) if age_s > max_age_s => out.push(storage_res(
                        "PF-10",
                        "backup_recency",
                        ProbeOutcomeKind::Fail,
                        format!(
                            "Latest backup in `{}` is {age_s}s old (limit {max_age_s}s).",
                            dir.display()
                        ),
                        Some("Run backup job immediately and inspect WAL archiving (RB-05)."),
                    )),
                    Some(age_s) => out.push(storage_res(
                        "PF-10",
                        "backup_recency",
                        ProbeOutcomeKind::Pass,
                        format!(
                            "Latest backup in `{}` is {age_s}s old (limit {max_age_s}s).",
                            dir.display()
                        ),
                        None,
                    )),
                    None => out.push(storage_res(
                        "PF-10",
                        "backup_recency",
                        ProbeOutcomeKind::Warn,
                        format!(
                            "No completed backup artifacts found yet in `{}`.",
                            dir.display()
                        ),
                        Some("Execute initial backup and restore drill."),
                    )),
                }
            }
            Ok(_) => out.push(storage_res(
                "PF-10",
                "backup_recency",
                ProbeOutcomeKind::Fail,
                format!(
                    "Backup path `{}` is a symlink or non-directory.",
                    dir.display()
                ),
                Some("Replace symlink with an owned non-symlink backup directory."),
            )),
            Err(_) => out.push(storage_res(
                "PF-10",
                "backup_recency",
                ProbeOutcomeKind::Warn,
                format!("Backup directory `{}` does not exist yet.", dir.display()),
                Some("Initialize backup target before production cutover."),
            )),
        }
    }

    let resolved_marker = drill_marker
        .filter(|p| fs::symlink_metadata(p).is_ok())
        .map(Path::to_path_buf)
        .or_else(|| {
            backup_dir
                .map(|d| d.join("restore-drill.json"))
                .filter(|p| fs::symlink_metadata(p).is_ok())
        })
        .or_else(|| {
            data_dir
                .map(|d| d.join("restore-drill.json"))
                .filter(|p| fs::symlink_metadata(p).is_ok())
        });

    if let Some(marker_path) = resolved_marker {
        evaluate_restore_drill_marker(&marker_path, thresholds, now_unix_s, &mut out);
    } else if drill_marker.is_some() {
        out.push(storage_res(
            "PF-11",
            "restore_drill_age",
            ProbeOutcomeKind::Fail,
            "Specified --restore-drill-marker file does not exist.".into(),
            Some("Execute `grdr server restore-drill` and record signed marker."),
        ));
    } else if backup_dir.is_some() {
        out.push(storage_res(
            "PF-11",
            "restore_drill_age",
            ProbeOutcomeKind::Warn,
            "No restore-drill.json record found in backup directory.".into(),
            Some("Run `grdr server restore-drill` before enabling production traffic."),
        ));
    }
    out
}

fn storage_res(
    id: &'static str,
    name: &'static str,
    kind: ProbeOutcomeKind,
    detail: String,
    remedy: Option<&'static str>,
) -> RawProbeResult {
    RawProbeResult {
        id,
        name,
        kind,
        err_slot: if matches!(kind, ProbeOutcomeKind::Pass) {
            ErrCodeSlot::None
        } else {
            ErrCodeSlot::Storage
        },
        detail,
        remedy,
    }
}

pub fn evaluate_disk_headroom_bytes(
    label: &str,
    total_bytes: u64,
    avail_bytes: u64,
    min_pct: u64,
) -> RawProbeResult {
    if total_bytes == 0 {
        return storage_res(
            "PF-12",
            "disk_headroom",
            ProbeOutcomeKind::Fail,
            format!("Unable to compute disk headroom for `{label}` (zero total capacity)."),
            Some("Ensure volume is mounted and readable."),
        );
    }
    let free_pct = u128::from(avail_bytes)
        .saturating_mul(100)
        .checked_div(u128::from(total_bytes))
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(0);
    if free_pct < min_pct {
        storage_res(
            "PF-12",
            "disk_headroom",
            ProbeOutcomeKind::Fail,
            format!("Disk free space on `{label}` is {free_pct}% (< {min_pct}% required)."),
            Some("Expand volume or prune aged spool/cache segments before running upgrades."),
        )
    } else {
        storage_res(
            "PF-12",
            "disk_headroom",
            ProbeOutcomeKind::Pass,
            format!("Disk free space on `{label}` is {free_pct}% (>= {min_pct}%)."),
            None,
        )
    }
}

pub fn probe_disk_headroom(path: &Path, thresholds: &PreflightThresholds) -> RawProbeResult {
    let label = path.display().to_string();
    if let Err(err) = fs_safe::reject_symlinks_on_existing_prefixes(path) {
        return storage_res(
            "PF-12",
            "disk_headroom",
            ProbeOutcomeKind::Fail,
            format!("Disk headroom path `{label}` rejected: {err}"),
            Some("Provide a non-symlink directory for disk headroom checks."),
        );
    }
    let Ok(meta) = fs::symlink_metadata(path) else {
        return storage_res(
            "PF-12",
            "disk_headroom",
            ProbeOutcomeKind::Fail,
            format!("Cannot inspect disk headroom for missing path `{label}`."),
            Some("Create directory before running --check-disk preflight."),
        );
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return storage_res(
            "PF-12",
            "disk_headroom",
            ProbeOutcomeKind::Fail,
            format!("Disk headroom target `{label}` must be a real non-symlink directory."),
            Some("Replace symlink or non-directory path with a real directory."),
        );
    }
    match query_fs_bytes(path) {
        Ok((total_bytes, avail_bytes)) => evaluate_disk_headroom_bytes(
            &label,
            total_bytes,
            avail_bytes,
            thresholds.disk_headroom_min_pct,
        ),
        Err(reason) => storage_res(
            "PF-12",
            "disk_headroom",
            ProbeOutcomeKind::Fail,
            format!("Failed querying filesystem headroom for `{label}`: {reason}"),
            Some("Verify volume health and host OS disk query tooling."),
        ),
    }
}

#[cfg(unix)]
fn query_fs_bytes(path: &Path) -> Result<(u64, u64), String> {
    let canon = fs::canonicalize(path).map_err(|e| format!("canonicalize failed: {e}"))?;
    let df_bin = if Path::new("/bin/df").is_file() {
        "/bin/df"
    } else if Path::new("/usr/bin/df").is_file() {
        "/usr/bin/df"
    } else {
        return Err("Neither /bin/df nor /usr/bin/df is present.".into());
    };
    let out = std::process::Command::new(df_bin)
        .arg("-kP")
        .arg("--")
        .arg(&canon)
        .output()
        .map_err(|e| format!("failed executing {df_bin}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{df_bin} exited with status {}", out.status));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data_line = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| "empty df -kP output".to_string())?;
    let cols: Vec<&str> = data_line.split_whitespace().collect();
    let total_kb = cols
        .get(1)
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| "missing df total column".to_string())?;
    let avail_kb = cols
        .get(3)
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| "missing df avail column".to_string())?;
    Ok((total_kb.saturating_mul(1024), avail_kb.saturating_mul(1024)))
}

#[cfg(windows)]
fn query_fs_bytes(path: &Path) -> Result<(u64, u64), String> {
    use std::path::{Component, Prefix};

    let abs = std::path::absolute(path).map_err(|e| format!("path resolve failed: {e}"))?;
    let Some(Component::Prefix(prefix_comp)) = abs.components().next() else {
        return Err("Windows path lacks a drive prefix.".into());
    };
    let drive_byte = match prefix_comp.kind() {
        Prefix::Disk(b) | Prefix::VerbatimDisk(b) => b,
        _ => return Err("Windows disk headroom requires a local drive letter.".into()),
    };
    if !drive_byte.is_ascii_alphabetic() {
        return Err("Invalid Windows drive letter byte.".into());
    }
    let drive = format!("{}:", char::from(drive_byte).to_ascii_uppercase());
    let dbytes = drive.as_bytes();
    if dbytes.len() != 2
        || !dbytes.first().is_some_and(u8::is_ascii_alphabetic)
        || dbytes.get(1) != Some(&b':')
    {
        return Err("Invalid validated Windows drive string.".into());
    }
    let out = std::process::Command::new("powershell")
        .env("GRDR_PROBE_DRIVE", &drive)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$d=[System.IO.DriveInfo]::new($env:GRDR_PROBE_DRIVE); Write-Output ($d.TotalSize.ToString() + ' ' + $d.AvailableFreeSpace.ToString())",
        ])
        .output()
        .map_err(|e| format!("powershell DriveInfo failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("DriveInfo failed with status {}", out.status));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.split_whitespace();
    let total = parts
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| "missing DriveInfo TotalSize".to_string())?;
    let avail = parts
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| "missing DriveInfo AvailableFreeSpace".to_string())?;
    Ok((total, avail))
}

fn evaluate_restore_drill_marker(
    path: &Path,
    thresholds: &PreflightThresholds,
    now_unix_s: i64,
    out: &mut Vec<RawProbeResult>,
) {
    let raw = match fs_safe::read_bounded_regular(path, MAX_DRILL_MARKER_BYTES) {
        Ok(b) => b,
        Err(err) => {
            out.push(storage_res(
                "PF-11",
                "restore_drill_age",
                ProbeOutcomeKind::Fail,
                format!("Failed safely reading `{}`: {err}", path.display()),
                Some("Regenerate restore-drill.json as a bounded regular file."),
            ));
            return;
        }
    };
    let parsed_ts = std::str::from_utf8(&raw)
        .ok()
        .and_then(|txt| serde_json::from_str::<serde_json::Value>(txt).ok())
        .and_then(|val| {
            val.get("completed_at")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .and_then(|s| s.parse::<jiff::Timestamp>().ok())
        .map(|t| t.as_second());

    let Some(completed_s) = parsed_ts else {
        out.push(storage_res(
            "PF-11",
            "restore_drill_age",
            ProbeOutcomeKind::Fail,
            format!(
                "Restore drill marker `{}` has missing, corrupt, or non-RFC3339 completed_at timestamp.",
                path.display()
            ),
            Some("Regenerate restore-drill.json using `grdr server restore-drill`."),
        ));
        return;
    };
    let age_days =
        u64::try_from(now_unix_s.saturating_sub(completed_s).max(0) / SECS_PER_DAY).unwrap_or(0);
    if age_days >= thresholds.restore_drill_fail_days {
        out.push(storage_res(
            "PF-11",
            "restore_drill_age",
            ProbeOutcomeKind::Fail,
            format!(
                "Last restore drill is {age_days}d old (>= {}d fail limit).",
                thresholds.restore_drill_fail_days
            ),
            Some("Execute quarterly `grdr server restore-drill`."),
        ));
    } else if age_days >= thresholds.restore_drill_warn_days {
        out.push(storage_res(
            "PF-11",
            "restore_drill_age",
            ProbeOutcomeKind::Warn,
            format!(
                "Last restore drill is {age_days}d old (>= {}d warn limit).",
                thresholds.restore_drill_warn_days
            ),
            Some("Schedule `grdr server restore-drill`."),
        ));
    } else {
        out.push(storage_res(
            "PF-11",
            "restore_drill_age",
            ProbeOutcomeKind::Pass,
            format!("Last restore drill is {age_days}d old."),
            None,
        ));
    }
}

fn newest_backup_age_s(dir: &Path, now_unix_s: i64) -> Option<u64> {
    let entries = fs::read_dir(dir).ok()?;
    let mut newest_s: Option<i64> = None;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') || name_str == "restore-drill.json" {
            continue;
        }
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() || !ft.is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if let Ok(mod_time) = meta.modified()
            && let Ok(dur) = mod_time.duration_since(UNIX_EPOCH)
            && let Ok(secs) = i64::try_from(dur.as_secs())
        {
            newest_s = Some(match newest_s {
                Some(prev) => prev.max(secs),
                None => secs,
            });
        }
    }
    newest_s.map(|s| u64::try_from(now_unix_s.saturating_sub(s).max(0)).unwrap_or(0))
}

pub fn check_directory_writable(
    name: &'static str,
    dir: &Path,
    warn_if_missing: bool,
) -> RawProbeResult {
    if let Err(err) = fs_safe::reject_symlinks_on_existing_prefixes(dir) {
        return storage_res(
            "PF-02",
            name,
            ProbeOutcomeKind::Fail,
            format!("Directory `{}` refused: {err}", dir.display()),
            Some("Use a real symlink-free directory path."),
        );
    }
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return storage_res(
                    "PF-02",
                    name,
                    ProbeOutcomeKind::Fail,
                    format!(
                        "Path `{}` is a symlink or is not a directory.",
                        dir.display()
                    ),
                    Some("Use a regular directory with no symlink/reparse components."),
                );
            }
            let probe = dir.join(format!(".grdr-preflight-{}", Uuid::now_v7().simple()));
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            match opts.open(&probe).and_then(|mut f| f.write_all(b"probe")) {
                Ok(()) => {
                    let _ = fs::remove_file(&probe);
                    storage_res(
                        "PF-02",
                        name,
                        ProbeOutcomeKind::Pass,
                        format!("Directory `{}` exists and is writable.", dir.display()),
                        None,
                    )
                }
                Err(err) => storage_res(
                    "PF-02",
                    name,
                    ProbeOutcomeKind::Fail,
                    format!("Directory `{}` is not writable: {err}", dir.display()),
                    Some("Grant directory ownership and write permissions to service user."),
                ),
            }
        }
        Err(_) => RawProbeResult {
            id: "PF-02",
            name,
            kind: if warn_if_missing {
                ProbeOutcomeKind::Pass
            } else {
                ProbeOutcomeKind::Warn
            },
            err_slot: ErrCodeSlot::None,
            detail: format!(
                "Directory `{}` does not exist yet and will be initialized on start.",
                dir.display()
            ),
            remedy: None,
        },
    }
}
