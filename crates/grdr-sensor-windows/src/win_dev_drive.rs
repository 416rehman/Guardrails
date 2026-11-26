// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

#[cfg(windows)]
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::WindowsSensorError;
#[cfg(any(windows, test))]
use crate::dev_drive::DevDriveTrust;
use crate::dev_drive::{
    DevDriveCoverageProbe, DevDriveVolume, parse_fsutil_devdrv_output, probe_dev_drive_coverage,
};

#[cfg(windows)]
const WIN32_DRIVE_FIXED: u32 = 3;
#[cfg(windows)]
const WIN32_DRIVE_REMOVABLE: u32 = 2;
#[cfg(windows)]
const WIN32_DRIVE_REMOTE: u32 = 4;
#[cfg(windows)]
const DEV_DRIVE_FS_REFS: &str = "ReFS";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDriveKind {
    Fixed,
    Removable,
    Remote,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnumeratedVolume {
    pub root_path: String,
    pub label: String,
    pub filesystem: String,
    pub drive_kind: WindowsDriveKind,
    pub is_refs: bool,
    pub dev_drive: Option<DevDriveVolume>,
    pub coverage: DevDriveCoverageProbe,
}

pub fn enumerate_windows_volumes(
    expected_filters: &[(&str, u32)],
) -> Result<Vec<EnumeratedVolume>, WindowsSensorError> {
    #[cfg(windows)]
    {
        let raw_vols = win32_enumerate_logical_volumes()?;
        let mut out = Vec::with_capacity(raw_vols.len());
        for (root, label, filesystem, drive_kind) in raw_vols {
            let is_refs = filesystem.eq_ignore_ascii_case(DEV_DRIVE_FS_REFS);
            let dev_drive = if is_refs {
                query_fsutil_devdrv(&root)
            } else {
                None
            };
            let coverage = match &dev_drive {
                Some(vol) => probe_dev_drive_coverage(vol, expected_filters),
                None => DevDriveCoverageProbe::FullCoverage,
            };
            out.push(EnumeratedVolume {
                root_path: root,
                label,
                filesystem,
                drive_kind,
                is_refs,
                dev_drive,
                coverage,
            });
        }
        Ok(out)
    }
    #[cfg(not(windows))]
    {
        let _ = expected_filters;
        Ok(Vec::new())
    }
}

pub fn probe_dev_drive_trust_from_output(
    volume_root: &str,
    fsutil_stdout: &str,
    expected_filters: &[(&str, u32)],
) -> Result<(DevDriveVolume, DevDriveCoverageProbe), WindowsSensorError> {
    let parsed = parse_fsutil_devdrv_output(volume_root, fsutil_stdout)?;
    let probe = probe_dev_drive_coverage(&parsed, expected_filters);
    Ok((parsed, probe))
}

#[cfg(windows)]
fn query_fsutil_devdrv(volume_root: &str) -> Option<DevDriveVolume> {
    let clean_arg = volume_root.trim_end_matches('\\');
    if clean_arg.is_empty() || clean_arg.chars().any(|c| c == '\0' || c.is_control()) {
        return None;
    }
    let sys_root = std::env::var_os("SystemRoot")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    let fsutil_exe = sys_root.join("System32").join("fsutil.exe");
    let output = Command::new(fsutil_exe)
        .args(["devdrv", "query", clean_arg])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Some(DevDriveVolume {
            volume_root: volume_root.to_string(),
            trust: DevDriveTrust::Untrusted,
            filter_policy: crate::dev_drive::DevDriveFilterPolicy::DisallowAntivirus,
            allowed_filters: Vec::new(),
        });
    }
    parse_fsutil_devdrv_output(volume_root, &stdout).ok()
}

#[cfg(windows)]
fn win32_enumerate_logical_volumes()
-> Result<Vec<(String, String, String, WindowsDriveKind)>, WindowsSensorError> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW,
    };

    #[allow(
        unsafe_code,
        reason = "Query required buffer size for Win32 logical drive list."
    )]
    // SAFETY: Passing 0 length and null pointer queries required UTF-16 buffer length.
    let needed = unsafe { GetLogicalDriveStringsW(0, null_mut()) };
    if needed == 0 {
        return Err(WindowsSensorError::DevDrive(
            "GetLogicalDriveStringsW returned 0".to_string(),
        ));
    }
    let cap = usize::try_from(needed.saturating_add(1)).unwrap_or(512);
    let mut buf = vec![0u16; cap];
    #[allow(unsafe_code, reason = "Read Win32 multi-string logical drive roots.")]
    // SAFETY: buf has cap u16 elements and written length fits inside buf.
    let written = unsafe { GetLogicalDriveStringsW(needed.saturating_add(1), buf.as_mut_ptr()) };
    if written == 0 {
        return Err(WindowsSensorError::DevDrive(
            "GetLogicalDriveStringsW read failed".to_string(),
        ));
    }
    let used = usize::try_from(written).unwrap_or(buf.len()).min(buf.len());
    let roots = split_multi_sz_utf16(buf.get(..used).unwrap_or(&buf));
    let mut out = Vec::with_capacity(roots.len());

    for root in roots {
        let mut wide_root: Vec<u16> = root.encode_utf16().collect();
        wide_root.push(0);
        #[allow(unsafe_code, reason = "Query drive type for enumerated root volume.")]
        // SAFETY: wide_root is NUL-terminated UTF-16 drive root.
        let kind_raw = unsafe { GetDriveTypeW(wide_root.as_ptr()) };
        let drive_kind = match kind_raw {
            WIN32_DRIVE_FIXED => WindowsDriveKind::Fixed,
            WIN32_DRIVE_REMOVABLE => WindowsDriveKind::Removable,
            WIN32_DRIVE_REMOTE => WindowsDriveKind::Remote,
            _ => WindowsDriveKind::Other,
        };
        let mut label_buf = [0u16; 260];
        let mut fs_buf = [0u16; 64];
        #[allow(
            unsafe_code,
            reason = "Query filesystem and volume label via GetVolumeInformationW."
        )]
        // SAFETY: wide_root is NUL-terminated; label_buf/fs_buf sizes match array lengths.
        let ok = unsafe {
            GetVolumeInformationW(
                wide_root.as_ptr(),
                label_buf.as_mut_ptr(),
                u32::try_from(label_buf.len()).unwrap_or(260),
                null_mut(),
                null_mut(),
                null_mut(),
                fs_buf.as_mut_ptr(),
                u32::try_from(fs_buf.len()).unwrap_or(64),
            )
        };
        let (label, filesystem) = if ok != 0 {
            (utf16_z_to_string(&label_buf), utf16_z_to_string(&fs_buf))
        } else {
            (String::new(), String::from("UNAVAILABLE"))
        };
        out.push((root, label, filesystem, drive_kind));
    }
    Ok(out)
}

#[cfg(windows)]
fn split_multi_sz_utf16(slice: &[u16]) -> Vec<String> {
    let mut out = Vec::new();
    for segment in slice.split(|&ch| ch == 0) {
        if !segment.is_empty() {
            out.push(String::from_utf16_lossy(segment));
        }
    }
    out
}

#[cfg(windows)]
fn utf16_z_to_string(slice: &[u16]) -> String {
    let nul = slice.iter().position(|&ch| ch == 0).unwrap_or(slice.len());
    String::from_utf16_lossy(slice.get(..nul).unwrap_or(slice))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_host_volumes_cleanly() {
        let volumes = enumerate_windows_volumes(&[("grdr-minifilter", 325_900)])
            .expect("enumerate volumes without admin");
        #[cfg(windows)]
        {
            assert!(!volumes.is_empty());
            assert!(
                volumes
                    .iter()
                    .any(|v| v.drive_kind == WindowsDriveKind::Fixed)
            );
        }
        #[cfg(not(windows))]
        {
            assert!(volumes.is_empty());
        }
    }

    #[test]
    fn bridges_refs_dev_drive_probe() {
        let raw = "Volume D:\\ is a trusted developer volume.\nFilters allowed on this volume: Wof\nAntivirus filters are disallowed";
        let (vol, probe) =
            probe_dev_drive_trust_from_output("D:\\", raw, &[("grdr-minifilter", 325_900)])
                .expect("parse");
        assert!(matches!(vol.trust, DevDriveTrust::Trusted));
        assert!(matches!(
            probe,
            DevDriveCoverageProbe::FileFilterDetached { .. }
        ));
    }
}
