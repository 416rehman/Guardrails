// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::WindowsSensorError;

#[cfg(windows)]
const MAX_SNAPSHOT_PROCESSES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WindowsProcessKey {
    pub pid: u32,
    pub creation_time_100ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeProcessSnapshot {
    pub key: WindowsProcessKey,
    pub parent_pid: u32,
    pub exe_name: String,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTreeDelta {
    pub spawned: Vec<NativeProcessSnapshot>,
    pub exited: Vec<WindowsProcessKey>,
    pub pid_reused: Vec<(WindowsProcessKey, WindowsProcessKey)>,
}

#[derive(Debug, Default)]
pub struct WindowsProcessTree {
    active_by_pid: BTreeMap<u32, NativeProcessSnapshot>,
    agent_roots: BTreeSet<WindowsProcessKey>,
}

impl WindowsProcessTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_agent_root(&mut self, key: WindowsProcessKey) {
        self.agent_roots.insert(key);
    }

    pub fn active_count(&self) -> usize {
        self.active_by_pid.len()
    }

    pub fn is_in_agent_lineage(&self, pid: u32) -> bool {
        let mut cursor = pid;
        let mut visited = 0usize;
        while visited < 64 {
            let Some(proc_info) = self.active_by_pid.get(&cursor) else {
                return false;
            };
            if self.agent_roots.contains(&proc_info.key) {
                return true;
            }
            if proc_info.parent_pid == 0 || proc_info.parent_pid == cursor {
                return false;
            }
            cursor = proc_info.parent_pid;
            visited = visited.saturating_add(1);
        }
        false
    }

    pub fn apply_snapshot(&mut self, next_list: Vec<NativeProcessSnapshot>) -> ProcessTreeDelta {
        let mut next_by_pid = BTreeMap::new();
        let mut spawned = Vec::new();
        let mut pid_reused = Vec::new();

        for proc_entry in next_list {
            let pid = proc_entry.key.pid;
            if let Some(prev) = self.active_by_pid.get(&pid) {
                if prev.key != proc_entry.key {
                    pid_reused.push((prev.key, proc_entry.key));
                    self.agent_roots.remove(&prev.key);
                    spawned.push(proc_entry.clone());
                }
            } else {
                spawned.push(proc_entry.clone());
            }
            next_by_pid.insert(pid, proc_entry);
        }

        let mut exited = Vec::new();
        for (pid, prev) in &self.active_by_pid {
            if !next_by_pid.contains_key(pid) {
                exited.push(prev.key);
                self.agent_roots.remove(&prev.key);
            }
        }
        self.active_by_pid = next_by_pid;

        ProcessTreeDelta {
            spawned,
            exited,
            pid_reused,
        }
    }

    pub fn refresh_from_os(&mut self) -> Result<ProcessTreeDelta, WindowsSensorError> {
        let snap = snapshot_native_processes()?;
        Ok(self.apply_snapshot(snap))
    }
}

pub fn snapshot_native_processes() -> Result<Vec<NativeProcessSnapshot>, WindowsSensorError> {
    #[cfg(windows)]
    {
        win32_snapshot_processes()
    }
    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

pub fn inspect_process_by_pid(
    pid: u32,
) -> Result<Option<NativeProcessSnapshot>, WindowsSensorError> {
    if pid == 0 {
        return Err(WindowsSensorError::Containment(
            "pid 0 is invalid for native Windows process query".to_string(),
        ));
    }
    #[cfg(windows)]
    {
        win32_inspect_pid(pid)
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Ok(None)
    }
}

#[cfg(windows)]
fn win32_snapshot_processes() -> Result<Vec<NativeProcessSnapshot>, WindowsSensorError> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    #[allow(unsafe_code, reason = "Capture Win32 ToolHelp process snapshot.")]
    // SAFETY: CreateToolhelp32Snapshot with TH32CS_SNAPPROCESS and pid 0 takes no pointers.
    let raw_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw_snap == INVALID_HANDLE_VALUE || raw_snap.is_null() {
        return Err(WindowsSensorError::Containment(
            "CreateToolhelp32Snapshot failed".to_string(),
        ));
    }
    #[allow(unsafe_code, reason = "Wrap snapshot HANDLE in RAII OwnedHandle.")]
    // SAFETY: raw_snap was validated non-null and not INVALID_HANDLE_VALUE immediately above.
    let snap_guard = unsafe { OwnedHandle::from_raw_handle(raw_snap as RawHandle) };
    let snap_handle = snap_guard.as_raw_handle() as HANDLE;

    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..Default::default()
    };
    let mut results = Vec::new();

    #[allow(unsafe_code, reason = "Read first entry from ToolHelp snapshot.")]
    // SAFETY: snap_handle is live and entry.dwSize is initialized to size_of::<PROCESSENTRY32W>().
    let mut has_next = unsafe { Process32FirstW(snap_handle, &mut entry) } != 0;
    while has_next && results.len() < MAX_SNAPSHOT_PROCESSES {
        let pid = entry.th32ProcessID;
        let ppid = entry.th32ParentProcessID;
        let exe_name = utf16_z_to_string(&entry.szExeFile);
        if pid != 0 {
            let (creation_time_100ns, image_path) = query_process_identity_fields(pid);
            results.push(NativeProcessSnapshot {
                key: WindowsProcessKey {
                    pid,
                    creation_time_100ns,
                },
                parent_pid: ppid,
                exe_name,
                image_path,
            });
        }
        #[allow(unsafe_code, reason = "Advance ToolHelp snapshot cursor.")]
        // SAFETY: snap_handle stays open and entry.dwSize remains initialized.
        let next_ok = unsafe { Process32NextW(snap_handle, &mut entry) } != 0;
        has_next = next_ok;
    }
    Ok(results)
}

#[cfg(windows)]
fn win32_inspect_pid(pid: u32) -> Result<Option<NativeProcessSnapshot>, WindowsSensorError> {
    let all = win32_snapshot_processes()?;
    Ok(all.into_iter().find(|p| p.key.pid == pid))
}

#[cfg(windows)]
pub(crate) fn query_process_identity_fields(pid: u32) -> (u64, Option<String>) {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use windows_sys::Win32::Foundation::{FILETIME, HANDLE};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    #[allow(
        unsafe_code,
        reason = "Open process handle for limited identity metadata."
    )]
    // SAFETY: OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION returns null on access denial or exit.
    let raw_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw_proc.is_null() {
        return (0, None);
    }
    #[allow(unsafe_code, reason = "Wrap process HANDLE in RAII OwnedHandle.")]
    // SAFETY: raw_proc was verified non-null immediately above.
    let proc_guard = unsafe { OwnedHandle::from_raw_handle(raw_proc as RawHandle) };
    let proc_handle = proc_guard.as_raw_handle() as HANDLE;

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    #[allow(
        unsafe_code,
        reason = "Query process creation FILETIME for PID-reuse key."
    )]
    // SAFETY: proc_handle is valid and all four FILETIME out-pointers point to stack locals.
    let times_ok = unsafe {
        GetProcessTimes(
            proc_handle,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    let start_100ns = if times_ok != 0 {
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime)
    } else {
        0
    };

    let mut buf = vec![0u16; 1_024];
    let mut len = u32::try_from(buf.len()).unwrap_or(1_024);
    #[allow(
        unsafe_code,
        reason = "Query Win32 executable path via QueryFullProcessImageNameW."
    )]
    // SAFETY: proc_handle is valid, buf has capacity len u16 elements, and len receives written length.
    let path_ok = unsafe { QueryFullProcessImageNameW(proc_handle, 0, buf.as_mut_ptr(), &mut len) };
    let image_path = if path_ok != 0 && len > 0 {
        usize::try_from(len)
            .ok()
            .and_then(|n| buf.get(..n))
            .map(String::from_utf16_lossy)
    } else {
        None
    };

    (start_100ns, image_path)
}

#[cfg(windows)]
fn utf16_z_to_string(slice: &[u16]) -> String {
    let nul_pos = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf16_lossy(slice.get(..nul_pos).unwrap_or(slice))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pid_reuse_and_clears_stale_agent_lineage() {
        let mut tree = WindowsProcessTree::new();
        let root_key = WindowsProcessKey {
            pid: 4242,
            creation_time_100ns: 100,
        };
        tree.mark_agent_root(root_key);
        let d1 = tree.apply_snapshot(vec![
            NativeProcessSnapshot {
                key: root_key,
                parent_pid: 100,
                exe_name: "claude.exe".into(),
                image_path: None,
            },
            NativeProcessSnapshot {
                key: WindowsProcessKey {
                    pid: 5000,
                    creation_time_100ns: 150,
                },
                parent_pid: 4242,
                exe_name: "powershell.exe".into(),
                image_path: None,
            },
        ]);
        assert_eq!(d1.spawned.len(), 2);
        assert!(tree.is_in_agent_lineage(5000));

        let reused_root = WindowsProcessKey {
            pid: 4242,
            creation_time_100ns: 999,
        };
        let d2 = tree.apply_snapshot(vec![NativeProcessSnapshot {
            key: reused_root,
            parent_pid: 1,
            exe_name: "unrelated.exe".into(),
            image_path: None,
        }]);
        assert_eq!(d2.pid_reused, vec![(root_key, reused_root)]);
        assert_eq!(d2.exited.len(), 1);
        assert!(!tree.is_in_agent_lineage(4242));
    }

    #[cfg(windows)]
    #[test]
    fn snapshots_current_windows_process_with_creation_time() {
        let me = std::process::id();
        let found = inspect_process_by_pid(me)
            .expect("inspect current pid")
            .expect("current process present in ToolHelp snapshot");
        assert_eq!(found.key.pid, me);
        assert_ne!(found.key.creation_time_100ns, 0);
        assert!(found.image_path.is_some());
    }
}
