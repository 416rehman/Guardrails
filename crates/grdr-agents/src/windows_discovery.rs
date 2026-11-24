// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::{
    AssuranceRecord, CodedError, ControlStrength, DiscoveredAgent, InstallProfile, OnFailure,
    TamperGrade, Visibility,
};

use crate::windows_process_parse::{
    AgentExecutionSurface, WindowsProcessEntry, classify_process_entry, is_wsl_bridge_image,
    parse_wsl_command_invocation,
};
#[cfg(windows)]
use crate::windows_process_parse::{parse_cim_process_json, parse_tasklist_csv};

pub const CODE_WIN_SNAPSHOT_UNAVAILABLE: &str = "GRDR-WIN-0001";
const SYSTEM_SOURCE_NAME: &str = "windows-system";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessInstanceKey {
    pub pid: u32,
    pub image_name: String,
    pub executable_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedWindowsAgent {
    pub key: ProcessInstanceKey,
    pub agent_id: String,
    pub agent_name: String,
    pub agent_kind: String,
    pub surface: AgentExecutionSurface,
    pub command_line: Option<String>,
    pub session_id: Option<u32>,
    pub first_observed_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WslBridgeProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_name: String,
    pub distro: Option<String>,
    pub command_line: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_kind", rename_all = "snake_case")]
pub enum WindowsDiscoveryEvent {
    AgentStarted {
        agent: ObservedWindowsAgent,
        observed_at: Timestamp,
    },
    AgentExited {
        key: ProcessInstanceKey,
        agent_kind: String,
        agent_name: String,
        surface: AgentExecutionSurface,
        observed_at: Timestamp,
    },
    WslBridgeObserved {
        bridge: WslBridgeProcess,
        observed_at: Timestamp,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum DiscoveryObserverState {
    Uninitialized,
    Active {
        active_agent_count: usize,
        active_wsl_bridge_count: usize,
        last_observed_at: Timestamp,
    },
    UnsupportedHost {
        os: String,
        reason: String,
    },
    Degraded {
        error_code: String,
        reason: String,
        last_observed_at: Timestamp,
    },
}

pub trait ProcessSnapshotSource {
    fn source_name(&self) -> &'static str;
    fn snapshot_processes(&self) -> Result<Vec<WindowsProcessEntry>, CodedError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWindowsProcessSource;

#[derive(Debug, Clone)]
pub struct WindowsDiscoveryTracker<S> {
    source: S,
    observer_state: DiscoveryObserverState,
    active_agents: BTreeMap<ProcessInstanceKey, ObservedWindowsAgent>,
    active_bridges: BTreeMap<u32, WslBridgeProcess>,
}

impl<T: ProcessSnapshotSource + ?Sized> ProcessSnapshotSource for &T {
    fn source_name(&self) -> &'static str {
        (**self).source_name()
    }

    fn snapshot_processes(&self) -> Result<Vec<WindowsProcessEntry>, CodedError> {
        (**self).snapshot_processes()
    }
}

impl ProcessSnapshotSource for SystemWindowsProcessSource {
    fn source_name(&self) -> &'static str {
        SYSTEM_SOURCE_NAME
    }

    fn snapshot_processes(&self) -> Result<Vec<WindowsProcessEntry>, CodedError> {
        query_system_windows_processes()
    }
}

impl Default for WindowsDiscoveryTracker<SystemWindowsProcessSource> {
    fn default() -> Self {
        Self::new(SystemWindowsProcessSource)
    }
}

impl<S: ProcessSnapshotSource> WindowsDiscoveryTracker<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            observer_state: DiscoveryObserverState::Uninitialized,
            active_agents: BTreeMap::new(),
            active_bridges: BTreeMap::new(),
        }
    }

    pub fn observer_state(&self) -> &DiscoveryObserverState {
        &self.observer_state
    }

    pub fn active_agents(&self) -> Vec<&ObservedWindowsAgent> {
        self.active_agents.values().collect()
    }

    pub fn active_wsl_bridges(&self) -> Vec<&WslBridgeProcess> {
        self.active_bridges.values().collect()
    }

    pub fn poll_delta(&mut self, now: Timestamp) -> Result<Vec<WindowsDiscoveryEvent>, CodedError> {
        match self.source.snapshot_processes() {
            Ok(entries) => Ok(self.apply_snapshot(&entries, now)),
            Err(err) => {
                self.observer_state = if self.source.source_name() == SYSTEM_SOURCE_NAME
                    && err.code == CODE_WIN_SNAPSHOT_UNAVAILABLE
                    && !cfg!(windows)
                {
                    DiscoveryObserverState::UnsupportedHost {
                        os: std::env::consts::OS.into(),
                        reason: err.message.clone(),
                    }
                } else {
                    DiscoveryObserverState::Degraded {
                        error_code: err.code.clone(),
                        reason: err.message.clone(),
                        last_observed_at: now,
                    }
                };
                Err(err)
            }
        }
    }

    pub fn apply_snapshot(
        &mut self,
        entries: &[WindowsProcessEntry],
        now: Timestamp,
    ) -> Vec<WindowsDiscoveryEvent> {
        let mut events = Vec::new();
        let mut current_agent_keys = BTreeSet::new();
        let mut current_bridge_pids = BTreeSet::new();

        for entry in entries {
            if is_wsl_bridge_image(entry) {
                current_bridge_pids.insert(entry.pid);
                if let Entry::Vacant(vacant) = self.active_bridges.entry(entry.pid) {
                    let distro = entry
                        .command_line
                        .as_deref()
                        .and_then(|cmd| parse_wsl_command_invocation(cmd).distro);
                    let bridge = WslBridgeProcess {
                        pid: entry.pid,
                        parent_pid: entry.parent_pid,
                        image_name: entry.image_name.clone(),
                        distro,
                        command_line: entry.command_line.clone(),
                    };
                    vacant.insert(bridge.clone());
                    events.push(WindowsDiscoveryEvent::WslBridgeObserved {
                        bridge,
                        observed_at: now,
                    });
                }
            }

            if let Some((spec, surface)) = classify_process_entry(entry) {
                let key = ProcessInstanceKey {
                    pid: entry.pid,
                    image_name: entry.image_name.clone(),
                    executable_path: entry.executable_path.clone(),
                };
                current_agent_keys.insert(key.clone());

                if let Entry::Vacant(vacant) = self.active_agents.entry(key) {
                    let agent = ObservedWindowsAgent {
                        key: vacant.key().clone(),
                        agent_id: spec.id.into(),
                        agent_name: spec.name.into(),
                        agent_kind: spec.kind.into(),
                        surface,
                        command_line: entry.command_line.clone(),
                        session_id: entry.session_id,
                        first_observed_at: now,
                    };
                    vacant.insert(agent.clone());
                    events.push(WindowsDiscoveryEvent::AgentStarted {
                        agent,
                        observed_at: now,
                    });
                }
            }
        }

        let exited_keys: Vec<ProcessInstanceKey> = self
            .active_agents
            .keys()
            .filter(|k| !current_agent_keys.contains(*k))
            .cloned()
            .collect();
        for key in exited_keys {
            if let Some(removed) = self.active_agents.remove(&key) {
                events.push(WindowsDiscoveryEvent::AgentExited {
                    key: removed.key,
                    agent_kind: removed.agent_kind,
                    agent_name: removed.agent_name,
                    surface: removed.surface,
                    observed_at: now,
                });
            }
        }

        self.active_bridges
            .retain(|pid, _| current_bridge_pids.contains(pid));
        self.observer_state = DiscoveryObserverState::Active {
            active_agent_count: self.active_agents.len(),
            active_wsl_bridge_count: self.active_bridges.len(),
            last_observed_at: now,
        };
        events
    }

    pub fn to_discovered_agents(&self, profile: InstallProfile) -> Vec<DiscoveredAgent> {
        let tamper = match profile {
            InstallProfile::Protected => TamperGrade::Admin,
            InstallProfile::User => TamperGrade::User,
        };
        let assurance = AssuranceRecord {
            visibility: Visibility::Observed,
            control: ControlStrength::None,
            on_failure: OnFailure::Open,
            tamper,
        };

        self.active_agents
            .values()
            .map(|observed| {
                let location = match &observed.surface {
                    AgentExecutionSurface::NativeWindows => observed
                        .key
                        .executable_path
                        .clone()
                        .unwrap_or_else(|| observed.key.image_name.clone()),
                    AgentExecutionSurface::WslBridge { distro, wsl_pid } => {
                        let label = distro.as_deref().unwrap_or("default");
                        format!("wsl://{label}/pid/{wsl_pid}")
                    }
                };
                DiscoveredAgent {
                    id: format!("{}-pid-{}", observed.agent_id, observed.key.pid),
                    name: observed.agent_name.clone(),
                    kind: observed.agent_kind.clone(),
                    config_path: location,
                    hook_installed: false,
                    mcp_count: 0,
                    assurance,
                    assurance_level: assurance.level(),
                    sponsor: None,
                    detected_at: observed.first_observed_at,
                }
            })
            .collect()
    }
}

pub fn discover_windows_processes_once() -> Result<Vec<ObservedWindowsAgent>, CodedError> {
    let mut tracker = WindowsDiscoveryTracker::default();
    let _events = tracker.poll_delta(Timestamp::now())?;
    Ok(tracker.active_agents().into_iter().cloned().collect())
}

#[cfg(windows)]
fn query_system_windows_processes() -> Result<Vec<WindowsProcessEntry>, CodedError> {
    use std::process::Command;

    let cim_cmd = "@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,SessionId) | ConvertTo-Json -Compress";
    if let Ok(output) = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", cim_cmd])
        .output()
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        return parse_cim_process_json(&text);
    }

    let fallback = Command::new("tasklist.exe")
        .args(["/FO", "CSV", "/NH"])
        .output()
        .map_err(|e| {
            CodedError::new(
                CODE_WIN_SNAPSHOT_UNAVAILABLE,
                format!("Failed querying Windows process snapshot: {e}"),
                "Ensure tasklist.exe or powershell.exe is accessible.",
            )
        })?;
    if !fallback.status.success() {
        return Err(CodedError::new(
            CODE_WIN_SNAPSHOT_UNAVAILABLE,
            format!("Windows process snapshot exited with {}", fallback.status),
            "Inspect permissions for querying local processes.",
        ));
    }
    let csv_text = String::from_utf8_lossy(&fallback.stdout);
    Ok(parse_tasklist_csv(&csv_text))
}

#[cfg(not(windows))]
fn query_system_windows_processes() -> Result<Vec<WindowsProcessEntry>, CodedError> {
    Err(CodedError::new(
        CODE_WIN_SNAPSHOT_UNAVAILABLE,
        "Windows process observation is not available on this operating system.",
        "Run on Windows or inject a ProcessSnapshotSource implementation.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct ScriptedProcessSource {
        responses: RefCell<Vec<Result<Vec<WindowsProcessEntry>, CodedError>>>,
    }

    impl ScriptedProcessSource {
        fn new(responses: Vec<Result<Vec<WindowsProcessEntry>, CodedError>>) -> Self {
            Self {
                responses: RefCell::new(responses),
            }
        }
    }

    impl ProcessSnapshotSource for ScriptedProcessSource {
        fn source_name(&self) -> &'static str {
            "mock-windows"
        }

        fn snapshot_processes(&self) -> Result<Vec<WindowsProcessEntry>, CodedError> {
            let mut guard = self.responses.borrow_mut();
            if guard.is_empty() {
                return Ok(Vec::new());
            }
            guard.remove(0)
        }
    }

    fn proc_entry(
        pid: u32,
        image_name: &str,
        executable_path: Option<&str>,
        command_line: Option<&str>,
    ) -> WindowsProcessEntry {
        WindowsProcessEntry {
            pid,
            parent_pid: 100,
            image_name: image_name.into(),
            executable_path: executable_path.map(str::to_string),
            command_line: command_line.map(str::to_string),
            session_id: Some(1),
        }
    }

    #[test]
    fn matches_all_native_windows_and_wsl_agent_harnesses() {
        let now = Timestamp::now();
        let snapshot = vec![
            proc_entry(
                101,
                "claude.exe",
                Some(r"D:\Tools\Anthropic\claude.exe"),
                Some("claude.exe --version"),
            ),
            proc_entry(102, "codex.exe", None, Some("codex.exe")),
            proc_entry(103, "copilot.exe", None, Some("copilot.exe")),
            proc_entry(104, "cursor.exe", None, Some("cursor.exe")),
            proc_entry(105, "agy.exe", None, Some("agy.exe")),
            proc_entry(
                201,
                "wsl.exe",
                None,
                Some(r"wsl.exe -d Ubuntu-24.04 -- /usr/local/bin/claude --print hi"),
            ),
            proc_entry(
                202,
                "wsl.exe",
                None,
                Some(r#"wsl.exe --distribution Debian -- bash -lc "copilot suggest""#),
            ),
            proc_entry(
                203,
                "wsl.exe",
                None,
                Some(r"wsl.exe -d Ubuntu -- ls -la claude.md"),
            ),
            proc_entry(204, "vmmemwsl.exe", None, None),
        ];

        let source = ScriptedProcessSource::new(vec![Ok(snapshot)]);
        let mut tracker = WindowsDiscoveryTracker::new(source);
        let events = tracker.poll_delta(now).unwrap();

        let started_kinds: Vec<String> = tracker
            .active_agents()
            .into_iter()
            .map(|a| a.agent_kind.clone())
            .collect();
        assert_eq!(started_kinds.len(), 7);
        assert!(started_kinds.contains(&"claude-code".to_string()));
        assert!(started_kinds.contains(&"codex".to_string()));
        assert!(started_kinds.contains(&"copilot".to_string()));
        assert!(started_kinds.contains(&"cursor".to_string()));
        assert!(started_kinds.contains(&"agy".to_string()));

        let wsl_claude = tracker
            .active_agents()
            .into_iter()
            .find(|a| a.key.pid == 201)
            .unwrap();
        assert_eq!(
            wsl_claude.surface,
            AgentExecutionSurface::WslBridge {
                distro: Some("Ubuntu-24.04".into()),
                wsl_pid: 201,
            }
        );

        let wsl_copilot = tracker
            .active_agents()
            .into_iter()
            .find(|a| a.key.pid == 202)
            .unwrap();
        assert_eq!(wsl_copilot.agent_kind, "copilot");

        assert!(tracker.active_agents().iter().all(|a| a.key.pid != 203));
        assert_eq!(tracker.active_wsl_bridges().len(), 4);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, WindowsDiscoveryEvent::WslBridgeObserved { .. }))
        );
    }

    #[test]
    fn tracks_delta_events_and_degraded_state_transitions() {
        let t1 = Timestamp::from_second(1_700_000_000).unwrap();
        let t2 = Timestamp::from_second(1_700_000_010).unwrap();
        let t3 = Timestamp::from_second(1_700_000_020).unwrap();
        let t4 = Timestamp::from_second(1_700_000_030).unwrap();

        let s1 = vec![proc_entry(500, "claude.exe", None, None)];
        let s2 = vec![proc_entry(500, "claude.exe", None, None)];
        let s3 = vec![proc_entry(500, "codex.exe", None, None)];

        let source = ScriptedProcessSource::new(vec![
            Ok(s1),
            Ok(s2),
            Ok(s3),
            Err(CodedError::new(
                CODE_WIN_SNAPSHOT_UNAVAILABLE,
                "snapshot command unavailable",
                "retry",
            )),
        ]);
        let mut tracker = WindowsDiscoveryTracker::new(source);
        assert_eq!(
            tracker.observer_state(),
            &DiscoveryObserverState::Uninitialized
        );

        let e1 = tracker.poll_delta(t1).unwrap();
        assert_eq!(e1.len(), 1);
        assert!(matches!(e1[0], WindowsDiscoveryEvent::AgentStarted { .. }));
        assert!(matches!(
            tracker.observer_state(),
            DiscoveryObserverState::Active {
                active_agent_count: 1,
                ..
            }
        ));

        let e2 = tracker.poll_delta(t2).unwrap();
        assert!(e2.is_empty());

        let e3 = tracker.poll_delta(t3).unwrap();
        assert_eq!(e3.len(), 2);
        assert!(e3.iter().any(|e| matches!(
            e,
            WindowsDiscoveryEvent::AgentStarted { agent, .. } if agent.agent_kind == "codex"
        )));
        assert!(e3.iter().any(|e| matches!(
            e,
            WindowsDiscoveryEvent::AgentExited { agent_kind, .. } if agent_kind == "claude-code"
        )));

        let discovered = tracker.to_discovered_agents(InstallProfile::Protected);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].assurance.visibility, Visibility::Observed);

        let err = tracker.poll_delta(t4).unwrap_err();
        assert_eq!(err.code, CODE_WIN_SNAPSHOT_UNAVAILABLE);
        assert!(matches!(
            tracker.observer_state(),
            DiscoveryObserverState::Degraded { .. }
        ));
    }
}
