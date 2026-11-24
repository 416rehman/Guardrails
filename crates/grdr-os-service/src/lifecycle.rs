// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ServiceError;

pub const PIPE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
pub const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
pub const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
pub const SD_NOTIFY_DEFAULT_PID_BASE: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum ServiceManagerState {
    Starting { wait_hint_ms: u32 },
    Ready,
    Reloading,
    Degraded { reason: String },
    Stopping { wait_hint_ms: u32 },
    Stopped { exit_code: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceManagerBackend {
    WindowsScm,
    Systemd,
    Launchd,
    Foreground,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsScmServiceState {
    StartPending,
    Running,
    StopPending,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerTransportKind {
    UnixSocket,
    WindowsNamedPipe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdoptedListener {
    pub endpoint_name: String,
    pub transport: ListenerTransportKind,
    pub descriptor_id: Option<i32>,
    pub path_or_pipe: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceActivationConfig {
    pub expected_pid: Option<u32>,
    pub listen_fds_raw: Option<String>,
    pub listen_pid_raw: Option<String>,
    pub listen_fdnames_raw: Option<String>,
    pub launchd_socket_names: Vec<String>,
    pub notify_socket: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedPipeAccessRight {
    FileReadData,
    FileWriteData,
    FileReadAttributes,
    ReadControl,
    Synchronize,
    FileCreatePipeInstance,
    FileGenericWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipeSecurityProfile {
    ProtectedService { service_sid: String },
    UserSession { user_sid: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedPipeDaclSpec {
    pub pipe_name: String,
    pub owner_sid: String,
    pub open_mode_flags: u32,
    pub pipe_mode_flags: u32,
    pub client_rights: Vec<NamedPipeAccessRight>,
    pub sddl: String,
}

pub trait ServiceAdapter: Send + Sync {
    fn backend_kind(&self) -> ServiceManagerBackend;
    fn report_state(&self, state: &ServiceManagerState) -> Result<(), ServiceError>;
    fn adopt_listeners(
        &self,
        cfg: &ServiceActivationConfig,
    ) -> Result<Vec<AdoptedListener>, ServiceError>;
}

#[derive(Debug, Clone)]
pub struct SystemServiceAdapter {
    backend: ServiceManagerBackend,
}

impl ServiceManagerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Starting { .. } => "starting",
            Self::Ready => "ready",
            Self::Reloading => "reloading",
            Self::Degraded { .. } => "degraded",
            Self::Stopping { .. } => "stopping",
            Self::Stopped { .. } => "stopped",
        }
    }

    pub fn transition_to(self, next: Self) -> Result<Self, ServiceError> {
        let valid = matches!(
            (&self, &next),
            (
                Self::Starting { .. },
                Self::Ready | Self::Degraded { .. } | Self::Stopping { .. } | Self::Stopped { .. }
            ) | (
                Self::Ready,
                Self::Reloading | Self::Degraded { .. } | Self::Stopping { .. }
            ) | (
                Self::Reloading,
                Self::Ready | Self::Degraded { .. } | Self::Stopping { .. }
            ) | (
                Self::Degraded { .. },
                Self::Ready | Self::Reloading | Self::Stopping { .. }
            ) | (Self::Stopping { .. }, Self::Stopped { .. })
        );
        if !valid {
            return Err(ServiceError::InvalidTransition {
                from: self.as_str().into(),
                to: next.as_str().into(),
            });
        }
        Ok(next)
    }

    pub fn to_windows_scm(&self) -> WindowsScmServiceState {
        match self {
            Self::Starting { .. } | Self::Reloading => WindowsScmServiceState::StartPending,
            Self::Ready | Self::Degraded { .. } => WindowsScmServiceState::Running,
            Self::Stopping { .. } => WindowsScmServiceState::StopPending,
            Self::Stopped { .. } => WindowsScmServiceState::Stopped,
        }
    }
}

impl NamedPipeAccessRight {
    pub const fn sddl_code(self) -> &'static str {
        match self {
            Self::FileReadData => "FR",
            Self::FileWriteData => "FW",
            Self::FileReadAttributes => "FA",
            Self::ReadControl => "RC",
            Self::Synchronize => "SY",
            Self::FileCreatePipeInstance => "FC",
            Self::FileGenericWrite => "GW",
        }
    }

    pub const fn is_forbidden_for_clients(self) -> bool {
        matches!(self, Self::FileCreatePipeInstance | Self::FileGenericWrite)
    }
}

impl Default for SystemServiceAdapter {
    fn default() -> Self {
        Self::detect()
    }
}

impl SystemServiceAdapter {
    pub fn detect() -> Self {
        let backend = if cfg!(target_os = "windows") {
            ServiceManagerBackend::WindowsScm
        } else if cfg!(target_os = "macos") {
            ServiceManagerBackend::Launchd
        } else if cfg!(target_os = "linux") {
            if std::env::var_os("NOTIFY_SOCKET").is_some()
                || std::env::var_os("LISTEN_FDS").is_some()
            {
                ServiceManagerBackend::Systemd
            } else {
                ServiceManagerBackend::Foreground
            }
        } else {
            ServiceManagerBackend::Foreground
        };
        Self { backend }
    }

    pub fn with_backend(backend: ServiceManagerBackend) -> Self {
        Self { backend }
    }
}

impl ServiceAdapter for SystemServiceAdapter {
    fn backend_kind(&self) -> ServiceManagerBackend {
        self.backend
    }

    fn report_state(&self, state: &ServiceManagerState) -> Result<(), ServiceError> {
        match self.backend {
            ServiceManagerBackend::Systemd => {
                let payload = format_sd_notify_payload(state);
                send_systemd_notify_from_env(&payload)
            }
            ServiceManagerBackend::WindowsScm
            | ServiceManagerBackend::Launchd
            | ServiceManagerBackend::Foreground => Ok(()),
        }
    }

    fn adopt_listeners(
        &self,
        cfg: &ServiceActivationConfig,
    ) -> Result<Vec<AdoptedListener>, ServiceError> {
        match self.backend {
            ServiceManagerBackend::Systemd => parse_systemd_listen_fds(cfg),
            ServiceManagerBackend::Launchd => Ok(plan_launchd_listeners(&cfg.launchd_socket_names)),
            ServiceManagerBackend::WindowsScm | ServiceManagerBackend::Foreground => Ok(Vec::new()),
        }
    }
}

pub fn format_sd_notify_payload(state: &ServiceManagerState) -> String {
    match state {
        ServiceManagerState::Starting { .. } => "STATUS=Starting\n".into(),
        ServiceManagerState::Ready => "READY=1\nSTATUS=Ready\n".into(),
        ServiceManagerState::Reloading => "RELOADING=1\nSTATUS=Reloading\n".into(),
        ServiceManagerState::Degraded { reason } => {
            let safe_reason: String = reason
                .chars()
                .filter(|c| *c != '\n' && *c != '\r')
                .collect();
            format!("READY=1\nSTATUS=Degraded: {safe_reason}\n")
        }
        ServiceManagerState::Stopping { .. } => "STOPPING=1\nSTATUS=Stopping\n".into(),
        ServiceManagerState::Stopped { exit_code } => {
            format!("STOPPING=1\nSTATUS=Stopped ({exit_code})\n")
        }
    }
}

pub fn parse_systemd_listen_fds(
    cfg: &ServiceActivationConfig,
) -> Result<Vec<AdoptedListener>, ServiceError> {
    let Some(raw_fds) = cfg.listen_fds_raw.as_deref() else {
        return Ok(Vec::new());
    };
    let count: u32 = raw_fds
        .trim()
        .parse()
        .map_err(|e| ServiceError::InvalidActivation(format!("invalid LISTEN_FDS: {e}")))?;
    if count == 0 {
        return Ok(Vec::new());
    }
    if let (Some(expected), Some(raw_pid)) = (cfg.expected_pid, cfg.listen_pid_raw.as_deref()) {
        let listen_pid: u32 = raw_pid
            .trim()
            .parse()
            .map_err(|e| ServiceError::InvalidActivation(format!("invalid LISTEN_PID: {e}")))?;
        if listen_pid != expected {
            return Err(ServiceError::InvalidActivation(format!(
                "LISTEN_PID {listen_pid} does not match process pid {expected}"
            )));
        }
    }

    let names: Vec<&str> = cfg
        .listen_fdnames_raw
        .as_deref()
        .map(|s| s.split(':').collect())
        .unwrap_or_default();

    let mut adopted = Vec::new();
    for idx in 0..count {
        let fd_num = SD_NOTIFY_DEFAULT_PID_BASE.saturating_add(idx);
        let fd_i32 = i32::try_from(fd_num)
            .map_err(|_| ServiceError::InvalidActivation("LISTEN_FDS overflow".into()))?;
        let name = names
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
            .copied()
            .filter(|n| !n.is_empty())
            .unwrap_or("decide");
        adopted.push(AdoptedListener {
            endpoint_name: name.to_string(),
            transport: ListenerTransportKind::UnixSocket,
            descriptor_id: Some(fd_i32),
            path_or_pipe: format!("fd://{fd_i32}"),
        });
    }
    Ok(adopted)
}

pub fn plan_launchd_listeners(socket_names: &[String]) -> Vec<AdoptedListener> {
    let mut out = Vec::new();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for name in socket_names {
        let trimmed = name.trim();
        if trimmed.is_empty() || seen.contains_key(trimmed) {
            continue;
        }
        seen.insert(trimmed, 1);
        out.push(AdoptedListener {
            endpoint_name: trimmed.to_string(),
            transport: ListenerTransportKind::UnixSocket,
            descriptor_id: None,
            path_or_pipe: format!("launchd://{trimmed}"),
        });
    }
    out
}

pub fn build_named_pipe_dacl(
    pipe_name: &str,
    profile: &PipeSecurityProfile,
    requested_client_rights: &[NamedPipeAccessRight],
) -> Result<NamedPipeDaclSpec, ServiceError> {
    if !pipe_name.starts_with(r"\\.\pipe\") || pipe_name.len() <= 9 {
        return Err(ServiceError::DaclViolation(format!(
            "invalid Windows named pipe path `{pipe_name}`"
        )));
    }
    for right in requested_client_rights {
        if right.is_forbidden_for_clients() {
            return Err(ServiceError::DaclViolation(format!(
                "client right {:?} is forbidden on endpoint pipes (RFC 0003)",
                right
            )));
        }
    }

    let rights = if requested_client_rights.is_empty() {
        vec![
            NamedPipeAccessRight::FileReadData,
            NamedPipeAccessRight::FileWriteData,
            NamedPipeAccessRight::FileReadAttributes,
            NamedPipeAccessRight::ReadControl,
            NamedPipeAccessRight::Synchronize,
        ]
    } else {
        requested_client_rights.to_vec()
    };

    let owner_sid = match profile {
        PipeSecurityProfile::ProtectedService { service_sid } => service_sid.trim(),
        PipeSecurityProfile::UserSession { user_sid } => user_sid.trim(),
    };
    if owner_sid.is_empty() {
        return Err(ServiceError::DaclViolation(
            "pipe owner SID cannot be empty".into(),
        ));
    }

    let client_ace_target = match profile {
        PipeSecurityProfile::ProtectedService { .. } => "AU",
        PipeSecurityProfile::UserSession { user_sid } => user_sid.trim(),
    };
    let sddl = format!(
        "O:{owner_sid}D:P(A;;GA;;;SY)(A;;GA;;;{owner_sid})(A;;0x00120083;;;{client_ace_target})"
    );

    Ok(NamedPipeDaclSpec {
        pipe_name: pipe_name.to_string(),
        owner_sid: owner_sid.to_string(),
        open_mode_flags: PIPE_ACCESS_DUPLEX | PIPE_FLAG_FIRST_PIPE_INSTANCE,
        pipe_mode_flags: PIPE_REJECT_REMOTE_CLIENTS,
        client_rights: rights,
        sddl,
    })
}

#[cfg(unix)]
fn send_systemd_notify_from_env(payload: &str) -> Result<(), ServiceError> {
    use std::os::unix::net::UnixDatagram;

    let Some(sock_path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    if sock_path.is_empty() {
        return Ok(());
    }
    let sock = UnixDatagram::unbound()
        .map_err(|e| ServiceError::NotifyFailed(format!("unbound unix datagram failed: {e}")))?;
    sock.send_to(payload.as_bytes(), sock_path)
        .map_err(|e| ServiceError::NotifyFailed(format!("sd_notify send failed: {e}")))?;
    Ok(())
}

#[cfg(not(unix))]
fn send_systemd_notify_from_env(_payload: &str) -> Result<(), ServiceError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_service_lifecycle_state_transitions_and_scm_mapping() {
        let s0 = ServiceManagerState::Starting { wait_hint_ms: 1000 };
        assert_eq!(s0.to_windows_scm(), WindowsScmServiceState::StartPending);

        let s1 = s0.transition_to(ServiceManagerState::Ready).unwrap();
        assert_eq!(s1.to_windows_scm(), WindowsScmServiceState::Running);

        let s2 = s1
            .transition_to(ServiceManagerState::Degraded {
                reason: "engine-overload".into(),
            })
            .unwrap();
        assert_eq!(s2.to_windows_scm(), WindowsScmServiceState::Running);

        let s3 = s2
            .transition_to(ServiceManagerState::Stopping { wait_hint_ms: 500 })
            .unwrap();
        assert_eq!(s3.to_windows_scm(), WindowsScmServiceState::StopPending);

        assert!(
            s3.clone()
                .transition_to(ServiceManagerState::Ready)
                .is_err()
        );
        let s4 = s3
            .transition_to(ServiceManagerState::Stopped { exit_code: 0 })
            .unwrap();
        assert_eq!(s4.to_windows_scm(), WindowsScmServiceState::Stopped);
    }

    #[test]
    fn parses_systemd_listen_fds_and_builds_sd_notify_payload() {
        let cfg = ServiceActivationConfig {
            expected_pid: Some(4242),
            listen_fds_raw: Some("2".into()),
            listen_pid_raw: Some("4242".into()),
            listen_fdnames_raw: Some("decide:local".into()),
            launchd_socket_names: vec![],
            notify_socket: None,
        };
        let listeners = parse_systemd_listen_fds(&cfg).unwrap();
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].endpoint_name, "decide");
        assert_eq!(listeners[0].descriptor_id, Some(3));
        assert_eq!(listeners[1].endpoint_name, "local");
        assert_eq!(listeners[1].descriptor_id, Some(4));

        let notify = format_sd_notify_payload(&ServiceManagerState::Ready);
        assert!(notify.contains("READY=1"));
    }

    #[test]
    fn rejects_forbidden_pipe_rights_and_builds_five_right_dacl() {
        let profile = PipeSecurityProfile::ProtectedService {
            service_sid: "S-1-5-80-12345".into(),
        };
        let err = build_named_pipe_dacl(
            r"\\.\pipe\grdr-decide",
            &profile,
            &[NamedPipeAccessRight::FileGenericWrite],
        )
        .unwrap_err();
        assert!(matches!(err, ServiceError::DaclViolation(_)));

        let err2 = build_named_pipe_dacl(
            r"\\.\pipe\grdr-decide",
            &profile,
            &[NamedPipeAccessRight::FileCreatePipeInstance],
        )
        .unwrap_err();
        assert!(matches!(err2, ServiceError::DaclViolation(_)));

        let spec = build_named_pipe_dacl(r"\\.\pipe\grdr-decide", &profile, &[]).unwrap();
        assert_eq!(spec.client_rights.len(), 5);
        assert_ne!(spec.open_mode_flags & PIPE_FLAG_FIRST_PIPE_INSTANCE, 0);
        assert_ne!(spec.pipe_mode_flags & PIPE_REJECT_REMOTE_CLIENTS, 0);
        assert!(spec.sddl.contains("O:S-1-5-80-12345"));
    }
}
