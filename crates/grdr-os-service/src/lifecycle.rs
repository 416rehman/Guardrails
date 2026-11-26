// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ServiceError;

pub const SD_NOTIFY_DEFAULT_PID_BASE: u32 = 3;
pub const MAX_SYSTEMD_LISTEN_FDS: u32 = 64;

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
            ServiceManagerBackend::WindowsScm => {
                let (scm_state, code) = match state {
                    ServiceManagerState::Starting { .. } => {
                        (crate::win_scm::ScmState::StartPending, 0)
                    }
                    ServiceManagerState::Ready | ServiceManagerState::Reloading => {
                        (crate::win_scm::ScmState::Running, 0)
                    }
                    ServiceManagerState::Degraded { .. } => (crate::win_scm::ScmState::Running, 0),
                    ServiceManagerState::Stopping { .. } => {
                        (crate::win_scm::ScmState::StopPending, 0)
                    }
                    ServiceManagerState::Stopped { exit_code } => {
                        (crate::win_scm::ScmState::Stopped, *exit_code)
                    }
                };
                crate::win_scm::report_scm_state(scm_state, code)
            }
            ServiceManagerBackend::Launchd | ServiceManagerBackend::Foreground => Ok(()),
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
            let safe_reason: String = reason.chars().filter(|c| !c.is_control()).collect();
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
    if count > MAX_SYSTEMD_LISTEN_FDS {
        return Err(ServiceError::InvalidActivation(format!(
            "LISTEN_FDS {count} exceeds maximum {MAX_SYSTEMD_LISTEN_FDS}"
        )));
    }
    let expected = cfg.expected_pid.filter(|p| *p != 0).ok_or_else(|| {
        ServiceError::InvalidActivation("non-zero expected_pid required when LISTEN_FDS > 0".into())
    })?;
    let raw_pid = cfg.listen_pid_raw.as_deref().ok_or_else(|| {
        ServiceError::InvalidActivation("LISTEN_PID is required when LISTEN_FDS > 0".into())
    })?;
    let listen_pid: u32 = raw_pid
        .trim()
        .parse()
        .map_err(|e| ServiceError::InvalidActivation(format!("invalid LISTEN_PID: {e}")))?;
    if listen_pid == 0 || listen_pid != expected {
        return Err(ServiceError::InvalidActivation(format!(
            "LISTEN_PID {listen_pid} invalid or does not match expected pid {expected}"
        )));
    }

    let raw_names = cfg.listen_fdnames_raw.as_deref().ok_or_else(|| {
        ServiceError::InvalidActivation("LISTEN_FDNAMES is required when LISTEN_FDS > 0".into())
    })?;
    let names: Vec<&str> = raw_names.split(':').collect();
    let count_usize = usize::try_from(count)
        .map_err(|_| ServiceError::InvalidActivation("LISTEN_FDS count overflow".into()))?;
    if names.len() != count_usize || names.iter().any(|n| n.trim().is_empty()) {
        return Err(ServiceError::InvalidActivation(format!(
            "LISTEN_FDNAMES count mismatch or empty entry for LISTEN_FDS={count}"
        )));
    }

    let mut adopted = Vec::with_capacity(count_usize);
    for (idx, name) in names.into_iter().enumerate() {
        let idx_u32 = u32::try_from(idx)
            .map_err(|_| ServiceError::InvalidActivation("LISTEN_FDS index overflow".into()))?;
        let fd_num = SD_NOTIFY_DEFAULT_PID_BASE.saturating_add(idx_u32);
        let fd_i32 = i32::try_from(fd_num)
            .map_err(|_| ServiceError::InvalidActivation("LISTEN_FDS fd overflow".into()))?;
        adopted.push(AdoptedListener {
            endpoint_name: name.trim().to_string(),
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

#[cfg(unix)]
pub(crate) fn send_systemd_notify_to_socket(
    raw_sock: &str,
    payload: &str,
) -> Result<(), ServiceError> {
    use std::os::unix::net::UnixDatagram;

    if raw_sock.is_empty() {
        return Ok(());
    }
    if raw_sock.contains('\0') {
        return Err(ServiceError::NotifyFailed(
            "NOTIFY_SOCKET contains NUL byte".into(),
        ));
    }
    let sock = UnixDatagram::unbound()
        .map_err(|e| ServiceError::NotifyFailed(format!("unbound unix datagram failed: {e}")))?;
    if let Some(abstract_name) = raw_sock.strip_prefix('@') {
        if abstract_name.is_empty() {
            return Err(ServiceError::NotifyFailed(
                "empty abstract NOTIFY_SOCKET".into(),
            ));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())
                .map_err(|e| ServiceError::NotifyFailed(format!("invalid abstract socket: {e}")))?;
            sock.send_to_addr(payload.as_bytes(), &addr)
                .map_err(|e| ServiceError::NotifyFailed(format!("sd_notify send failed: {e}")))?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err(ServiceError::NotifyFailed(
                "abstract NOTIFY_SOCKET is only supported on Linux".into(),
            ));
        }
    }
    if !raw_sock.starts_with('/') {
        return Err(ServiceError::NotifyFailed(
            "NOTIFY_SOCKET must be absolute or `@` abstract".into(),
        ));
    }
    sock.send_to(payload.as_bytes(), raw_sock)
        .map_err(|e| ServiceError::NotifyFailed(format!("sd_notify send failed: {e}")))?;
    Ok(())
}

#[cfg(unix)]
fn send_systemd_notify_from_env(payload: &str) -> Result<(), ServiceError> {
    let Some(sock_os) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let sock_str = sock_os
        .to_str()
        .ok_or_else(|| ServiceError::NotifyFailed("NOTIFY_SOCKET is not valid UTF-8".into()))?;
    send_systemd_notify_to_socket(sock_str, payload)
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
    fn parses_systemd_listen_fds_and_rejects_missing_pid_or_overflow() {
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

        let missing_pid = ServiceActivationConfig {
            listen_pid_raw: None,
            ..cfg.clone()
        };
        assert!(matches!(
            parse_systemd_listen_fds(&missing_pid),
            Err(ServiceError::InvalidActivation(_))
        ));

        let dos_count = ServiceActivationConfig {
            listen_fds_raw: Some("4294967295".into()),
            ..cfg.clone()
        };
        assert!(matches!(
            parse_systemd_listen_fds(&dos_count),
            Err(ServiceError::InvalidActivation(_))
        ));

        let missing_expected_pid = ServiceActivationConfig {
            expected_pid: None,
            ..cfg.clone()
        };
        assert!(matches!(
            parse_systemd_listen_fds(&missing_expected_pid),
            Err(ServiceError::InvalidActivation(_))
        ));

        let zero_pid = ServiceActivationConfig {
            expected_pid: Some(0),
            listen_pid_raw: Some("0".into()),
            ..cfg.clone()
        };
        assert!(matches!(
            parse_systemd_listen_fds(&zero_pid),
            Err(ServiceError::InvalidActivation(_))
        ));

        let missing_names = ServiceActivationConfig {
            listen_fdnames_raw: None,
            ..cfg
        };
        assert!(matches!(
            parse_systemd_listen_fds(&missing_names),
            Err(ServiceError::InvalidActivation(_))
        ));

        let notify = format_sd_notify_payload(&ServiceManagerState::Ready);
        assert!(notify.contains("READY=1"));
        let degraded = format_sd_notify_payload(&ServiceManagerState::Degraded {
            reason: "bad\0reason\nREADY=1".into(),
        });
        assert!(!degraded.contains('\0'));
        assert!(!degraded.contains("bad\0"));
        assert!(!degraded.contains("reason\nREADY=1"));
        #[cfg(unix)]
        {
            assert!(matches!(
                send_systemd_notify_to_socket("relative.sock", "READY=1\n"),
                Err(ServiceError::NotifyFailed(_))
            ));
            assert!(matches!(
                send_systemd_notify_to_socket("@", "READY=1\n"),
                Err(ServiceError::NotifyFailed(_))
            ));
            assert!(matches!(
                send_systemd_notify_to_socket("/tmp/\0evil", "READY=1\n"),
                Err(ServiceError::NotifyFailed(_))
            ));
        }
    }
}
