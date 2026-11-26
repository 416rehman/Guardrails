// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Endpoint peer claim, policy, verified identity, and P8-redacted refusal types
//! (`docs/decisions/ADR-0051`, `docs/design/11`).

use std::fmt;

use crate::messages::EndpointServiceKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Protected,
    User,
    Inherited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalCategory {
    Tamper,
    Configuration,
    Coverage,
    Transient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScmServiceState {
    Unknown,
    Running,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnixPeerClaims {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<u32>,
    pub has_pidfd: bool,
    pub peer_started_at_ticks: Option<u64>,
    pub local_peertoken_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsPeerClaims {
    pub pid: u32,
    pub peer_sid: String,
    pub integrity_rid: u32,
    pub is_app_container: bool,
    pub thread_token_open_as_self: bool,
    pub peer_started_at_100ns: Option<u64>,
    pub server_pid_from_pipe: Option<u32>,
    pub pipe_owner_sid: Option<String>,
    pub scm_pre_pids: Vec<u32>,
    pub scm_post_pids: Vec<u32>,
    pub scm_state: ScmServiceState,
    pub scm_expected_sid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OsPeerClaims {
    Unix(UnixPeerClaims),
    Windows(WindowsPeerClaims),
    Inherited,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPeer {
    profile: Profile,
    uid: Option<u32>,
    gid: Option<u32>,
    pid: Option<u32>,
    windows_sid: Option<String>,
    integrity_rid: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentityPolicy {
    pub profile: Profile,
    pub allowed_server_uids: Vec<u32>,
    pub expected_windows_sids: Vec<String>,
    pub minimum_integrity_rid: u32,
    pub require_start_time_before_connect: bool,
    pub require_kernel_peer_token: bool,
}

// grdr:allow-s4 independent orthogonal peer-enforcement flags across OS mechanisms
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerIdentityPolicy {
    pub profile: Profile,
    pub allowed_client_uids: Vec<u32>,
    pub allowed_windows_sids: Vec<String>,
    pub minimum_integrity_rid: u32,
    pub reject_app_container: bool,
    pub require_start_time_before_connect: bool,
    pub require_open_as_self_pipe_check: bool,
    pub require_kernel_peer_token: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    PathUnsafe {
        path: String,
        detail: String,
    },
    UidMismatch {
        expected_uids: Vec<u32>,
        actual_uid: u32,
    },
    StartTimeSkew {
        started_ticks: u64,
        connected_at_ticks: u64,
    },
    StartTimeMissing,
    WindowsSidMismatch {
        expected: Vec<String>,
        actual: String,
    },
    WindowsIntegrityTooLow {
        actual_rid: u32,
        minimum_rid: u32,
    },
    WindowsServerPidMismatch {
        actual_pid: Option<u32>,
        expected_scm_pids: Vec<u32>,
    },
    WindowsAppContainerDisallowed,
    MissingPeerToken {
        detail: String,
    },
    ProtocolVersionMismatch {
        expected: u32,
        found: u32,
    },
    ChannelMismatch {
        expected: EndpointServiceKind,
        found: i32,
    },
    FrameError {
        detail: String,
    },
    ProfileRejected {
        profile: Profile,
        detail: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    UnsafeEndpointPath(Evidence),
    ForeignPeerUid(Evidence),
    PidReuseSuspected(Evidence),
    UnauthenticatedPeer(Evidence),
    UntrustedServerIdentity(Evidence),
    PrivilegeTooLow(Evidence),
    ProtocolRejected(Evidence),
    PolicyProfileMismatch(Evidence),
    TransientServerRestart(Evidence),
}

impl VerifiedPeer {
    #[must_use]
    pub(crate) const fn inherited() -> Self {
        Self {
            profile: Profile::Inherited,
            uid: None,
            gid: None,
            pid: None,
            windows_sid: None,
            integrity_rid: None,
        }
    }

    #[must_use]
    pub(crate) const fn unix(profile: Profile, uid: u32, gid: u32, pid: Option<u32>) -> Self {
        Self {
            profile,
            uid: Some(uid),
            gid: Some(gid),
            pid,
            windows_sid: None,
            integrity_rid: None,
        }
    }

    #[must_use]
    pub(crate) fn windows(profile: Profile, win: &WindowsPeerClaims) -> Self {
        Self {
            profile,
            uid: None,
            gid: None,
            pid: Some(win.pid),
            windows_sid: Some(win.peer_sid.clone()),
            integrity_rid: Some(win.integrity_rid),
        }
    }

    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    #[must_use]
    pub const fn uid(&self) -> Option<u32> {
        self.uid
    }

    #[must_use]
    pub const fn gid(&self) -> Option<u32> {
        self.gid
    }

    #[must_use]
    pub const fn pid(&self) -> Option<u32> {
        self.pid
    }

    #[must_use]
    pub fn windows_sid(&self) -> Option<&str> {
        self.windows_sid.as_deref()
    }

    #[must_use]
    pub const fn integrity_rid(&self) -> Option<u32> {
        self.integrity_rid
    }
}

impl Refusal {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsafeEndpointPath(_) => "GRDR-WIRE-0018",
            Self::ForeignPeerUid(_) => "GRDR-WIRE-0019",
            Self::PidReuseSuspected(_) => "GRDR-WIRE-0020",
            Self::UnauthenticatedPeer(_) => "GRDR-WIRE-0021",
            Self::UntrustedServerIdentity(_) => "GRDR-WIRE-0022",
            Self::PrivilegeTooLow(_) => "GRDR-WIRE-0023",
            Self::ProtocolRejected(_) => "GRDR-WIRE-0024",
            Self::PolicyProfileMismatch(_) => "GRDR-WIRE-0025",
            Self::TransientServerRestart(_) => "GRDR-WIRE-0035",
        }
    }

    #[must_use]
    pub const fn category(&self) -> RefusalCategory {
        match self {
            Self::UnsafeEndpointPath(_)
            | Self::ForeignPeerUid(_)
            | Self::UnauthenticatedPeer(_)
            | Self::UntrustedServerIdentity(_)
            | Self::PrivilegeTooLow(_)
            | Self::ProtocolRejected(_) => RefusalCategory::Tamper,
            Self::PolicyProfileMismatch(_) => RefusalCategory::Configuration,
            Self::PidReuseSuspected(_) => match self.evidence() {
                Evidence::StartTimeMissing => RefusalCategory::Coverage,
                _ => RefusalCategory::Tamper,
            },
            Self::TransientServerRestart(_) => RefusalCategory::Transient,
        }
    }

    #[must_use]
    pub const fn evidence(&self) -> &Evidence {
        match self {
            Self::UnsafeEndpointPath(ev)
            | Self::ForeignPeerUid(ev)
            | Self::PidReuseSuspected(ev)
            | Self::UnauthenticatedPeer(ev)
            | Self::UntrustedServerIdentity(ev)
            | Self::PrivilegeTooLow(ev)
            | Self::ProtocolRejected(ev)
            | Self::PolicyProfileMismatch(ev)
            | Self::TransientServerRestart(ev) => ev,
        }
    }

    #[must_use]
    pub const fn redacted_summary(&self) -> &'static str {
        match self.evidence() {
            Evidence::PathUnsafe { .. } => "endpoint path validation failed",
            Evidence::UidMismatch { .. } => "peer uid rejected by policy",
            Evidence::StartTimeSkew { .. } => "peer start time newer than connection",
            Evidence::StartTimeMissing => "peer process start time unavailable",
            Evidence::WindowsSidMismatch { .. } => "windows peer SID rejected by policy",
            Evidence::WindowsIntegrityTooLow { .. } => "windows integrity level below minimum",
            Evidence::WindowsServerPidMismatch { .. } => "windows pipe PID disagrees with SCM",
            Evidence::WindowsAppContainerDisallowed => "AppContainer client rejected by policy",
            Evidence::MissingPeerToken { .. } => "kernel peer token proof unavailable",
            Evidence::ProtocolVersionMismatch { .. } => "wire protocol version mismatch",
            Evidence::ChannelMismatch { .. } => "endpoint service mismatch",
            Evidence::FrameError { .. } => "wire frame decode or framing failure",
            Evidence::ProfileRejected { .. } => "endpoint profile policy mismatch",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.redacted_summary())
    }
}

impl std::error::Error for Refusal {}
