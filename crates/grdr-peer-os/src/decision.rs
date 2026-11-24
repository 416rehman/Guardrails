// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    pub pid: u32,
    pub started_at_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExeIdentity {
    pub exe_path: Option<String>,
    pub signer_team_id: Option<String>,
    pub signing_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentChainNode {
    pub pid: u32,
    pub ppid: u32,
    pub exe_path: Option<String>,
    pub started_at_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixPeerCreds {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub pidfd_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsAuditToken {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub pidversion: u32,
    pub audit_session_id: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "service_state", rename_all = "snake_case")]
pub enum ServiceProcessCheck {
    Valid { pid: u32 },
    ServiceRestarting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsPipePeer {
    pub client_pid: u32,
    pub pipe_owner_sid: String,
    pub expected_service_sid: Option<String>,
    pub scm_pid_sample_1: Option<u32>,
    pub scm_pid_sample_2: Option<u32>,
    pub message_identity_sid: Option<String>,
    pub integrity_rid: Option<u32>,
    pub open_as_self_verified: bool,
    pub process_created_ns: u64,
    pub connected_at_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "os", rename_all = "snake_case")]
pub enum PeerCredentials {
    Linux(UnixPeerCreds),
    MacOs(MacOsAuditToken),
    Windows(WindowsPipePeer),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "hold", rename_all = "snake_case")]
pub enum ProcessHold {
    Atomic { key: ProcessKey },
    Confirmed { key: ProcessKey },
    Unheld,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerObservation {
    pub credentials: PeerCredentials,
    pub hold: ProcessHold,
    pub parent_pid: u32,
    pub started_at_ticks: u64,
    pub exe: Option<ExeIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAuthPolicy {
    pub expected_unix_uid: Option<u32>,
    pub expected_windows_sid: Option<String>,
    pub require_process_hold: bool,
    pub min_integrity_rid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerClass {
    RootOrSystem,
    ExpectedUser,
    ForeignPrincipal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerEvidence {
    Tamper,
    Unverifiable,
    Transient,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum PeerRefusal {
    ServerForeign { seen: OwnerClass },
    ServiceRestarting,
    UnverifiableHold,
    MissingMessageIdentity,
    PidReused,
    LowIntegrityDenied { seen_rid: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedPeer {
    pub pid: u32,
    pub principal_label: String,
    pub hold_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PeerAuthDecision {
    Accepted(VerifiedPeer),
    Refused {
        reason: PeerRefusal,
        evidence: PeerEvidence,
    },
}

impl PeerRefusal {
    pub const fn evidence(&self) -> PeerEvidence {
        match self {
            Self::ServerForeign { .. } | Self::PidReused => PeerEvidence::Tamper,
            Self::ServiceRestarting => PeerEvidence::Transient,
            Self::UnverifiableHold
            | Self::MissingMessageIdentity
            | Self::LowIntegrityDenied { .. } => PeerEvidence::Unverifiable,
        }
    }
}

impl WindowsPipePeer {
    pub fn check_service_pid(&self) -> ServiceProcessCheck {
        match (self.scm_pid_sample_1, self.scm_pid_sample_2) {
            (Some(a), Some(b)) if a != 0 && a == b => ServiceProcessCheck::Valid { pid: a },
            _ => ServiceProcessCheck::ServiceRestarting,
        }
    }
}

pub fn evaluate_peer_auth(obs: &PeerObservation, policy: &PeerAuthPolicy) -> PeerAuthDecision {
    if policy.require_process_hold && matches!(obs.hold, ProcessHold::Unheld) {
        return PeerAuthDecision::Refused {
            reason: PeerRefusal::UnverifiableHold,
            evidence: PeerRefusal::UnverifiableHold.evidence(),
        };
    }

    match &obs.credentials {
        PeerCredentials::Linux(creds) => {
            if let Some(expected_uid) = policy.expected_unix_uid
                && creds.uid != expected_uid
            {
                let reason = PeerRefusal::ServerForeign {
                    seen: classify_unix_owner(creds.uid, expected_uid),
                };
                return PeerAuthDecision::Refused {
                    evidence: reason.evidence(),
                    reason,
                };
            }
            if !creds.pidfd_verified {
                let reason = PeerRefusal::UnverifiableHold;
                return PeerAuthDecision::Refused {
                    evidence: reason.evidence(),
                    reason,
                };
            }
            PeerAuthDecision::Accepted(VerifiedPeer {
                pid: creds.pid,
                principal_label: format!("uid:{}", creds.uid),
                hold_confirmed: !matches!(obs.hold, ProcessHold::Unheld),
            })
        }
        PeerCredentials::MacOs(token) => {
            if let Some(expected_uid) = policy.expected_unix_uid
                && token.uid != expected_uid
            {
                let reason = PeerRefusal::ServerForeign {
                    seen: classify_unix_owner(token.uid, expected_uid),
                };
                return PeerAuthDecision::Refused {
                    evidence: reason.evidence(),
                    reason,
                };
            }
            PeerAuthDecision::Accepted(VerifiedPeer {
                pid: token.pid,
                principal_label: format!("uid:{}:asid:{}", token.uid, token.audit_session_id),
                hold_confirmed: !matches!(obs.hold, ProcessHold::Unheld),
            })
        }
        PeerCredentials::Windows(win) => evaluate_windows_peer(win, policy, &obs.hold),
    }
}

fn evaluate_windows_peer(
    win: &WindowsPipePeer,
    policy: &PeerAuthPolicy,
    hold: &ProcessHold,
) -> PeerAuthDecision {
    if let Some(expected_sid) = &policy.expected_windows_sid
        && win.pipe_owner_sid != *expected_sid
    {
        let reason = PeerRefusal::ServerForeign {
            seen: OwnerClass::ForeignPrincipal,
        };
        return PeerAuthDecision::Refused {
            evidence: reason.evidence(),
            reason,
        };
    }

    if win.expected_service_sid.is_some()
        && matches!(
            win.check_service_pid(),
            ServiceProcessCheck::ServiceRestarting
        )
    {
        let reason = PeerRefusal::ServiceRestarting;
        return PeerAuthDecision::Refused {
            evidence: reason.evidence(),
            reason,
        };
    }

    if win.process_created_ns > win.connected_at_ns {
        let reason = PeerRefusal::PidReused;
        return PeerAuthDecision::Refused {
            evidence: reason.evidence(),
            reason,
        };
    }

    if !win.open_as_self_verified || win.message_identity_sid.is_none() {
        let reason = PeerRefusal::MissingMessageIdentity;
        return PeerAuthDecision::Refused {
            evidence: reason.evidence(),
            reason,
        };
    }

    if let (Some(min_rid), Some(seen_rid)) = (policy.min_integrity_rid, win.integrity_rid)
        && seen_rid < min_rid
    {
        let reason = PeerRefusal::LowIntegrityDenied { seen_rid };
        return PeerAuthDecision::Refused {
            evidence: reason.evidence(),
            reason,
        };
    }

    let sid = win.message_identity_sid.as_deref().unwrap_or("unknown");
    PeerAuthDecision::Accepted(VerifiedPeer {
        pid: win.client_pid,
        principal_label: format!("sid:{sid}"),
        hold_confirmed: !matches!(hold, ProcessHold::Unheld),
    })
}

fn classify_unix_owner(seen_uid: u32, expected_uid: u32) -> OwnerClass {
    if seen_uid == 0 {
        OwnerClass::RootOrSystem
    } else if seen_uid == expected_uid {
        OwnerClass::ExpectedUser
    } else {
        OwnerClass::ForeignPrincipal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_service_restart_is_transient_while_foreign_owner_is_tamper() {
        let base = WindowsPipePeer {
            client_pid: 400,
            pipe_owner_sid: "S-1-5-80-1".into(),
            expected_service_sid: Some("S-1-5-80-1".into()),
            scm_pid_sample_1: Some(500),
            scm_pid_sample_2: Some(501),
            message_identity_sid: Some("S-1-5-21-9".into()),
            integrity_rid: Some(0x2000),
            open_as_self_verified: true,
            process_created_ns: 100,
            connected_at_ns: 200,
        };
        let policy = PeerAuthPolicy {
            expected_unix_uid: None,
            expected_windows_sid: Some("S-1-5-80-1".into()),
            require_process_hold: true,
            min_integrity_rid: Some(0x2000),
        };
        let obs = PeerObservation {
            credentials: PeerCredentials::Windows(base.clone()),
            hold: ProcessHold::Confirmed {
                key: ProcessKey {
                    pid: 400,
                    started_at_ticks: 100,
                },
            },
            parent_pid: 100,
            started_at_ticks: 100,
            exe: None,
        };
        assert_eq!(
            evaluate_peer_auth(&obs, &policy),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::ServiceRestarting,
                evidence: PeerEvidence::Transient,
            }
        );

        let mut stable = base.clone();
        stable.scm_pid_sample_2 = Some(500);
        stable.process_created_ns = 300;
        let obs_reuse = PeerObservation {
            credentials: PeerCredentials::Windows(stable),
            ..obs.clone()
        };
        assert_eq!(
            evaluate_peer_auth(&obs_reuse, &policy),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::PidReused,
                evidence: PeerEvidence::Tamper,
            }
        );

        let mut foreign = base;
        foreign.pipe_owner_sid = "S-1-5-21-attacker".into();
        let obs_foreign = PeerObservation {
            credentials: PeerCredentials::Windows(foreign),
            ..obs
        };
        assert!(matches!(
            evaluate_peer_auth(&obs_foreign, &policy),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::ServerForeign { .. },
                evidence: PeerEvidence::Tamper,
            }
        ));
    }
}
