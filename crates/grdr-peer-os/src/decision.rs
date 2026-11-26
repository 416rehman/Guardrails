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
    pub pipe_server_pid: Option<u32>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalPolicy {
    #[default]
    StrictExpected,
    AllowAnyLocalPrincipal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAuthPolicy {
    pub expected_unix_uid: Option<u32>,
    pub expected_windows_sid: Option<String>,
    pub require_process_hold: bool,
    pub min_integrity_rid: Option<u32>,
    #[serde(default)]
    pub principal_policy: PrincipalPolicy,
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

impl ProcessHold {
    pub const fn held_pid(&self) -> Option<u32> {
        match self {
            Self::Atomic { key } | Self::Confirmed { key } => Some(key.pid),
            Self::Unheld => None,
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
    let cred_pid = match &obs.credentials {
        PeerCredentials::Linux(c) => c.pid,
        PeerCredentials::MacOs(t) => t.pid,
        PeerCredentials::Windows(w) => w.client_pid,
    };

    if cred_pid == 0 {
        return refuse(PeerRefusal::UnverifiableHold);
    }

    if let Some(held_pid) = obs.hold.held_pid() {
        if held_pid != cred_pid {
            return refuse(PeerRefusal::UnverifiableHold);
        }
    } else if policy.require_process_hold {
        return refuse(PeerRefusal::UnverifiableHold);
    }

    match &obs.credentials {
        PeerCredentials::Linux(creds) => {
            if let Some(expected_uid) = policy.expected_unix_uid {
                if creds.uid != expected_uid {
                    return refuse(PeerRefusal::ServerForeign {
                        seen: classify_unix_owner(creds.uid, expected_uid),
                    });
                }
            } else if policy.principal_policy != PrincipalPolicy::AllowAnyLocalPrincipal {
                return refuse(PeerRefusal::ServerForeign {
                    seen: OwnerClass::ForeignPrincipal,
                });
            }
            if !creds.pidfd_verified {
                return refuse(PeerRefusal::UnverifiableHold);
            }
            PeerAuthDecision::Accepted(VerifiedPeer {
                pid: creds.pid,
                principal_label: format!("uid:{}", creds.uid),
                hold_confirmed: !matches!(obs.hold, ProcessHold::Unheld),
            })
        }
        PeerCredentials::MacOs(token) => {
            if let Some(expected_uid) = policy.expected_unix_uid {
                if token.uid != expected_uid {
                    return refuse(PeerRefusal::ServerForeign {
                        seen: classify_unix_owner(token.uid, expected_uid),
                    });
                }
            } else if policy.principal_policy != PrincipalPolicy::AllowAnyLocalPrincipal {
                return refuse(PeerRefusal::ServerForeign {
                    seen: OwnerClass::ForeignPrincipal,
                });
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
    let Ok(owner_sid) = crate::scm_probe::validate_windows_sid(&win.pipe_owner_sid) else {
        return refuse(PeerRefusal::ServerForeign {
            seen: OwnerClass::ForeignPrincipal,
        });
    };

    if policy.expected_windows_sid.is_none()
        && win.expected_service_sid.is_none()
        && policy.principal_policy != PrincipalPolicy::AllowAnyLocalPrincipal
    {
        return refuse(PeerRefusal::ServerForeign {
            seen: OwnerClass::ForeignPrincipal,
        });
    }

    if let Some(expected_sid) = &policy.expected_windows_sid {
        let Ok(clean_expected) = crate::scm_probe::validate_windows_sid(expected_sid) else {
            return refuse(PeerRefusal::UnverifiableHold);
        };
        if owner_sid != clean_expected {
            return refuse(PeerRefusal::ServerForeign {
                seen: OwnerClass::ForeignPrincipal,
            });
        }
    }

    if let Some(expected_service_sid) = &win.expected_service_sid {
        let Ok(clean_svc_sid) = crate::scm_probe::validate_windows_sid(expected_service_sid) else {
            return refuse(PeerRefusal::UnverifiableHold);
        };
        if owner_sid != clean_svc_sid {
            return refuse(PeerRefusal::ServerForeign {
                seen: OwnerClass::ForeignPrincipal,
            });
        }
        match win.check_service_pid() {
            ServiceProcessCheck::ServiceRestarting => {
                return refuse(PeerRefusal::ServiceRestarting);
            }
            ServiceProcessCheck::Valid { pid } => {
                if win.pipe_server_pid != Some(pid) {
                    return refuse(PeerRefusal::ServerForeign {
                        seen: OwnerClass::ForeignPrincipal,
                    });
                }
            }
        }
    }

    if win.process_created_ns > win.connected_at_ns {
        return refuse(PeerRefusal::PidReused);
    }

    let Some(msg_sid_raw) = win.message_identity_sid.as_deref() else {
        return refuse(PeerRefusal::MissingMessageIdentity);
    };
    let Ok(msg_sid) = crate::scm_probe::validate_windows_sid(msg_sid_raw) else {
        return refuse(PeerRefusal::MissingMessageIdentity);
    };
    if !win.open_as_self_verified {
        return refuse(PeerRefusal::MissingMessageIdentity);
    }

    if let Some(min_rid) = policy.min_integrity_rid {
        match win.integrity_rid {
            None => return refuse(PeerRefusal::UnverifiableHold),
            Some(seen_rid) if seen_rid < min_rid => {
                return refuse(PeerRefusal::LowIntegrityDenied { seen_rid });
            }
            Some(_) => {}
        }
    }

    PeerAuthDecision::Accepted(VerifiedPeer {
        pid: win.client_pid,
        principal_label: format!("sid:{msg_sid}"),
        hold_confirmed: !matches!(hold, ProcessHold::Unheld),
    })
}

fn refuse(reason: PeerRefusal) -> PeerAuthDecision {
    PeerAuthDecision::Refused {
        evidence: reason.evidence(),
        reason,
    }
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

    fn sample_windows_peer() -> WindowsPipePeer {
        WindowsPipePeer {
            client_pid: 400,
            pipe_owner_sid: "S-1-5-80-1".into(),
            expected_service_sid: Some("S-1-5-80-1".into()),
            pipe_server_pid: Some(500),
            scm_pid_sample_1: Some(500),
            scm_pid_sample_2: Some(500),
            message_identity_sid: Some("S-1-5-21-9".into()),
            integrity_rid: Some(0x2000),
            open_as_self_verified: true,
            process_created_ns: 100,
            connected_at_ns: 200,
        }
    }

    fn sample_windows_policy() -> PeerAuthPolicy {
        PeerAuthPolicy {
            expected_unix_uid: None,
            expected_windows_sid: Some("S-1-5-80-1".into()),
            require_process_hold: true,
            min_integrity_rid: Some(0x2000),
            principal_policy: PrincipalPolicy::StrictExpected,
        }
    }

    #[test]
    fn windows_service_restart_is_transient_while_foreign_owner_is_tamper() {
        let mut restarting = sample_windows_peer();
        restarting.scm_pid_sample_2 = Some(501);
        let policy = sample_windows_policy();
        let obs = PeerObservation {
            credentials: PeerCredentials::Windows(restarting),
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

        let mut reused = sample_windows_peer();
        reused.process_created_ns = 300;
        let obs_reuse = PeerObservation {
            credentials: PeerCredentials::Windows(reused),
            ..obs.clone()
        };
        assert_eq!(
            evaluate_peer_auth(&obs_reuse, &policy),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::PidReused,
                evidence: PeerEvidence::Tamper,
            }
        );

        let mut foreign = sample_windows_peer();
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

    #[test]
    fn windows_fail_closes_missing_integrity_and_server_pid_mismatch_and_hold_pid() {
        let policy = sample_windows_policy();
        let mut missing_rid = sample_windows_peer();
        missing_rid.integrity_rid = None;
        let obs_rid = PeerObservation {
            credentials: PeerCredentials::Windows(missing_rid),
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
            evaluate_peer_auth(&obs_rid, &policy),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::UnverifiableHold,
                evidence: PeerEvidence::Unverifiable,
            }
        );

        let mut mismatched_server = sample_windows_peer();
        mismatched_server.pipe_server_pid = Some(999);
        let obs_srv = PeerObservation {
            credentials: PeerCredentials::Windows(mismatched_server),
            ..obs_rid.clone()
        };
        assert!(matches!(
            evaluate_peer_auth(&obs_srv, &policy),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::ServerForeign { .. },
                evidence: PeerEvidence::Tamper,
            }
        ));

        let mut no_id = sample_windows_peer();
        no_id.open_as_self_verified = false;
        let obs_noid = PeerObservation {
            credentials: PeerCredentials::Windows(no_id),
            ..obs_rid
        };
        assert_eq!(
            evaluate_peer_auth(&obs_noid, &policy),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::MissingMessageIdentity,
                evidence: PeerEvidence::Unverifiable,
            }
        );

        let mismatched_hold = PeerObservation {
            credentials: PeerCredentials::Linux(UnixPeerCreds {
                uid: 1000,
                gid: 1000,
                pid: 400,
                pidfd_verified: true,
            }),
            hold: ProcessHold::Confirmed {
                key: ProcessKey {
                    pid: 999,
                    started_at_ticks: 1,
                },
            },
            parent_pid: 1,
            started_at_ticks: 1,
            exe: None,
        };
        assert_eq!(
            evaluate_peer_auth(
                &mismatched_hold,
                &PeerAuthPolicy {
                    expected_unix_uid: Some(1000),
                    expected_windows_sid: None,
                    require_process_hold: true,
                    min_integrity_rid: None,
                    principal_policy: PrincipalPolicy::StrictExpected,
                }
            ),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::UnverifiableHold,
                evidence: PeerEvidence::Unverifiable,
            }
        );

        let mut low_il = sample_windows_peer();
        low_il.integrity_rid = Some(0x1000);
        let obs_low_il = PeerObservation {
            credentials: PeerCredentials::Windows(low_il),
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
            evaluate_peer_auth(&obs_low_il, &policy),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::LowIntegrityDenied { seen_rid: 0x1000 },
                evidence: PeerEvidence::Unverifiable,
            }
        );

        let mut blank_msg_sid = sample_windows_peer();
        blank_msg_sid.message_identity_sid = Some(String::new());
        let obs_blank_msg = PeerObservation {
            credentials: PeerCredentials::Windows(blank_msg_sid),
            ..obs_low_il.clone()
        };
        assert_eq!(
            evaluate_peer_auth(&obs_blank_msg, &policy),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::MissingMessageIdentity,
                evidence: PeerEvidence::Unverifiable,
            }
        );

        let zero_pid_mac = PeerObservation {
            credentials: PeerCredentials::MacOs(MacOsAuditToken {
                uid: 501,
                gid: 20,
                pid: 0,
                pidversion: 1,
                audit_session_id: 100,
            }),
            hold: ProcessHold::Unheld,
            parent_pid: 1,
            started_at_ticks: 1,
            exe: None,
        };
        assert_eq!(
            evaluate_peer_auth(
                &zero_pid_mac,
                &PeerAuthPolicy {
                    expected_unix_uid: Some(501),
                    expected_windows_sid: None,
                    require_process_hold: false,
                    min_integrity_rid: None,
                    principal_policy: PrincipalPolicy::StrictExpected,
                }
            ),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::UnverifiableHold,
                evidence: PeerEvidence::Unverifiable,
            }
        );

        let strict_no_expected = PeerObservation {
            credentials: PeerCredentials::MacOs(MacOsAuditToken {
                uid: 501,
                gid: 20,
                pid: 700,
                pidversion: 1,
                audit_session_id: 100,
            }),
            hold: ProcessHold::Unheld,
            parent_pid: 1,
            started_at_ticks: 1,
            exe: None,
        };
        assert!(matches!(
            evaluate_peer_auth(
                &strict_no_expected,
                &PeerAuthPolicy {
                    expected_unix_uid: None,
                    expected_windows_sid: None,
                    require_process_hold: false,
                    min_integrity_rid: None,
                    principal_policy: PrincipalPolicy::StrictExpected,
                }
            ),
            PeerAuthDecision::Refused {
                reason: PeerRefusal::ServerForeign { .. },
                evidence: PeerEvidence::Tamper,
            }
        ));
    }
}
