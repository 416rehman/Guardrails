// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Pure OS-peer claim evaluation policies (`ADR-0051`, `docs/design/11`).

use crate::peer_auth::{
    ClientIdentityPolicy, Evidence, OsPeerClaims, Profile, Refusal, ScmServiceState,
    ServerIdentityPolicy, VerifiedPeer, WindowsPeerClaims,
};

const MAX_UNIX_UID_SENTINEL: u32 = u32::MAX;

pub fn verify_client_peer(
    claims: &OsPeerClaims,
    connected_at_ticks: u64,
    policy: &ServerIdentityPolicy,
) -> Result<VerifiedPeer, Refusal> {
    match claims {
        OsPeerClaims::Inherited => {
            if policy.profile != Profile::Inherited {
                return Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
                    profile: policy.profile,
                    detail: "inherited peer requires Inherited profile".to_string(),
                }));
            }
            Ok(VerifiedPeer::inherited())
        }
        OsPeerClaims::Unix(unix) => {
            if policy.profile == Profile::Inherited {
                return Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
                    profile: policy.profile,
                    detail: "unix peer claims invalid under Inherited profile".to_string(),
                }));
            }
            if unix.uid == MAX_UNIX_UID_SENTINEL || unix.gid == MAX_UNIX_UID_SENTINEL {
                return Err(Refusal::ForeignPeerUid(Evidence::UidMismatch {
                    expected_uids: policy.allowed_client_uids.clone(),
                    actual_uid: unix.uid,
                }));
            }
            if policy.require_kernel_peer_token
                && !(unix.has_pidfd || unix.local_peertoken_verified)
            {
                return Err(Refusal::UnauthenticatedPeer(Evidence::MissingPeerToken {
                    detail: "kernel pidfd or LOCAL_PEERTOKEN proof required".to_string(),
                }));
            }
            if !policy.allowed_client_uids.contains(&unix.uid) {
                return Err(Refusal::ForeignPeerUid(Evidence::UidMismatch {
                    expected_uids: policy.allowed_client_uids.clone(),
                    actual_uid: unix.uid,
                }));
            }
            check_start_time(
                unix.peer_started_at_ticks,
                connected_at_ticks,
                policy.require_start_time_before_connect,
            )?;
            Ok(VerifiedPeer::unix(
                policy.profile,
                unix.uid,
                unix.gid,
                unix.pid,
            ))
        }
        OsPeerClaims::Windows(win) => {
            if policy.profile == Profile::Inherited {
                return Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
                    profile: policy.profile,
                    detail: "windows peer claims invalid under Inherited profile".to_string(),
                }));
            }
            if policy.require_open_as_self_pipe_check && !win.thread_token_open_as_self {
                return Err(Refusal::UnauthenticatedPeer(Evidence::MissingPeerToken {
                    detail: "OpenThreadToken(OpenAsSelf=TRUE) check required".to_string(),
                }));
            }
            if policy.reject_app_container && win.is_app_container {
                return Err(Refusal::PrivilegeTooLow(
                    Evidence::WindowsAppContainerDisallowed,
                ));
            }
            check_win_integrity(win.integrity_rid, policy.minimum_integrity_rid)?;
            if policy.allowed_windows_sids.is_empty()
                || win.peer_sid.is_empty()
                || !policy
                    .allowed_windows_sids
                    .iter()
                    .any(|s| s == &win.peer_sid)
            {
                return Err(Refusal::UnauthenticatedPeer(Evidence::WindowsSidMismatch {
                    expected: policy.allowed_windows_sids.clone(),
                    actual: win.peer_sid.clone(),
                }));
            }
            check_start_time(
                win.peer_started_at_100ns,
                connected_at_ticks,
                policy.require_start_time_before_connect,
            )?;
            Ok(VerifiedPeer::windows(policy.profile, win))
        }
    }
}

pub fn verify_server_peer(
    claims: &OsPeerClaims,
    connected_at_ticks: u64,
    policy: &ClientIdentityPolicy,
) -> Result<VerifiedPeer, Refusal> {
    match claims {
        OsPeerClaims::Inherited => {
            if policy.profile != Profile::Inherited {
                return Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
                    profile: policy.profile,
                    detail: "inherited peer requires Inherited profile".to_string(),
                }));
            }
            Ok(VerifiedPeer::inherited())
        }
        OsPeerClaims::Unix(unix) => {
            if policy.profile == Profile::Inherited {
                return Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
                    profile: policy.profile,
                    detail: "unix server claims invalid under Inherited profile".to_string(),
                }));
            }
            if unix.uid == MAX_UNIX_UID_SENTINEL || unix.gid == MAX_UNIX_UID_SENTINEL {
                return Err(Refusal::UntrustedServerIdentity(Evidence::UidMismatch {
                    expected_uids: policy.allowed_server_uids.clone(),
                    actual_uid: unix.uid,
                }));
            }
            if policy.require_kernel_peer_token
                && !(unix.has_pidfd || unix.local_peertoken_verified)
            {
                return Err(Refusal::UntrustedServerIdentity(
                    Evidence::MissingPeerToken {
                        detail: "kernel pidfd or LOCAL_PEERTOKEN proof required".to_string(),
                    },
                ));
            }
            if !policy.allowed_server_uids.contains(&unix.uid) {
                return Err(Refusal::UntrustedServerIdentity(Evidence::UidMismatch {
                    expected_uids: policy.allowed_server_uids.clone(),
                    actual_uid: unix.uid,
                }));
            }
            let allow_missing_protected_unix_start = policy.profile == Profile::Protected
                && unix.local_peertoken_verified
                && unix.uid == 0;
            check_server_start_time(
                unix.peer_started_at_ticks,
                connected_at_ticks,
                policy.require_start_time_before_connect,
                allow_missing_protected_unix_start,
            )?;
            Ok(VerifiedPeer::unix(
                policy.profile,
                unix.uid,
                unix.gid,
                unix.pid,
            ))
        }
        OsPeerClaims::Windows(win) => verify_windows_server_claims(win, connected_at_ticks, policy),
    }
}

fn verify_windows_server_claims(
    win: &WindowsPeerClaims,
    connected_at_ticks: u64,
    policy: &ClientIdentityPolicy,
) -> Result<VerifiedPeer, Refusal> {
    if policy.profile == Profile::Inherited {
        return Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
            profile: policy.profile,
            detail: "windows server claims invalid under Inherited profile".to_string(),
        }));
    }
    if policy.expected_windows_sids.is_empty()
        || win.peer_sid.is_empty()
        || !policy
            .expected_windows_sids
            .iter()
            .any(|s| s == &win.peer_sid)
    {
        return Err(Refusal::UntrustedServerIdentity(
            Evidence::WindowsSidMismatch {
                expected: policy.expected_windows_sids.clone(),
                actual: win.peer_sid.clone(),
            },
        ));
    }
    if win.pipe_owner_sid.as_deref() != Some(win.peer_sid.as_str()) {
        return Err(Refusal::UntrustedServerIdentity(
            Evidence::WindowsSidMismatch {
                expected: policy.expected_windows_sids.clone(),
                actual: win.pipe_owner_sid.clone().unwrap_or_default(),
            },
        ));
    }
    if let Some(scm_sid) = win.scm_expected_sid.as_ref()
        && scm_sid != &win.peer_sid
    {
        return Err(Refusal::UntrustedServerIdentity(
            Evidence::WindowsSidMismatch {
                expected: policy.expected_windows_sids.clone(),
                actual: win.peer_sid.clone(),
            },
        ));
    }

    if policy.profile == Profile::Protected {
        if win.scm_state != ScmServiceState::Running
            || win.scm_pre_pids.is_empty()
            || win.scm_post_pids.is_empty()
        {
            return Err(Refusal::UntrustedServerIdentity(
                Evidence::WindowsServerPidMismatch {
                    actual_pid: win.server_pid_from_pipe,
                    expected_scm_pids: win.scm_post_pids.clone(),
                },
            ));
        }
        if win.scm_pre_pids != win.scm_post_pids {
            return Err(Refusal::TransientServerRestart(
                Evidence::WindowsServerPidMismatch {
                    actual_pid: win.server_pid_from_pipe,
                    expected_scm_pids: win.scm_post_pids.clone(),
                },
            ));
        }
        let matches_scm = win
            .server_pid_from_pipe
            .is_some_and(|p| win.scm_post_pids.contains(&p));
        if !matches_scm {
            return Err(Refusal::UntrustedServerIdentity(
                Evidence::WindowsServerPidMismatch {
                    actual_pid: win.server_pid_from_pipe,
                    expected_scm_pids: win.scm_post_pids.clone(),
                },
            ));
        }
    }

    check_win_integrity(win.integrity_rid, policy.minimum_integrity_rid)?;
    // Protected SCM services are already dual-PID + pipe-owner verified above; OpenProcess
    // against SYSTEM/service processes from an unprivileged hook can legitimately omit start time.
    let allow_missing_protected_win_start = policy.profile == Profile::Protected;
    check_server_start_time(
        win.peer_started_at_100ns,
        connected_at_ticks,
        policy.require_start_time_before_connect,
        allow_missing_protected_win_start,
    )?;
    Ok(VerifiedPeer::windows(policy.profile, win))
}

fn check_server_start_time(
    started: Option<u64>,
    connected_at_ticks: u64,
    required: bool,
    allow_missing_kernel_attested: bool,
) -> Result<(), Refusal> {
    match started {
        Some(_) => check_start_time(started, connected_at_ticks, required),
        None if allow_missing_kernel_attested => Ok(()),
        None => check_start_time(None, connected_at_ticks, required),
    }
}

fn check_start_time(
    started: Option<u64>,
    connected_at_ticks: u64,
    required: bool,
) -> Result<(), Refusal> {
    if !required {
        return Ok(());
    }
    let Some(ticks) = started else {
        return Err(Refusal::PidReuseSuspected(Evidence::StartTimeMissing));
    };
    if ticks == 0 || connected_at_ticks == 0 || ticks > connected_at_ticks {
        return Err(Refusal::PidReuseSuspected(Evidence::StartTimeSkew {
            started_ticks: ticks,
            connected_at_ticks,
        }));
    }
    Ok(())
}

fn check_win_integrity(actual_rid: u32, minimum_rid: u32) -> Result<(), Refusal> {
    if actual_rid < minimum_rid {
        return Err(Refusal::PrivilegeTooLow(Evidence::WindowsIntegrityTooLow {
            actual_rid,
            minimum_rid,
        }));
    }
    Ok(())
}
