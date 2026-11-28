// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::slice;
use std::sync::Mutex;

use grdr_fastpath::{FastActionClass, FastVerdict, FloorRuleRef};
use grdr_model::ActionClass;
use jiff::Timestamp;

use crate::brand::MacOsLimitsSnapshot;
use crate::es_eval::{
    EsAuthAction, EsAuthDecision, EsCoordinatorRuntime, EsNotifyEventKind, FloorEvaluator,
};
use crate::es_tree::{EsAuditToken, EsClientConcern, EsEventPayload, ProcessTreeKey};
use crate::ffi_types::{
    GRDR_MAC_ES_FLAG_IMMUTABLE_CDHASH, GrdrMacAuditTokenC, GrdrMacEsEventC, GrdrMacEsEventKind,
    GrdrMacEsFollower, GrdrMacEsVerdictC, GrdrMacFfiStatus, GrdrMacFloorRuleC, GrdrMacVerdictCode,
    MAX_FFI_FLOOR_RULES, copy_str_into_fixed,
};

pub(crate) struct FfiFollowerHolder {
    pub(crate) inner: Mutex<EsCoordinatorRuntime>,
}

pub(crate) struct DecodedFloorRule<'a> {
    pub(crate) rule_id: &'a str,
    pub(crate) action_mask: u32,
    pub(crate) prefix: Option<[&'a str; 1]>,
    pub(crate) contains: Option<[&'a str; 1]>,
    pub(crate) agent: Option<[&'a str; 1]>,
    pub(crate) verdict: FastVerdict,
}

#[allow(
    unsafe_code,
    reason = "Evaluate decoded fixed-layout ES event under follower Mutex."
)]
// SAFETY: Caller verified non-null follower, event, and out_verdict pointers.
pub(crate) unsafe fn eval_es_event_inner(
    follower: *mut GrdrMacEsFollower,
    event_ptr: *const GrdrMacEsEventC,
    floor: FloorEvaluator<'_>,
    out_verdict: *mut GrdrMacEsVerdictC,
) -> Result<GrdrMacFfiStatus, GrdrMacFfiStatus> {
    // SAFETY: Caller verified event_ptr non-null.
    #[allow(unsafe_code, reason = "Copy caller GrdrMacEsEventC by value.")]
    let ev = unsafe { *event_ptr };
    let concern = decode_es_concern(ev.concern_code)?;
    let kind = decode_es_kind(ev.kind_code)?;
    // SAFETY: Bounded pointer/length checks performed by read_utf8_arg.
    #[allow(unsafe_code, reason = "Read UTF-8 strings from GrdrMacEsEventC.")]
    let (actor_tok, target_tok, path, secondary_path, session_id, agent_name) = unsafe {
        (
            decode_audit_token_c(&ev.actor)?,
            decode_audit_token_c(&ev.target)?,
            read_utf8_arg(ev.path_ptr, ev.path_len)?,
            read_utf8_arg(ev.secondary_path_ptr, ev.secondary_path_len)?,
            read_utf8_arg(ev.session_id_ptr, ev.session_id_len)?,
            read_utf8_arg(ev.agent_name_ptr, ev.agent_name_len)?,
        )
    };
    // SAFETY: Valid FfiFollowerHolder pointer created by grdr_macos_follower_new.
    #[allow(unsafe_code, reason = "Lock opaque EsCoordinatorRuntime holder.")]
    let holder = unsafe { &*follower.cast::<FfiFollowerHolder>() };
    let mut rt = holder
        .inner
        .lock()
        .map_err(|_| GrdrMacFfiStatus::ErrLockPoisoned)?;

    let mut out = GrdrMacEsVerdictC {
        verdict_code: GrdrMacVerdictCode::Allow as u8,
        ..Default::default()
    };

    match kind {
        GrdrMacEsEventKind::RegisterRoot => {
            if session_id.is_empty() {
                return Err(GrdrMacFfiStatus::ErrInvalidArg);
            }
            if !agent_name.is_empty() {
                rt.register_session_agent(session_id, agent_name);
            }
            let apply = rt.tree.apply_event(&EsEventPayload::RegisterAgentRoot {
                root: actor_tok,
                session_id: session_id.to_string(),
            });
            out.action_class_code = encode_action_class(ActionClass::AgentSpawn);
            out.governed_member = 1;
            out.session_id_len = copy_str_into_fixed(session_id, &mut out.session_id);
            if let Some(key) = apply.unmuted_targets.first() {
                out.unmuted_pid = key.pid;
                out.unmuted_pidversion = key.pidversion;
            }
        }
        GrdrMacEsEventKind::NotifyFork => {
            let apply = rt.tree.apply_event(&EsEventPayload::NotifyFork {
                parent: actor_tok.key,
                child: target_tok,
            });
            out.action_class_code = FastActionClass::Exec as u8;
            out.governed_member = u8::from(apply.session_id.is_some());
            if let Some(sid) = &apply.session_id {
                out.session_id_len = copy_str_into_fixed(sid, &mut out.session_id);
            }
            if let Some(key) = apply.unmuted_targets.first() {
                out.unmuted_pid = key.pid;
                out.unmuted_pidversion = key.pidversion;
            }
        }
        GrdrMacEsEventKind::NotifyExec => {
            let apply = rt.tree.apply_event(&EsEventPayload::NotifyExec {
                old_key: actor_tok.key,
                new_token: target_tok,
                executable_path: path.to_string(),
            });
            out.action_class_code = FastActionClass::Exec as u8;
            out.governed_member = u8::from(apply.session_id.is_some());
            if let Some(sid) = &apply.session_id {
                out.session_id_len = copy_str_into_fixed(sid, &mut out.session_id);
            }
        }
        GrdrMacEsEventKind::NotifyExit => {
            let apply = rt
                .tree
                .apply_event(&EsEventPayload::NotifyExit { key: actor_tok.key });
            let occurred_at = Timestamp::from_nanosecond(i128::from(ev.timestamp_ns))
                .unwrap_or(Timestamp::UNIX_EPOCH);
            out.action_class_code = FastActionClass::Exec as u8;
            if let Some(denied) = rt
                .tree
                .consume_exit_for_denied_exec(actor_tok.key, occurred_at)
            {
                out.synthesized_denied_exec = 1;
                out.governed_member = 1;
                out.session_id_len = copy_str_into_fixed(&denied.session_id, &mut out.session_id);
                out.matched_rule_id_len =
                    copy_str_into_fixed(&denied.reason, &mut out.matched_rule_id);
            } else {
                out.governed_member = u8::from(apply.session_id.is_some());
                if let Some(sid) = &apply.session_id {
                    out.session_id_len = copy_str_into_fixed(sid, &mut out.session_id);
                }
            }
        }
        auth_kind @ (GrdrMacEsEventKind::AuthExec
        | GrdrMacEsEventKind::AuthOpen
        | GrdrMacEsEventKind::AuthUnlink
        | GrdrMacEsEventKind::AuthRename
        | GrdrMacEsEventKind::AuthSignal
        | GrdrMacEsEventKind::AuthGetTask
        | GrdrMacEsEventKind::AuthProcSuspendResume
        | GrdrMacEsEventKind::AuthCreate
        | GrdrMacEsEventKind::AuthTruncate
        | GrdrMacEsEventKind::AuthLink
        | GrdrMacEsEventKind::AuthClone
        | GrdrMacEsEventKind::AuthUipcConnect) => {
            if concern == EsClientConcern::Recorder {
                return Err(GrdrMacFfiStatus::ErrInvalidArg);
            }
            let auth_action = match auth_kind {
                GrdrMacEsEventKind::AuthExec => EsAuthAction::Exec {
                    old_key: actor_tok.key,
                    target: &target_tok,
                    executable_path: path,
                },
                GrdrMacEsEventKind::AuthOpen => EsAuthAction::FileOpen {
                    target_path: path,
                    write_requested: (ev.access_flags & 0x2) != 0,
                },
                GrdrMacEsEventKind::AuthCreate => EsAuthAction::FileCreate { target_path: path },
                GrdrMacEsEventKind::AuthTruncate => {
                    EsAuthAction::FileTruncate { target_path: path }
                }
                GrdrMacEsEventKind::AuthLink => EsAuthAction::FileLink {
                    source_path: path,
                    dest_path: secondary_path,
                },
                GrdrMacEsEventKind::AuthClone => EsAuthAction::FileClone {
                    source_path: path,
                    dest_path: secondary_path,
                },
                GrdrMacEsEventKind::AuthUnlink => EsAuthAction::FileUnlink { target_path: path },
                GrdrMacEsEventKind::AuthRename => EsAuthAction::FileRename {
                    source_path: path,
                    dest_path: secondary_path,
                },
                GrdrMacEsEventKind::AuthUipcConnect => {
                    EsAuthAction::UipcConnect { socket_path: path }
                }
                GrdrMacEsEventKind::AuthSignal => EsAuthAction::SelfSignal {
                    target_pid: target_tok.key.pid,
                },
                GrdrMacEsEventKind::AuthGetTask => EsAuthAction::SelfGetTask {
                    target_pid: target_tok.key.pid,
                },
                GrdrMacEsEventKind::AuthProcSuspendResume => EsAuthAction::SelfSuspend {
                    target_pid: target_tok.key.pid,
                },
                _ => return Err(GrdrMacFfiStatus::ErrInvalidArg),
            };
            let immutable_cdhash = (ev.event_flags & GRDR_MAC_ES_FLAG_IMMUTABLE_CDHASH) != 0;
            let eval = rt.evaluate_auth_event_with_concern(
                concern,
                &actor_tok,
                auth_action,
                floor,
                ev.default_deny != 0,
                ev.elapsed_ms,
                ev.kernel_deadline_ms,
                immutable_cdhash,
            );
            match eval.decision {
                EsAuthDecision::Allow { should_cache } => {
                    out.verdict_code = GrdrMacVerdictCode::Allow as u8;
                    out.should_cache = u8::from(should_cache);
                }
                EsAuthDecision::AllowWithTamperAlert => {
                    out.verdict_code = GrdrMacVerdictCode::Allow as u8;
                    out.should_cache = 0;
                    out.tamper_alert = 1;
                }
                EsAuthDecision::Deny => {
                    out.verdict_code = GrdrMacVerdictCode::Deny as u8;
                    out.should_cache = 0;
                }
            }
            out.governed_member = u8::from(eval.governed_member);
            out.action_class_code = encode_action_class(eval.action_class);
            if let Some(sid) = &eval.session_id {
                out.session_id_len = copy_str_into_fixed(sid, &mut out.session_id);
            }
            if let Some(rule) = &eval.matched_rule_id {
                out.matched_rule_id_len = copy_str_into_fixed(rule, &mut out.matched_rule_id);
            }
            if let Some(key) = eval.unmuted_target {
                out.unmuted_pid = key.pid;
                out.unmuted_pidversion = key.pidversion;
            }
        }
        notify_kind @ (GrdrMacEsEventKind::NotifyUipcConnect
        | GrdrMacEsEventKind::NotifyXpcConnect
        | GrdrMacEsEventKind::NotifySudo
        | GrdrMacEsEventKind::NotifySu
        | GrdrMacEsEventKind::NotifyAuthPetition
        | GrdrMacEsEventKind::NotifyAuthJudgement
        | GrdrMacEsEventKind::NotifyTccModify
        | GrdrMacEsEventKind::NotifyBtmLaunchItemAdd
        | GrdrMacEsEventKind::NotifyCreate
        | GrdrMacEsEventKind::NotifyRename
        | GrdrMacEsEventKind::NotifyUnlink
        | GrdrMacEsEventKind::NotifyBootstrapLookup) => {
            let nkind = match notify_kind {
                GrdrMacEsEventKind::NotifyUipcConnect => EsNotifyEventKind::UipcConnect,
                GrdrMacEsEventKind::NotifyXpcConnect => EsNotifyEventKind::XpcConnect,
                GrdrMacEsEventKind::NotifySudo => EsNotifyEventKind::Sudo,
                GrdrMacEsEventKind::NotifySu => EsNotifyEventKind::Su,
                GrdrMacEsEventKind::NotifyAuthPetition => EsNotifyEventKind::AuthorizationPetition,
                GrdrMacEsEventKind::NotifyAuthJudgement => {
                    EsNotifyEventKind::AuthorizationJudgement
                }
                GrdrMacEsEventKind::NotifyTccModify => EsNotifyEventKind::TccModify,
                GrdrMacEsEventKind::NotifyBtmLaunchItemAdd => EsNotifyEventKind::BtmLaunchItemAdd,
                GrdrMacEsEventKind::NotifyCreate => EsNotifyEventKind::Create,
                GrdrMacEsEventKind::NotifyRename => EsNotifyEventKind::Rename,
                GrdrMacEsEventKind::NotifyUnlink => EsNotifyEventKind::Unlink,
                GrdrMacEsEventKind::NotifyBootstrapLookup => EsNotifyEventKind::BootstrapLookup,
                _ => return Err(GrdrMacFfiStatus::ErrInvalidArg),
            };
            let rec = rt.normalize_notify_event(actor_tok.key, nkind, path);
            out.action_class_code = encode_action_class(rec.action_class);
            out.governed_member = u8::from(rec.governed_session.is_some());
            if let Some(sid) = &rec.governed_session {
                out.session_id_len = copy_str_into_fixed(sid, &mut out.session_id);
            }
        }
    }
    out.member_count = rt.tree.member_count();
    #[allow(
        unsafe_code,
        reason = "Write evaluated GrdrMacEsVerdictC to caller output."
    )]
    // SAFETY: Caller verified out_verdict is valid aligned pointer.
    unsafe {
        *out_verdict = out;
    }
    Ok(GrdrMacFfiStatus::Ok)
}

#[allow(unsafe_code, reason = "Read UTF-8 GrdrMacAuditTokenC across C ABI.")]
// SAFETY: Bounded pointer/length checks performed by read_utf8_arg.
unsafe fn decode_audit_token_c(raw: &GrdrMacAuditTokenC) -> Result<EsAuditToken, GrdrMacFfiStatus> {
    // SAFETY: Caller pointer validated by read_utf8_arg.
    #[allow(unsafe_code, reason = "Read Team ID UTF-8 slice across C ABI.")]
    let team = unsafe { read_utf8_arg(raw.team_id_ptr, raw.team_id_len) }?;
    Ok(EsAuditToken {
        key: ProcessTreeKey {
            pid: raw.key.pid,
            pidversion: raw.key.pidversion,
        },
        uid: raw.uid,
        team_id: (!team.is_empty()).then(|| team.to_string()),
    })
}

#[allow(
    unsafe_code,
    reason = "Validate and read bounded byte slice across C ABI."
)]
// SAFETY: Enforces zero-length early return, non-null check, and operational frame cap before slice::from_raw_parts.
pub(crate) unsafe fn read_bytes_arg<'a>(
    ptr: *const u8,
    len: usize,
) -> Result<&'a [u8], GrdrMacFfiStatus> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(GrdrMacFfiStatus::ErrNullPtr);
    }
    let cap = MacOsLimitsSnapshot::try_embedded()
        .map_err(|_| GrdrMacFfiStatus::ErrInternal)?
        .ipc_max_frame_bytes;
    if len > cap {
        return Err(GrdrMacFfiStatus::ErrInvalidArg);
    }
    // SAFETY: Caller guarantees ptr covers len readable bytes within cap.
    #[allow(unsafe_code, reason = "Slice caller-provided readable byte buffer.")]
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

#[allow(
    unsafe_code,
    reason = "Validate and read bounded UTF-8 slice across C ABI."
)]
// SAFETY: Validates pointer and length via read_bytes_arg prior to UTF-8 conversion.
pub(crate) unsafe fn read_utf8_arg<'a>(
    ptr: *const u8,
    len: usize,
) -> Result<&'a str, GrdrMacFfiStatus> {
    // SAFETY: Validated by read_bytes_arg.
    #[allow(unsafe_code, reason = "Read bounded byte slice before UTF-8 check.")]
    let bytes = unsafe { read_bytes_arg(ptr, len) }?;
    std::str::from_utf8(bytes).map_err(|_| GrdrMacFfiStatus::ErrInvalidUtf8)
}

#[allow(
    unsafe_code,
    reason = "Read fixed GrdrMacFloorRuleC slice across C ABI."
)]
// SAFETY: Enforces null checks and MAX_FFI_FLOOR_RULES bound before slice::from_raw_parts.
pub(crate) unsafe fn read_floor_rules_c<'a>(
    rules_ptr: *const GrdrMacFloorRuleC,
    rules_len: usize,
) -> Result<Vec<DecodedFloorRule<'a>>, GrdrMacFfiStatus> {
    if rules_len == 0 {
        return Ok(Vec::new());
    }
    if rules_ptr.is_null() {
        return Err(GrdrMacFfiStatus::ErrNullPtr);
    }
    if rules_len > MAX_FFI_FLOOR_RULES {
        return Err(GrdrMacFfiStatus::ErrInvalidArg);
    }
    #[allow(
        unsafe_code,
        reason = "Borrow bounded GrdrMacFloorRuleC slice across C ABI."
    )]
    // SAFETY: Caller guarantees rules_ptr covers rules_len aligned elements.
    let raw_slice = unsafe { slice::from_raw_parts(rules_ptr, rules_len) };
    let mut out = Vec::with_capacity(rules_len);
    for rule in raw_slice {
        // SAFETY: Each field pointer/len validated by read_utf8_arg.
        #[allow(unsafe_code, reason = "Validate UTF-8 fields on GrdrMacFloorRuleC.")]
        let (rule_id, prefix, contains, agent) = unsafe {
            (
                read_utf8_arg(rule.rule_id_ptr, rule.rule_id_len)?,
                read_utf8_arg(rule.prefix_ptr, rule.prefix_len)?,
                read_utf8_arg(rule.contains_ptr, rule.contains_len)?,
                read_utf8_arg(rule.agent_ptr, rule.agent_len)?,
            )
        };
        let verdict = match rule.verdict_code {
            0 => FastVerdict::Allow,
            1 => FastVerdict::StepUp,
            2 => FastVerdict::Deny,
            _ => return Err(GrdrMacFfiStatus::ErrInvalidArg),
        };
        out.push(DecodedFloorRule {
            rule_id,
            action_mask: rule.action_mask,
            prefix: (!prefix.is_empty()).then_some([prefix]),
            contains: (!contains.is_empty()).then_some([contains]),
            agent: (!agent.is_empty()).then_some([agent]),
            verdict,
        });
    }
    Ok(out)
}

pub(crate) fn with_decoded_floor_refs<R>(
    decoded: &[DecodedFloorRule<'_>],
    default_action: FastActionClass,
    f: impl FnOnce(&[FloorRuleRef<'_>]) -> R,
) -> R {
    let mut refs = Vec::with_capacity(decoded.len());
    for d in decoded {
        let mask = if d.action_mask == 0 {
            1u32 << (default_action as u8)
        } else {
            d.action_mask
        };
        refs.push(FloorRuleRef {
            rule_id: d.rule_id,
            action_mask: mask,
            prefixes: d.prefix.as_ref().map_or(&[][..], |a| a.as_slice()),
            contains: d.contains.as_ref().map_or(&[][..], |a| a.as_slice()),
            agents: d.agent.as_ref().map_or(&[][..], |a| a.as_slice()),
            verdict: d.verdict,
        });
    }
    f(&refs)
}

pub(crate) fn wrap_status(
    res: Result<Result<GrdrMacFfiStatus, GrdrMacFfiStatus>, Box<dyn std::any::Any + Send>>,
) -> i32 {
    match res {
        Ok(Ok(s)) | Ok(Err(s)) => s as i32,
        Err(_) => GrdrMacFfiStatus::ErrPanic as i32,
    }
}

fn decode_es_concern(raw: u8) -> Result<EsClientConcern, GrdrMacFfiStatus> {
    match raw {
        0 => Ok(EsClientConcern::Recorder),
        1 => Ok(EsClientConcern::ExecAuthorizer),
        2 => Ok(EsClientConcern::ProtectedPathGuard),
        3 => Ok(EsClientConcern::SelfProtection),
        _ => Err(GrdrMacFfiStatus::ErrInvalidArg),
    }
}

fn decode_es_kind(raw: u8) -> Result<GrdrMacEsEventKind, GrdrMacFfiStatus> {
    match raw {
        1 => Ok(GrdrMacEsEventKind::RegisterRoot),
        2 => Ok(GrdrMacEsEventKind::NotifyFork),
        3 => Ok(GrdrMacEsEventKind::AuthExec),
        4 => Ok(GrdrMacEsEventKind::NotifyExec),
        5 => Ok(GrdrMacEsEventKind::NotifyExit),
        6 => Ok(GrdrMacEsEventKind::AuthOpen),
        7 => Ok(GrdrMacEsEventKind::AuthUnlink),
        8 => Ok(GrdrMacEsEventKind::AuthRename),
        9 => Ok(GrdrMacEsEventKind::AuthSignal),
        10 => Ok(GrdrMacEsEventKind::AuthGetTask),
        11 => Ok(GrdrMacEsEventKind::AuthProcSuspendResume),
        12 => Ok(GrdrMacEsEventKind::NotifyUipcConnect),
        13 => Ok(GrdrMacEsEventKind::NotifyXpcConnect),
        14 => Ok(GrdrMacEsEventKind::NotifySudo),
        15 => Ok(GrdrMacEsEventKind::NotifySu),
        16 => Ok(GrdrMacEsEventKind::NotifyAuthPetition),
        17 => Ok(GrdrMacEsEventKind::NotifyAuthJudgement),
        18 => Ok(GrdrMacEsEventKind::NotifyTccModify),
        19 => Ok(GrdrMacEsEventKind::NotifyBtmLaunchItemAdd),
        20 => Ok(GrdrMacEsEventKind::AuthCreate),
        21 => Ok(GrdrMacEsEventKind::AuthTruncate),
        22 => Ok(GrdrMacEsEventKind::AuthLink),
        23 => Ok(GrdrMacEsEventKind::AuthClone),
        24 => Ok(GrdrMacEsEventKind::AuthUipcConnect),
        25 => Ok(GrdrMacEsEventKind::NotifyCreate),
        26 => Ok(GrdrMacEsEventKind::NotifyRename),
        27 => Ok(GrdrMacEsEventKind::NotifyUnlink),
        28 => Ok(GrdrMacEsEventKind::NotifyBootstrapLookup),
        _ => Err(GrdrMacFfiStatus::ErrInvalidArg),
    }
}

const fn encode_action_class(class: ActionClass) -> u8 {
    match class {
        ActionClass::Exec => 0,
        ActionClass::FileRead => 1,
        ActionClass::FileWrite => 2,
        ActionClass::FileDelete => 3,
        ActionClass::NetConnect => 4,
        ActionClass::Elevate => 8,
        ActionClass::ConfigChange => 9,
        ActionClass::AgentSpawn => 10,
        _ => 0,
    }
}
