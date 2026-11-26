// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::lineage::{LineageState, ProcLineageEntry};
use crate::wire::{RingEventKind, RingEventVerdict};

pub const MAX_EXPECTATIONS: usize = 64;
pub const MAX_PROTECTED_PATHS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EnforcementMode {
    Observe = 0,
    Enforce = 1,
    DegradedTracepoint = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HookDecision {
    Allow = 0,
    Observe = 1,
    Deny = 2,
    TamperDeny = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HookAuditReason {
    None = 0,
    DefaultPolicy = 1,
    ExplicitExpectationAllow = 2,
    ExplicitExpectationDeny = 3,
    ExpectationExpired = 4,
    SelfProtectGuardrailsPid = 5,
    SelfProtectControlPath = 6,
    BpfTamperBlocked = 7,
    KernelModuleBlocked = 8,
    SandboxEscapeBlocked = 9,
    LineageOverflow = 10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ExpectationKey {
    pub session_hash: u64,
    pub kind: RingEventKind,
    pub target_hash: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ExpectationRule {
    pub key: ExpectationKey,
    pub allow: bool,
    pub expires_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookEvalOutcome {
    pub decision: HookDecision,
    pub reason: HookAuditReason,
    pub verdict: RingEventVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookPolicyState<const E: usize = MAX_EXPECTATIONS, const P: usize = MAX_PROTECTED_PATHS>
{
    pub mode: EnforcementMode,
    pub protected_grdr_tgid: u32,
    pub lineage_overflow: bool,
    expectations: [Option<ExpectationRule>; E],
    protected_path_hashes: [Option<u64>; P],
    protected_inodes: [Option<(u64, u64)>; P],
}

impl<const E: usize, const P: usize> HookPolicyState<E, P> {
    pub const fn new(mode: EnforcementMode, protected_grdr_tgid: u32) -> Self {
        Self {
            mode,
            protected_grdr_tgid,
            lineage_overflow: false,
            expectations: [None; E],
            protected_path_hashes: [None; P],
            protected_inodes: [None; P],
        }
    }

    pub fn set_lineage_overflow(&mut self, overflow: bool) {
        self.lineage_overflow = overflow;
    }

    pub fn protect_inode(&mut self, dev: u64, ino: u64) -> bool {
        if ino == 0 {
            return false;
        }
        for slot in &mut self.protected_inodes {
            if let Some(existing) = slot
                && *existing == (dev, ino)
            {
                return true;
            }
        }
        for slot in &mut self.protected_inodes {
            if slot.is_none() {
                *slot = Some((dev, ino));
                return true;
            }
        }
        false
    }

    pub fn install_expectation(&mut self, rule: ExpectationRule) -> bool {
        for slot in &mut self.expectations {
            if let Some(existing) = slot
                && existing.key == rule.key
            {
                *existing = rule;
                return true;
            }
        }
        for slot in &mut self.expectations {
            if slot.is_none() {
                *slot = Some(rule);
                return true;
            }
        }
        false
    }

    pub fn protect_path(&mut self, path: &[u8]) -> bool {
        let hash = fnv1a_64(path);
        for slot in &mut self.protected_path_hashes {
            if let Some(existing) = slot
                && *existing == hash
            {
                return true;
            }
        }
        for slot in &mut self.protected_path_hashes {
            if slot.is_none() {
                *slot = Some(hash);
                return true;
            }
        }
        false
    }

    pub fn evaluate_file_open(
        &self,
        lineage: Option<&ProcLineageEntry>,
        path: &[u8],
        write_intent: bool,
        now_ns: u64,
    ) -> HookEvalOutcome {
        self.evaluate_file_open_with_inode(lineage, 0, 0, path, write_intent, now_ns)
    }

    pub fn evaluate_file_open_with_inode(
        &self,
        lineage: Option<&ProcLineageEntry>,
        dev: u64,
        ino: u64,
        path: &[u8],
        write_intent: bool,
        now_ns: u64,
    ) -> HookEvalOutcome {
        if write_intent
            && (self.is_protected_inode(dev, ino) || self.is_protected_path(fnv1a_64(path)))
        {
            return self.apply_mode(
                HookDecision::TamperDeny,
                HookAuditReason::SelfProtectControlPath,
                true,
            );
        }
        if is_escaped_suspect(lineage) {
            return self.apply_mode(
                HookDecision::Deny,
                HookAuditReason::SandboxEscapeBlocked,
                true,
            );
        }
        let key_hash = if ino != 0 {
            inode_expectation_hash(dev, ino)
        } else {
            fnv1a_64(path)
        };
        self.evaluate_expectation(lineage, RingEventKind::FileOpen, key_hash, now_ns)
    }

    pub fn evaluate_execve(
        &self,
        lineage: Option<&ProcLineageEntry>,
        executable_path: &[u8],
        now_ns: u64,
    ) -> HookEvalOutcome {
        if is_escaped_suspect(lineage) {
            return self.apply_mode(
                HookDecision::Deny,
                HookAuditReason::SandboxEscapeBlocked,
                true,
            );
        }
        self.evaluate_expectation(
            lineage,
            RingEventKind::Execve,
            fnv1a_64(executable_path),
            now_ns,
        )
    }

    pub fn evaluate_net_connect(
        &self,
        lineage: Option<&ProcLineageEntry>,
        endpoint_key: &[u8],
        now_ns: u64,
    ) -> HookEvalOutcome {
        if is_escaped_suspect(lineage) {
            return self.apply_mode(
                HookDecision::Deny,
                HookAuditReason::SandboxEscapeBlocked,
                true,
            );
        }
        self.evaluate_expectation(
            lineage,
            RingEventKind::NetConnect,
            fnv1a_64(endpoint_key),
            now_ns,
        )
    }

    pub fn evaluate_ptrace(
        &self,
        lineage: Option<&ProcLineageEntry>,
        target_tgid: u32,
        now_ns: u64,
    ) -> HookEvalOutcome {
        if self.protected_grdr_tgid != 0 && target_tgid == self.protected_grdr_tgid {
            return self.apply_mode(
                HookDecision::TamperDeny,
                HookAuditReason::SelfProtectGuardrailsPid,
                true,
            );
        }
        if is_escaped_suspect(lineage) {
            return self.apply_mode(
                HookDecision::Deny,
                HookAuditReason::SandboxEscapeBlocked,
                true,
            );
        }
        self.evaluate_expectation(
            lineage,
            RingEventKind::TaskPtrace,
            u64::from(target_tgid),
            now_ns,
        )
    }

    pub fn evaluate_bpf_or_module_op(
        &self,
        lineage: Option<&ProcLineageEntry>,
        is_module_load: bool,
    ) -> HookEvalOutcome {
        if is_escaped_suspect(lineage) {
            return self.apply_mode(
                HookDecision::Deny,
                HookAuditReason::SandboxEscapeBlocked,
                true,
            );
        }
        let Some(entry) = lineage else {
            if self.lineage_overflow {
                return self.apply_mode(HookDecision::Deny, HookAuditReason::LineageOverflow, true);
            }
            return HookEvalOutcome {
                decision: HookDecision::Allow,
                reason: HookAuditReason::DefaultPolicy,
                verdict: RingEventVerdict::Observed,
            };
        };
        if !entry.is_managed() {
            if self.lineage_overflow {
                return self.apply_mode(HookDecision::Deny, HookAuditReason::LineageOverflow, true);
            }
            return HookEvalOutcome {
                decision: HookDecision::Allow,
                reason: HookAuditReason::DefaultPolicy,
                verdict: RingEventVerdict::Observed,
            };
        }
        let reason = if is_module_load {
            HookAuditReason::KernelModuleBlocked
        } else {
            HookAuditReason::BpfTamperBlocked
        };
        self.apply_mode(HookDecision::TamperDeny, reason, true)
    }

    fn is_protected_path(&self, path_hash: u64) -> bool {
        self.protected_path_hashes
            .iter()
            .flatten()
            .any(|hash| *hash == path_hash)
    }

    fn is_protected_inode(&self, dev: u64, ino: u64) -> bool {
        ino != 0
            && self
                .protected_inodes
                .iter()
                .flatten()
                .any(|entry| *entry == (dev, ino))
    }

    fn evaluate_expectation(
        &self,
        lineage: Option<&ProcLineageEntry>,
        kind: RingEventKind,
        target_hash: u64,
        now_ns: u64,
    ) -> HookEvalOutcome {
        let Some(entry) = lineage else {
            if self.lineage_overflow {
                return self.apply_mode(HookDecision::Deny, HookAuditReason::LineageOverflow, true);
            }
            return HookEvalOutcome {
                decision: HookDecision::Allow,
                reason: HookAuditReason::DefaultPolicy,
                verdict: RingEventVerdict::Observed,
            };
        };
        if !entry.is_managed() {
            if self.lineage_overflow {
                return self.apply_mode(HookDecision::Deny, HookAuditReason::LineageOverflow, true);
            }
            return HookEvalOutcome {
                decision: HookDecision::Allow,
                reason: HookAuditReason::DefaultPolicy,
                verdict: RingEventVerdict::Observed,
            };
        }
        for rule in self.expectations.iter().flatten() {
            if rule.key.session_hash == entry.session_hash
                && rule.key.kind == kind
                && rule.key.target_hash == target_hash
            {
                if now_ns > rule.expires_ns {
                    return self.apply_mode(
                        HookDecision::Deny,
                        HookAuditReason::ExpectationExpired,
                        false,
                    );
                }
                if rule.allow {
                    return HookEvalOutcome {
                        decision: HookDecision::Allow,
                        reason: HookAuditReason::ExplicitExpectationAllow,
                        verdict: RingEventVerdict::Allowed,
                    };
                }
                return self.apply_mode(
                    HookDecision::Deny,
                    HookAuditReason::ExplicitExpectationDeny,
                    false,
                );
            }
        }
        self.apply_mode(HookDecision::Observe, HookAuditReason::DefaultPolicy, false)
    }

    fn apply_mode(
        &self,
        decision: HookDecision,
        reason: HookAuditReason,
        self_protect: bool,
    ) -> HookEvalOutcome {
        match (self.mode, decision) {
            (EnforcementMode::Enforce, HookDecision::Deny | HookDecision::TamperDeny) => {
                HookEvalOutcome {
                    decision,
                    reason,
                    verdict: RingEventVerdict::Denied,
                }
            }
            (EnforcementMode::Enforce, HookDecision::Allow) => HookEvalOutcome {
                decision,
                reason,
                verdict: RingEventVerdict::Allowed,
            },
            (EnforcementMode::Enforce, HookDecision::Observe) => HookEvalOutcome {
                decision: HookDecision::Observe,
                reason,
                verdict: RingEventVerdict::Observed,
            },
            (_, _) if self_protect && matches!(self.mode, EnforcementMode::Observe) => {
                HookEvalOutcome {
                    decision: HookDecision::Observe,
                    reason,
                    verdict: RingEventVerdict::AuditOnly,
                }
            }
            (EnforcementMode::Observe | EnforcementMode::DegradedTracepoint, _) => {
                HookEvalOutcome {
                    decision: HookDecision::Observe,
                    reason,
                    verdict: RingEventVerdict::AuditOnly,
                }
            }
        }
    }
}

const fn is_escaped_suspect(lineage: Option<&ProcLineageEntry>) -> bool {
    matches!(
        lineage,
        Some(entry) if matches!(entry.state, LineageState::EscapedSuspect)
    )
}

pub fn inode_expectation_hash(dev: u64, ino: u64) -> u64 {
    let [d0, d1, d2, d3, d4, d5, d6, d7] = dev.to_le_bytes();
    let [i0, i1, i2, i3, i4, i5, i6, i7] = ino.to_le_bytes();
    let buf = [
        d0, d1, d2, d3, d4, d5, d6, d7, i0, i1, i2, i3, i4, i5, i6, i7,
    ];
    fnv1a_64(&buf)
}

pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks_inventory::{BpfAttachKind, BpfMapKind, hook_inventory, map_inventory};
    use crate::lineage::{IsolationScope, TaskNsIds};

    fn sample_lineage(state: LineageState) -> ProcLineageEntry {
        ProcLineageEntry {
            tgid: 1200,
            ppid: 1000,
            root_agent_tgid: 1000,
            session_hash: 0x55AA,
            cgroup_id: 90,
            ns: TaskNsIds::new(1, 2, 3, 4),
            state,
            isolation: IsolationScope::Host,
            generation: 1,
            verdict_cap: RingEventVerdict::Denied,
        }
    }

    #[test]
    fn inventory_covers_five_channels_lsm_tracepoint_fmodret_and_cgroup_hooks() {
        let hooks = hook_inventory();
        assert!(hooks.iter().any(|h| matches!(h.attach, BpfAttachKind::Lsm)));
        assert!(
            hooks
                .iter()
                .any(|h| matches!(h.attach, BpfAttachKind::Tracepoint))
        );
        assert!(
            hooks
                .iter()
                .any(|h| matches!(h.attach, BpfAttachKind::FmodRet))
        );
        assert!(
            hooks
                .iter()
                .any(|h| matches!(h.attach, BpfAttachKind::CgroupSockAddr))
        );
        let maps = map_inventory();
        assert_eq!(
            maps.iter()
                .filter(|m| matches!(m.kind, BpfMapKind::RingBuf))
                .count(),
            5
        );
        assert!(maps.iter().any(|m| m.name == "proc_lineage"));
        assert!(maps.iter().any(|m| m.name == "expectation_map"));
    }

    #[test]
    fn enforces_self_protection_expiry_and_observe_degradation() {
        let mut policy: HookPolicyState<8, 4> = HookPolicyState::new(EnforcementMode::Enforce, 777);
        assert!(policy.protect_path(b"/etc/grdr/guardrails.toml"));
        assert!(policy.install_expectation(ExpectationRule {
            key: ExpectationKey {
                session_hash: 0x55AA,
                kind: RingEventKind::FileOpen,
                target_hash: fnv1a_64(b"/workspace/README.md"),
            },
            allow: true,
            expires_ns: 500,
        }));

        let managed = sample_lineage(LineageState::TrackedChild);
        let allowed = policy.evaluate_file_open(Some(&managed), b"/workspace/README.md", true, 400);
        assert_eq!(allowed.verdict, RingEventVerdict::Allowed);

        let expired = policy.evaluate_file_open(Some(&managed), b"/workspace/README.md", true, 501);
        assert_eq!(expired.reason, HookAuditReason::ExpectationExpired);
        assert_eq!(expired.verdict, RingEventVerdict::Denied);

        let tamper_file =
            policy.evaluate_file_open(Some(&managed), b"/etc/grdr/guardrails.toml", true, 400);
        assert_eq!(tamper_file.reason, HookAuditReason::SelfProtectControlPath);
        assert_eq!(tamper_file.decision, HookDecision::TamperDeny);

        let tamper_ptrace = policy.evaluate_ptrace(Some(&managed), 777, 400);
        assert_eq!(
            tamper_ptrace.reason,
            HookAuditReason::SelfProtectGuardrailsPid
        );
        assert_eq!(tamper_ptrace.verdict, RingEventVerdict::Denied);

        let escaped = sample_lineage(LineageState::EscapedSuspect);
        let exec_escape = policy.evaluate_execve(Some(&escaped), b"/bin/sh", 400);
        assert_eq!(exec_escape.reason, HookAuditReason::SandboxEscapeBlocked);
        assert_eq!(exec_escape.verdict, RingEventVerdict::Denied);

        let observe = HookPolicyState::<4, 2>::new(EnforcementMode::DegradedTracepoint, 777);
        let degraded = observe.evaluate_bpf_or_module_op(Some(&managed), false);
        assert_eq!(degraded.verdict, RingEventVerdict::AuditOnly);
        assert_eq!(degraded.reason, HookAuditReason::BpfTamperBlocked);
    }

    #[test]
    fn denies_escaped_suspect_across_all_hooks_protects_inode_and_fails_closed_on_overflow() {
        let mut policy: HookPolicyState<8, 4> = HookPolicyState::new(EnforcementMode::Enforce, 777);
        assert!(policy.protect_inode(8, 999_001));
        assert!(!policy.protect_inode(8, 0));

        let escaped = sample_lineage(LineageState::EscapedSuspect);
        for outcome in [
            policy.evaluate_file_open_with_inode(
                Some(&escaped),
                8,
                42,
                b"/workspace/ok.txt",
                false,
                10,
            ),
            policy.evaluate_ptrace(Some(&escaped), 1234, 10),
            policy.evaluate_net_connect(Some(&escaped), b"1.2.3.4:443", 10),
            policy.evaluate_bpf_or_module_op(Some(&escaped), false),
        ] {
            assert_eq!(outcome.verdict, RingEventVerdict::Denied);
            assert_eq!(outcome.reason, HookAuditReason::SandboxEscapeBlocked);
        }

        let managed = sample_lineage(LineageState::ContainedSandbox);
        let inode_tamper = policy.evaluate_file_open_with_inode(
            Some(&managed),
            8,
            999_001,
            b"/tmp/hardlink_alias",
            true,
            10,
        );
        assert_eq!(inode_tamper.decision, HookDecision::TamperDeny);
        assert_eq!(inode_tamper.reason, HookAuditReason::SelfProtectControlPath);

        assert_eq!(
            policy
                .evaluate_file_open(None, b"/workspace/unmanaged.txt", false, 10)
                .verdict,
            RingEventVerdict::Observed
        );
        policy.set_lineage_overflow(true);
        let overflow_file = policy.evaluate_file_open(None, b"/workspace/unmanaged.txt", false, 10);
        assert_eq!(overflow_file.verdict, RingEventVerdict::Denied);
        assert_eq!(overflow_file.reason, HookAuditReason::LineageOverflow);
        let overflow_bpf = policy.evaluate_bpf_or_module_op(None, true);
        assert_eq!(overflow_bpf.verdict, RingEventVerdict::Denied);
        assert_eq!(overflow_bpf.reason, HookAuditReason::LineageOverflow);
    }
}
