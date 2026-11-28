// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub const GRDR_MACOS_ABI_VERSION: u32 = 2;
pub const GRDR_MAC_ES_FLAG_IMMUTABLE_CDHASH: u32 = 1;
pub const MAX_FFI_FLOOR_RULES: usize = 1_024;
pub const MAX_FFI_SEATBELT_PATHS: usize = 256;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrdrMacFfiStatus {
    Ok = 0,
    ErrNullPtr = -1,
    ErrInvalidArg = -2,
    ErrInvalidUtf8 = -3,
    ErrBufferTooSmall = -4,
    ErrLockPoisoned = -5,
    ErrPanic = -6,
    ErrInternal = -7,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrdrMacVerdictCode {
    Allow = 0,
    AllowOpaqueWithFinding = 1,
    StepUp = 2,
    Deny = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrdrMacEsEventKind {
    RegisterRoot = 1,
    NotifyFork = 2,
    AuthExec = 3,
    NotifyExec = 4,
    NotifyExit = 5,
    AuthOpen = 6,
    AuthUnlink = 7,
    AuthRename = 8,
    AuthSignal = 9,
    AuthGetTask = 10,
    AuthProcSuspendResume = 11,
    NotifyUipcConnect = 12,
    NotifyXpcConnect = 13,
    NotifySudo = 14,
    NotifySu = 15,
    NotifyAuthPetition = 16,
    NotifyAuthJudgement = 17,
    NotifyTccModify = 18,
    NotifyBtmLaunchItemAdd = 19,
    AuthCreate = 20,
    AuthTruncate = 21,
    AuthLink = 22,
    AuthClone = 23,
    AuthUipcConnect = 24,
    NotifyCreate = 25,
    NotifyRename = 26,
    NotifyUnlink = 27,
    NotifyBootstrapLookup = 28,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrdrMacEsConcernCode {
    Recorder = 0,
    ExecAuthorizer = 1,
    ProtectedPathGuard = 2,
    SelfProtection = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrdrMacTlsSniStatusCode {
    Found = 0,
    NeedMoreBytes = 1,
    NotTls = 2,
    NoSni = 3,
    Malformed = 4,
}

#[repr(C)]
pub struct GrdrMacEsFollower {
    pub(crate) _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GrdrMacProcessKeyC {
    pub pid: u32,
    pub pidversion: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacAuditTokenC {
    pub key: GrdrMacProcessKeyC,
    pub uid: u32,
    pub reserved: u32,
    pub team_id_ptr: *const u8,
    pub team_id_len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacBrandInfoC {
    pub abi_version: u32,
    pub bundle_id_len: u16,
    pub own_prefix_len: u16,
    pub netext_bundle_id_len: u16,
    pub esext_bundle_id_len: u16,
    pub product_name_len: u16,
    pub daemon_label_len: u16,
    pub app_group_id_len: u16,
    pub reserved_align: u16,
    pub bundle_id: [u8; 128],
    pub own_prefix: [u8; 128],
    pub netext_bundle_id: [u8; 128],
    pub esext_bundle_id: [u8; 128],
    pub product_name: [u8; 128],
    pub daemon_label: [u8; 128],
    pub app_group_id: [u8; 128],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacTokenLookupOutC {
    pub governed: u8,
    pub reserved: [u8; 3],
    pub root_pid: u32,
    pub session_id_len: u16,
    pub agent_name_len: u16,
    pub session_id: [u8; 128],
    pub agent_name: [u8; 64],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacEsEventC {
    pub kind_code: u8,
    pub concern_code: u8,
    pub default_deny: u8,
    pub reserved0: u8,
    pub access_flags: u32,
    pub event_flags: u32,
    pub reserved1: u32,
    pub seq_num: u64,
    pub timestamp_ns: i64,
    pub elapsed_ms: u64,
    pub kernel_deadline_ms: u64,
    pub actor: GrdrMacAuditTokenC,
    pub target: GrdrMacAuditTokenC,
    pub path_ptr: *const u8,
    pub path_len: usize,
    pub secondary_path_ptr: *const u8,
    pub secondary_path_len: usize,
    pub session_id_ptr: *const u8,
    pub session_id_len: usize,
    pub agent_name_ptr: *const u8,
    pub agent_name_len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacEsVerdictC {
    pub verdict_code: u8,
    pub should_cache: u8,
    pub tamper_alert: u8,
    pub governed_member: u8,
    pub action_class_code: u8,
    pub synthesized_denied_exec: u8,
    pub reserved: [u8; 2],
    pub member_count: usize,
    pub unmuted_pid: u32,
    pub unmuted_pidversion: u32,
    pub session_id_len: u16,
    pub matched_rule_id_len: u16,
    pub session_id: [u8; 128],
    pub matched_rule_id: [u8; 128],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacFloorRuleC {
    pub rule_id_ptr: *const u8,
    pub rule_id_len: usize,
    pub action_mask: u32,
    pub verdict_code: u8,
    pub reserved: [u8; 3],
    pub prefix_ptr: *const u8,
    pub prefix_len: usize,
    pub contains_ptr: *const u8,
    pub contains_len: usize,
    pub agent_ptr: *const u8,
    pub agent_len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacNeFlowC {
    pub flow_id: u64,
    pub pid: u32,
    pub pidversion: u32,
    pub governed_process: u8,
    pub transport_code: u8,
    pub remote_port: u16,
    pub default_deny: u8,
    pub reserved: [u8; 3],
    pub agent_name_ptr: *const u8,
    pub agent_name_len: usize,
    pub host_name_ptr: *const u8,
    pub host_name_len: usize,
    pub tls_sni_ptr: *const u8,
    pub tls_sni_len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacNeVerdictC {
    pub verdict_code: u8,
    pub reserved: u8,
    pub rule_id_len: u16,
    pub rule_id: [u8; 128],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacTlsSniOutC {
    pub status_code: u8,
    pub reserved: u8,
    pub sni_len: u16,
    pub sni: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacDnsParseOutC {
    pub tx_id: u16,
    pub is_response: u8,
    pub rcode: u8,
    pub qtype: u16,
    pub ip_count: u8,
    pub reserved: u8,
    pub min_ttl_secs: u32,
    pub qname_len: u16,
    pub ip_families: [u8; 8],
    pub qname: [u8; 256],
    pub ips: [[u8; 16]; 8],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacCapabilitiesC {
    pub process_probe_available: u8,
    pub developer_program_held: u8,
    pub signing_status_code: u8,
    pub content_filter_rung: u8,
    pub dns_proxy_rung: u8,
    pub transparent_proxy_rung: u8,
    pub es_status_code: u8,
    pub own_extension_count: u8,
    pub foreign_extension_count: u8,
    pub vpn_proxy_count: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacStrSliceC {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacSeatbeltRequestC {
    pub agent_ptr: *const u8,
    pub agent_len: usize,
    pub session_id_ptr: *const u8,
    pub session_id_len: usize,
    pub workspace_ptr: *const u8,
    pub workspace_len: usize,
    pub decide_socket_ptr: *const u8,
    pub decide_socket_len: usize,
    pub state_dirs_ptr: *const GrdrMacStrSliceC,
    pub state_dirs_len: usize,
    pub protected_paths_ptr: *const GrdrMacStrSliceC,
    pub protected_paths_len: usize,
    pub proxy_port: u16,
    pub agent_has_own_seatbelt: u8,
    pub deny_elevation_binaries: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrMacSeatbeltPlanC {
    pub containment_code: u8,
    pub visibility_is_claimed: u8,
    pub on_failure_closed: u8,
    pub has_profile: u8,
    pub reserved: u32,
    pub profile_len: usize,
    pub profile_buf: *mut u8,
    pub profile_buf_cap: usize,
}

pub(crate) fn copy_str_into_fixed<const N: usize>(src: &str, dst: &mut [u8; N]) -> u16 {
    dst.fill(0);
    let src_bytes = src.as_bytes();
    let copy_len = src_bytes.len().min(N);
    if let (Some(src_slice), Some(dst_slice)) = (src_bytes.get(..copy_len), dst.get_mut(..copy_len))
    {
        dst_slice.copy_from_slice(src_slice);
    }
    u16::try_from(copy_len).unwrap_or(u16::MAX)
}

impl Default for GrdrMacBrandInfoC {
    fn default() -> Self {
        Self {
            abi_version: GRDR_MACOS_ABI_VERSION,
            bundle_id_len: 0,
            own_prefix_len: 0,
            netext_bundle_id_len: 0,
            esext_bundle_id_len: 0,
            product_name_len: 0,
            daemon_label_len: 0,
            app_group_id_len: 0,
            reserved_align: 0,
            bundle_id: [0; 128],
            own_prefix: [0; 128],
            netext_bundle_id: [0; 128],
            esext_bundle_id: [0; 128],
            product_name: [0; 128],
            daemon_label: [0; 128],
            app_group_id: [0; 128],
        }
    }
}

impl Default for GrdrMacTokenLookupOutC {
    fn default() -> Self {
        Self {
            governed: 0,
            reserved: [0; 3],
            root_pid: 0,
            session_id_len: 0,
            agent_name_len: 0,
            session_id: [0; 128],
            agent_name: [0; 64],
        }
    }
}

impl Default for GrdrMacEsVerdictC {
    fn default() -> Self {
        Self {
            verdict_code: GrdrMacVerdictCode::Deny as u8,
            should_cache: 0,
            tamper_alert: 0,
            governed_member: 0,
            action_class_code: 0,
            synthesized_denied_exec: 0,
            reserved: [0; 2],
            member_count: 0,
            unmuted_pid: 0,
            unmuted_pidversion: 0,
            session_id_len: 0,
            matched_rule_id_len: 0,
            session_id: [0; 128],
            matched_rule_id: [0; 128],
        }
    }
}

impl Default for GrdrMacNeVerdictC {
    fn default() -> Self {
        Self {
            verdict_code: GrdrMacVerdictCode::Deny as u8,
            reserved: 0,
            rule_id_len: 0,
            rule_id: [0; 128],
        }
    }
}

impl Default for GrdrMacTlsSniOutC {
    fn default() -> Self {
        Self {
            status_code: GrdrMacTlsSniStatusCode::NotTls as u8,
            reserved: 0,
            sni_len: 0,
            sni: [0; 256],
        }
    }
}

impl Default for GrdrMacDnsParseOutC {
    fn default() -> Self {
        Self {
            tx_id: 0,
            is_response: 0,
            rcode: 0,
            qtype: 0,
            ip_count: 0,
            reserved: 0,
            min_ttl_secs: 0,
            qname_len: 0,
            ip_families: [0; 8],
            qname: [0; 256],
            ips: [[0; 16]; 8],
        }
    }
}

impl Default for GrdrMacCapabilitiesC {
    fn default() -> Self {
        Self {
            process_probe_available: 0,
            developer_program_held: 0,
            signing_status_code: 3,
            content_filter_rung: 0,
            dns_proxy_rung: 0,
            transparent_proxy_rung: 0,
            es_status_code: 1,
            own_extension_count: 0,
            foreign_extension_count: 0,
            vpn_proxy_count: 0,
        }
    }
}
