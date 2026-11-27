// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#ifndef GRDR_SENSOR_MACOS_H
#define GRDR_SENSOR_MACOS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GRDR_MAC_ES_FLAG_IMMUTABLE_CDHASH 1u

typedef struct GrdrMacEsFollower GrdrMacEsFollower;

typedef enum GrdrMacFfiStatus {
    GRDR_MAC_FFI_OK = 0,
    GRDR_MAC_FFI_ERR_NULL_PTR = -1,
    GRDR_MAC_FFI_ERR_INVALID_ARG = -2,
    GRDR_MAC_FFI_ERR_INVALID_UTF8 = -3,
    GRDR_MAC_FFI_ERR_BUFFER_TOO_SMALL = -4,
    GRDR_MAC_FFI_ERR_LOCK_POISONED = -5,
    GRDR_MAC_FFI_ERR_PANIC = -6,
    GRDR_MAC_FFI_ERR_INTERNAL = -7
} GrdrMacFfiStatus;

typedef enum GrdrMacVerdictCode {
    GRDR_MAC_VERDICT_ALLOW = 0,
    GRDR_MAC_VERDICT_ALLOW_OPAQUE = 1,
    GRDR_MAC_VERDICT_STEP_UP = 2,
    GRDR_MAC_VERDICT_DENY = 3
} GrdrMacVerdictCode;

typedef enum GrdrMacEsEventKind {
    GRDR_MAC_ES_REGISTER_ROOT = 1,
    GRDR_MAC_ES_NOTIFY_FORK = 2,
    GRDR_MAC_ES_AUTH_EXEC = 3,
    GRDR_MAC_ES_NOTIFY_EXEC = 4,
    GRDR_MAC_ES_NOTIFY_EXIT = 5,
    GRDR_MAC_ES_AUTH_OPEN = 6,
    GRDR_MAC_ES_AUTH_UNLINK = 7,
    GRDR_MAC_ES_AUTH_RENAME = 8,
    GRDR_MAC_ES_AUTH_SIGNAL = 9,
    GRDR_MAC_ES_AUTH_GET_TASK = 10,
    GRDR_MAC_ES_AUTH_PROC_SUSPEND_RESUME = 11,
    GRDR_MAC_ES_NOTIFY_UIPC_CONNECT = 12,
    GRDR_MAC_ES_NOTIFY_XPC_CONNECT = 13,
    GRDR_MAC_ES_NOTIFY_SUDO = 14,
    GRDR_MAC_ES_NOTIFY_SU = 15,
    GRDR_MAC_ES_NOTIFY_AUTH_PETITION = 16,
    GRDR_MAC_ES_NOTIFY_AUTH_JUDGEMENT = 17,
    GRDR_MAC_ES_NOTIFY_TCC_MODIFY = 18,
    GRDR_MAC_ES_NOTIFY_BTM_LAUNCH_ITEM_ADD = 19,
    GRDR_MAC_ES_AUTH_CREATE = 20,
    GRDR_MAC_ES_AUTH_TRUNCATE = 21,
    GRDR_MAC_ES_AUTH_LINK = 22,
    GRDR_MAC_ES_AUTH_CLONE = 23,
    GRDR_MAC_ES_AUTH_UIPC_CONNECT = 24,
    GRDR_MAC_ES_NOTIFY_CREATE = 25,
    GRDR_MAC_ES_NOTIFY_RENAME = 26,
    GRDR_MAC_ES_NOTIFY_UNLINK = 27,
    GRDR_MAC_ES_NOTIFY_BOOTSTRAP_LOOKUP = 28
} GrdrMacEsEventKind;

typedef enum GrdrMacEsConcernCode {
    GRDR_MAC_ES_CONCERN_RECORDER = 0,
    GRDR_MAC_ES_CONCERN_EXEC_AUTHORIZER = 1,
    GRDR_MAC_ES_CONCERN_PROTECTED_PATH_GUARD = 2,
    GRDR_MAC_ES_CONCERN_SELF_PROTECTION = 3
} GrdrMacEsConcernCode;

typedef enum GrdrMacTlsSniStatusCode {
    GRDR_MAC_TLS_SNI_FOUND = 0,
    GRDR_MAC_TLS_SNI_NEED_MORE_BYTES = 1,
    GRDR_MAC_TLS_SNI_NOT_TLS = 2,
    GRDR_MAC_TLS_SNI_NO_SNI = 3,
    GRDR_MAC_TLS_SNI_MALFORMED = 4
} GrdrMacTlsSniStatusCode;

typedef struct GrdrMacProcessKeyC {
    uint32_t pid;
    uint32_t pidversion;
} GrdrMacProcessKeyC;

typedef struct GrdrMacAuditTokenC {
    GrdrMacProcessKeyC key;
    uint32_t uid;
    uint32_t reserved;
    const uint8_t* team_id_ptr;
    size_t team_id_len;
} GrdrMacAuditTokenC;

typedef struct GrdrMacBrandInfoC {
    uint32_t abi_version;
    uint16_t bundle_id_len;
    uint16_t own_prefix_len;
    uint16_t netext_bundle_id_len;
    uint16_t esext_bundle_id_len;
    uint16_t product_name_len;
    uint16_t daemon_label_len;
    uint16_t app_group_id_len;
    uint16_t reserved_align;
    uint8_t bundle_id[128];
    uint8_t own_prefix[128];
    uint8_t netext_bundle_id[128];
    uint8_t esext_bundle_id[128];
    uint8_t product_name[128];
    uint8_t daemon_label[128];
    uint8_t app_group_id[128];
} GrdrMacBrandInfoC;

typedef struct GrdrMacTokenLookupOutC {
    uint8_t governed;
    uint8_t reserved[3];
    uint32_t root_pid;
    uint16_t session_id_len;
    uint16_t agent_name_len;
    uint8_t session_id[128];
    uint8_t agent_name[64];
} GrdrMacTokenLookupOutC;

typedef struct GrdrMacEsEventC {
    uint8_t kind_code;
    uint8_t concern_code;
    uint8_t default_deny;
    uint8_t reserved0;
    uint32_t access_flags;
    uint32_t event_flags;
    uint32_t reserved1;
    uint64_t seq_num;
    int64_t timestamp_ns;
    uint64_t elapsed_ms;
    uint64_t kernel_deadline_ms;
    GrdrMacAuditTokenC actor;
    GrdrMacAuditTokenC target;
    const uint8_t* path_ptr;
    size_t path_len;
    const uint8_t* secondary_path_ptr;
    size_t secondary_path_len;
    const uint8_t* session_id_ptr;
    size_t session_id_len;
    const uint8_t* agent_name_ptr;
    size_t agent_name_len;
} GrdrMacEsEventC;

typedef struct GrdrMacEsVerdictC {
    uint8_t verdict_code;
    uint8_t should_cache;
    uint8_t tamper_alert;
    uint8_t governed_member;
    uint8_t action_class_code;
    uint8_t synthesized_denied_exec;
    uint8_t reserved[2];
    size_t member_count;
    uint32_t unmuted_pid;
    uint32_t unmuted_pidversion;
    uint16_t session_id_len;
    uint16_t matched_rule_id_len;
    uint8_t session_id[128];
    uint8_t matched_rule_id[128];
} GrdrMacEsVerdictC;

typedef struct GrdrMacFloorRuleC {
    const uint8_t* rule_id_ptr;
    size_t rule_id_len;
    uint32_t action_mask;
    uint8_t verdict_code;
    uint8_t reserved[3];
    const uint8_t* prefix_ptr;
    size_t prefix_len;
    const uint8_t* contains_ptr;
    size_t contains_len;
    const uint8_t* agent_ptr;
    size_t agent_len;
} GrdrMacFloorRuleC;

typedef struct GrdrMacNeFlowC {
    uint64_t flow_id;
    uint32_t pid;
    uint32_t pidversion;
    uint8_t governed_process;
    uint8_t transport_code;
    uint16_t remote_port;
    uint8_t default_deny;
    uint8_t reserved[3];
    const uint8_t* agent_name_ptr;
    size_t agent_name_len;
    const uint8_t* host_name_ptr;
    size_t host_name_len;
    const uint8_t* tls_sni_ptr;
    size_t tls_sni_len;
} GrdrMacNeFlowC;

typedef struct GrdrMacNeVerdictC {
    uint8_t verdict_code;
    uint8_t reserved;
    uint16_t rule_id_len;
    uint8_t rule_id[128];
} GrdrMacNeVerdictC;

typedef struct GrdrMacTlsSniOutC {
    uint8_t status_code;
    uint8_t reserved;
    uint16_t sni_len;
    uint8_t sni[256];
} GrdrMacTlsSniOutC;

typedef struct GrdrMacDnsParseOutC {
    uint16_t tx_id;
    uint8_t is_response;
    uint8_t rcode;
    uint16_t qtype;
    uint8_t ip_count;
    uint8_t reserved;
    uint32_t min_ttl_secs;
    uint16_t qname_len;
    uint8_t ip_families[8];
    uint8_t qname[256];
    uint8_t ips[8][16];
} GrdrMacDnsParseOutC;

typedef struct GrdrMacCapabilitiesC {
    uint8_t process_probe_available;
    uint8_t developer_program_held;
    uint8_t signing_status_code;
    uint8_t content_filter_rung;
    uint8_t dns_proxy_rung;
    uint8_t transparent_proxy_rung;
    uint8_t es_status_code;
    uint8_t own_extension_count;
    uint8_t foreign_extension_count;
    uint8_t vpn_proxy_count;
} GrdrMacCapabilitiesC;

typedef struct GrdrMacStrSliceC {
    const uint8_t* ptr;
    size_t len;
} GrdrMacStrSliceC;

typedef struct GrdrMacSeatbeltRequestC {
    const uint8_t* agent_ptr;
    size_t agent_len;
    const uint8_t* session_id_ptr;
    size_t session_id_len;
    const uint8_t* workspace_ptr;
    size_t workspace_len;
    const uint8_t* decide_socket_ptr;
    size_t decide_socket_len;
    const GrdrMacStrSliceC* state_dirs_ptr;
    size_t state_dirs_len;
    const GrdrMacStrSliceC* protected_paths_ptr;
    size_t protected_paths_len;
    uint16_t proxy_port;
    uint8_t agent_has_own_seatbelt;
    uint8_t deny_elevation_binaries;
} GrdrMacSeatbeltRequestC;

typedef struct GrdrMacSeatbeltPlanC {
    uint8_t containment_code;
    uint8_t visibility_is_claimed;
    uint8_t on_failure_closed;
    uint8_t has_profile;
    uint32_t reserved;
    size_t profile_len;
    uint8_t* profile_buf;
    size_t profile_buf_cap;
} GrdrMacSeatbeltPlanC;

uint32_t grdr_macos_abi_version(void);
int32_t grdr_macos_get_brand_info(GrdrMacBrandInfoC* out_info);

GrdrMacEsFollower* grdr_macos_follower_new(void);
void grdr_macos_follower_free(GrdrMacEsFollower* ptr);

int32_t grdr_macos_follower_mute_team(
    GrdrMacEsFollower* follower,
    const uint8_t* team_id_ptr,
    size_t team_id_len
);

int32_t grdr_macos_follower_register_self_pid(
    GrdrMacEsFollower* follower,
    uint32_t pid
);

int32_t grdr_macos_follower_add_protected_path(
    GrdrMacEsFollower* follower,
    const uint8_t* path_ptr,
    size_t path_len
);

int32_t grdr_macos_follower_add_self_path(
    GrdrMacEsFollower* follower,
    const uint8_t* path_ptr,
    size_t path_len
);

int32_t grdr_macos_follower_lookup_token(
    const GrdrMacEsFollower* follower,
    uint32_t pid,
    uint32_t pidversion,
    GrdrMacTokenLookupOutC* out_info
);

int32_t grdr_macos_eval_es_event_c(
    GrdrMacEsFollower* follower,
    const GrdrMacEsEventC* event,
    const GrdrMacFloorRuleC* floor_rules,
    size_t floor_len,
    GrdrMacEsVerdictC* out_verdict
);

int32_t grdr_macos_eval_es_event_bin_c(
    GrdrMacEsFollower* follower,
    const GrdrMacEsEventC* event,
    const uint8_t* floor_bin_ptr,
    size_t floor_bin_len,
    GrdrMacEsVerdictC* out_verdict
);

int32_t grdr_macos_eval_ne_flow_c(
    const GrdrMacNeFlowC* flow,
    const GrdrMacFloorRuleC* floor_rules,
    size_t floor_len,
    GrdrMacNeVerdictC* out_verdict
);

int32_t grdr_macos_eval_ne_flow_bin_c(
    const GrdrMacNeFlowC* flow,
    const uint8_t* floor_bin_ptr,
    size_t floor_bin_len,
    GrdrMacNeVerdictC* out_verdict
);

int32_t grdr_macos_peek_tls_sni_c(
    const uint8_t* bytes_ptr,
    size_t bytes_len,
    GrdrMacTlsSniOutC* out_sni
);

int32_t grdr_macos_parse_dns_packet_c(
    const uint8_t* pkt_ptr,
    size_t pkt_len,
    GrdrMacDnsParseOutC* out_dns
);

int32_t grdr_macos_match_model_host_c(
    const uint8_t* host_ptr,
    size_t host_len,
    uint8_t* out_matched
);

int32_t grdr_macos_probe_capabilities_c(GrdrMacCapabilitiesC* out_caps);

int32_t grdr_macos_probe_capabilities_with_follower_c(
    const GrdrMacEsFollower* follower,
    GrdrMacCapabilitiesC* out_caps
);

int32_t grdr_macos_self_signing_info_c(
    uint8_t* out_team_ptr,
    size_t team_cap,
    size_t* out_team_len,
    uint8_t* out_es_entitled
);

int32_t grdr_macos_plan_seatbelt_c(
    const GrdrMacSeatbeltRequestC* req,
    GrdrMacSeatbeltPlanC* out_plan
);

#ifdef __cplusplus
}
#endif

#endif
