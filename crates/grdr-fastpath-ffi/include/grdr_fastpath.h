// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#ifndef GRDR_FASTPATH_H
#define GRDR_FASTPATH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum GrdrFastStatus {
    GRDR_FAST_OK = 0,
    GRDR_FAST_ERR_NULL_PTR = -1,
    GRDR_FAST_ERR_INVALID_ARG = -2,
    GRDR_FAST_ERR_INVALID_UTF8 = -3,
    GRDR_FAST_ERR_LIMIT_EXCEEDED = -4,
    GRDR_FAST_ERR_NOT_EVALUABLE = -5,
    GRDR_FAST_ERR_STATE = -6
} GrdrFastStatus;

typedef enum GrdrFastVerdict {
    GRDR_FAST_VERDICT_ALLOW = 0,
    GRDR_FAST_VERDICT_STEP_UP = 1,
    GRDR_FAST_VERDICT_DENY = 2
} GrdrFastVerdict;

enum {
    GRDR_FP_REQ_USER_IDENTITY = 1u << 0,
    GRDR_FP_REQ_OS_FILE_SENSOR = 1u << 1,
    GRDR_FP_REQ_NET_EGRESS_SENSOR = 1u << 2,
    GRDR_FP_REQ_COMMAND_PARSER = 1u << 3,
    GRDR_FP_REQ_SESSION_STORE = 1u << 4
};

typedef struct GrdrFastRuleC {
    size_t struct_size;
    const uint8_t* rule_id_ptr;
    size_t rule_id_len;
    uint32_t action_mask;
    const uint8_t* needle_ptr;
    size_t needle_len;
    uint8_t verdict;
} GrdrFastRuleC;

typedef struct GrdrFpHostProfileC {
    size_t struct_size;
    uint8_t principal_attestation;
    uint8_t user_identity;
    uint8_t os_file_sensor;
    uint8_t net_egress_sensor;
    uint8_t command_parser;
    uint8_t session_store;
} GrdrFpHostProfileC;

int32_t grdr_fastpath_eval_rules(
    uint8_t action_code,
    const uint8_t* agent_ptr,
    size_t agent_len,
    const uint8_t* target_ptr,
    size_t target_len,
    const GrdrFastRuleC* rules_ptr,
    size_t rules_len,
    uint8_t* out_verdict,
    size_t* out_matched_index
);

int32_t grdr_fastpath_assess_host_profile(
    const GrdrFpHostProfileC* profile,
    uint8_t req_mask
);

#ifdef __cplusplus
}
#endif

#endif
