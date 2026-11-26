// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#ifndef GRDR_SENSOR_MACOS_H
#define GRDR_SENSOR_MACOS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct GrdrMacEsFollower GrdrMacEsFollower;

uint32_t grdr_macos_abi_version(void);
GrdrMacEsFollower* grdr_macos_follower_new(void);
void grdr_macos_follower_free(GrdrMacEsFollower* ptr);

char* grdr_macos_apply_es_event(
    GrdrMacEsFollower* follower,
    const uint8_t* event_json_ptr,
    size_t event_json_len
);

char* grdr_macos_follower_mute_team(
    GrdrMacEsFollower* follower,
    const uint8_t* team_id_ptr,
    size_t team_id_len
);

char* grdr_macos_eval_es_auth_exec(
    GrdrMacEsFollower* follower,
    const uint8_t* event_json_ptr,
    size_t event_json_len,
    const uint8_t* floor_json_ptr,
    size_t floor_json_len,
    uint8_t default_deny
);

char* grdr_macos_eval_ne_flow(
    const uint8_t* flow_json_ptr,
    size_t flow_json_len,
    const uint8_t* floor_json_ptr,
    size_t floor_json_len,
    uint8_t default_deny
);

char* grdr_macos_plan_seatbelt(
    const uint8_t* agent_ptr,
    size_t agent_len,
    uint8_t own_seatbelt,
    const uint8_t* spec_json_ptr,
    size_t spec_json_len
);

char* grdr_macos_probe_capabilities(void);
void grdr_macos_free_string(char* ptr);

#ifdef __cplusplus
}
#endif

#endif
