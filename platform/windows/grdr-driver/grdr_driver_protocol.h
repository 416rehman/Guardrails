// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#ifndef GRDR_DRIVER_PROTOCOL_H
#define GRDR_DRIVER_PROTOCOL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GRDR_DRIVER_PROTOCOL_MAGIC_BYTES { 'G', 'R', 'D', 'R', 'W', 'M', '0', '1' }
#define GRDR_DRIVER_PROTOCOL_VERSION 1u
#define GRDR_DRIVER_REPLY_DEADLINE_MS 50u
#define GRDR_MAX_DRIVER_PAYLOAD_LEN (64u * 1024u)
#define GRDR_MAX_EARLY_BUGCHECKS 2u

#define GRDR_MSG_PROCESS_CREATE 1u
#define GRDR_MSG_FILE_PRE_CREATE 2u
#define GRDR_MSG_WFP_CONNECT 3u
#define GRDR_MSG_FLOOR_VERDICT 4u

#define GRDR_VERDICT_ALLOW 0u
#define GRDR_VERDICT_DENY 1u
#define GRDR_VERDICT_ASK 2u

#define GRDR_PORT_NAME L"\\GrdrDriverPort"
#define GRDR_ALTITUDE_PLACEHOLDER L"325900"

typedef struct GrdrDriverProtocolHeader {
    uint8_t magic[8];
    uint32_t version;
    uint32_t message_kind;
    uint32_t payload_len;
    uint32_t reply_deadline_ms;
} GrdrDriverProtocolHeader;

typedef struct GrdrDriverVerdictReply {
    GrdrDriverProtocolHeader header;
    uint32_t verdict;
    uint32_t flags;
} GrdrDriverVerdictReply;

#ifdef __cplusplus
}
#endif

#endif
