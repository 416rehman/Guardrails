// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Registered `grdr-wire` error codes (`contracts/codes/registry.toml`, `ARCH-017`).

pub const CODE_WIRE_FRAME_TOO_LARGE: &str = "GRDR-WIRE-0001";
pub const CODE_WIRE_TRUNCATED_FRAME: &str = "GRDR-WIRE-0002";
pub const CODE_WIRE_INVALID_MAGIC: &str = "GRDR-WIRE-0003";
pub const CODE_WIRE_UNSUPPORTED_VERSION: &str = "GRDR-WIRE-0004";
pub const CODE_WIRE_CODEC: &str = "GRDR-WIRE-0005";
pub const CODE_WIRE_CRYPTO: &str = "GRDR-WIRE-0006";
pub const CODE_WIRE_REPLAY_DETECTED: &str = "GRDR-WIRE-0007";
pub const CODE_WIRE_EXPIRED_TIMESTAMP: &str = "GRDR-WIRE-0008";
pub const CODE_WIRE_IPC_LIMITS_UNAVAILABLE: &str = "GRDR-WIRE-0009";
pub const CODE_WIRE_IPC_FRAME_TOO_LARGE: &str = "GRDR-WIRE-0010";
pub const CODE_WIRE_IPC_TRUNCATED_FRAME: &str = "GRDR-WIRE-0011";
pub const CODE_WIRE_IPC_ZERO_LENGTH: &str = "GRDR-WIRE-0012";
pub const CODE_WIRE_IPC_INVALID_PROTOBUF: &str = "GRDR-WIRE-0013";
pub const CODE_WIRE_IPC_EMPTY_PAYLOAD: &str = "GRDR-WIRE-0014";
pub const CODE_WIRE_IPC_CREDIT_EXHAUSTED: &str = "GRDR-WIRE-0015";
pub const CODE_WIRE_IPC_CREDIT_OVERFLOW: &str = "GRDR-WIRE-0016";
pub const CODE_WIRE_IPC_PROTOCOL_VERSION: &str = "GRDR-WIRE-0017";
pub const CODE_WIRE_PEER_UNSAFE_PATH: &str = "GRDR-WIRE-0018";
pub const CODE_WIRE_PEER_FOREIGN_UID: &str = "GRDR-WIRE-0019";
pub const CODE_WIRE_PEER_PID_REUSE: &str = "GRDR-WIRE-0020";
pub const CODE_WIRE_PEER_UNAUTHENTICATED: &str = "GRDR-WIRE-0021";
pub const CODE_WIRE_PEER_UNTRUSTED_SERVER: &str = "GRDR-WIRE-0022";
pub const CODE_WIRE_PEER_PRIVILEGE_TOO_LOW: &str = "GRDR-WIRE-0023";
pub const CODE_WIRE_PEER_PROTOCOL_REJECTED: &str = "GRDR-WIRE-0024";
pub const CODE_WIRE_PEER_PROFILE_MISMATCH: &str = "GRDR-WIRE-0025";
pub const CODE_WIRE_FLOOR_TRUNCATED: &str = "GRDR-WIRE-0026";
pub const CODE_WIRE_FLOOR_INVALID_HEADER: &str = "GRDR-WIRE-0027";
pub const CODE_WIRE_FLOOR_TOO_MANY_RULES: &str = "GRDR-WIRE-0028";
pub const CODE_WIRE_FLOOR_MALFORMED_FIELD: &str = "GRDR-WIRE-0029";
pub const CODE_WIRE_FLOOR_UNTRUSTED_SIGNATURE: &str = "GRDR-WIRE-0030";
pub const CODE_WIRE_FLOOR_EXPIRED: &str = "GRDR-WIRE-0031";
pub const CODE_WIRE_FLOOR_TOO_LARGE: &str = "GRDR-WIRE-0033";
pub const CODE_WIRE_FLOOR_EMPTY_KEYS: &str = "GRDR-WIRE-0034";
pub const CODE_WIRE_PEER_TRANSIENT_RESTART: &str = "GRDR-WIRE-0035";
pub const CODE_WIRE_IPC_END_OF_STREAM: &str = "GRDR-WIRE-0036";
pub const CODE_WIRE_IPC_TIMED_OUT: &str = "GRDR-WIRE-0037";
pub const CODE_WIRE_IPC_IO: &str = "GRDR-WIRE-0038";
pub const CODE_WIRE_EGRESS_BLOCKED: &str = "GRDR-WIRE-0039";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_codes_match_registry_toml() {
        let reg = include_str!("../../../contracts/codes/registry.toml");
        for code in [
            CODE_WIRE_FRAME_TOO_LARGE,
            CODE_WIRE_TRUNCATED_FRAME,
            CODE_WIRE_INVALID_MAGIC,
            CODE_WIRE_UNSUPPORTED_VERSION,
            CODE_WIRE_CODEC,
            CODE_WIRE_CRYPTO,
            CODE_WIRE_REPLAY_DETECTED,
            CODE_WIRE_EXPIRED_TIMESTAMP,
            CODE_WIRE_IPC_LIMITS_UNAVAILABLE,
            CODE_WIRE_IPC_FRAME_TOO_LARGE,
            CODE_WIRE_IPC_TRUNCATED_FRAME,
            CODE_WIRE_IPC_ZERO_LENGTH,
            CODE_WIRE_IPC_INVALID_PROTOBUF,
            CODE_WIRE_IPC_EMPTY_PAYLOAD,
            CODE_WIRE_IPC_CREDIT_EXHAUSTED,
            CODE_WIRE_IPC_CREDIT_OVERFLOW,
            CODE_WIRE_IPC_PROTOCOL_VERSION,
            CODE_WIRE_PEER_UNSAFE_PATH,
            CODE_WIRE_PEER_FOREIGN_UID,
            CODE_WIRE_PEER_PID_REUSE,
            CODE_WIRE_PEER_UNAUTHENTICATED,
            CODE_WIRE_PEER_UNTRUSTED_SERVER,
            CODE_WIRE_PEER_PRIVILEGE_TOO_LOW,
            CODE_WIRE_PEER_PROTOCOL_REJECTED,
            CODE_WIRE_PEER_PROFILE_MISMATCH,
            CODE_WIRE_FLOOR_TRUNCATED,
            CODE_WIRE_FLOOR_INVALID_HEADER,
            CODE_WIRE_FLOOR_TOO_MANY_RULES,
            CODE_WIRE_FLOOR_MALFORMED_FIELD,
            CODE_WIRE_FLOOR_UNTRUSTED_SIGNATURE,
            CODE_WIRE_FLOOR_EXPIRED,
            CODE_WIRE_FLOOR_TOO_LARGE,
            CODE_WIRE_FLOOR_EMPTY_KEYS,
            CODE_WIRE_PEER_TRANSIENT_RESTART,
            CODE_WIRE_IPC_END_OF_STREAM,
            CODE_WIRE_IPC_TIMED_OUT,
            CODE_WIRE_IPC_IO,
            CODE_WIRE_EGRESS_BLOCKED,
        ] {
            assert!(
                reg.contains(&format!("{code} =")),
                "{code} missing from contracts/codes/registry.toml"
            );
        }
    }
}
