// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_model::api::TrustedKeyInfo;
use grdr_wire::endpoint::{PathComponentFact, PathExpectation, PathNodeKind, check_path};
use grdr_wire::floor_bin::{MAX_FLOOR_RULES, verify_and_decode_floor_table};
use grdr_wire::frame::{
    CreditFlow, WirePayload, decode_proto_frame, decode_proto_payload, encode_proto_frame,
};
use grdr_wire::peer_auth::Profile;
use grdr_wire::{WireEnvelope, decode_frame, encode_frame, verify_envelope};
use libfuzzer_sys::fuzz_target;

const RFC8032_VEC1_PUBKEY_B64: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }
    let trusted = [TrustedKeyInfo {
        key_id: "fuzz-wire-k1".to_string(),
        public_key_b64: RFC8032_VEC1_PUBKEY_B64.to_string(),
    }];
    let pub_refs = [("fuzz-wire-k1", RFC8032_VEC1_PUBKEY_B64)];

    assert!(verify_and_decode_floor_table(data, &[], 1_750_000_000).is_err());
    if let Ok(verified) = verify_and_decode_floor_table(data, &pub_refs, 1_750_000_000) {
        assert!(verified.document.rules.len() <= MAX_FLOOR_RULES);
    }

    if let Ok((envelope, consumed)) = decode_frame::<serde_json::Value>(data) {
        assert!(consumed <= data.len());
        assert!(verify_envelope(&envelope, &[]).is_err());
        if let Ok(encoded) = encode_frame(&envelope)
            && let Ok((roundtrip, _)) = decode_frame::<serde_json::Value>(&encoded)
        {
            assert_eq!(roundtrip.payload, envelope.payload);
        }
        match verify_envelope(&envelope, &trusted) {
            Ok(()) | Err(_) => {}
        }
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(env) = serde_json::from_str::<WireEnvelope<serde_json::Value>>(text)
    {
        assert!(verify_envelope(&env, &[]).is_err());
        match verify_envelope(&env, &trusted) {
            Ok(()) | Err(_) => {}
        }
    }

    if let Ok((frame, consumed)) = decode_proto_frame(data, 1_048_576) {
        assert!(consumed <= data.len());
        if let Ok(encoded) = encode_proto_frame(&frame, 1_048_576)
            && let Ok((roundtrip, c2)) = decode_proto_frame(&encoded, 1_048_576)
        {
            assert_eq!(c2, encoded.len());
            assert_eq!(roundtrip.stream_id, frame.stream_id);
            assert_eq!(roundtrip.seq, frame.seq);
        }
        let mut zero_flow = CreditFlow::new(0);
        if matches!(
            frame.payload,
            Some(WirePayload::DecideRequest(_) | WirePayload::Heartbeat(_))
        ) {
            assert!(zero_flow.try_consume_send(&frame).is_ok());
        }
        let mut flow = CreditFlow::new(2);
        match flow.record_inbound(&frame) {
            Ok(()) | Err(_) => {}
        }
        match flow.try_consume_send(&frame) {
            Ok(()) | Err(_) => {}
        }
    }
    match decode_proto_payload(data, 1_048_576) {
        Ok(_) | Err(_) => {}
    }

    if let Some(&first_mode) = data.first() {
        let res = check_path(
            &[
                PathComponentFact {
                    path: "/".into(),
                    is_leaf: false,
                    node_kind: PathNodeKind::Directory,
                    owner_uid: 0,
                    gid: 0,
                    posix_mode: 0o755,
                    dev: 1,
                    ino: 1,
                    post_dev: 1,
                    post_ino: 1,
                },
                PathComponentFact {
                    path: "/run".into(),
                    is_leaf: false,
                    node_kind: PathNodeKind::Directory,
                    owner_uid: 0,
                    gid: 0,
                    posix_mode: u32::from(first_mode) | 0o700,
                    dev: 1,
                    ino: 2,
                    post_dev: 1,
                    post_ino: 2,
                },
                PathComponentFact {
                    path: "/run/decide.sock".into(),
                    is_leaf: true,
                    node_kind: PathNodeKind::Socket,
                    owner_uid: 0,
                    gid: 0,
                    posix_mode: 0o600,
                    dev: 1,
                    ino: 3,
                    post_dev: 1,
                    post_ino: 3,
                },
            ],
            &PathExpectation {
                profile: Profile::Protected,
                trusted_owner_uids: vec![0],
                trusted_group_gids: vec![0],
                allow_world_writable_socket_leaf: false,
            },
        );
        if (u32::from(first_mode) & 0o002) != 0 {
            assert!(res.is_err());
        }
    }
});
