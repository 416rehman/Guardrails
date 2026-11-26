// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_update::{
    DsseEnvelope, DsseLimits, RootMetadata, SignedMetadata, SnapshotMetadata, TargetsMetadata,
    TimestampMetadata, UpdateTrust, dsse_pae, verify_dsse_envelope_with_limits,
};
use jiff::Timestamp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }
    let _ = dsse_pae("application/vnd.grdr.pack-manifest+json", data);
    if let Ok(env) = serde_json::from_slice::<DsseEnvelope>(data) {
        let limits = DsseLimits {
            max_payload_bytes: 64 * 1024,
        };
        let _ = env.decode_payload_with_limits(&limits);
        let _ = verify_dsse_envelope_with_limits(&env, &[], 1, &limits);
    }
    if let Ok(root) = serde_json::from_slice::<SignedMetadata<RootMetadata>>(data) {
        let _ = UpdateTrust::new(root, Timestamp::UNIX_EPOCH);
    }
    let _ = serde_json::from_slice::<SignedMetadata<TargetsMetadata>>(data);
    let _ = serde_json::from_slice::<SignedMetadata<SnapshotMetadata>>(data);
    let _ = serde_json::from_slice::<SignedMetadata<TimestampMetadata>>(data);
});
