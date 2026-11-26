// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_model::api::TrustedKeyInfo;
use grdr_update::{
    DsseEnvelope, DsseLimits, FreshnessStatement, RootMetadata, SignedMetadata, SnapshotMetadata,
    TargetsMetadata, TimestampMetadata, TufRootKind, UpdateTrust, dsse_pae,
    verify_dsse_envelope_with_limits,
};
use jiff::Timestamp;
use libfuzzer_sys::fuzz_target;

const RFC8032_VEC1_PUBKEY_B64: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

fn split_chunks(mut data: &[u8], count: usize) -> Vec<&[u8]> {
    let mut chunks = Vec::with_capacity(count);
    for idx in 0..count {
        if idx.saturating_add(1) == count || data.len() < 2 {
            chunks.push(data);
            data = &[];
        } else {
            let requested = usize::from(u16::from_le_bytes([data[0], data[1]]));
            let rest = &data[2..];
            let take = requested.min(rest.len());
            chunks.push(&rest[..take]);
            data = &rest[take..];
        }
    }
    chunks
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }
    let chunks = split_chunks(data, 6);
    let c_root = chunks[0];
    let c_ts = chunks[1];
    let c_snap = chunks[2];
    let c_targets = chunks[3];
    let c_dsse = chunks[4];
    let c_fresh = chunks[5];

    let pae = dsse_pae("application/vnd.grdr.pack-manifest+json", c_dsse);
    assert!(pae.starts_with(b"DSSEv1 "));

    let limits = DsseLimits {
        max_payload_bytes: 64 * 1024,
    };
    let pinned_key = TrustedKeyInfo {
        key_id: "fuzz-key-1".to_string(),
        public_key_b64: RFC8032_VEC1_PUBKEY_B64.to_string(),
    };

    if let Ok(env) = serde_json::from_slice::<DsseEnvelope>(c_dsse) {
        if let Ok(decoded) = env.decode_payload_with_limits(&limits) {
            assert!(decoded.len() <= limits.max_payload_bytes);
        }
        assert!(verify_dsse_envelope_with_limits(&env, &[], 1, &limits).is_err());
        match verify_dsse_envelope_with_limits(&env, std::slice::from_ref(&pinned_key), 1, &limits)
        {
            Ok(_) | Err(_) => {}
        }
    }

    let now = Timestamp::UNIX_EPOCH;
    if let Ok(root) = serde_json::from_slice::<SignedMetadata<RootMetadata>>(c_root) {
        let root_keys: Vec<TrustedKeyInfo> = root.signed.keys.values().cloned().collect();
        if let Ok(env) = serde_json::from_slice::<DsseEnvelope>(c_dsse) {
            match verify_dsse_envelope_with_limits(&env, &root_keys, 1, &limits) {
                Ok(_) | Err(_) => {}
            }
        }
        if let Ok(mut trust) = UpdateTrust::new(root.clone(), now) {
            match trust.rotate_root(TufRootKind::Project, root, now) {
                Ok(()) | Err(_) => {}
            }
            let fresh_opt =
                serde_json::from_slice::<SignedMetadata<FreshnessStatement>>(c_fresh).ok();
            if let (Ok(ts), Ok(snap), Ok(targets)) = (
                serde_json::from_slice::<SignedMetadata<TimestampMetadata>>(c_ts),
                serde_json::from_slice::<SignedMetadata<SnapshotMetadata>>(c_snap),
                serde_json::from_slice::<SignedMetadata<TargetsMetadata>>(c_targets),
            ) {
                match trust.verify_project_chain(
                    &ts,
                    &snap,
                    &targets,
                    None,
                    fresh_opt.as_ref(),
                    now,
                ) {
                    Ok(_) | Err(_) => {}
                }
            }
        }
    }

    if let Ok(stmt) = serde_json::from_slice::<SignedMetadata<FreshnessStatement>>(c_fresh)
        && let Ok(encoded) = serde_json::to_vec(&stmt)
    {
        assert!(!encoded.is_empty());
    }
});
