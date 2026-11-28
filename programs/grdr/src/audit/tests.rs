// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Independent audit verifier unit, NIST vector, tamper, and isolation tests (`04-15`).

use std::fs;

use grdr_model::{ActionClass, AuditLane, ControlPoint, DecisionReceipt, Mode, Verdict};
use jiff::Timestamp;
use serde_json::{Map, Value, json};

use super::commitments::{build_five_way_commitments, compute_commitment_root_digest};
use super::json_strict::canonical_json_bytes;
use super::lane_chain::{compute_lane_entry_hash, lane_genesis_hash};
use super::merkle::{merkle_consistency_proof, merkle_inclusion_proof, merkle_root_hex};
use super::sha256::{Sha256, constant_time_eq, sha256_hex};
use super::types::{GENESIS_PREV_HASH, LaneEntryKind};
use super::verify_chain::{compute_chain_hash, compute_receipt_digest};
use super::{
    AuditLogFormat, ExpectedAuditAnchor, MAX_AUDIT_LINE_BYTES, default_daemon_wal_path,
    resolve_default_audit_path_for, verify_and_collect_observations, verify_audit_file,
    verify_audit_file_with_anchor,
};

const TEST_SALTS: [[u8; 32]; 5] = [[0xA1; 32], [0xB2; 32], [0xC3; 32], [0xD4; 32], [0xE5; 32]];

fn make_chained_line(seq: u64, prev_hash: &str, event: &str) -> (String, String) {
    let mut obj = Map::new();
    obj.insert("seq".into(), json!(seq));
    obj.insert("prev_hash".into(), json!(prev_hash));
    obj.insert("event".into(), json!(event));
    let canonical = canonical_json_bytes(0, &Value::Object(obj.clone())).unwrap();
    let entry_hash = compute_chain_hash(prev_hash, &canonical);
    obj.insert("entry_hash".into(), json!(entry_hash));
    (
        serde_json::to_string(&Value::Object(obj)).unwrap(),
        entry_hash,
    )
}

fn expected_anchor(dev: &str, ep: u64, head: &str) -> ExpectedAuditAnchor {
    ExpectedAuditAnchor {
        device_id: Some(dev.into()),
        epoch: Some(ep),
        head_hash: Some(head.into()),
    }
}

fn expected_anchor_head(head: &str) -> ExpectedAuditAnchor {
    ExpectedAuditAnchor {
        device_id: None,
        epoch: None,
        head_hash: Some(head.to_owned()),
    }
}

fn build_sample_receipt(target: &str) -> DecisionReceipt {
    let ts = Timestamp::from_second(1_700_000_000).unwrap();
    let mut receipt = DecisionReceipt {
        receipt_id: String::new(),
        attempt_id: "att-1".into(),
        session_id: "sess-1".into(),
        device_id: "dev-1".into(),
        agent_name: "claude-code".into(),
        action_class: ActionClass::Exec,
        control_point: ControlPoint::Hook,
        target: target.into(),
        verdict: Verdict::Deny,
        would_be: None,
        rule_id: Some("essentials.git-safety".into()),
        pack_id: Some("pack-essentials-slice0".into()),
        mode_applied: Some(Mode::Block),
        grant_id: None,
        reason: "Blocked commit bypass flag.".into(),
        next_step: "Run without --no-verify.".into(),
        receipt_digest: String::new(),
        decided_at: ts,
        key_id: None,
        signature: None,
        signature_verified: None,
    };
    let digest = compute_receipt_digest(&receipt);
    receipt.receipt_id = format!("rcp_{}", digest.get(..32).unwrap_or(""));
    receipt.receipt_digest = digest;
    receipt
}

fn flip_single_byte_in_json_text(text: &str, needle: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let pos = text.find(needle).unwrap();
    bytes[pos] ^= 0x01;
    String::from_utf8(bytes).unwrap()
}

fn make_chained_pair() -> (String, String, String) {
    let mut obj = Map::new();
    obj.insert("seq".into(), json!(0));
    obj.insert("prev_hash".into(), json!(GENESIS_PREV_HASH));
    obj.insert("event".into(), json!("boot"));
    let canonical = canonical_json_bytes(0, &Value::Object(obj)).unwrap();
    let entry_hash = compute_chain_hash(GENESIS_PREV_HASH, &canonical);
    let line = json!({
        "seq": 0,
        "prev_hash": GENESIS_PREV_HASH,
        "entry_hash": entry_hash,
        "event": "boot"
    })
    .to_string();
    (GENESIS_PREV_HASH.into(), entry_hash, line)
}

#[test]
fn independent_verifier_contains_zero_grdr_core_or_grdr_crypto_references() {
    let sources = [
        ("sha256.rs", include_str!("sha256.rs")),
        ("types.rs", include_str!("types.rs")),
        ("verify_chain.rs", include_str!("verify_chain.rs")),
        ("commitments.rs", include_str!("commitments.rs")),
        ("merkle.rs", include_str!("merkle.rs")),
        ("lane.rs", include_str!("lane.rs")),
        ("lane_chain.rs", include_str!("lane_chain.rs")),
        ("json_strict.rs", include_str!("json_strict.rs")),
        ("mod.rs", include_str!("mod.rs")),
        ("tests.rs", include_str!("tests.rs")),
    ];
    let forbidden_paths = [
        format!("{}_core::", "grdr"),
        format!("{}_crypto::", "grdr"),
        format!("{}::", "sha2"),
        format!("{}::", "subtle"),
    ];
    let forbidden_prod_tokens = [format!("{}_core", "grdr"), format!("{}_crypto", "grdr")];
    for (name, body) in sources {
        for needle in &forbidden_paths {
            assert!(
                !body.contains(needle.as_str()),
                "audit verifier file `{name}` must stay strictly isolated from `{needle}`"
            );
        }
        if name != "tests.rs" {
            for needle in &forbidden_prod_tokens {
                assert!(
                    !body.contains(needle.as_str()),
                    "audit verifier file `{name}` must stay strictly isolated from `{needle}`"
                );
            }
        }
    }
}

#[test]
fn standalone_sha256_matches_nist_fips_180_4_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    let mut streaming = Sha256::new();
    streaming.update(b"abcdbcdecdef");
    streaming.update(b"defgefghfghighij");
    streaming.update(b"hijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
        streaming.finalize_hex(),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    assert!(constant_time_eq(b"digest-a", b"digest-a"));
    assert!(!constant_time_eq(b"digest-a", b"digest-b"));
    assert!(!constant_time_eq(b"digest-a", b"digest-ab"));
}

#[test]
fn verify_audit_file_validates_hash_chain_and_rejects_mixed_symlink_dup_keys() {
    let dir = std::env::temp_dir().join(format!("grdr-audit-cli-{}", uuid::Uuid::now_v7()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");

    let (l0, h0) = make_chained_line(0, GENESIS_PREV_HASH, "session.start");
    let (l1, h1) = make_chained_line(1, &h0, "decision.receipt");
    fs::write(&path, format!("{l0}\n{l1}\n")).unwrap();

    let ok = verify_audit_file(&path).unwrap();
    assert!(ok.verified);
    assert_eq!(ok.entries, 2);
    assert_eq!(ok.format, AuditLogFormat::HashChain);
    assert_eq!(ok.head_hash, h1);
    assert_eq!(
        verify_audit_file_with_anchor(
            &path,
            Some(&ExpectedAuditAnchor {
                head_hash: Some(h0.clone()),
                ..Default::default()
            })
        )
        .unwrap_err()
        .code(),
        "GRDR-AUDIT-0005"
    );

    let flipped_l1 = flip_single_byte_in_json_text(&l1, "decision.receipt");
    fs::write(&path, format!("{l0}\n{flipped_l1}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0005"
    );

    let dup_line = format!(
        "{{\"seq\":0,\"seq\":1,\"prev_hash\":\"{GENESIS_PREV_HASH}\",\"entry_hash\":\"{h0}\"}}"
    );
    fs::write(&path, format!("{dup_line}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );

    let bogus_lane = format!(
        "{{\"lane\":\"event\",\"epoch\":1,\"seq\":1,\"prev_hash\":\"{h0}\",\"entry_hash\":\"{h1}\"}}"
    );
    fs::write(&path, format!("{l0}\n{bogus_lane}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );

    let dir_as_file = dir.join("subdir");
    fs::create_dir_all(&dir_as_file).unwrap();
    assert_eq!(
        verify_audit_file(&dir_as_file).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );

    fs::write(&path, "").unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0002"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn verify_audit_file_validates_receipt_wal_and_preserves_line_numbers() {
    let dir = std::env::temp_dir().join(format!("grdr-audit-wal-{}", uuid::Uuid::now_v7()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipts.wal.jsonl");

    let mut receipt = build_sample_receipt("git commit --no-verify");
    let l1 = serde_json::to_string(&receipt).unwrap();
    receipt.receipt_id = "rcp_secret_must_not_leak".into();
    let l3 = serde_json::to_string(&receipt).unwrap();
    fs::write(&path, format!("{l1}\n\n{l3}\n")).unwrap();
    let err = verify_audit_file(&path).unwrap_err();
    assert_eq!(err.code(), "GRDR-AUDIT-0005");
    assert!(
        err.to_string().contains("line 3"),
        "expected physical line 3: {err}"
    );
    assert!(!err.to_string().contains("rcp_secret_must_not_leak"));

    fs::write(&path, format!("{l1}\n")).unwrap();
    let ok = verify_audit_file(&path).unwrap();
    assert_eq!(ok.format, AuditLogFormat::ReceiptWal);

    let wal_ok =
        verify_audit_file_with_anchor(&path, Some(&expected_anchor_head(&ok.head_hash))).unwrap();
    assert_eq!(wal_ok.head_hash, ok.head_hash);

    let flipped_wal = flip_single_byte_in_json_text(&l1, "claude-code");
    fs::write(&path, format!("{flipped_wal}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0005"
    );

    fs::write(&path, format!("{l1}\n")).unwrap();
    assert_eq!(
        verify_audit_file_with_anchor(&path, Some(&expected_anchor_head(GENESIS_PREV_HASH)))
            .unwrap_err()
            .code(),
        "GRDR-AUDIT-0005"
    );
    let bad_head_err =
        verify_audit_file_with_anchor(&path, Some(&expected_anchor_head("WAL_SECRET_BAD_DIGEST")))
            .unwrap_err();
    assert_eq!(bad_head_err.code(), "GRDR-AUDIT-0003");
    assert!(!bad_head_err.to_string().contains("WAL_SECRET_BAD_DIGEST"));
    assert_eq!(
        verify_audit_file_with_anchor(
            &path,
            Some(&ExpectedAuditAnchor {
                device_id: Some("dev-1".into()),
                epoch: None,
                head_hash: None,
            }),
        )
        .unwrap_err()
        .code(),
        "GRDR-AUDIT-0010"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn verify_audit_file_validates_reduced_copy_from_chained_full_and_rejects_smuggling() {
    let dir = std::env::temp_dir().join(format!("grdr-audit-lane-{}", uuid::Uuid::now_v7()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("lane.jsonl");

    let salts = [
        &TEST_SALTS[0][..],
        &TEST_SALTS[1][..],
        &TEST_SALTS[2][..],
        &TEST_SALTS[3][..],
        &TEST_SALTS[4][..],
    ];
    let payloads = [
        &b"alice@org"[..],
        &b"exec"[..],
        &b"risk=high"[..],
        &b"cat /etc/passwd"[..],
        &b"body"[..],
    ];
    let full_comm = build_five_way_commitments(salts, payloads).unwrap();
    let root_digest = compute_commitment_root_digest(&full_comm).unwrap();
    let mut reduced_comm = full_comm.clone();
    reduced_comm.salt_identifier = None;
    reduced_comm.salt_argument = None;
    reduced_comm.salt_body = None;

    let genesis = lane_genesis_hash("dev-1", 1, AuditLane::Event, Some(GENESIS_PREV_HASH)).unwrap();
    let ev_kind = LaneEntryKind::Event {
        commitments: &full_comm,
        commitment_root_digest: &root_digest,
        payloads: [
            Some(payloads[0]),
            Some(payloads[1]),
            Some(payloads[2]),
            Some(payloads[3]),
            Some(payloads[4]),
        ],
        withheld_classes: None,
        merkle: None,
        merkle_consistency: None,
    };
    let h0 = compute_lane_entry_hash(&genesis, 1, AuditLane::Event, 0, &ev_kind).unwrap();

    let gap_kind = LaneEntryKind::Gap {
        start_seq: 1,
        end_seq: 2,
        dropped_count: 2,
        reason: "ringbuffer_drop",
    };
    let h_gap = compute_lane_entry_hash(&h0, 1, AuditLane::Event, 1, &gap_kind).unwrap();
    let h3 = compute_lane_entry_hash(&h_gap, 1, AuditLane::Event, 3, &ev_kind).unwrap();

    let leaves: [&[u8]; 3] = [h0.as_bytes(), root_digest.as_bytes(), h3.as_bytes()];
    let mroot2 = merkle_root_hex(&leaves[..2]);
    let mroot3 = merkle_root_hex(&leaves);
    let inc2 = merkle_inclusion_proof(&leaves, 2).unwrap();
    let cons23 = merkle_consistency_proof(&leaves, 2).unwrap();

    let l0_full = json!({
        "anchor": { "device_id": "dev-1", "epoch": 1, "prev_epoch_final_hash": GENESIS_PREV_HASH },
        "lane": "event",
        "epoch": 1,
        "seq": 0,
        "integrity": { "prev": genesis, "digest": h0, "commitments": full_comm, "commitment_root_digest": root_digest },
        "payloads": { "identifier": "alice@org", "structural": "exec", "derived": "risk=high", "content.argument": "cat /etc/passwd", "content.body": "body" },
        "capture_level": "full_content"
    });
    let l0_reduced_from_full = json!({
        "anchor": { "device_id": "dev-1", "epoch": 1, "prev_epoch_final_hash": GENESIS_PREV_HASH },
        "lane": "event",
        "epoch": 1,
        "seq": 0,
        "integrity": { "prev": genesis, "digest": h0, "commitments": reduced_comm, "commitment_root_digest": root_digest },
        "payloads": { "structural": "exec", "derived": "risk=high" },
        "capture_level": "metadata",
        "redaction": { "withheld_classes": ["identifier", "content.argument", "content.body"] }
    });
    let l_gap = json!({
        "lane": "event", "epoch": 1, "seq": 1, "kind": "gap",
        "prev_hash": h0, "entry_hash": h_gap,
        "gap": { "start_seq": 1, "end_seq": 2, "dropped_count": 2, "reason": "ringbuffer_drop" }
    });
    let l3 = json!({
        "lane": "event", "epoch": 1, "seq": 3, "prev_hash": h_gap, "entry_hash": h3,
        "commitments": full_comm, "commitment_root_digest": root_digest,
        "payloads": { "identifier": "alice@org", "structural": "exec", "derived": "risk=high", "content.argument": "cat /etc/passwd", "content.body": "body" },
        "merkle": { "leaf": h3, "leaf_index": 2, "tree_size": 3, "audit_path": inc2, "expected_root": mroot3 },
        "merkle_consistency": { "first_size": 2, "second_size": 3, "first_root": mroot2, "second_root": mroot3, "proof": cons23 }
    });

    fs::write(&path, format!("{l0_full}\n{l_gap}\n{l3}\n")).unwrap();
    let full_sum = verify_audit_file(&path).unwrap();
    assert_eq!(full_sum.head_hash, h3);

    fs::write(&path, format!("{l0_reduced_from_full}\n{l_gap}\n{l3}\n")).unwrap();
    let red_sum =
        verify_audit_file_with_anchor(&path, Some(&expected_anchor("dev-1", 1, &h3))).unwrap();
    assert_eq!(red_sum.head_hash, h3);

    let l0_red_text = serde_json::to_string(&l0_reduced_from_full).unwrap();
    let flipped_reduced = flip_single_byte_in_json_text(&l0_red_text, "risk=high");
    fs::write(&path, format!("{flipped_reduced}\n{l_gap}\n{l3}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0007"
    );

    let mut smuggled = l0_full.clone();
    smuggled["kind"] = json!("event");
    smuggled["gap"] = json!({ "start_seq": 0, "end_seq": 0, "dropped_count": 1, "reason": "x" });
    fs::write(&path, format!("{smuggled}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );

    let mut gap_with_merkle = l_gap.clone();
    gap_with_merkle["merkle"] = l3["merkle"].clone();
    fs::write(&path, format!("{l0_full}\n{gap_with_merkle}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0009"
    );

    let mut dual_hash = l3.clone();
    dual_hash["integrity"] = json!({ "prev": h_gap, "digest": h3 });
    fs::write(&path, format!("{dual_hash}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );

    let mut no_epoch = l3.clone();
    no_epoch.as_object_mut().unwrap().remove("epoch");
    fs::write(&path, format!("{no_epoch}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );

    let mut bad_anchor = l3.clone();
    bad_anchor["anchor"] =
        json!({ "device_id": "dev-2", "epoch": 1, "prev_epoch_final_hash": GENESIS_PREV_HASH });
    fs::write(&path, format!("{l0_full}\n{l_gap}\n{bad_anchor}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0010"
    );

    let bad_lane = json!({
        "anchor": { "device_id": "dev-1", "epoch": 1, "prev_epoch_final_hash": GENESIS_PREV_HASH },
        "lane": "SECRET_LANE_TOKEN",
        "epoch": 1,
        "seq": 0,
        "prev_hash": genesis,
        "entry_hash": h0,
        "commitments": reduced_comm,
        "commitment_root_digest": root_digest
    });
    fs::write(&path, format!("{bad_lane}\n")).unwrap();
    let lane_err = verify_audit_file(&path).unwrap_err();
    assert_eq!(lane_err.code(), "GRDR-AUDIT-0010");
    assert!(!lane_err.to_string().contains("SECRET_LANE_TOKEN"));

    let mut no_anchor = l0_full.clone();
    no_anchor.as_object_mut().unwrap().remove("anchor");
    fs::write(&path, format!("{no_anchor}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0010"
    );

    let mut l0_meta_no_red = l0_full.clone();
    l0_meta_no_red["capture_level"] = json!("metadata");
    l0_meta_no_red["payloads"] =
        json!({ "identifier": "alice@org", "structural": "exec", "derived": "risk=high" });
    l0_meta_no_red["integrity"]["commitments"] = {
        let mut m = full_comm.clone();
        m.salt_argument = None;
        m.salt_body = None;
        serde_json::to_value(m).unwrap()
    };
    fs::write(&path, format!("{l0_meta_no_red}\n")).unwrap();
    assert!(verify_audit_file(&path).is_ok());

    let mut l0_meta_undercut = l0_full.clone();
    l0_meta_undercut["capture_level"] = json!("metadata");
    l0_meta_undercut["redaction"] = json!({ "withheld_classes": [] });
    fs::write(&path, format!("{l0_meta_undercut}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );

    let mut l0_full_redacted = l0_full.clone();
    l0_full_redacted["capture_level"] = json!("full_content");
    l0_full_redacted["redaction"] = json!({ "withheld_classes": ["content.body"] });
    fs::write(&path, format!("{l0_full_redacted}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0007"
    );

    fs::write(&path, format!("{l0_full}\n")).unwrap();
    let (obs_sum, obs) = verify_and_collect_observations(&path).unwrap();
    assert_eq!(obs_sum.entries, 1);
    assert_eq!(obs.covered_observations, 1);
    assert_eq!(obs.sample_ids, vec![h0.clone()]);

    assert_eq!(
        verify_audit_file_with_anchor(&path, Some(&expected_anchor("other", 1, &h0)))
            .unwrap_err()
            .code(),
        "GRDR-AUDIT-0010"
    );
    assert_eq!(
        verify_audit_file_with_anchor(&path, Some(&expected_anchor("dev-1", 2, &h0)))
            .unwrap_err()
            .code(),
        "GRDR-AUDIT-0010"
    );
    assert_eq!(
        verify_audit_file_with_anchor(&path, Some(&expected_anchor("dev-1", 1, GENESIS_PREV_HASH)))
            .unwrap_err()
            .code(),
        "GRDR-AUDIT-0005"
    );

    let nested_dup = format!(
        "{{\"outer\":{{\"a\":1,\"a\":2}},\"lane\":\"event\",\"epoch\":1,\"seq\":0,\"prev_hash\":\"{genesis}\",\"entry_hash\":\"{h0}\"}}"
    );
    fs::write(&path, format!("{nested_dup}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );
    let esc_dup = format!(
        "{{\"outer\":{{\"a\":1,\"\\u0061\":2}},\"lane\":\"event\",\"epoch\":1,\"seq\":0,\"prev_hash\":\"{genesis}\",\"entry_hash\":\"{h0}\"}}"
    );
    fs::write(&path, format!("{esc_dup}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );
    fs::write(&path, format!("{l0_full} trailing\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );
    let deep = format!("{{\"x\":{}0{}}}", "[".repeat(70), "]".repeat(70));
    fs::write(&path, format!("{deep}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );
    fs::write(
        &path,
        format!("{{\"x\":\"{}\"}}\n", "a".repeat(MAX_AUDIT_LINE_BYTES + 16)),
    )
    .unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );

    let h1_b = compute_lane_entry_hash(&h0, 1, AuditLane::Event, 1, &ev_kind).unwrap();
    let l1_grow_no_proof = json!({
        "lane": "event", "epoch": 1, "seq": 1, "prev_hash": h0, "entry_hash": h1_b,
        "commitments": full_comm, "commitment_root_digest": root_digest,
        "payloads": { "identifier": "alice@org", "structural": "exec", "derived": "risk=high", "content.argument": "cat /etc/passwd", "content.body": "body" },
        "merkle": { "leaf": h1_b, "leaf_index": 2, "tree_size": 3, "audit_path": merkle_inclusion_proof(&[h0.as_bytes(), root_digest.as_bytes(), h1_b.as_bytes()], 2).unwrap(), "expected_root": merkle_root_hex(&[h0.as_bytes(), root_digest.as_bytes(), h1_b.as_bytes()]) }
    });
    let mut l0_with_m = l0_full.clone();
    l0_with_m["merkle"] = json!({
        "leaf": h0, "leaf_index": 0, "tree_size": 2,
        "audit_path": merkle_inclusion_proof(&[h0.as_bytes(), root_digest.as_bytes()], 0).unwrap(),
        "expected_root": mroot2
    });
    fs::write(&path, format!("{l0_with_m}\n{l1_grow_no_proof}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0008"
    );

    #[cfg(unix)]
    {
        let link_path = dir.join("sym.jsonl");
        std::os::unix::fs::symlink(&path, &link_path).unwrap();
        assert_eq!(
            verify_audit_file(&link_path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );
    }
    #[cfg(windows)]
    {
        let junc_dir = dir.join("junc_dir");
        let real_sub = dir.join("real_sub");
        fs::create_dir_all(&real_sub).unwrap();
        fs::write(real_sub.join("a.jsonl"), format!("{l0_full}\n")).unwrap();
        if std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junc_dir)
            .arg(&real_sub)
            .output()
            .is_ok_and(|o| o.status.success())
        {
            assert_eq!(
                verify_audit_file(&junc_dir.join("a.jsonl"))
                    .unwrap_err()
                    .code(),
                "GRDR-AUDIT-0003"
            );
        }
    }

    let mut forged_rid = l0_full.clone();
    forged_rid["receipt_id"] = json!("forged-rid");
    fs::write(&path, format!("{forged_rid}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );
    let mut forged_int = l0_full.clone();
    forged_int["integrity"]["bogus"] = json!(true);
    fs::write(&path, format!("{forged_int}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );
    let mixed_line2 = format!(
        "{{\"seq\":0,\"prev_hash\":\"{GENESIS_PREV_HASH}\",\"entry_hash\":\"{h0}\",\"lane\":\"event\"}}"
    );
    let (_, _, ch0_txt) = make_chained_pair();
    fs::write(&path, format!("{ch0_txt}\n{mixed_line2}\n")).unwrap();
    assert_eq!(
        verify_audit_file(&path).unwrap_err().code(),
        "GRDR-AUDIT-0003"
    );

    let mut bad_l2 = l3.clone();
    bad_l2["extra_untrusted"] = json!(1);
    fs::write(&path, format!("{l0_full}\n{l_gap}\n{bad_l2}\n")).unwrap();
    let l3_err = verify_audit_file(&path).unwrap_err();
    assert_eq!(l3_err.code(), "GRDR-AUDIT-0003");
    assert!(l3_err.to_string().contains("line 3"), "got: {l3_err}");

    let def_root = dir.join("default_home");
    let state_dir = def_root.join("state");
    let wal_base = dir.join("wal_base");
    let wal_file = default_daemon_wal_path(&def_root, Some(&wal_base));
    fs::create_dir_all(wal_file.parent().unwrap()).unwrap();
    fs::write(&wal_file, "wal\n").unwrap();
    assert_eq!(
        resolve_default_audit_path_for(&state_dir, &def_root, Some(&wal_base)).unwrap(),
        wal_file
    );
    fs::create_dir_all(&state_dir).unwrap();
    let chain_file = state_dir.join("audit.jsonl");
    fs::write(&chain_file, "chain\n").unwrap();
    assert_eq!(
        resolve_default_audit_path_for(&state_dir, &def_root, Some(&wal_base)).unwrap(),
        chain_file
    );
    #[cfg(unix)]
    {
        let _ = fs::remove_file(&chain_file);
        std::os::unix::fs::symlink(&wal_file, &chain_file).unwrap();
        assert_eq!(
            resolve_default_audit_path_for(&state_dir, &def_root, Some(&wal_base))
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0003"
        );
    }

    let wal_norm_path = dir.join("wal_target_strict.jsonl");
    let mut receipt = build_sample_receipt("https://pastebin.com/raw/secret");
    receipt.target = "HTTPS://PASTEBIN.COM/raw/secret".into();
    fs::write(
        &wal_norm_path,
        format!("{}\n", serde_json::to_string(&receipt).unwrap()),
    )
    .unwrap();
    assert_eq!(
        verify_audit_file(&wal_norm_path).unwrap_err().code(),
        "GRDR-AUDIT-0005"
    );

    let _ = fs::remove_dir_all(&dir);
}
