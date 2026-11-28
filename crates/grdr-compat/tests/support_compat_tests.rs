// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::path::PathBuf;

use grdr_compat::{
    CODE_COMPAT_FORBIDDEN_JUMP, CODE_COMPAT_INVALID_CONTRACT, CODE_COMPAT_INVALID_RANGE,
    CODE_COMPAT_UNSUPPORTED_VERSION, CompatMatrix, EMBEDDED_SUPPORT_TOML, ManifestCompatGraph,
    ManifestComponentState, ManifestContractRange, NegotiationOutcome, NegotiationRequest,
    ProtocolCapability, SemVer, VersionRange, diff_component_digests, evaluate_manifest_compat,
    generate_upgrade_path_doc, load_embedded_support_contract, negotiate_compatibility,
    parse_support_toml, validate_direct_transition, validate_hop_sequence,
};

const SERIES_MAJOR: u32 = 1;
const SERIES_MAX_MINOR: u32 = 14;

#[test]
fn semver_parse_and_range_matching_work() {
    let v = SemVer::parse("v1.4.2-rc1").expect("valid semver");
    assert_eq!(v, SemVer::new(1, 4, 2));
    assert!(SemVer::parse("1.2").is_err());
    for bad in ["+1.0.0", "1.+2.0", "1.2.+3", "01.2.3", "1.2.3-", "1.2.3+"] {
        assert!(SemVer::parse(bad).is_err(), "must reject invalid `{bad}`");
    }

    let range = VersionRange {
        min_inclusive: SemVer::new(0, 1, 0),
        max_exclusive: Some(SemVer::new(2, 0, 0)),
    };
    assert!(range.contains(v));
    assert!(!range.contains(SemVer::new(2, 0, 0)));
}

#[test]
fn support_toml_drives_compat_matrix_and_negotiation() {
    let support = load_embedded_support_contract().expect("parse embedded support.toml");
    assert_eq!(support.release_policy.max_upgrade_minor_hop, 2);
    assert_eq!(support.release_policy.lts_interval_minors, 12);
    assert_eq!(support.compatibility_matrix.wire_major, 1);
    assert_eq!(support.compatibility_matrix.schema_rev, 1);

    let matrix = CompatMatrix::default_v1();
    assert_eq!(matrix.protocol_version, SemVer::new(1, 0, 0));
    assert!(matrix.entries.iter().any(|e| e.component == "grdr-daemon"));
    assert!(matrix.entries.iter().any(|e| e.component == "grdr-mcp"));
    assert!(matrix.entries.iter().any(|e| e.component == "grdr-desktop"));

    let ok = negotiate_compatibility(
        &matrix,
        &NegotiationRequest {
            component: "grdr-mcp".into(),
            client_version: SemVer::new(0, 1, 0),
            advertised_capabilities: vec![
                ProtocolCapability::McpToolPinning,
                ProtocolCapability::StepUpApproval,
                ProtocolCapability::SignedReceipts,
            ],
        },
    );
    assert!(matches!(ok, NegotiationOutcome::Compatible { .. }));

    let warn = negotiate_compatibility(
        &matrix,
        &NegotiationRequest {
            component: "grdr-mcp".into(),
            client_version: SemVer::new(0, 1, 0),
            advertised_capabilities: vec![ProtocolCapability::McpToolPinning],
        },
    );
    assert!(matches!(
        warn,
        NegotiationOutcome::CompatibleWithWarnings { .. }
    ));

    let bad = negotiate_compatibility(
        &matrix,
        &NegotiationRequest {
            component: "grdr-mcp".into(),
            client_version: SemVer::new(3, 0, 0),
            advertised_capabilities: vec![ProtocolCapability::McpToolPinning],
        },
    );
    assert!(matches!(bad, NegotiationOutcome::Incompatible { .. }));
}

#[test]
fn upgrade_path_generator_matches_contract_and_refuses_all_forbidden_jumps() {
    let support = load_embedded_support_contract().expect("parse embedded support.toml");
    let doc = generate_upgrade_path_doc(&support, SERIES_MAJOR, SERIES_MAX_MINOR)
        .expect("generate upgrade path doc");
    assert_eq!(doc.lts_minors, vec![12]);
    assert!(!doc.forbidden_jumps.is_empty());

    // Refuse 100% of every entry in the generated forbidden_jumps table.
    for jump in &doc.forbidden_jumps {
        let from = SemVer::parse(&jump.from_version).expect("valid from semver");
        let to = SemVer::parse(&jump.to_version).expect("valid to semver");
        let err =
            validate_direct_transition(&doc, from, to).expect_err("forbidden jump must be refused");
        assert_eq!(err.code(), CODE_COMPAT_FORBIDDEN_JUMP);
    }

    // Valid stepped hop through LTS stop v1.12.0 is accepted, while skipping v1.12.0 directly is rejected.
    let valid_plan = validate_hop_sequence(
        &doc,
        &[
            SemVer::new(1, 10, 0),
            SemVer::new(1, 12, 0),
            SemVer::new(1, 14, 0),
        ],
    )
    .expect("stepped path through LTS stop must pass");
    assert!(!valid_plan.is_rollback);

    let direct_skip_lts =
        validate_direct_transition(&doc, SemVer::new(1, 11, 0), SemVer::new(1, 13, 0))
            .expect_err("direct jump across LTS stop 1.12.0 must fail");
    assert_eq!(direct_skip_lts.code(), CODE_COMPAT_FORBIDDEN_JUMP);

    // Rollback within 1 minor is allowed; rollback of 2 minors is refused.
    assert!(
        validate_direct_transition(&doc, SemVer::new(1, 14, 0), SemVer::new(1, 13, 0))
            .expect("1-minor rollback allowed")
            .is_rollback
    );
    assert_eq!(
        validate_direct_transition(&doc, SemVer::new(1, 14, 0), SemVer::new(1, 12, 0))
            .expect_err("2-minor rollback must fail")
            .code(),
        CODE_COMPAT_FORBIDDEN_JUMP
    );

    let contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("contracts")
        .join("upgrade-path.json");
    let raw =
        std::fs::read_to_string(&contract_path).expect("contracts/upgrade-path.json must exist");
    let parsed: grdr_compat::UpgradePathDocument =
        serde_json::from_str(&raw).expect("valid contracts/upgrade-path.json");
    assert_eq!(
        parsed, doc,
        "contracts/upgrade-path.json must stay in sync with support.toml"
    );
}

#[test]
fn manifest_compat_graph_and_patch_digest_diff_enforce_contract_bounds() {
    let support = load_embedded_support_contract().expect("parse embedded support.toml");
    let mut contracts = BTreeMap::new();
    for c in &support.compatibility_matrix.contracts {
        contracts.insert(
            c.name.clone(),
            ManifestContractRange {
                min: c.version.clone(),
                max: c.version.clone(),
            },
        );
    }

    let valid = ManifestCompatGraph {
        wire_major: 1,
        schema_rev: 1,
        pack_format: SemVer::new(1, 0, 0),
        driver_interface: SemVer::new(1, 0, 0),
        contracts: contracts.clone(),
        min_upgrade_from: SemVer::new(1, 0, 0),
        required_stops: vec![SemVer::new(1, 12, 0)],
        postgresql_major: 18,
        kubernetes_min: "1.35.0".into(),
        helm_min: SemVer::new(3, 19, 0),
    };
    evaluate_manifest_compat(&support, &valid).expect("valid manifest compat passes");

    let mut bad_pack = valid.clone();
    bad_pack.pack_format = SemVer::new(2, 0, 0);
    assert_eq!(
        evaluate_manifest_compat(&support, &bad_pack)
            .expect_err("unsupported pack_format")
            .code(),
        CODE_COMPAT_UNSUPPORTED_VERSION
    );

    let mut bad_driver = valid.clone();
    bad_driver.driver_interface = SemVer::new(0, 9, 0);
    assert_eq!(
        evaluate_manifest_compat(&support, &bad_driver)
            .expect_err("unsupported driver_interface")
            .code(),
        CODE_COMPAT_UNSUPPORTED_VERSION
    );

    let mut bad_k8s = valid.clone();
    bad_k8s.kubernetes_min = "1.34.0".into();
    assert_eq!(
        evaluate_manifest_compat(&support, &bad_k8s)
            .expect_err("EOL k8s rejected")
            .code(),
        CODE_COMPAT_UNSUPPORTED_VERSION
    );

    // Patch release updates only changed component digest.
    let prev = vec![
        ManifestComponentState {
            name: "grdr-daemon".into(),
            version: SemVer::new(1, 4, 0),
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            signed: true,
        },
        ManifestComponentState {
            name: "grdr-mcp".into(),
            version: SemVer::new(1, 4, 0),
            sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            signed: true,
        },
    ];
    let next = vec![
        ManifestComponentState {
            name: "grdr-daemon".into(),
            version: SemVer::new(1, 4, 1),
            sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            signed: true,
        },
        ManifestComponentState {
            name: "grdr-mcp".into(),
            version: SemVer::new(1, 4, 0),
            sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            signed: true,
        },
    ];
    let deltas = diff_component_digests(&prev, &next);
    assert_eq!(deltas.len(), 2);
    assert!(deltas[0].changed);
    assert!(!deltas[1].changed);
    assert_eq!(deltas[1].previous_sha256, deltas[1].next_sha256);
}

#[test]
fn strict_support_toml_and_manifest_validation_fail_closed() {
    let support = load_embedded_support_contract().expect("parse embedded support.toml");

    // Strict support.toml parser refuses unknown section, unknown key, dup key, dup component, unescaped quote.
    let bad_section = format!("{EMBEDDED_SUPPORT_TOML}\n[evil_section]\nfoo = \"bar\"\n");
    assert_eq!(
        parse_support_toml(&bad_section)
            .expect_err("unknown section rejected")
            .code(),
        CODE_COMPAT_INVALID_CONTRACT
    );
    let bad_key = EMBEDDED_SUPPORT_TOML.replace(
        "cadence = \"monthly\"",
        "cadence = \"monthly\"\nextra = \"x\"",
    );
    assert_eq!(
        parse_support_toml(&bad_key)
            .expect_err("unknown key rejected")
            .code(),
        CODE_COMPAT_INVALID_CONTRACT
    );
    let dup_key = EMBEDDED_SUPPORT_TOML.replace(
        "cadence = \"monthly\"",
        "cadence = \"monthly\"\ncadence = \"weekly\"",
    );
    assert_eq!(
        parse_support_toml(&dup_key)
            .expect_err("duplicate key rejected")
            .code(),
        CODE_COMPAT_INVALID_CONTRACT
    );
    let dup_comp = format!(
        "{EMBEDDED_SUPPORT_TOML}\n[[compatibility_matrix.components]]\ncomponent = \"grdr-daemon\"\nmin_inclusive = \"0.1.0\"\n"
    );
    assert_eq!(
        parse_support_toml(&dup_comp)
            .expect_err("duplicate component rejected")
            .code(),
        CODE_COMPAT_INVALID_CONTRACT
    );
    let empty_k8s = EMBEDDED_SUPPORT_TOML.replace(
        "supported_versions = [\"1.35\", \"1.36\", \"1.37\"]",
        "supported_versions = []",
    );
    assert_eq!(
        parse_support_toml(&empty_k8s)
            .expect_err("empty kubernetes supported_versions rejected")
            .code(),
        CODE_COMPAT_INVALID_CONTRACT
    );
    let unescaped =
        EMBEDDED_SUPPORT_TOML.replace("cadence = \"monthly\"", "cadence = \"mon\"thly\"");
    assert_eq!(
        parse_support_toml(&unescaped)
            .expect_err("unescaped interior quote rejected")
            .code(),
        CODE_COMPAT_INVALID_CONTRACT
    );

    // Multiline arrays, trailing comma, escaped quotes/backslashes, and embedded commas parse cleanly.
    let multiline = EMBEDDED_SUPPORT_TOML
        .replace("cadence = \"monthly\"", "cadence = \"month\\\"ly\\\\1\"")
        .replace(
            "supported_versions = [\"1.35\", \"1.36\", \"1.37\"]",
            "supported_versions = [\n  \"1.35\",\n  \"1.36\",\n  \"1.37\",\n]",
        )
        .replace(
            "excluded = [\"minio-archived\"]",
            "excluded = [\"legacy, inc\", \"minio-archived\",]",
        );
    assert!(parse_support_toml(&multiline).is_ok());

    let mut contracts = BTreeMap::new();
    for c in &support.compatibility_matrix.contracts {
        contracts.insert(
            c.name.clone(),
            ManifestContractRange {
                min: c.version.clone(),
                max: c.version.clone(),
            },
        );
    }
    let valid = ManifestCompatGraph {
        wire_major: 1,
        schema_rev: 1,
        pack_format: SemVer::new(1, 0, 0),
        driver_interface: SemVer::new(1, 0, 0),
        contracts: contracts.clone(),
        min_upgrade_from: SemVer::new(1, 0, 0),
        required_stops: vec![SemVer::new(1, 12, 0)],
        postgresql_major: 18,
        kubernetes_min: "1.35.0".into(),
        helm_min: SemVer::new(3, 19, 0),
    };

    let mut widened_frozen = valid.clone();
    widened_frozen.contracts.insert(
        "grdr.bootstrap".into(),
        ManifestContractRange {
            min: "v1alpha1".into(),
            max: "v1".into(),
        },
    );
    assert_eq!(
        evaluate_manifest_compat(&support, &widened_frozen)
            .expect_err("widening frozen contract must fail")
            .code(),
        CODE_COMPAT_UNSUPPORTED_VERSION
    );

    let mut inverted_contract = valid.clone();
    inverted_contract.contracts.insert(
        "grdr.ingest".into(),
        ManifestContractRange {
            min: "2.0.0".into(),
            max: "1.0.0".into(),
        },
    );
    assert_eq!(
        evaluate_manifest_compat(&support, &inverted_contract)
            .expect_err("inverted range must fail")
            .code(),
        CODE_COMPAT_INVALID_RANGE
    );

    let mut bad_from = valid.clone();
    bad_from.min_upgrade_from = SemVer::new(0, 9, 0);
    assert!(evaluate_manifest_compat(&support, &bad_from).is_err());

    let mut bad_stop = valid.clone();
    bad_stop.required_stops = vec![SemVer::new(1, 13, 0)];
    assert!(evaluate_manifest_compat(&support, &bad_stop).is_err());

    let mut bad_k8s = valid;
    bad_k8s.kubernetes_min = "v1.35.foo".into();
    assert!(evaluate_manifest_compat(&support, &bad_k8s).is_err());

    // validate_direct_transition rejects bad doc schema, zero hop/interval, and explicit forbidden_jumps.
    let mut doc = generate_upgrade_path_doc(&support, SERIES_MAJOR, SERIES_MAX_MINOR).unwrap();
    let mut bad_schema = doc.clone();
    bad_schema.schema = "grdr.upgrade-path.v99".into();
    assert_eq!(
        validate_direct_transition(&bad_schema, SemVer::new(1, 0, 0), SemVer::new(1, 1, 0))
            .expect_err("bad schema rejected")
            .code(),
        CODE_COMPAT_INVALID_CONTRACT
    );
    let mut zero_hop = doc.clone();
    zero_hop.max_upgrade_minor_hop = 0;
    assert!(
        validate_direct_transition(&zero_hop, SemVer::new(1, 0, 0), SemVer::new(1, 1, 0)).is_err()
    );

    doc.forbidden_jumps.push(grdr_compat::ForbiddenJumpEntry {
        from_version: "1.0.0".into(),
        to_version: "1.1.0".into(),
        reason: "custom policy freeze".into(),
    });
    assert_eq!(
        validate_direct_transition(&doc, SemVer::new(1, 0, 0), SemVer::new(1, 1, 0))
            .expect_err("explicit forbidden_jumps enforced")
            .code(),
        CODE_COMPAT_FORBIDDEN_JUMP
    );

    let broken_matrix = CompatMatrix {
        protocol_version: SemVer::new(1, 0, 0),
        entries: Vec::new(),
        contract_error: Some("embedded contract invalid".into()),
    };
    let out = negotiate_compatibility(
        &broken_matrix,
        &NegotiationRequest {
            component: "grdr-mcp".into(),
            client_version: SemVer::new(0, 1, 0),
            advertised_capabilities: Vec::new(),
        },
    );
    assert!(matches!(
        out,
        NegotiationOutcome::Incompatible { ref code, .. } if code == CODE_COMPAT_INVALID_CONTRACT
    ));
}
