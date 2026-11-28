// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_fastpath::{
    AssuranceVerdict, BinaryRuleInput, FastActionClass, FastVerdict, FastpathBrandManifest,
    FastpathHostStatus, FastpathInterestView, FastpathTablesManifest, HostCapabilityState,
    HostEvalOutcome, HostProfile, LABEL_CREDENTIAL_ACCESSED, LabelBundleState, PRINCIPAL_SESSION,
    encode_binary_floor, encoded_binary_floor_size, evaluate_failsafe_with_manifest,
    evaluate_floor_with_host, scan_hook_payload_with_manifest,
};

#[test]
fn p14_custom_manifest_overrides_scanner_and_failsafe_tables() {
    let custom_toml = r#"
schema = "grdr.fastpath-tables.v1alpha1"
[tools]
file_tools = ["custom_read"]
net_tools = []
shell_quote_keys = ["command"]
mcp_target_keys = ["target"]
file_target_keys = ["file_path"]
net_target_keys = ["url"]
default_target_keys = ["target"]

[scanner_patterns]
entries = [
  "CONTROL_PATH|.acme-guard/",
]

[failsafe_rules]
entries = [
  "control_file|deny|.acme-guard/|acme.control|Custom brand control path blocked.",
]
"#;
    let manifest = FastpathTablesManifest::from_toml(custom_toml);
    let payload = br#"{"tool_name":"Bash","tool_input":{"target":"cat .acme-guard/policy.json"}}"#;
    let scanned = scan_hook_payload_with_manifest(payload, 4096, &manifest);
    assert_ne!(scanned.flags, 0);

    let hit = evaluate_failsafe_with_manifest(
        &manifest,
        FastActionClass::FileWrite,
        ".acme-guard/policy.json",
    )
    .expect("custom failsafe hit expected");
    assert_eq!(hit.rule_id, "acme.control");
    assert_eq!(hit.verdict, FastVerdict::Deny);
}

#[test]
fn em16_brand_manifest_loads_dynamically_from_brand_toml() {
    let embedded = FastpathBrandManifest::embedded();
    assert_eq!(embedded.schema, "grdr.brand.v1alpha1");
    assert!(!embedded.product_name.is_empty());
    assert!(!embedded.publisher.is_empty());

    let oem_toml = r#"
schema = "grdr.brand.v1alpha1"
namespace = "acme"
product_name = "Acme Shield"
short_name = "Shield"
publisher = "Acme Corp"
domain = "shield.acme.example"
copyright_holder = "Acme Corp Authors"
"#;
    let swapped = FastpathBrandManifest::from_toml(oem_toml);
    assert_eq!(swapped.namespace, "acme");
    assert_eq!(swapped.product_name, "Acme Shield");
    assert_eq!(swapped.short_name, "Shield");
    assert_eq!(swapped.publisher, "Acme Corp");
    assert_eq!(swapped.domain, "shield.acme.example");
}

#[test]
fn host_profile_assurance_and_label_bundle_tag_enforced() {
    let minimal = HostProfile::minimal_sandbox();
    assert_eq!(
        minimal.assess_rule_requirements(false, false, false),
        AssuranceVerdict::Evaluable
    );
    assert!(matches!(
        minimal.assess_rule_requirements(true, false, false),
        AssuranceVerdict::NotEvaluable(_)
    ));
    let mut pending = HostProfile::full_endpoint();
    pending.session_store = HostCapabilityState::Pending;
    assert!(matches!(
        pending.assess_rule_requirements(false, false, true),
        AssuranceVerdict::NotEvaluable(_)
    ));

    let entry = [BinaryRuleInput {
        rule_id: "r.taint.exfil",
        reason: "Blocked credential taint exfiltration",
        action_mask: FastActionClass::NetRequest.bit(),
        principal_mask: PRINCIPAL_SESSION,
        label_mask: LABEL_CREDENTIAL_ACCESSED,
        verdict: FastVerdict::Deny,
        agents: &[],
        prefixes: &[],
        contains: &["api.evil.example"],
    }];
    let (size, _) = encoded_binary_floor_size(&entry).unwrap();
    let mut buf = vec![0u8; size];
    encode_binary_floor(&entry, &mut buf).unwrap();

    let expected_tag = [0xA5u8; 32];
    let interest = FastpathInterestView {
        action_mask: FastActionClass::NetRequest.bit(),
        path_prefixes: &[],
        net_domains: &["api.evil.example"],
        label_mask: LABEL_CREDENTIAL_ACCESSED,
        expected_bundle_tag: expected_tag,
    };

    let mismatch = evaluate_floor_with_host(
        &buf,
        &interest,
        LabelBundleState::MissingOrLate,
        FastActionClass::NetRequest,
        PRINCIPAL_SESSION,
        "claude-code",
        "https://api.evil.example/upload",
    );
    assert_eq!(
        mismatch,
        HostEvalOutcome::StateError(FastpathHostStatus::LabelStateMismatch)
    );

    let wrong_tag = evaluate_floor_with_host(
        &buf,
        &interest,
        LabelBundleState::Ready {
            active_labels_mask: LABEL_CREDENTIAL_ACCESSED,
            bundle_tag: [0x01u8; 32],
        },
        FastActionClass::NetRequest,
        PRINCIPAL_SESSION,
        "claude-code",
        "https://api.evil.example/upload",
    );
    assert_eq!(
        wrong_tag,
        HostEvalOutcome::StateError(FastpathHostStatus::LabelStateMismatch)
    );

    let hit = evaluate_floor_with_host(
        &buf,
        &interest,
        LabelBundleState::Ready {
            active_labels_mask: LABEL_CREDENTIAL_ACCESSED,
            bundle_tag: expected_tag,
        },
        FastActionClass::NetRequest,
        PRINCIPAL_SESSION,
        "claude-code",
        "https://api.evil.example/upload",
    );
    assert!(matches!(hit, HostEvalOutcome::Matched(h) if h.verdict == FastVerdict::Deny));
}
