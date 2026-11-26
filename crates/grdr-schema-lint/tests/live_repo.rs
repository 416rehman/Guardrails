// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Integration tests validating the live repository schemas and P7 pack manifests.

use std::path::PathBuf;

use grdr_model::IdentityMode;
use grdr_schema_lint::{
    EvidenceQueryDecl, FieldReadDecl, LintError, LintFinding, PackDataClass, PackKind,
    PackManifest, lint_cedar_policy_in_mode, lint_pack_manifest, lint_proto_source, lint_repo_root,
    lint_text_against_vocabulary, parse_vocabulary_toml,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn live_repository_proto_cedar_and_vocabulary_pass_all_lints() {
    let report_res = lint_repo_root(&repo_root());
    assert!(report_res.is_ok(), "repo lint should run: {report_res:?}");
    if let Ok(report) = report_res {
        assert!(
            report.proto_files_checked >= 10,
            "expected >= 10 proto files, saw {}",
            report.proto_files_checked
        );
        assert_eq!(report.cedar_files_checked, 3);
        assert!(report.vocab_terms_checked >= 8);
        assert!(
            report.is_clean(),
            "live repo lint produced findings: {:?}",
            report.findings
        );
    }
}

#[test]
fn proto_lint_handles_comments_single_line_messages_oneof_and_optional_floats() {
    let bad_proto = r#"
syntax = "proto3";
package grdr.test.v1alpha1;
/* multi-line
   comment message Fake {} */
message ActionAttempt { oneof kind { string target = 1; } optional double ratio = 2 [(policy_readable) = true]; map<string, float> weights = 3 [(policy_readable) = true]; }
"#;
    let mut findings = Vec::new();
    lint_proto_source("bad.proto", bad_proto, &mut findings);
    assert!(
        findings
            .iter()
            .any(|f| f.message.contains("ActionAttempt.target"))
    );
    assert_eq!(
        findings
            .iter()
            .filter(|f| f.message.contains("floating-point"))
            .count(),
        2
    );
}

#[test]
fn proto_lint_rejects_unspecified_data_class_and_any_field() {
    let bad_proto = r#"
syntax = "proto3";
package grdr.test.v1alpha1;
message ActionAttempt {
  string target = 1;
  google.protobuf.Any extra = 2 [(data_class) = DATA_CLASS_UNSPECIFIED];
}
"#;
    let mut findings = Vec::new();
    lint_proto_source("bad.proto", bad_proto, &mut findings);
    assert!(findings.iter().any(|f| f.message.contains("Any")));
    assert!(
        findings
            .iter()
            .any(|f| f.message.contains("DATA_CLASS_UNSPECIFIED"))
    );
    assert!(
        findings
            .iter()
            .any(|f| f.message.contains("ActionAttempt.target"))
    );
}

#[test]
fn vocabulary_lint_and_cedar_whitespace_user_check_hold() {
    let raw_res = std::fs::read_to_string(
        repo_root()
            .join("contracts")
            .join("interface")
            .join("vocabulary.toml"),
    );
    assert!(raw_res.is_ok(), "read vocabulary.toml: {raw_res:?}");
    if let Ok(raw) = raw_res {
        let reg_res = parse_vocabulary_toml(&raw);
        assert!(reg_res.is_ok(), "parse vocabulary.toml: {reg_res:?}");
        if let Ok(registry) = reg_res {
            let mut findings: Vec<LintFinding> = Vec::new();
            lint_text_against_vocabulary(
                &registry,
                "ui.label",
                "Endpoint security posture",
                &mut findings,
            );
            assert_eq!(findings.len(), 1);
            assert!(
                findings
                    .first()
                    .is_some_and(|f| f.message.contains("posture"))
            );
        }
    }

    let incomplete_vocab = "[brand]\nname = \"Guardrails ADR\"\n[[term]]\nterm = \"Leaked\"\n[[term]]\nkey = \"mode\"\n";
    let parsed_res = parse_vocabulary_toml(incomplete_vocab);
    assert!(parsed_res.is_ok());
    if let Ok(parsed) = parsed_res {
        assert_eq!(parsed.terms.len(), 1);
        assert!(parsed.terms.first().is_some_and(|t| t.term.is_empty()));
    }

    let obfuscated_user_policy = r#"
@id("bad.user-rule")
forbid (principal is Grdr :: User, action == Grdr::Action::"exec", resource)
when { principal.department == "eng" };
"#;
    let res =
        lint_cedar_policy_in_mode("custom", obfuscated_user_policy, IdentityMode::Pseudonymous);
    assert!(matches!(res, Err(LintError::CedarViolation { .. })));

    let comment_only = r#"
// Comment mentioning Grdr::User should not fail
@id("ok.session-rule")
forbid (principal is Grdr::Session, action == Grdr::Action::"exec", resource);
"#;
    assert!(lint_cedar_policy_in_mode("custom", comment_only, IdentityMode::Pseudonymous).is_ok());
}

#[test]
fn p7_pack_lint_validates_data_class_order_manifest_subset_and_allow_list_group_by() {
    let valid = PackManifest {
        id: "grdr.compliance".into(),
        version: "1.0.0".into(),
        kind: PackKind::Compliance,
        reads: vec![
            FieldReadDecl {
                path: "receipt.verdict".into(),
                data_class: PackDataClass::Derived,
            },
            FieldReadDecl {
                path: "receipt.action_class".into(),
                data_class: PackDataClass::Structural,
            },
        ],
        commands: vec![],
        executables: vec![],
        urls: vec![],
        env_vars_to_set: vec![],
        mcp_servers_to_start: vec![],
        evidence_queries: vec![EvidenceQueryDecl {
            id: "q.preexec".into(),
            reads: vec![FieldReadDecl {
                path: "receipt.action_class".into(),
                data_class: PackDataClass::Structural,
            }],
            max_class: PackDataClass::Derived,
            group_by: vec!["capability".into()],
        }],
        rule_snippets: vec![],
        per_person_scoring: false,
    };
    assert!(lint_pack_manifest(&valid, IdentityMode::Pseudonymous).is_ok());

    let mut identifier_pack = valid.clone();
    identifier_pack.reads.push(FieldReadDecl {
        path: "session.device_id".into(),
        data_class: PackDataClass::Identifier,
    });
    assert!(
        lint_pack_manifest(&identifier_pack, IdentityMode::Pseudonymous).is_ok(),
        "PackDataClass currently permits Identifier reads matching EvidenceDataClass and signed grdr.compliance"
    );

    let mut content_pack = valid.clone();
    content_pack.reads.push(FieldReadDecl {
        path: "action.command".into(),
        data_class: PackDataClass::Content,
    });
    assert!(
        matches!(
            lint_pack_manifest(&content_pack, IdentityMode::Pseudonymous),
            Err(LintError::PackViolation { ref detail, .. }) if detail.contains("exceeds `derived`")
        ),
        "compliance packs capped at Derived must reject Content reads"
    );

    let mut undeclared_read = valid.clone();
    if let Some(q) = undeclared_read.evidence_queries.first_mut() {
        q.reads.push(FieldReadDecl {
            path: "receipt.reason".into(),
            data_class: PackDataClass::Derived,
        });
    }
    assert!(matches!(
        lint_pack_manifest(&undeclared_read, IdentityMode::Named),
        Err(LintError::PackViolation { .. })
    ));

    let mut spaced_exec = valid.clone();
    spaced_exec.rule_snippets.push("bash   -c 'id'".into());
    assert!(matches!(
        lint_pack_manifest(&spaced_exec, IdentityMode::Named),
        Err(LintError::PackViolation { .. })
    ));

    let mut policy_with_query = valid.clone();
    policy_with_query.kind = PackKind::Policy;
    assert!(matches!(
        lint_pack_manifest(&policy_with_query, IdentityMode::Named),
        Err(LintError::PackViolation { .. })
    ));

    let mut bad_query = valid;
    if let Some(first) = bad_query.evidence_queries.first_mut() {
        first.group_by.push("attempt.user_id".into());
    }
    assert!(matches!(
        lint_pack_manifest(&bad_query, IdentityMode::Named),
        Err(LintError::PackViolation { .. })
    ));
}
