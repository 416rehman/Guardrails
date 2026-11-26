// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Conformance validation for `packs/credential-locator` (P14 schema, Cedar strict modes, H1-H12, vectors).

use std::collections::BTreeSet;
use std::path::Path;

use grdr_identity::broker_types::ContainmentStatus;
use grdr_identity::locator::{ArtifactScanContext, CredentialLocatorPack, HygieneRuleId};
use grdr_model::IdentityMode;
use grdr_schema_lint::{VocabularyRegistry, lint_cedar_policy_in_mode, lint_pack_manifest};

use crate::ConformanceError;
use crate::pack_manifest::{
    check_no_em_dash_or_vocab, conf_err, parse_pack_manifest_toml, read_regular_text, unquote,
};

const TEST_HMAC_KEY: &[u8] = b"grdr-conformance-locator-hmac-01";

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocatorVectorSpec {
    id: String,
    path: String,
    expect_locator: Option<String>,
    expect_hygiene: Option<String>,
    expect_honeytoken: bool,
    expect_none: bool,
}

pub fn validate_credential_locator_pack(
    dir: &Path,
    vocab: &VocabularyRegistry,
) -> Result<usize, ConformanceError> {
    let manifest_path = dir.join("pack.toml");
    let manifest_raw = read_regular_text(&manifest_path)?;
    check_no_em_dash_or_vocab(&manifest_path, &manifest_raw, vocab)?;
    let manifest = parse_pack_manifest_toml(&manifest_raw)?;
    lint_pack_manifest(&manifest, IdentityMode::Named)
        .map_err(|e| conf_err("cred-pack-lint", &e.to_string()))?;
    lint_pack_manifest(&manifest, IdentityMode::Pseudonymous)
        .map_err(|e| conf_err("cred-pack-lint", &e.to_string()))?;

    let cedar_path = dir.join("rules").join("credential-hygiene.cedar");
    let cedar_src = read_regular_text(&cedar_path)?;
    check_no_em_dash_or_vocab(&cedar_path, &cedar_src, vocab)?;
    lint_cedar_policy_in_mode(&manifest.id, &cedar_src, IdentityMode::Named)
        .map_err(|e| conf_err("cred-cedar-lint", &e.to_string()))?;
    lint_cedar_policy_in_mode(&manifest.id, &cedar_src, IdentityMode::Pseudonymous)
        .map_err(|e| conf_err("cred-cedar-lint", &e.to_string()))?;

    for rel in ["lists/locators.yaml", "lists/hygiene-rules.yaml"] {
        let p = dir.join(rel);
        let txt = read_regular_text(&p)?;
        check_no_em_dash_or_vocab(&p, &txt, vocab)?;
    }

    let pack = CredentialLocatorPack::load_from_dir(dir)
        .map_err(|e| conf_err("cred-pack-load", &e.to_string()))?;
    if pack.locators().is_empty() || pack.hygiene_rules().len() != 12 {
        return Err(conf_err(
            "cred-pack-load",
            "expected non-empty locators and 12 H1-H12 hygiene rules",
        ));
    }

    let vectors_raw = read_regular_text(&dir.join("tests").join("locator-vectors.yaml"))?;
    let vectors = parse_locator_vectors_yaml(&vectors_raw)?;
    if vectors.is_empty() {
        return Err(conf_err("cred-vectors", "locator-vectors.yaml is empty"));
    }

    for vec_item in &vectors {
        verify_single_locator_vector(&pack, vec_item)?;
    }
    Ok(vectors.len())
}

fn verify_single_locator_vector(
    pack: &CredentialLocatorPack,
    vec_item: &LocatorVectorSpec,
) -> Result<(), ConformanceError> {
    let (sample, ctx) = fixture_for_vector(vec_item);
    let found = pack
        .scan_artifact(TEST_HMAC_KEY, &sample, &ctx)
        .map_err(|e| conf_err("cred-vectors", &e.to_string()))?;
    if vec_item.expect_none {
        if found.is_some() {
            return Err(conf_err(
                "cred-vectors",
                &format!("negative vector `{}` unexpectedly matched", vec_item.id),
            ));
        }
        return Ok(());
    }
    let finding = found.ok_or_else(|| {
        conf_err(
            "cred-vectors",
            &format!("vector `{}` did not match any locator", vec_item.id),
        )
    })?;
    if let Some(exp_loc) = vec_item.expect_locator.as_deref()
        && finding.locator_id != exp_loc
    {
        return Err(conf_err(
            "cred-vectors",
            &format!(
                "vector `{}` expected locator `{exp_loc}`, got `{}`",
                vec_item.id, finding.locator_id
            ),
        ));
    }
    if finding.honeytoken != vec_item.expect_honeytoken {
        return Err(conf_err(
            "cred-vectors",
            &format!(
                "vector `{}` expected honeytoken={}, got {}",
                vec_item.id, vec_item.expect_honeytoken, finding.honeytoken
            ),
        ));
    }
    if let Some(exp_hyg) = vec_item.expect_hygiene.as_deref() {
        let want_rule = parse_hygiene_rule_id(exp_hyg)?;
        if !finding
            .hygiene_findings
            .iter()
            .any(|h| h.rule_id == want_rule)
        {
            return Err(conf_err(
                "cred-vectors",
                &format!(
                    "vector `{}` missing expected hygiene rule `{exp_hyg}`",
                    vec_item.id
                ),
            ));
        }
    }
    Ok(())
}

fn fixture_for_vector(vec_item: &LocatorVectorSpec) -> (String, ArtifactScanContext) {
    let mut ctx = ArtifactScanContext {
        artifact_path: vec_item.path.clone(),
        readable_by_agent_lineages: vec!["claude-code".to_owned()],
        containment: ContainmentStatus::Contained,
        signals: BTreeSet::new(),
    };
    let sample = match vec_item.expect_locator.as_deref() {
        Some("aws-shared-credentials") => {
            format!(
                "[default]\naws_access_key_id = {}\n",
                concat!("AK", "IATEST000000000001")
            )
        }
        Some("mcp-config-env") => {
            "{\"mcpServers\":{\"s\":{\"env\":{\"TOKEN\":\"mcp_unit_test_value\"}}}}".to_owned()
        }
        Some("ssh-private-key") => {
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntestkeybody\n-----END OPENSSH PRIVATE KEY-----"
                .to_owned()
        }
        Some("shell-profile-export") => "export TEST_API_TOKEN=\"unit_test_val_1234\"".to_owned(),
        Some("kubeconfig-static") => {
            ctx.containment = ContainmentStatus::Uncontained;
            "apiVersion: v1\nclusters:\n- cluster: {}\nusers:\n- user:\n    token: kube_test_token_value\n"
                .to_owned()
        }
        Some("honeytoken-trap") => "GRDR_HONEY_DECOY_VECTOR_001".to_owned(),
        _ => "# Plain non-credential README\n".to_owned(),
    };
    (sample, ctx)
}

fn parse_hygiene_rule_id(raw: &str) -> Result<HygieneRuleId, ConformanceError> {
    match raw {
        "H1" => Ok(HygieneRuleId::H1),
        "H2" => Ok(HygieneRuleId::H2),
        "H3" => Ok(HygieneRuleId::H3),
        "H4" => Ok(HygieneRuleId::H4),
        "H5" => Ok(HygieneRuleId::H5),
        "H6" => Ok(HygieneRuleId::H6),
        "H7" => Ok(HygieneRuleId::H7),
        "H8" => Ok(HygieneRuleId::H8),
        "H9" => Ok(HygieneRuleId::H9),
        "H10" => Ok(HygieneRuleId::H10),
        "H11" => Ok(HygieneRuleId::H11),
        "H12" => Ok(HygieneRuleId::H12),
        other => Err(conf_err(
            "cred-vectors",
            &format!("unknown hygiene rule `{other}`"),
        )),
    }
}

fn parse_locator_vectors_yaml(raw: &str) -> Result<Vec<LocatorVectorSpec>, ConformanceError> {
    let mut out = Vec::new();
    let mut current: Option<LocatorVectorSpec> = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("format:")
            || trimmed.starts_with("pack_id:")
            || trimmed == "vectors:"
        {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("- id:") {
            if let Some(prev) = current.take() {
                out.push(prev);
            }
            current = Some(LocatorVectorSpec {
                id: unquote(rest),
                path: String::new(),
                expect_locator: None,
                expect_hygiene: None,
                expect_honeytoken: false,
                expect_none: false,
            });
            continue;
        }
        let Some(item) = current.as_mut() else {
            continue;
        };
        if let Some((k, v)) = trimmed.split_once(':') {
            let val = unquote(v);
            match k.trim() {
                "path" => item.path = val,
                "expect_locator" => item.expect_locator = Some(val),
                "expect_hygiene" => item.expect_hygiene = Some(val),
                "expect_honeytoken" => item.expect_honeytoken = val == "true",
                "expect_none" => item.expect_none = val == "true",
                other => {
                    return Err(conf_err(
                        "cred-vectors",
                        &format!("unsupported locator vector field `{other}`"),
                    ));
                }
            }
        }
    }
    if let Some(last) = current.take() {
        out.push(last);
    }
    Ok(out)
}
