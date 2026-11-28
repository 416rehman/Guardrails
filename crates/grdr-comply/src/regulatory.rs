// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Crypto allow-list CI check, CRA Annex I matrix, SOC 2 ownership pack, and VPAT 2.5 INT generator.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::pack_loader::{load_yaml_checked, yaml_req_seq, yaml_req_str, yaml_req_str_list};
use crate::registry::CapabilityRegistry;
use crate::{ComplyError, markdown_safe};

const EMBEDDED_REGULATORY_PACK_YAML: &str = include_str!("../data/regulatory-pack.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpatSurface {
    WebConsole,
    RuneDesktop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VpatConformanceLevel {
    Supports,
    PartiallySupports,
    DoesNotSupport,
    NotApplicable,
    NotEvaluated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoAllowlistReport {
    pub approved_crates: Vec<String>,
    pub unapproved_crates: Vec<String>,
    pub export_doc_missing_markers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CraAnnexIRow {
    pub id: String,
    pub part: String,
    pub obligation: String,
    pub capabilities: Vec<String>,
    pub artifact: String,
    pub all_capabilities_registered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CraAnnexIMatrixReport {
    pub regulation: String,
    pub rows: Vec<CraAnnexIRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Soc2ControlOwnershipRow {
    pub control_id: String,
    pub owner: String,
    pub category: String,
    pub capability: String,
    pub evidence_source: String,
    pub mapped_in_registry: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Soc2ReadinessPack {
    pub schema: String,
    pub total_controls: usize,
    pub owner_mapped_percent: u32,
    pub controls: Vec<Soc2ControlOwnershipRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpatCriterionRow {
    pub criterion: String,
    pub level: String,
    pub title: String,
    pub conformance: VpatConformanceLevel,
    pub remarks: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vpat25Report {
    pub edition: String,
    pub surface: VpatSurface,
    pub product_version: String,
    pub wcag_target: String,
    pub evaluated_at: Timestamp,
    pub rows: Vec<VpatCriterionRow>,
}

pub fn verify_crypto_allowlist(
    observed_crypto_crates: &[&str],
    export_doc_markdown: Option<&str>,
) -> Result<CryptoAllowlistReport, ComplyError> {
    let doc = load_yaml_checked(EMBEDDED_REGULATORY_PACK_YAML, "regulatory-pack.yaml")?;
    let allow = doc
        .get("crypto_allowlist")
        .ok_or_else(|| ComplyError::Serialization {
            detail: "regulatory-pack.yaml missing `crypto_allowlist`".into(),
        })?;
    let approved = yaml_req_str_list(allow, "approved_crates", "crypto_allowlist")?;
    let restricted = yaml_req_str_list(allow, "restricted_primitives", "crypto_allowlist")?;
    let markers = yaml_req_str_list(allow, "export_doc_markers", "crypto_allowlist")?;

    let approved_set: BTreeSet<&str> = approved.iter().map(String::as_str).collect();
    let restricted_set: BTreeSet<&str> = restricted.iter().map(String::as_str).collect();
    let mut unapproved = Vec::new();
    for krate in observed_crypto_crates {
        let norm = krate.trim();
        if norm.is_empty() {
            continue;
        }
        if !approved_set.contains(norm) || restricted_set.contains(norm) {
            unapproved.push(norm.to_owned());
        }
    }

    let mut missing_markers = Vec::new();
    if let Some(md) = export_doc_markdown {
        for m in &markers {
            if !md.contains(m.as_str()) {
                missing_markers.push(m.clone());
            }
        }
    }

    if !unapproved.is_empty() || !missing_markers.is_empty() {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "crypto allow-list failure: unapproved={unapproved:?}, missing_export_markers={missing_markers:?}"
            ),
        });
    }

    Ok(CryptoAllowlistReport {
        approved_crates: approved,
        unapproved_crates: unapproved,
        export_doc_missing_markers: missing_markers,
    })
}

pub fn generate_cra_annex_i_matrix(
    registry: &CapabilityRegistry,
) -> Result<CraAnnexIMatrixReport, ComplyError> {
    let doc = load_yaml_checked(EMBEDDED_REGULATORY_PACK_YAML, "regulatory-pack.yaml")?;
    let seq = yaml_req_seq(&doc, "cra_annex_i", "regulatory-pack.yaml")?;
    let mut rows = Vec::with_capacity(seq.len());
    for node in seq {
        let id = yaml_req_str(node, "id", "cra_annex_i")?.to_owned();
        let caps = yaml_req_str_list(node, "capabilities", &id)?;
        let all_ok = caps.iter().all(|c| registry.capabilities.contains_key(c));
        rows.push(CraAnnexIRow {
            id: id.clone(),
            part: yaml_req_str(node, "part", &id)?.to_owned(),
            obligation: yaml_req_str(node, "obligation", &id)?.to_owned(),
            capabilities: caps,
            artifact: yaml_req_str(node, "artifact", &id)?.to_owned(),
            all_capabilities_registered: all_ok,
        });
    }
    Ok(CraAnnexIMatrixReport {
        regulation: "Regulation (EU) 2024/2847 Annex I".into(),
        rows,
    })
}

pub fn generate_soc2_readiness_pack(
    registry: &CapabilityRegistry,
) -> Result<Soc2ReadinessPack, ComplyError> {
    let doc = load_yaml_checked(EMBEDDED_REGULATORY_PACK_YAML, "regulatory-pack.yaml")?;
    let seq = yaml_req_seq(&doc, "soc2_controls", "regulatory-pack.yaml")?;
    let mut controls = Vec::with_capacity(seq.len());
    let mut owned_count = 0usize;

    for node in seq {
        let control_id = yaml_req_str(node, "control_id", "soc2_controls")?.to_owned();
        let owner = yaml_req_str(node, "owner", &control_id)?.to_owned();
        let capability = yaml_req_str(node, "capability", &control_id)?.to_owned();
        if !owner.trim().is_empty() {
            owned_count = owned_count.saturating_add(1);
        }
        let mapped_in_registry = registry.capabilities.contains_key(&capability);
        controls.push(Soc2ControlOwnershipRow {
            control_id: control_id.clone(),
            owner,
            category: yaml_req_str(node, "category", &control_id)?.to_owned(),
            capability,
            evidence_source: yaml_req_str(node, "evidence_source", &control_id)?.to_owned(),
            mapped_in_registry,
        });
    }
    let total_controls = controls.len();
    let owner_mapped_percent = u32::try_from(owned_count.saturating_mul(100))
        .unwrap_or(0)
        .checked_div(u32::try_from(total_controls).unwrap_or(1))
        .unwrap_or(0);

    Ok(Soc2ReadinessPack {
        schema: "grdr.soc2.readiness.v1".into(),
        total_controls,
        owner_mapped_percent,
        controls,
    })
}

pub fn generate_vpat_report(
    surface: VpatSurface,
    product_version: &str,
    observed: &BTreeMap<String, VpatConformanceLevel>,
    evaluated_at: Timestamp,
) -> Result<Vpat25Report, ComplyError> {
    let doc = load_yaml_checked(EMBEDDED_REGULATORY_PACK_YAML, "regulatory-pack.yaml")?;
    let seq = yaml_req_seq(&doc, "wcag_22_aa", "regulatory-pack.yaml")?;
    let mut rows = Vec::with_capacity(seq.len());

    for node in seq {
        let criterion = yaml_req_str(node, "criterion", "wcag_22_aa")?.to_owned();
        let surf_scope = yaml_req_str(node, "surface", &criterion)?;
        let applicable = match surface {
            VpatSurface::WebConsole => surf_scope == "web" || surf_scope == "web-and-desktop",
            VpatSurface::RuneDesktop => surf_scope == "desktop" || surf_scope == "web-and-desktop",
        };
        let conformance = if !applicable {
            VpatConformanceLevel::NotApplicable
        } else {
            observed
                .get(&criterion)
                .copied()
                .unwrap_or(VpatConformanceLevel::NotEvaluated)
        };
        rows.push(VpatCriterionRow {
            criterion: criterion.clone(),
            level: yaml_req_str(node, "level", &criterion)?.to_owned(),
            title: yaml_req_str(node, "title", &criterion)?.to_owned(),
            conformance,
            remarks: yaml_req_str(node, "check_method", &criterion)?.to_owned(),
        });
    }

    Ok(Vpat25Report {
        edition: "VPAT 2.5 INT".into(),
        surface,
        product_version: product_version.to_owned(),
        wcag_target: "WCAG 2.2 AA".into(),
        evaluated_at,
        rows,
    })
}

pub fn render_vpat_markdown(report: &Vpat25Report) -> String {
    let surface_name = match report.surface {
        VpatSurface::WebConsole => "Guardrails Console (Web)",
        VpatSurface::RuneDesktop => "Guardrails Desktop (Rune)",
    };
    let mut out = format!(
        "# {} Accessibility Conformance Report ({} {})\n\nTarget: {} | Evaluated: {}\n\n| Criterion | Level | Title | Conformance Level | Remarks and Explanations |\n|---|---|---|---|---|\n",
        markdown_safe(&report.edition),
        surface_name,
        markdown_safe(&report.product_version),
        markdown_safe(&report.wcag_target),
        report.evaluated_at
    );
    for r in &report.rows {
        let lvl = match r.conformance {
            VpatConformanceLevel::Supports => "Supports",
            VpatConformanceLevel::PartiallySupports => "Partially Supports",
            VpatConformanceLevel::DoesNotSupport => "Does Not Support",
            VpatConformanceLevel::NotApplicable => "Not Applicable",
            VpatConformanceLevel::NotEvaluated => "Not Evaluated",
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            markdown_safe(&r.criterion),
            markdown_safe(&r.level),
            markdown_safe(&r.title),
            lvl,
            markdown_safe(&r.remarks)
        ));
    }
    out
}

pub fn verify_cargo_lock_crypto(
    cargo_lock: &str,
    export_doc_markdown: Option<&str>,
) -> Result<CryptoAllowlistReport, ComplyError> {
    let observed = extract_workspace_crypto_crates(cargo_lock);
    let refs: Vec<&str> = observed.iter().map(String::as_str).collect();
    verify_crypto_allowlist(&refs, export_doc_markdown)
}

pub fn extract_workspace_crypto_crates(cargo_lock: &str) -> Vec<String> {
    let mut found = BTreeSet::new();
    let mut in_deps = false;
    let mut pkg_crates: Vec<String> = Vec::new();

    for raw in cargo_lock.lines() {
        let line = raw.trim();
        if line == "[[package]]" {
            collect_crypto_names(&pkg_crates, &mut found);
            in_deps = false;
            pkg_crates.clear();
            continue;
        }
        if let Some(pkg_name) = line
            .strip_prefix("name = \"")
            .and_then(|s| s.strip_suffix('"'))
        {
            pkg_crates.push(pkg_name.trim().to_owned());
            continue;
        }
        if line.starts_with("dependencies = [") {
            if let Some(rest) = line.strip_prefix("dependencies = [") {
                if let Some(inline) = rest.strip_suffix(']') {
                    collect_inline_dep_items(inline, &mut pkg_crates);
                } else {
                    in_deps = true;
                }
            }
            continue;
        }
        if in_deps {
            if line == "]" {
                in_deps = false;
            } else {
                collect_inline_dep_items(line, &mut pkg_crates);
            }
        }
    }
    collect_crypto_names(&pkg_crates, &mut found);
    found.into_iter().collect()
}

fn collect_inline_dep_items(raw: &str, dest: &mut Vec<String>) {
    for part in raw.split(',') {
        let clean = part.trim().trim_matches('"').trim();
        if clean.is_empty() {
            continue;
        }
        let crate_name = clean.split_whitespace().next().unwrap_or(clean);
        if !crate_name.is_empty() {
            dest.push(crate_name.to_owned());
        }
    }
}

fn collect_crypto_names(deps: &[String], out: &mut BTreeSet<String>) {
    const PREFIX_STEMS: &[&str] = &[
        "ed25519",
        "x25519",
        "chacha",
        "sha1",
        "sha-1",
        "sha2",
        "sha3",
        "md5",
        "md-5",
        "hmac",
        "hkdf",
        "argon",
        "pbkdf",
        "blowfish",
        "openssl",
        "rustls",
        "aws-lc",
        "zeroize",
        "subtle",
        "getrandom",
        "blake",
        "aead",
        "poly1305",
        "curve25519",
        "cipher",
        "digest",
        "signature",
        "fiat-crypto",
    ];
    const EXACT_OR_TOKEN_STEMS: &[&str] = &[
        "aes", "rsa", "des", "rc4", "ring", "md5", "sha1", "sha2", "sha3", "hmac", "hkdf",
        "crypto", "openssl", "rustls", "aead",
    ];
    for dep in deps {
        let lower = dep.to_ascii_lowercase();
        if lower.starts_with("grdr-") || lower.ends_with("-probe") {
            continue;
        }
        let prefix_hit = PREFIX_STEMS.iter().any(|stem| lower.starts_with(stem));
        let token_hit = lower.split(['-', '_']).any(|tok| {
            EXACT_OR_TOKEN_STEMS
                .iter()
                .any(|stem| tok == *stem || (stem.len() >= 4 && tok.starts_with(stem)))
                || matches!(tok, "aes" | "rsa" | "des" | "rc4" | "md5")
        });
        if prefix_hit || token_hit {
            out.insert(dep.clone());
        }
    }
}
