// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Distribution manifest (`dist.toml`) parser and server profile adapter closure resolver (`D-34`, `E2`, `GRDR-CFG-0007`).

use std::collections::BTreeMap;

use grdr_model::CodedError;
use serde::{Deserialize, Serialize};

use crate::dist_parse::{parse_dist_manifest_toml, parse_support_bus_map_strict};
use crate::tenant::ProfileKind;

pub const CODE_CFG_PROFILE_CLOSURE: &str = "GRDR-CFG-0007";
pub const EMBEDDED_DIST_TOML: &str = include_str!("../../../deploy/release/dist.toml");
pub const EMBEDDED_SUPPORT_TOML: &str = include_str!("../../../contracts/support.toml");
const EXPECTED_DIST_SCHEMA: &str = "grdr.dist.v1alpha1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistManifest {
    pub schema: String,
    pub brand_manifest: String,
    pub channel_default: String,
    pub phone_home: bool,
    pub release_manifest_schema: String,
    pub compatibility_matrix: String,
    pub tier1_adapters: Vec<String>,
    pub contrib_adapters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileAdapterRule {
    pub relational: Vec<String>,
    pub bus: Vec<String>,
    pub events: Vec<String>,
    pub blobs: Vec<String>,
    pub keys: Vec<String>,
    pub max_orgs: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileClosureRequest {
    pub profile: ProfileKind,
    pub relational_adapter: String,
    pub bus_adapter: String,
    pub events_adapter: String,
    pub blob_adapter: String,
    pub keys_adapter: String,
    pub organisation_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedProfileClosure {
    pub profile: ProfileKind,
    pub relational_adapter: String,
    pub bus_adapter: String,
    pub events_adapter: String,
    pub blob_adapter: String,
    pub keys_adapter: String,
    pub admitted_adapters: Vec<String>,
}

pub fn load_embedded_dist_manifest() -> Result<DistManifest, CodedError> {
    parse_dist_toml(EMBEDDED_DIST_TOML)
}

pub fn parse_dist_toml(raw: &str) -> Result<DistManifest, CodedError> {
    let manifest = parse_dist_manifest_toml(raw)?;
    if manifest.schema != EXPECTED_DIST_SCHEMA {
        return Err(cfg_err(format!(
            "unsupported dist.toml schema `{}` (expected `{EXPECTED_DIST_SCHEMA}`)",
            manifest.schema
        )));
    }
    if manifest.phone_home {
        return Err(cfg_err(
            "dist.toml violates P16 invariant: phone_home must remain false",
        ));
    }
    if manifest.tier1_adapters.is_empty() {
        return Err(cfg_err("dist.toml [adapters].tier1 cannot be empty"));
    }
    Ok(manifest)
}

pub fn resolve_profile_closure(
    manifest: &DistManifest,
    req_cfg: &ProfileClosureRequest,
) -> Result<ResolvedProfileClosure, CodedError> {
    resolve_profile_closure_with_support(manifest, req_cfg, EMBEDDED_SUPPORT_TOML)
}

pub fn resolve_profile_closure_with_support(
    manifest: &DistManifest,
    req_cfg: &ProfileClosureRequest,
    support_toml: &str,
) -> Result<ResolvedProfileClosure, CodedError> {
    let support_bus = parse_support_bus_map_strict(support_toml)?;
    let profile_name = profile_label(req_cfg.profile);
    if req_cfg.organisation_count == 0 {
        return Err(cfg_err(format!(
            "profile `{profile_name}` requires organisation_count >= 1"
        )));
    }
    let rule = profile_rule(req_cfg.profile, manifest, &support_bus)?;

    if let Some(max_orgs) = rule.max_orgs
        && req_cfg.organisation_count > max_orgs
    {
        return Err(cfg_err(format!(
            "profile `{profile_name}` supports at most {max_orgs} organisation(s), got {}",
            req_cfg.organisation_count
        )));
    }

    let selected = [
        (
            "relational",
            req_cfg.relational_adapter.as_str(),
            &rule.relational,
        ),
        ("bus", req_cfg.bus_adapter.as_str(), &rule.bus),
        ("events", req_cfg.events_adapter.as_str(), &rule.events),
        ("blob", req_cfg.blob_adapter.as_str(), &rule.blobs),
        ("keys", req_cfg.keys_adapter.as_str(), &rule.keys),
    ];

    let mut admitted = Vec::with_capacity(selected.len());
    for (slot_name, adapter_name, allowed_for_slot) in selected {
        let trimmed = adapter_name.trim();
        if trimmed.is_empty() || is_forbidden_test_adapter(trimmed) {
            return Err(cfg_err(format!(
                "{slot_name} adapter `{adapter_name}` is forbidden in production profile `{profile_name}`"
            )));
        }
        if !allowed_for_slot.iter().any(|a| a == trimmed) {
            return Err(cfg_err(format!(
                "{slot_name} adapter `{trimmed}` is not part of profile `{profile_name}`"
            )));
        }
        if slot_requires_dist_admission(slot_name)
            && !manifest.tier1_adapters.iter().any(|a| a == trimmed)
            && !manifest.contrib_adapters.iter().any(|a| a == trimmed)
        {
            return Err(cfg_err(format!(
                "{slot_name} adapter `{trimmed}` is not admitted in dist.toml"
            )));
        }
        if !admitted.iter().any(|a| a == trimmed) {
            admitted.push(trimmed.to_owned());
        }
    }

    Ok(ResolvedProfileClosure {
        profile: req_cfg.profile,
        relational_adapter: req_cfg.relational_adapter.trim().to_owned(),
        bus_adapter: req_cfg.bus_adapter.trim().to_owned(),
        events_adapter: req_cfg.events_adapter.trim().to_owned(),
        blob_adapter: req_cfg.blob_adapter.trim().to_owned(),
        keys_adapter: req_cfg.keys_adapter.trim().to_owned(),
        admitted_adapters: admitted,
    })
}

fn slot_requires_dist_admission(slot_name: &str) -> bool {
    matches!(slot_name, "relational" | "bus" | "events" | "blob" | "keys")
}

fn is_forbidden_test_adapter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("memory") || lower.contains("testkit") || lower.contains("kitkey")
}

fn profile_label(profile: ProfileKind) -> &'static str {
    match profile {
        ProfileKind::Embedded => "embedded",
        ProfileKind::Ha => "ha",
        ProfileKind::Distributed => "distributed",
    }
}

fn admit_exact(manifest: &DistManifest, allow: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for src in manifest
        .tier1_adapters
        .iter()
        .chain(manifest.contrib_adapters.iter())
    {
        if allow.contains(&src.as_str()) && !out.iter().any(|x| x == src) {
            out.push(src.clone());
        }
    }
    out
}

fn bus_allowlist_for_profile(
    profile: ProfileKind,
    support_bus: &BTreeMap<String, String>,
) -> Result<&'static [&'static str], CodedError> {
    let label = profile_label(profile);
    let Some(bus_token) = support_bus.get(label).map(String::as_str) else {
        return Err(cfg_err(format!(
            "support.toml [platform.bus] missing `{label}` mapping"
        )));
    };
    match profile {
        ProfileKind::Embedded if bus_token == "sqlite-log" => Ok(&["grdr-bus-log"]),
        ProfileKind::Ha if bus_token == "postgresql-log" => Ok(&["grdr-bus-log"]),
        ProfileKind::Distributed if bus_token.starts_with("nats-jetstream") => {
            Ok(&["grdr-bus-nats"])
        }
        _ => Err(cfg_err(format!(
            "support.toml [platform.bus].{label} = `{bus_token}` is unsupported"
        ))),
    }
}

fn profile_rule(
    profile: ProfileKind,
    manifest: &DistManifest,
    support_bus: &BTreeMap<String, String>,
) -> Result<ProfileAdapterRule, CodedError> {
    let bus_allow = bus_allowlist_for_profile(profile, support_bus)?;
    let rule = match profile {
        ProfileKind::Embedded => ProfileAdapterRule {
            relational: admit_exact(manifest, &["grdr-rel-sqlite"]),
            bus: admit_exact(manifest, bus_allow),
            events: admit_exact(manifest, &["grdr-lake"]),
            blobs: admit_exact(manifest, &["grdr-store-local", "grdr-blob"]),
            keys: admit_exact(manifest, &["local", "kms"]),
            max_orgs: Some(1),
        },
        ProfileKind::Ha | ProfileKind::Distributed => ProfileAdapterRule {
            relational: admit_exact(manifest, &["grdr-rel-postgres"]),
            bus: admit_exact(manifest, bus_allow),
            events: admit_exact(manifest, &["grdr-lake"]),
            blobs: admit_exact(manifest, &["grdr-blob"]),
            keys: admit_exact(manifest, &["local", "kms"]),
            max_orgs: None,
        },
    };
    Ok(rule)
}

pub(crate) fn cfg_err(detail: impl Into<String>) -> CodedError {
    CodedError::new(
        CODE_CFG_PROFILE_CLOSURE,
        detail.into(),
        "Select adapters belonging to the chosen server profile (`embedded`, `ha`, `distributed`) in dist.toml.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_dist_toml() -> String {
        format!(
            "{EMBEDDED_DIST_TOML}\ncontrib = [\"grdr-blob\", \"kms\", \"evil-grdr-rel-sqlite\"]\n"
        )
    }

    fn req_for(
        profile: ProfileKind,
        relational: &str,
        bus: &str,
        blob: &str,
        keys: &str,
        orgs: usize,
    ) -> ProfileClosureRequest {
        ProfileClosureRequest {
            profile,
            relational_adapter: relational.into(),
            bus_adapter: bus.into(),
            events_adapter: "grdr-lake".into(),
            blob_adapter: blob.into(),
            keys_adapter: keys.into(),
            organisation_count: orgs,
        }
    }

    #[test]
    fn embedded_dist_manifest_resolves_all_three_profiles_and_rejects_mismatches() {
        let embedded_manifest = load_embedded_dist_manifest().expect("load embedded dist.toml");
        assert!(!embedded_manifest.phone_home);
        assert!(
            embedded_manifest
                .tier1_adapters
                .iter()
                .any(|a| a == "grdr-bus-nats")
        );

        let mut manifest = parse_dist_toml(&full_dist_toml()).expect("parse full dist manifest");
        manifest.tier1_adapters.push("local".into());

        let emb = resolve_profile_closure(
            &manifest,
            &req_for(
                ProfileKind::Embedded,
                "grdr-rel-sqlite",
                "grdr-bus-log",
                "grdr-store-local",
                "local",
                1,
            ),
        )
        .expect("embedded profile passes");
        assert_eq!(emb.bus_adapter, "grdr-bus-log");

        // Contrib-admitted `grdr-blob` and `kms` work cleanly across Ha and Distributed.
        let ha = resolve_profile_closure(
            &manifest,
            &req_for(
                ProfileKind::Ha,
                "grdr-rel-postgres",
                "grdr-bus-log",
                "grdr-blob",
                "kms",
                4,
            ),
        )
        .expect("ha profile with contrib adapters passes");
        assert_eq!(ha.relational_adapter, "grdr-rel-postgres");

        let dist = resolve_profile_closure(
            &manifest,
            &req_for(
                ProfileKind::Distributed,
                "grdr-rel-postgres",
                "grdr-bus-nats",
                "grdr-blob",
                "local",
                4,
            ),
        )
        .expect("distributed profile passes");
        assert_eq!(dist.bus_adapter, "grdr-bus-nats");

        // Unadmitted blob/keys adapters on raw embedded dist.toml fail closed via slot_requires_dist_admission.
        assert_eq!(
            resolve_profile_closure(
                &embedded_manifest,
                &req_for(
                    ProfileKind::Ha,
                    "grdr-rel-postgres",
                    "grdr-bus-log",
                    "grdr-blob",
                    "local",
                    1,
                ),
            )
            .expect_err("unadmitted blob/keys rejected")
            .code,
            CODE_CFG_PROFILE_CLOSURE
        );

        // Substring spoof in contrib (`evil-grdr-rel-sqlite`) is rejected by exact matching.
        assert_eq!(
            resolve_profile_closure(
                &manifest,
                &req_for(
                    ProfileKind::Embedded,
                    "evil-grdr-rel-sqlite",
                    "grdr-bus-log",
                    "grdr-store-local",
                    "local",
                    1,
                ),
            )
            .expect_err("substring spoof rejected")
            .code,
            CODE_CFG_PROFILE_CLOSURE
        );

        // organisation_count == 0, multi-org Embedded, wrong bus, Memory*, and Distributed missing bus fail.
        for bad_req in [
            req_for(
                ProfileKind::Embedded,
                "grdr-rel-sqlite",
                "grdr-bus-log",
                "grdr-store-local",
                "local",
                0,
            ),
            req_for(
                ProfileKind::Embedded,
                "grdr-rel-sqlite",
                "grdr-bus-log",
                "grdr-store-local",
                "local",
                2,
            ),
            req_for(
                ProfileKind::Ha,
                "grdr-rel-postgres",
                "grdr-bus-nats",
                "grdr-blob",
                "local",
                2,
            ),
            req_for(
                ProfileKind::Distributed,
                "grdr-rel-postgres",
                "grdr-bus-log",
                "grdr-blob",
                "local",
                2,
            ),
            req_for(
                ProfileKind::Ha,
                "MemoryRelationalStore",
                "grdr-bus-log",
                "grdr-blob",
                "local",
                1,
            ),
        ] {
            assert_eq!(
                resolve_profile_closure(&manifest, &bad_req)
                    .expect_err("invalid closure request must fail")
                    .code,
                CODE_CFG_PROFILE_CLOSURE
            );
        }

        // Strict parser rejects malformed lines, unknown section/keys, empty array items, and missing distributed bus.
        assert!(parse_dist_toml(&format!("{EMBEDDED_DIST_TOML}\nnot_a_kv_line\n")).is_err());
        assert!(parse_dist_toml(&format!("{EMBEDDED_DIST_TOML}\n[evil]\nx = \"1\"\n")).is_err());
        let empty_item = EMBEDDED_DIST_TOML.replace("\"grdr-store-local\",", "\"\",");
        assert!(parse_dist_toml(&empty_item).is_err());

        let escaped = EMBEDDED_DIST_TOML.replace(
            "channel_default = \"broad\"",
            "channel_default = \"br\\\"oad\"",
        );
        assert_eq!(
            parse_dist_toml(&escaped).unwrap().channel_default,
            "br\"oad"
        );

        assert!(
            resolve_profile_closure_with_support(
                &manifest,
                &req_for(
                    ProfileKind::Distributed,
                    "grdr-rel-postgres",
                    "grdr-bus-nats",
                    "grdr-blob",
                    "local",
                    2,
                ),
                "[platform.bus]\nembedded = \"sqlite-log\"\nha = \"postgresql-log\"\n",
            )
            .is_err()
        );
    }
}
