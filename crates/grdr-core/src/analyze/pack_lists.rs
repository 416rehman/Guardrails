// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Cached embedded YAML list catalogs, signal pack builders, and dynamic regex recognisers (`P14`).

use std::path::Path;
use std::sync::OnceLock;

use regex::bytes::{Regex as BytesRegex, RegexBuilder as BytesRegexBuilder};

use crate::analyze::content::FindingDetectorKind;
use crate::analyze::pack_io::{pack_list_max_bytes, read_pack_child_text};
use crate::analyze::pack_lists_data::{
    EMBEDDED_AGENT_CONTROL_YAML, EMBEDDED_CONTENT_RECOGNISERS_YAML, EMBEDDED_DATAFLOW_SINKS_YAML,
    EMBEDDED_DESTRUCTIVE_YAML, EMBEDDED_EGRESS_YAML, EMBEDDED_ESSENTIALS_PROTECTED_YAML,
    EMBEDDED_NETWORK_ENDPOINTS_YAML, EMBEDDED_PROTECTED_PATHS_YAML, EMBEDDED_SECRET_PATHS_YAML,
    EMBEDDED_SIGNAL_PATTERNS_YAML, EMBEDDED_SUPPLY_CHAIN_YAML, extract_list,
    normalize_pack_path_item, parse_lists_map, push_unique, push_unique_slice,
};
pub use crate::analyze::pack_lists_data::{
    NetEndpointCatalog, ProtectedPathCatalog, SignalPatternCatalog,
};
use crate::detect::yaml::{YamlValue, parse_yaml};

const CONTENT_REGEX_SIZE_LIMIT: usize = 256 * 1024;
const CONTENT_REGEX_DFA_SIZE_LIMIT: usize = 256 * 1024;
const CONTENT_RECOGNISERS_FORMAT: &str = "grdr.content-recognisers.v1";
const MAX_RECOGNISERS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecogniserPostValidator {
    None,
    PemBlock,
    PemHeaderUncovered,
    LuhnSubranges,
    IbanMod97,
    UsSsnBounds,
}

#[derive(Debug, Clone)]
pub struct CompiledRecogniser {
    pub id: String,
    pub detector_kind: FindingDetectorKind,
    pub rule_kind: String,
    pub regex: BytesRegex,
    pub capture_group: usize,
    pub exclude_prefix: Option<Vec<u8>>,
    pub post_validator: RecogniserPostValidator,
}

#[derive(Debug, Clone)]
pub struct ContentRecogniserCatalog {
    pub rules: Vec<CompiledRecogniser>,
}

pub struct SignalYamlSources<'a> {
    pub protected_paths_yaml: &'a str,
    pub signal_patterns_yaml: &'a str,
    pub essentials_protected_yaml: &'a str,
    pub agent_control_yaml: &'a str,
    pub destructive_yaml: &'a str,
    pub egress_yaml: &'a str,
    pub secrets_yaml: &'a str,
    pub supply_chain_yaml: &'a str,
    pub dataflow_sinks_yaml: &'a str,
}

impl SignalPatternCatalog {
    pub fn from_yaml_sources(src: &SignalYamlSources<'_>) -> Result<Self, String> {
        let sig = parse_lists_map(src.signal_patterns_yaml)?;
        let ess = parse_lists_map(src.essentials_protected_yaml)?;
        let agt = parse_lists_map(src.agent_control_yaml)?;
        let dest = parse_lists_map(src.destructive_yaml)?;
        let eg = parse_lists_map(src.egress_yaml)?;
        let sec = parse_lists_map(src.secrets_yaml)?;
        let sup = parse_lists_map(src.supply_chain_yaml)?;
        let df = parse_lists_map(src.dataflow_sinks_yaml)?;

        let base_paths = parse_lists_map(src.protected_paths_yaml)?;
        let grdr_control_segs: Vec<String> = extract_list(&base_paths, "grdr_control_contains")
            .into_iter()
            .map(|item| item.trim_end_matches('/').to_owned())
            .collect();

        let flag_only = extract_list(&sig, "destructive_flag_only_commands");
        let mut destructive_patterns = extract_list(&sig, "destructive_patterns");
        let mut destructive_risk_patterns = extract_list(&sig, "destructive_risk_patterns");
        for item in extract_list(&dest, "destructive_commands") {
            push_unique(&mut destructive_risk_patterns, item.clone());
            if !flag_only.iter().any(|f| f == &item) {
                push_unique(&mut destructive_patterns, item);
            }
        }

        let mut egress_exfil_patterns = extract_list(&sig, "egress_exfil_patterns");
        push_unique_slice(
            &mut egress_exfil_patterns,
            extract_list(&eg, "blocked_metadata_hosts"),
        );
        push_unique_slice(
            &mut egress_exfil_patterns,
            extract_list(&eg, "monitored_upload_hosts"),
        );

        let mut external_network_risk_patterns =
            extract_list(&sig, "external_network_risk_patterns");
        push_unique_slice(
            &mut external_network_risk_patterns,
            extract_list(&eg, "monitored_upload_hosts"),
        );

        let unsafe_installers = extract_list(&sup, "unsafe_installers");
        let mut pkg_publish_patterns = extract_list(&sig, "pkg_publish_patterns");
        for item in &unsafe_installers {
            if item.contains("publish") || item.contains("upload") {
                push_unique(&mut pkg_publish_patterns, item.clone());
            }
        }

        let mut hook_bypass_risk_patterns = extract_list(&sig, "hook_bypass_risk_patterns");
        push_unique_slice(
            &mut hook_bypass_risk_patterns,
            extract_list(&ess, "bypass_flags"),
        );

        let mut agent_control_risk_patterns = extract_list(&sig, "agent_control_risk_patterns");
        push_unique_slice(
            &mut agent_control_risk_patterns,
            extract_list(&agt, "protected_control_paths"),
        );

        let mut extra_control_segments = extract_list(&sig, "extra_control_segments");
        for item in extract_list(&agt, "protected_control_paths") {
            let trimmed = item.trim_end_matches('/').to_owned();
            if !grdr_control_segs.contains(&trimmed) {
                push_unique(&mut extra_control_segments, trimmed);
            }
        }

        let mut credential_risk_patterns = extract_list(&sig, "credential_risk_patterns");
        push_unique_slice(
            &mut credential_risk_patterns,
            extract_list(&sec, "credential_stores"),
        );

        let mut extra_cred_segments = extract_list(&sig, "extra_cred_segments");
        for item in extract_list(&sec, "credential_stores") {
            push_unique(
                &mut extra_cred_segments,
                item.trim_end_matches('/').to_owned(),
            );
        }
        for item in extract_list(&ess, "credential_stores") {
            let norm = normalize_pack_path_item(&item);
            if norm.starts_with(".ssh/") {
                push_unique(&mut extra_cred_segments, ".ssh".into());
            } else if norm.starts_with(".aws/") {
                push_unique(&mut extra_cred_segments, ".aws".into());
            } else if norm.starts_with(".config/gh") {
                push_unique(&mut extra_cred_segments, ".config/gh".into());
            } else if !norm.is_empty() {
                push_unique(&mut extra_cred_segments, norm);
            }
        }

        Ok(Self {
            destructive_patterns,
            egress_exfil_patterns,
            pkg_publish_patterns,
            cloud_admin_patterns: extract_list(&sig, "cloud_admin_patterns"),
            secret_value_patterns: extract_list(&sig, "secret_value_patterns"),
            extra_control_segments,
            extra_cred_segments,
            agent_control_risk_patterns,
            credential_risk_patterns,
            hook_bypass_risk_patterns,
            destructive_risk_patterns,
            privilege_escalation_patterns: extract_list(&sig, "privilege_escalation_patterns"),
            external_network_risk_patterns,
            mcp_write_verbs: extract_list(&sig, "mcp_write_verbs"),
            mcp_write_tokens: extract_list(&sig, "mcp_write_tokens"),
            mcp_read_tokens: extract_list(&sig, "mcp_read_tokens"),
            bypass_permission_flags: extract_list(&sig, "bypass_permission_flags"),
            hooks_disabled_flags: extract_list(&sig, "hooks_disabled_flags"),
            no_sandbox_flags: extract_list(&sig, "no_sandbox_flags"),
            grdr_disable_flags: extract_list(&sig, "grdr_disable_flags"),
            unsafe_installers,
            sink_classes: extract_list(&df, "default_sink_classes"),
            analyze_opaque_patterns: extract_list(&sig, "analyze_opaque_patterns"),
            message_send_patterns: extract_list(&sig, "message_send_patterns"),
        })
    }

    pub fn load_from_packs_dir(packs_dir: &Path) -> Result<Self, String> {
        let max_bytes = pack_list_max_bytes()?;
        let sig = read_pack_child_text(packs_dir, "lists/signal-patterns.yaml", max_bytes)?;
        let ess = read_pack_child_text(
            packs_dir,
            "essentials/lists/protected-paths.yaml",
            max_bytes,
        )?;
        let agt = read_pack_child_text(
            packs_dir,
            "agents/lists/agent-control-files.yaml",
            max_bytes,
        )?;
        let dest = read_pack_child_text(
            packs_dir,
            "destructive/lists/destructive-patterns.yaml",
            max_bytes,
        )?;
        let eg = read_pack_child_text(
            packs_dir,
            "egress/lists/egress-destinations.yaml",
            max_bytes,
        )?;
        let sec = read_pack_child_text(packs_dir, "secrets/lists/secret-paths.yaml", max_bytes)?;
        let sup = read_pack_child_text(
            packs_dir,
            "supply-chain/lists/supply-chain-patterns.yaml",
            max_bytes,
        )?;
        let prot = read_pack_child_text(packs_dir, "lists/protected-paths.yaml", max_bytes)?;
        let df = read_pack_child_text(packs_dir, "dataflow/lists/sink-classes.yaml", max_bytes)?;
        Self::from_yaml_sources(&SignalYamlSources {
            protected_paths_yaml: &prot,
            signal_patterns_yaml: &sig,
            essentials_protected_yaml: &ess,
            agent_control_yaml: &agt,
            destructive_yaml: &dest,
            egress_yaml: &eg,
            secrets_yaml: &sec,
            supply_chain_yaml: &sup,
            dataflow_sinks_yaml: &df,
        })
    }
}

impl ContentRecogniserCatalog {
    pub fn from_yaml(yaml_src: &str) -> Result<Self, String> {
        let max_bytes = usize::try_from(pack_list_max_bytes()?).unwrap_or(usize::MAX);
        if yaml_src.len() > max_bytes {
            return Err("recognisers YAML exceeds byte limit".into());
        }
        let doc = parse_yaml(yaml_src).map_err(|e| format!("invalid recogniser YAML: {e}"))?;
        let format = doc
            .get("format")
            .and_then(YamlValue::as_str)
            .ok_or_else(|| "recognisers YAML missing `format` header".to_owned())?;
        if format != CONTENT_RECOGNISERS_FORMAT {
            return Err(format!("unexpected recognisers YAML format `{format}`"));
        }
        let items = doc
            .get("recognisers")
            .and_then(YamlValue::as_seq)
            .ok_or_else(|| "recognisers YAML missing `recognisers` sequence".to_owned())?;
        if items.len() > MAX_RECOGNISERS {
            return Err("recognisers count exceeds bound".into());
        }
        let mut rules = Vec::with_capacity(items.len());
        for item in items {
            let map = item
                .as_map()
                .ok_or_else(|| "recogniser entry must be mapping".to_owned())?;
            let id = required_str(map, "id")?;
            let detector_kind = match required_str(map, "detector_kind")?.as_str() {
                "secret" => FindingDetectorKind::Secret,
                "pii" => FindingDetectorKind::Pii,
                other => return Err(format!("unknown detector_kind `{other}`")),
            };
            let rule_kind = required_str(map, "rule_kind")?;
            let pattern = required_str(map, "regex")?;
            let regex = BytesRegexBuilder::new(&pattern)
                .size_limit(CONTENT_REGEX_SIZE_LIMIT)
                .dfa_size_limit(CONTENT_REGEX_DFA_SIZE_LIMIT)
                .build()
                .map_err(|e| format!("invalid regex in recogniser `{id}`: {e}"))?;
            let capture_group = match map.get("capture_group") {
                None => 0usize,
                Some(val) => {
                    let raw = val.as_i64().ok_or_else(|| {
                        format!("invalid non-integer capture_group in recogniser `{id}`")
                    })?;
                    let idx = usize::try_from(raw)
                        .map_err(|_| format!("negative capture_group in recogniser `{id}`"))?;
                    if idx >= regex.captures_len() {
                        return Err(format!(
                            "capture_group {idx} out of bounds for recogniser `{id}`"
                        ));
                    }
                    idx
                }
            };
            let exclude_prefix = match map.get("exclude_prefix") {
                None => None,
                Some(val) => {
                    let s = val
                        .as_str()
                        .ok_or_else(|| format!("non-string exclude_prefix in recogniser `{id}`"))?;
                    Some(s.as_bytes().to_vec())
                }
            };
            let post_validator_str = match map.get("post_validator") {
                None => "none",
                Some(val) => val
                    .as_str()
                    .ok_or_else(|| format!("non-string post_validator in recogniser `{id}`"))?,
            };
            let post_validator = match post_validator_str {
                "none" => RecogniserPostValidator::None,
                "pem_block" => RecogniserPostValidator::PemBlock,
                "pem_header_uncovered" => RecogniserPostValidator::PemHeaderUncovered,
                "luhn_subranges" => RecogniserPostValidator::LuhnSubranges,
                "iban_mod97" => RecogniserPostValidator::IbanMod97,
                "us_ssn_bounds" => RecogniserPostValidator::UsSsnBounds,
                other => return Err(format!("unknown post_validator `{other}`")),
            };
            rules.push(CompiledRecogniser {
                id,
                detector_kind,
                rule_kind,
                regex,
                capture_group,
                exclude_prefix,
                post_validator,
            });
        }
        Ok(Self { rules })
    }

    pub fn load_from_packs_dir(packs_dir: &Path) -> Result<Self, String> {
        let yaml = read_pack_child_text(
            packs_dir,
            "lists/content-recognisers.yaml",
            pack_list_max_bytes()?,
        )?;
        Self::from_yaml(&yaml)
    }
}

pub fn default_protected_path_catalog() -> Result<&'static ProtectedPathCatalog, &'static str> {
    static CACHE: OnceLock<Result<ProtectedPathCatalog, String>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            ProtectedPathCatalog::from_yaml_sources(
                EMBEDDED_PROTECTED_PATHS_YAML,
                EMBEDDED_ESSENTIALS_PROTECTED_YAML,
                EMBEDDED_AGENT_CONTROL_YAML,
                EMBEDDED_SECRET_PATHS_YAML,
            )
        })
        .as_ref()
        .map_err(|_| "embedded protected path YAML catalog failed to load")
}

pub fn default_net_endpoint_catalog() -> Result<&'static NetEndpointCatalog, &'static str> {
    static CACHE: OnceLock<Result<NetEndpointCatalog, String>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            NetEndpointCatalog::from_yaml_sources(
                EMBEDDED_NETWORK_ENDPOINTS_YAML,
                EMBEDDED_EGRESS_YAML,
            )
        })
        .as_ref()
        .map_err(|_| "embedded network endpoint YAML catalog failed to load")
}

pub fn default_signal_pattern_catalog() -> Result<&'static SignalPatternCatalog, &'static str> {
    static CACHE: OnceLock<Result<SignalPatternCatalog, String>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            SignalPatternCatalog::from_yaml_sources(&SignalYamlSources {
                protected_paths_yaml: EMBEDDED_PROTECTED_PATHS_YAML,
                signal_patterns_yaml: EMBEDDED_SIGNAL_PATTERNS_YAML,
                essentials_protected_yaml: EMBEDDED_ESSENTIALS_PROTECTED_YAML,
                agent_control_yaml: EMBEDDED_AGENT_CONTROL_YAML,
                destructive_yaml: EMBEDDED_DESTRUCTIVE_YAML,
                egress_yaml: EMBEDDED_EGRESS_YAML,
                secrets_yaml: EMBEDDED_SECRET_PATHS_YAML,
                supply_chain_yaml: EMBEDDED_SUPPLY_CHAIN_YAML,
                dataflow_sinks_yaml: EMBEDDED_DATAFLOW_SINKS_YAML,
            })
        })
        .as_ref()
        .map_err(|_| "embedded signal pattern YAML catalog failed to load")
}

pub fn default_content_recognisers() -> Result<&'static ContentRecogniserCatalog, &'static str> {
    static CACHE: OnceLock<Result<ContentRecogniserCatalog, String>> = OnceLock::new();
    CACHE
        .get_or_init(|| ContentRecogniserCatalog::from_yaml(EMBEDDED_CONTENT_RECOGNISERS_YAML))
        .as_ref()
        .map_err(|_| "embedded content recognisers YAML catalog failed to load")
}

fn required_str(
    map: &std::collections::BTreeMap<String, YamlValue>,
    key: &str,
) -> Result<String, String> {
    map.get(key)
        .and_then(YamlValue::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("missing string key `{key}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::content::scan_deterministic_content_with_catalog;
    use crate::analyze::path_rules::{ProtectedPathClass, classify_protected_path_with_catalog};

    #[test]
    fn loads_dynamic_protected_paths_and_custom_recognisers_from_yaml() {
        let base = include_str!("../../../../packs/lists/protected-paths.yaml");
        let custom_ess = "format: grdr.policy-lists.v1\npack_id: grdr.essentials\nlists:\n  agent_control:\n    - \".mcp.json\"\n  grdr_control:\n    - \"/corp-vault/\"\n";
        let cat = ProtectedPathCatalog::from_yaml_sources(
            base,
            custom_ess,
            EMBEDDED_AGENT_CONTROL_YAML,
            EMBEDDED_SECRET_PATHS_YAML,
        )
        .expect("custom yaml catalog");
        assert!(
            cat.classify("/repo/.mcp.json")
                .contains(&ProtectedPathClass::AgentControl)
        );
        assert!(
            classify_protected_path_with_catalog("/corp-vault/key", &cat)
                .contains(&ProtectedPathClass::GrdrControl)
        );

        let def_cat = default_protected_path_catalog().expect("default protected paths");
        assert!(
            def_cat
                .classify("/repo/.mcp.json")
                .contains(&ProtectedPathClass::AgentControl)
        );
        assert!(
            def_cat
                .classify("/etc/grdr/config.toml")
                .contains(&ProtectedPathClass::GrdrControl)
        );
        assert!(
            def_cat
                .classify("/repo/.agents/hooks/pre.sh")
                .contains(&ProtectedPathClass::MonitoringConfig)
        );

        let custom_rec_yaml = "format: grdr.content-recognisers.v1\npack_id: custom.rec\nrecognisers:\n  - id: corp_pat\n    detector_kind: secret\n    rule_kind: corp_token\n    regex: 'corp_live_[0-9]{12}'\n";
        let rec_cat =
            ContentRecogniserCatalog::from_yaml(custom_rec_yaml).expect("custom recogniser");
        let sample = ["key=", "corp_live_", "123456789012"].concat();
        let report = scan_deterministic_content_with_catalog(sample.as_bytes(), None, &rec_cat);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].label, "corp_token");

        let bad_rec = "format: grdr.content-recognisers.v1\npack_id: bad\nrecognisers:\n  - id: broken\n    detector_kind: secret\n    rule_kind: bad\n    regex: '[unclosed'\n";
        assert!(ContentRecogniserCatalog::from_yaml(bad_rec).is_err());
    }

    #[test]
    fn rejects_malformed_truncated_and_oversized_catalog_inputs() {
        let mut over =
            String::from("format: grdr.policy-lists.v1\npack_id: test\nlists:\n  items:\n");
        for i in 0..=2_048 {
            over.push_str(&format!("    - \"item-{i}\"\n"));
        }
        assert!(parse_lists_map(&over).is_err());

        let null_list = "format: grdr.policy-lists.v1\npack_id: test\nlists:\n  items: null\n";
        assert!(parse_lists_map(null_list).is_err());

        let bad_fmt = "format: wrong.v1\npack_id: test\nlists:\n  items:\n    - \"a\"\n";
        assert!(parse_lists_map(bad_fmt).is_err());

        assert_eq!(normalize_pack_path_item("~/.ssh/id_**"), ".ssh/id_");
        let cat = default_protected_path_catalog().expect("default protected paths");
        assert!(
            cat.classify(r"C:\repo\.claude\settings.json")
                .contains(&ProtectedPathClass::AgentControl)
        );

        let bad_fmt_rec = "format: wrong.v1\npack_id: r\nrecognisers: []\n";
        assert!(ContentRecogniserCatalog::from_yaml(bad_fmt_rec).is_err());

        let neg_cap = "format: grdr.content-recognisers.v1\npack_id: r\nrecognisers:\n  - id: x\n    detector_kind: secret\n    rule_kind: k\n    regex: '(abc)'\n    capture_group: -1\n";
        assert!(ContentRecogniserCatalog::from_yaml(neg_cap).is_err());

        let oob_cap = "format: grdr.content-recognisers.v1\npack_id: r\nrecognisers:\n  - id: x\n    detector_kind: secret\n    rule_kind: k\n    regex: '(abc)'\n    capture_group: 2\n";
        assert!(ContentRecogniserCatalog::from_yaml(oob_cap).is_err());

        let bad_post = "format: grdr.content-recognisers.v1\npack_id: r\nrecognisers:\n  - id: x\n    detector_kind: secret\n    rule_kind: k\n    regex: 'abc'\n    post_validator: 42\n";
        assert!(ContentRecogniserCatalog::from_yaml(bad_post).is_err());
    }
}
