// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Typed YAML pack-list schemas and directory/embedded loaders (`P14`).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;

use crate::analyze::pack_io::{pack_list_max_bytes, read_pack_child_text};
use crate::analyze::path_rules::ProtectedPathClass;
use crate::detect::yaml::{YamlValue, parse_yaml};

const POLICY_LISTS_FORMAT: &str = "grdr.policy-lists.v1";
const MAX_PATTERNS_PER_LIST: usize = 2_048;

pub(crate) const EMBEDDED_PROTECTED_PATHS_YAML: &str =
    include_str!("../../../../packs/lists/protected-paths.yaml");
pub(crate) const EMBEDDED_ESSENTIALS_PROTECTED_YAML: &str =
    include_str!("../../../../packs/essentials/lists/protected-paths.yaml");
pub(crate) const EMBEDDED_AGENT_CONTROL_YAML: &str =
    include_str!("../../../../packs/agents/lists/agent-control-files.yaml");
pub(crate) const EMBEDDED_SECRET_PATHS_YAML: &str =
    include_str!("../../../../packs/secrets/lists/secret-paths.yaml");
pub(crate) const EMBEDDED_SIGNAL_PATTERNS_YAML: &str =
    include_str!("../../../../packs/lists/signal-patterns.yaml");
pub(crate) const EMBEDDED_DESTRUCTIVE_YAML: &str =
    include_str!("../../../../packs/destructive/lists/destructive-patterns.yaml");
pub(crate) const EMBEDDED_EGRESS_YAML: &str =
    include_str!("../../../../packs/egress/lists/egress-destinations.yaml");
pub(crate) const EMBEDDED_SUPPLY_CHAIN_YAML: &str =
    include_str!("../../../../packs/supply-chain/lists/supply-chain-patterns.yaml");
pub(crate) const EMBEDDED_DATAFLOW_SINKS_YAML: &str =
    include_str!("../../../../packs/dataflow/lists/sink-classes.yaml");
pub(crate) const EMBEDDED_NETWORK_ENDPOINTS_YAML: &str =
    include_str!("../../../../packs/lists/network-endpoints.yaml");
pub(crate) const EMBEDDED_CONTENT_RECOGNISERS_YAML: &str =
    include_str!("../../../../packs/lists/content-recognisers.yaml");

#[derive(Debug, Clone, Default)]
pub(crate) struct PathRulePatterns {
    pub(crate) contains: Vec<String>,
    pub(crate) exact: Vec<String>,
    pub(crate) prefixes: Vec<String>,
    pub(crate) segments: Vec<String>,
    pub(crate) env_exact_segments: Vec<String>,
    pub(crate) env_segment_prefixes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProtectedPathCatalog {
    pub(crate) agent_control: PathRulePatterns,
    pub(crate) grdr_control: PathRulePatterns,
    pub(crate) monitoring_config: PathRulePatterns,
    pub(crate) cred_store: PathRulePatterns,
    pub(crate) private_key: PathRulePatterns,
    pub(crate) agent_store: PathRulePatterns,
    pub(crate) browser_store: PathRulePatterns,
    pub(crate) autorun: PathRulePatterns,
    pub(crate) session_tmp: PathRulePatterns,
}

#[derive(Debug, Clone)]
pub struct NetEndpointCatalog {
    pub cloud_metadata_hosts: Vec<String>,
    pub paste_capture_hosts: Vec<String>,
    pub tunnel_service_hosts: Vec<String>,
    pub model_provider_hosts: Vec<String>,
    pub package_registry_hosts: Vec<String>,
    pub multi_tenant_api_hosts: Vec<String>,
    pub cloud_aws_ips: Vec<String>,
    pub cloud_aws_domains: Vec<String>,
    pub cloud_aws_segments: Vec<String>,
    pub cloud_gcp_domains: Vec<String>,
    pub cloud_gcp_segments: Vec<String>,
    pub cloud_azure_domains: Vec<String>,
    pub cloud_azure_segments: Vec<String>,
    pub llm_anthropic_domains: Vec<String>,
    pub llm_anthropic_segments: Vec<String>,
    pub llm_openai_domains: Vec<String>,
    pub llm_openai_segments: Vec<String>,
    pub llm_local_hosts: Vec<String>,
    pub llm_local_segments: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SignalPatternCatalog {
    pub destructive_patterns: Vec<String>,
    pub egress_exfil_patterns: Vec<String>,
    pub pkg_publish_patterns: Vec<String>,
    pub cloud_admin_patterns: Vec<String>,
    pub secret_value_patterns: Vec<String>,
    pub extra_control_segments: Vec<String>,
    pub extra_cred_segments: Vec<String>,
    pub agent_control_risk_patterns: Vec<String>,
    pub credential_risk_patterns: Vec<String>,
    pub hook_bypass_risk_patterns: Vec<String>,
    pub destructive_risk_patterns: Vec<String>,
    pub privilege_escalation_patterns: Vec<String>,
    pub external_network_risk_patterns: Vec<String>,
    pub mcp_write_verbs: Vec<String>,
    pub mcp_write_tokens: Vec<String>,
    pub mcp_read_tokens: Vec<String>,
    pub bypass_permission_flags: Vec<String>,
    pub hooks_disabled_flags: Vec<String>,
    pub no_sandbox_flags: Vec<String>,
    pub grdr_disable_flags: Vec<String>,
    pub unsafe_installers: Vec<String>,
    pub sink_classes: Vec<String>,
    pub analyze_opaque_patterns: Vec<String>,
    pub message_send_patterns: Vec<String>,
}

impl PathRulePatterns {
    pub(crate) fn matches(&self, lower_path: &str) -> bool {
        if self.exact.iter().any(|p| lower_path == p)
            || self.prefixes.iter().any(|p| lower_path.starts_with(p))
            || self.contains.iter().any(|n| lower_path.contains(n))
            || ends_with_any_segment(lower_path, &self.segments)
        {
            return true;
        }
        if !self.env_exact_segments.is_empty() || !self.env_segment_prefixes.is_empty() {
            return lower_path.split('/').any(|seg| {
                self.env_exact_segments.iter().any(|e| seg == e)
                    || self.env_segment_prefixes.iter().any(|p| seg.starts_with(p))
            });
        }
        false
    }

    fn extend_unique_contains(&mut self, items: impl IntoIterator<Item = String>) {
        let mut seen: BTreeSet<String> = self.contains.iter().cloned().collect();
        for item in items {
            let norm = normalize_pack_path_item(&item);
            if !norm.is_empty() && seen.insert(norm.clone()) {
                self.contains.push(norm);
            }
        }
    }
}

impl ProtectedPathCatalog {
    pub fn from_yaml_sources(
        lists_yaml: &str,
        essentials_yaml: &str,
        agents_yaml: &str,
        secrets_yaml: &str,
    ) -> Result<Self, String> {
        let base = parse_lists_map(lists_yaml)?;
        let ess = parse_lists_map(essentials_yaml)?;
        let agt = parse_lists_map(agents_yaml)?;
        let sec = parse_lists_map(secrets_yaml)?;

        let mut grdr_control = PathRulePatterns {
            contains: extract_list(&base, "grdr_control_contains"),
            ..PathRulePatterns::default()
        };
        grdr_control.extend_unique_contains(extract_list(&ess, "grdr_control"));

        let mut agent_control = PathRulePatterns {
            contains: extract_list(&base, "agent_control_contains"),
            segments: extract_list(&base, "agent_control_segments"),
            ..PathRulePatterns::default()
        };
        for item in extract_list(&ess, "agent_control") {
            let norm = normalize_pack_path_item(&item);
            if norm.is_empty() {
                continue;
            }
            if norm.contains('/') {
                push_unique(&mut agent_control.contains, norm);
            } else {
                push_unique(&mut agent_control.segments, norm);
            }
        }
        for item in extract_list(&agt, "protected_control_paths") {
            let norm = normalize_pack_path_item(&item);
            if norm.is_empty() || grdr_control.contains.contains(&norm) {
                continue;
            }
            push_unique(&mut agent_control.contains, norm);
        }

        let mut monitoring_config = PathRulePatterns {
            contains: extract_list(&base, "monitoring_config_contains"),
            ..PathRulePatterns::default()
        };
        monitoring_config.extend_unique_contains(extract_list(&ess, "monitoring_config"));

        let mut cred_store = PathRulePatterns {
            contains: extract_list(&base, "cred_store_contains"),
            env_exact_segments: extract_list(&base, "cred_store_env_exact_segments"),
            env_segment_prefixes: extract_list(&base, "cred_store_env_segment_prefixes"),
            ..PathRulePatterns::default()
        };
        let mut private_key = PathRulePatterns {
            contains: extract_list(&base, "private_key_contains"),
            ..PathRulePatterns::default()
        };
        for item in extract_list(&ess, "credential_stores")
            .into_iter()
            .chain(extract_list(&sec, "credential_stores"))
        {
            let norm = normalize_pack_path_item(&item);
            if norm.is_empty() {
                continue;
            }
            if is_private_key_pattern(&norm) {
                push_unique(&mut private_key.contains, norm);
            } else {
                push_unique(&mut cred_store.contains, norm);
            }
        }

        let agent_store = PathRulePatterns {
            contains: extract_list(&base, "agent_store_contains"),
            ..PathRulePatterns::default()
        };
        let browser_store = PathRulePatterns {
            contains: extract_list(&base, "browser_store_contains"),
            ..PathRulePatterns::default()
        };
        let autorun = PathRulePatterns {
            contains: extract_list(&base, "autorun_contains"),
            exact: extract_list(&base, "autorun_exact"),
            segments: extract_list(&base, "autorun_segments"),
            ..PathRulePatterns::default()
        };
        let session_tmp = PathRulePatterns {
            contains: extract_list(&base, "session_tmp_contains"),
            exact: extract_list(&base, "session_tmp_exact"),
            prefixes: extract_list(&base, "session_tmp_prefixes"),
            ..PathRulePatterns::default()
        };

        Ok(Self {
            agent_control,
            grdr_control,
            monitoring_config,
            cred_store,
            private_key,
            agent_store,
            browser_store,
            autorun,
            session_tmp,
        })
    }

    pub fn load_from_packs_dir(packs_dir: &Path) -> Result<Self, String> {
        let cap = pack_list_max_bytes()?;
        let lists = read_pack_child_text(packs_dir, "lists/protected-paths.yaml", cap)?;
        let ess = read_pack_child_text(packs_dir, "essentials/lists/protected-paths.yaml", cap)?;
        let agt = read_pack_child_text(packs_dir, "agents/lists/agent-control-files.yaml", cap)?;
        let sec = read_pack_child_text(packs_dir, "secrets/lists/secret-paths.yaml", cap)?;
        Self::from_yaml_sources(&lists, &ess, &agt, &sec)
    }

    #[must_use]
    pub fn classify(&self, path: &str) -> Vec<ProtectedPathClass> {
        let lower = path.replace('\\', "/").to_ascii_lowercase();
        let mut classes = Vec::new();
        let checks = [
            (ProtectedPathClass::AgentControl, &self.agent_control),
            (ProtectedPathClass::GrdrControl, &self.grdr_control),
            (
                ProtectedPathClass::MonitoringConfig,
                &self.monitoring_config,
            ),
            (ProtectedPathClass::CredStore, &self.cred_store),
            (ProtectedPathClass::PrivateKey, &self.private_key),
            (ProtectedPathClass::AgentStore, &self.agent_store),
            (ProtectedPathClass::BrowserStore, &self.browser_store),
            (ProtectedPathClass::Autorun, &self.autorun),
            (ProtectedPathClass::SessionTmp, &self.session_tmp),
        ];
        for (class, rules) in checks {
            if rules.matches(&lower) {
                classes.push(class);
            }
        }
        classes
    }
}

impl NetEndpointCatalog {
    pub fn from_yaml_sources(net_yaml: &str, egress_yaml: &str) -> Result<Self, String> {
        let map = parse_lists_map(net_yaml)?;
        let eg = parse_lists_map(egress_yaml)?;

        let mut cloud_metadata_hosts = extract_list(&map, "cloud_metadata_hosts");
        let mut cloud_aws_ips = extract_list(&map, "cloud_aws_ips");
        for item in extract_list(&eg, "blocked_metadata_hosts") {
            let norm = item.trim().to_ascii_lowercase();
            if norm.is_empty() {
                continue;
            }
            let is_numeric_ip = norm.parse::<IpAddr>().is_ok() || norm.starts_with("0x");
            if is_numeric_ip {
                push_unique(&mut cloud_aws_ips, norm.clone());
                if norm.parse::<IpAddr>().is_ok() {
                    push_unique(&mut cloud_metadata_hosts, norm);
                }
            } else {
                push_unique(&mut cloud_metadata_hosts, norm);
            }
        }
        let cloud_gcp_domains = extract_list(&map, "cloud_gcp_domains");

        Ok(Self {
            cloud_metadata_hosts,
            paste_capture_hosts: extract_list(&map, "paste_capture_hosts"),
            tunnel_service_hosts: extract_list(&map, "tunnel_service_hosts"),
            model_provider_hosts: extract_list(&map, "model_provider_hosts"),
            package_registry_hosts: extract_list(&map, "package_registry_hosts"),
            multi_tenant_api_hosts: extract_list(&map, "multi_tenant_api_hosts"),
            cloud_aws_ips,
            cloud_aws_domains: extract_list(&map, "cloud_aws_domains"),
            cloud_aws_segments: extract_list(&map, "cloud_aws_segments"),
            cloud_gcp_domains,
            cloud_gcp_segments: extract_list(&map, "cloud_gcp_segments"),
            cloud_azure_domains: extract_list(&map, "cloud_azure_domains"),
            cloud_azure_segments: extract_list(&map, "cloud_azure_segments"),
            llm_anthropic_domains: extract_list(&map, "llm_anthropic_domains"),
            llm_anthropic_segments: extract_list(&map, "llm_anthropic_segments"),
            llm_openai_domains: extract_list(&map, "llm_openai_domains"),
            llm_openai_segments: extract_list(&map, "llm_openai_segments"),
            llm_local_hosts: extract_list(&map, "llm_local_hosts"),
            llm_local_segments: extract_list(&map, "llm_local_segments"),
        })
    }

    pub fn load_from_packs_dir(packs_dir: &Path) -> Result<Self, String> {
        let cap = pack_list_max_bytes()?;
        let net = read_pack_child_text(packs_dir, "lists/network-endpoints.yaml", cap)?;
        let eg = read_pack_child_text(packs_dir, "egress/lists/egress-destinations.yaml", cap)?;
        Self::from_yaml_sources(&net, &eg)
    }
}

pub(crate) fn parse_lists_map(
    yaml_src: &str,
) -> Result<std::collections::BTreeMap<String, Vec<String>>, String> {
    let max_bytes = usize::try_from(pack_list_max_bytes()?).unwrap_or(usize::MAX);
    if yaml_src.len() > max_bytes {
        return Err("pack list YAML exceeds byte limit".into());
    }
    let doc = parse_yaml(yaml_src).map_err(|e| format!("invalid pack list YAML: {e}"))?;
    let format = doc
        .get("format")
        .and_then(YamlValue::as_str)
        .ok_or_else(|| "pack list YAML missing `format` header".to_owned())?;
    if format != POLICY_LISTS_FORMAT {
        return Err(format!("unexpected pack list YAML format `{format}`"));
    }
    let Some(lists) = doc.get("lists").and_then(YamlValue::as_map) else {
        return Err("pack list YAML missing `lists` mapping".into());
    };
    let mut out = std::collections::BTreeMap::new();
    for (key, val) in lists {
        let raw_items = val
            .try_to_string_list()
            .map_err(|e| format!("invalid list `{key}` in pack YAML: {e}"))?;
        if raw_items.len() > MAX_PATTERNS_PER_LIST {
            return Err(format!(
                "pack list `{key}` exceeds {MAX_PATTERNS_PER_LIST} entries ({})",
                raw_items.len()
            ));
        }
        let items: Vec<String> = raw_items
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        out.insert(key.clone(), items);
    }
    Ok(out)
}

pub(crate) fn extract_list(
    map: &std::collections::BTreeMap<String, Vec<String>>,
    key: &str,
) -> Vec<String> {
    map.get(key).cloned().unwrap_or_default()
}

pub(crate) fn push_unique(vec: &mut Vec<String>, val: String) {
    if !val.is_empty() && !vec.contains(&val) {
        vec.push(val);
    }
}

pub(crate) fn push_unique_slice(vec: &mut Vec<String>, items: impl IntoIterator<Item = String>) {
    for item in items {
        push_unique(vec, item);
    }
}

pub(crate) fn normalize_pack_path_item(raw: &str) -> String {
    let trimmed = raw.trim().to_ascii_lowercase().replace('\\', "/");
    let no_home = trimmed.strip_prefix("~/").unwrap_or(&trimmed);
    let no_glob_tail = no_home.trim_end_matches('*');
    no_glob_tail.to_owned()
}

fn is_private_key_pattern(norm: &str) -> bool {
    norm.contains(".ssh/")
        || norm.contains(".gnupg/")
        || norm.contains("id_rsa")
        || norm.contains("id_ed25519")
        || norm.contains("id_ecdsa")
        || norm.ends_with(".pem")
        || norm.ends_with(".p12")
        || norm.ends_with(".pfx")
}

fn ends_with_any_segment(path: &str, segs: &[String]) -> bool {
    segs.iter().any(|seg| {
        path == seg
            || path
                .strip_suffix(seg.as_str())
                .is_some_and(|prefix| prefix.ends_with('/'))
    })
}
