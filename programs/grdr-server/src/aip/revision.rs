// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use grdr_crypto::sha256_hex;
use grdr_proto::common::{CollectionKind, RevisionMeta};

#[derive(Debug)]
pub struct RevisionTable {
    entries: BTreeMap<&'static str, AtomicU64>,
}

impl Default for RevisionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RevisionTable {
    pub fn new() -> Self {
        let mut entries = BTreeMap::new();
        for key in [
            "overview",
            "keys",
            "packs",
            "browser_policies",
            "devices",
            "agents",
            "mcp_servers",
            "artifacts",
            "connect_config",
            "integrations",
            "sessions",
            "users",
            "privacy_config",
            "approvals",
            "findings",
            "incidents",
            "kill_switch",
            "audit_events",
        ] {
            entries.insert(key, AtomicU64::new(1));
        }
        Self { entries }
    }

    pub fn current(&self, collection: CollectionKind) -> u64 {
        self.entries
            .get(collection_key(collection))
            .map(|v| v.load(Ordering::Acquire))
            .unwrap_or(1)
    }

    pub fn bump(&self, collection: CollectionKind) -> u64 {
        let rev = self
            .entries
            .get(collection_key(collection))
            .map(|v| v.fetch_add(1, Ordering::AcqRel).saturating_add(1))
            .unwrap_or(1);
        if let Some(overview) = self.entries.get("overview") {
            overview.fetch_add(1, Ordering::AcqRel);
        }
        rev
    }

    pub fn meta_for(
        &self,
        collection: CollectionKind,
        tenant: &str,
        params_digest_seed: &str,
    ) -> RevisionMeta {
        let hwm = self.current(collection);
        let raw = format!(
            "{tenant}:{}:{hwm}:{params_digest_seed}",
            collection_key(collection)
        );
        let hash = sha256_hex(raw.as_bytes());
        let short: String = hash.chars().take(16).collect();
        RevisionMeta {
            etag: format!("\"{short}-v{hwm}\""),
            high_water_mark: hwm,
        }
    }
}

pub fn etag_matches(if_none_match: Option<&str>, current_etag: &str) -> bool {
    let Some(header) = if_none_match else {
        return false;
    };
    let trimmed = header.trim();
    if trimmed == "*" {
        return true;
    }
    let normalized_cur = current_etag.trim().trim_start_matches("W/");
    trimmed.split(',').any(|candidate| {
        let norm = candidate.trim().trim_start_matches("W/");
        norm == normalized_cur
    })
}

fn collection_key(kind: CollectionKind) -> &'static str {
    match kind {
        CollectionKind::Overview => "overview",
        CollectionKind::Keys => "keys",
        CollectionKind::Packs => "packs",
        CollectionKind::BrowserPolicies => "browser_policies",
        CollectionKind::Devices => "devices",
        CollectionKind::Agents => "agents",
        CollectionKind::McpServers => "mcp_servers",
        CollectionKind::Artifacts => "artifacts",
        CollectionKind::ConnectConfig => "connect_config",
        CollectionKind::Integrations => "integrations",
        CollectionKind::Sessions => "sessions",
        CollectionKind::Users => "users",
        CollectionKind::PrivacyConfig => "privacy_config",
        CollectionKind::Approvals => "approvals",
        CollectionKind::Findings => "findings",
        CollectionKind::Incidents => "incidents",
        CollectionKind::KillSwitch => "kill_switch",
        CollectionKind::AuditEvents => "audit_events",
    }
}
