// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Manifest hash pinning, first-sight non-promotion, poisoning filtering, and
//! NFKC/case-folded tool shadowing detection.

use std::collections::BTreeMap;

use unicode_normalization::UnicodeNormalization;

use grdr_crypto::sha256_hex;
use grdr_mcp_proto::{
    PinVerification, ToolDescriptor, ToolPin, canonical_tool_digest, detect_tool_poisoning,
    verify_tool_pin,
};

use crate::McpBrokerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinApprovalState {
    UnpinnedFirstSight,
    ApprovedMatched,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedCatalog {
    pub manifest_hash: String,
    pub manifest_pinned: bool,
    pub allowed_tools: Vec<ToolDescriptor>,
    pub blocked_tools: Vec<(String, McpBrokerError)>,
}

/// Maintains explicit approved tool/manifest pins separately from first-sight runtime observations.
/// Never silently promotes an unpinned tool/server into `manifest_pinned = true`.
#[derive(Debug, Default, Clone)]
pub struct PinRegistry {
    approved_manifests: BTreeMap<String, String>,
    approved_tools: BTreeMap<(String, String), ToolPin>,
    first_seen_digests: BTreeMap<(String, String), String>,
    canonical_owners: BTreeMap<String, (String, String)>,
}

impl PinRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn approve_manifest(&mut self, server_name: &str, tools: &[ToolDescriptor]) -> String {
        let hash = compute_manifest_hash(tools);
        self.approved_manifests
            .insert(server_name.to_owned(), hash.clone());
        for desc in tools {
            let key = (server_name.to_owned(), desc.name.clone());
            let digest = canonical_tool_digest(desc);
            self.approved_tools.insert(
                key,
                ToolPin {
                    server_name: server_name.to_owned(),
                    tool_name: desc.name.clone(),
                    digest_sha256: digest,
                    schema_version: 1,
                },
            );
        }
        hash
    }

    #[must_use]
    pub fn is_manifest_pinned(&self, server_name: &str) -> bool {
        self.approved_manifests.contains_key(server_name)
    }

    /// Inspects a `tools/list` catalog from `server_name`:
    /// - verifies against approved manifest hash if present (drift rejects all tools),
    /// - drops tools containing poisoning findings,
    /// - detects NFKC + case-folded + punctuation-normalized shadowing across servers,
    /// - records first-sight digest without promoting `manifest_pinned`.
    pub fn inspect_tools_list(
        &mut self,
        server_name: &str,
        tools: &[ToolDescriptor],
    ) -> Result<InspectedCatalog, McpBrokerError> {
        let manifest_hash = compute_manifest_hash(tools);
        if let Some(expected_manifest) = self.approved_manifests.get(server_name)
            && expected_manifest != &manifest_hash
        {
            return Err(McpBrokerError::PinDrift {
                tool: server_name.to_owned(),
                detail: format!(
                    "manifest_hash drifted (expected {expected_manifest}, got {manifest_hash})"
                ),
            });
        }

        let mut allowed_tools = Vec::new();
        let mut blocked_tools = Vec::new();

        for desc in tools {
            let poisoning = detect_tool_poisoning(desc);
            if !poisoning.is_empty() {
                let summary = poisoning
                    .iter()
                    .map(|f| format!("{:?}: {}", f.signals, f.detail))
                    .collect::<Vec<_>>()
                    .join("; ");
                blocked_tools.push((
                    desc.name.clone(),
                    McpBrokerError::ToolPoisoning {
                        tool: desc.name.clone(),
                        detail: summary,
                    },
                ));
                continue;
            }

            let key = (server_name.to_owned(), desc.name.clone());
            let shadow_key = canonical_shadow_key(&desc.name);
            if let Some(existing_owner) = self.canonical_owners.get(&shadow_key)
                && existing_owner != &key
            {
                blocked_tools.push((
                    desc.name.clone(),
                    McpBrokerError::ToolShadowing {
                        tool: desc.name.clone(),
                        conflicts_with: format!("{}::{}", existing_owner.0, existing_owner.1),
                    },
                ));
                continue;
            }

            if let Err(err) = self.verify_or_record_tool(server_name, desc) {
                blocked_tools.push((desc.name.clone(), err));
                continue;
            }

            self.canonical_owners.insert(shadow_key, key);
            allowed_tools.push(desc.clone());
        }

        Ok(InspectedCatalog {
            manifest_hash,
            manifest_pinned: self.is_manifest_pinned(server_name),
            allowed_tools,
            blocked_tools,
        })
    }

    pub fn verify_tool_call(
        &self,
        server_name: &str,
        tool_name: &str,
        desc: Option<&ToolDescriptor>,
    ) -> Result<PinApprovalState, McpBrokerError> {
        if server_name.trim().is_empty() || tool_name.trim().is_empty() {
            return Err(McpBrokerError::Transport(
                "server_name and tool_name cannot be empty".into(),
            ));
        }
        let key = (server_name.to_owned(), tool_name.to_owned());
        let shadow_key = canonical_shadow_key(tool_name);
        if let Some(owner) = self.canonical_owners.get(&shadow_key)
            && owner != &key
        {
            return Err(McpBrokerError::ToolShadowing {
                tool: tool_name.to_owned(),
                conflicts_with: format!("{}::{}", owner.0, owner.1),
            });
        }

        let Some(descriptor) = desc else {
            if self.approved_manifests.contains_key(server_name)
                || self.approved_tools.contains_key(&key)
            {
                return Err(McpBrokerError::PinDrift {
                    tool: tool_name.to_owned(),
                    detail: "pinned tool or server invoked without matching descriptor snapshot"
                        .into(),
                });
            }
            return Ok(PinApprovalState::UnpinnedFirstSight);
        };

        let poisoning = detect_tool_poisoning(descriptor);
        if !poisoning.is_empty() {
            return Err(McpBrokerError::ToolPoisoning {
                tool: tool_name.to_owned(),
                detail: "poisoning pattern detected in live descriptor".into(),
            });
        }

        if let Some(pin) = self.approved_tools.get(&key) {
            return match verify_tool_pin(descriptor, Some(pin)) {
                PinVerification::Matched => Ok(PinApprovalState::ApprovedMatched),
                PinVerification::Drifted { expected, actual } => Err(McpBrokerError::PinDrift {
                    tool: tool_name.to_owned(),
                    detail: format!("approved pin mismatch (expected {expected}, got {actual})"),
                }),
                PinVerification::Unpinned => Ok(PinApprovalState::UnpinnedFirstSight),
            };
        }
        if self.approved_manifests.contains_key(server_name) {
            return Err(McpBrokerError::PinDrift {
                tool: tool_name.to_owned(),
                detail: "undeclared tool rejected on manifest-pinned server".into(),
            });
        }

        let actual = canonical_tool_digest(descriptor);
        if let Some(observed) = self.first_seen_digests.get(&key)
            && observed != &actual
        {
            return Err(McpBrokerError::PinDrift {
                tool: tool_name.to_owned(),
                detail: format!(
                    "mid-session rug pull changed unpinned schema ({observed} -> {actual})"
                ),
            });
        }
        Ok(PinApprovalState::UnpinnedFirstSight)
    }

    fn verify_or_record_tool(
        &mut self,
        server_name: &str,
        desc: &ToolDescriptor,
    ) -> Result<PinApprovalState, McpBrokerError> {
        let key = (server_name.to_owned(), desc.name.clone());
        if let Some(pin) = self.approved_tools.get(&key) {
            return match verify_tool_pin(desc, Some(pin)) {
                PinVerification::Matched => Ok(PinApprovalState::ApprovedMatched),
                PinVerification::Drifted { expected, actual } => Err(McpBrokerError::PinDrift {
                    tool: desc.name.clone(),
                    detail: format!("approved pin mismatch (expected {expected}, got {actual})"),
                }),
                PinVerification::Unpinned => Ok(PinApprovalState::UnpinnedFirstSight),
            };
        }

        let digest = canonical_tool_digest(desc);
        if let Some(first) = self.first_seen_digests.get(&key) {
            if first != &digest {
                return Err(McpBrokerError::PinDrift {
                    tool: desc.name.clone(),
                    detail: format!(
                        "mid-session unpinned descriptor mutated ({first} -> {digest})"
                    ),
                });
            }
        } else {
            // Observe without marking approved/pinned (design/17 section 7.3).
            self.first_seen_digests.insert(key, digest);
        }
        Ok(PinApprovalState::UnpinnedFirstSight)
    }
}

#[must_use]
pub fn canonical_shadow_key(raw: &str) -> String {
    let nfkc: String = raw.nfkc().collect();
    let nfc: String = nfkc.nfc().collect();
    nfc.chars()
        .flat_map(char::to_lowercase)
        .filter(|ch| ch.is_alphanumeric())
        .collect()
}

#[must_use]
pub fn compute_manifest_hash(tools: &[ToolDescriptor]) -> String {
    let mut entries: Vec<(String, String, String)> = tools
        .iter()
        .map(|tool| {
            (
                canonical_shadow_key(&tool.name),
                tool.name.clone(),
                canonical_tool_digest(tool),
            )
        })
        .collect();
    entries.sort();
    let mut buf = String::from("grdr.mcp.manifest.v1|");
    for (canon, name, digest) in entries {
        buf.push_str(&canon);
        buf.push(':');
        buf.push_str(&name);
        buf.push('=');
        buf.push_str(&digest);
        buf.push(';');
    }
    sha256_hex(buf.as_bytes())
}
