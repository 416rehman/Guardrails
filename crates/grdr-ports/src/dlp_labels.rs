// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! External sensitivity label readers (MSIP, Microsoft Purview, Google Drive) with org GUID and SiteId enforcement (`D-28`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use grdr_model::CodedError;
use grdr_schema::limits::load_embedded_limits;

use crate::dlp::{
    CODE_DLP_IO, ExternalSensitivityLabel, LabelReaderPort, MAX_LABEL_METADATA_BYTES,
    ProtectionMarking, SensitivitySource, SensitivityTier, dlp_err,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgLabelTable {
    pub guid_tiers: BTreeMap<String, SensitivityTier>,
    pub org_site_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MsipLabelReader;

#[derive(Debug, Clone, Copy, Default)]
pub struct PurviewLabelReader;

#[derive(Debug, Clone, Copy, Default)]
pub struct GoogleDriveLabelReader;

impl OrgLabelTable {
    #[must_use]
    pub fn lookup_guid_tier(&self, label_id: &str) -> Option<SensitivityTier> {
        let lower = label_id.to_ascii_lowercase();
        if let Some(&tier) = self.guid_tiers.get(&lower) {
            return Some(tier);
        }
        self.guid_tiers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(label_id))
            .map(|(_, &tier)| tier)
    }

    #[must_use]
    pub fn is_known_org_site(&self, site_id: &str) -> bool {
        self.org_site_ids
            .iter()
            .any(|known| known.eq_ignore_ascii_case(site_id))
    }
}

impl MsipLabelReader {
    /// Parses local MSIP properties using org GUID mappings and tenant `SiteId` enforcement (`docs/design/16` s.10).
    pub fn read_labels_with_table(
        &self,
        _object_ref: &str,
        raw_metadata: &[u8],
        table: &OrgLabelTable,
    ) -> Result<Vec<ExternalSensitivityLabel>, CodedError> {
        let text = decode_bounded_utf8(raw_metadata)?;
        let (mut by_id, mut disabled, mut parents, mut names, mut sites, mut enc) = (
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        );
        for raw_entry in text.lines().flat_map(|line| line.split(';')) {
            let Some((key, val)) = raw_entry.trim().split_once('=') else {
                continue;
            };
            let Some(rest) = key.trim().strip_prefix("MSIP_Label_") else {
                continue;
            };
            let Some((raw_id, suffix)) = rest.split_once('_') else {
                continue;
            };
            if raw_id.is_empty() {
                continue;
            }
            let id = raw_id.to_ascii_lowercase();
            let val = val.trim().trim_matches('"');
            by_id.insert(id.clone());
            match suffix {
                "Name" => {
                    names.insert(id, val.to_owned());
                }
                "Parent" if !val.is_empty() => {
                    parents.insert(id, val.to_ascii_lowercase());
                }
                "SiteId" if !val.is_empty() => {
                    sites.insert(id, val.to_ascii_lowercase());
                }
                "Enabled" if val.eq_ignore_ascii_case("false") || val == "0" => {
                    disabled.insert(id);
                }
                "Protection" | "Rights" | "Method" | "ContentBits"
                    if is_rms_encrypted_marker(suffix, val) =>
                {
                    enc.insert(id);
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        for id in by_id {
            if disabled.contains(&id) {
                continue;
            }
            let label_name = names.get(&id).cloned().unwrap_or_else(|| id.clone());
            let tier = resolve_tier(&id, &label_name, table);
            let site_id = sites.get(&id).cloned();
            let foreign_site = is_foreign_site(site_id.as_deref(), table);
            let tag = if foreign_site {
                "sensitive:external-label".into()
            } else {
                format!("sensitive:{}", tier_tag(tier))
            };
            out.push(ExternalSensitivityLabel {
                source: SensitivitySource::Msip,
                parent_label_id: parents.get(&id).cloned(),
                label_id: id.clone(),
                label_name,
                tier,
                protection: if enc.contains(&id) {
                    ProtectionMarking::RmsOrEncrypted
                } else {
                    ProtectionMarking::Unencrypted
                },
                policy_tag: Some(tag),
                advisory_only: false,
                site_id,
                foreign_site,
            });
        }
        Ok(out)
    }
}

impl LabelReaderPort for MsipLabelReader {
    fn source(&self) -> SensitivitySource {
        SensitivitySource::Msip
    }
    fn read_labels_with_table(
        &self,
        object_ref: &str,
        raw_metadata: &[u8],
        table: &OrgLabelTable,
    ) -> Result<Vec<ExternalSensitivityLabel>, CodedError> {
        Self::read_labels_with_table(self, object_ref, raw_metadata, table)
    }
}

impl PurviewLabelReader {
    /// Parses Microsoft Purview `processContent` JSON using org GUID mappings, tenant `siteId`, and `restrictionAction` allowlist.
    pub fn read_labels_with_table(
        &self,
        _object_ref: &str,
        raw_metadata: &[u8],
        table: &OrgLabelTable,
    ) -> Result<Vec<ExternalSensitivityLabel>, CodedError> {
        if raw_metadata.is_empty() {
            return Ok(Vec::new());
        }
        let val = decode_bounded_json(raw_metadata)?;
        let entries = val
            .get("labels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![val.clone()]);
        let top_site = extract_non_empty_lower(&val, &["siteId"]);
        let mut out = Vec::new();
        for item in entries {
            let Some(id) = item
                .get("sensitivityLabelId")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let name = item
                .get("displayName")
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
                .unwrap_or(id);
            let prot = item
                .get("protectionEnabled")
                .or_else(|| item.get("hasProtection"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let tier = resolve_tier(&id.to_ascii_lowercase(), name, table);
            let act = match item.get("restrictionAction") {
                None | Some(Value::Null) => None,
                Some(v) => {
                    let raw_act = v
                        .as_str()
                        .map(str::trim)
                        .map(str::to_ascii_lowercase)
                        .ok_or_else(|| {
                            dlp_err(CODE_DLP_IO, "Purview restrictionAction must be a string")
                        })?;
                    if !matches!(raw_act.as_str(), "warn" | "audit" | "block") {
                        return Err(dlp_err(
                            CODE_DLP_IO,
                            "unsupported Purview restrictionAction value",
                        ));
                    }
                    Some(format!("advisory:purview:{raw_act}"))
                }
            };
            let site_id = extract_non_empty_lower(&item, &["siteId"]).or_else(|| top_site.clone());
            let foreign_site = is_foreign_site(site_id.as_deref(), table);
            let fallback_tag = if foreign_site {
                "advisory:external-label".into()
            } else {
                format!("advisory:{}", tier_tag(tier))
            };
            out.push(ExternalSensitivityLabel {
                source: SensitivitySource::MicrosoftPurview,
                label_id: id.to_owned(),
                label_name: name.to_owned(),
                tier,
                parent_label_id: item
                    .get("parentId")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                protection: if prot {
                    ProtectionMarking::RmsOrEncrypted
                } else {
                    ProtectionMarking::Unencrypted
                },
                policy_tag: act.or(Some(fallback_tag)),
                advisory_only: true,
                site_id,
                foreign_site,
            });
        }
        Ok(out)
    }
}

impl LabelReaderPort for PurviewLabelReader {
    fn source(&self) -> SensitivitySource {
        SensitivitySource::MicrosoftPurview
    }
    fn read_labels_with_table(
        &self,
        object_ref: &str,
        raw_metadata: &[u8],
        table: &OrgLabelTable,
    ) -> Result<Vec<ExternalSensitivityLabel>, CodedError> {
        Self::read_labels_with_table(self, object_ref, raw_metadata, table)
    }
}

impl GoogleDriveLabelReader {
    /// Parses Google Drive label metadata using org GUID mappings and tenant `siteId`/`customerId` checks.
    pub fn read_labels_with_table(
        &self,
        _object_ref: &str,
        raw_metadata: &[u8],
        table: &OrgLabelTable,
    ) -> Result<Vec<ExternalSensitivityLabel>, CodedError> {
        if raw_metadata.is_empty() {
            return Ok(Vec::new());
        }
        let val = decode_bounded_json(raw_metadata)?;
        let Some(labels) = val
            .get("labelInfo")
            .and_then(|i| i.get("labels"))
            .and_then(Value::as_array)
            .or_else(|| val.get("labels").and_then(Value::as_array))
        else {
            return Ok(Vec::new());
        };
        let top_site = extract_non_empty_lower(&val, &["siteId", "customerId"]);
        let mut out = Vec::new();
        for item in labels {
            let Some(id) = item.get("id").and_then(Value::as_str) else {
                continue;
            };
            let name = item
                .get("title")
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
                .unwrap_or(id);
            let tier = resolve_tier(&id.to_ascii_lowercase(), name, table);
            let site_id = extract_non_empty_lower(item, &["siteId", "customerId"])
                .or_else(|| top_site.clone());
            let foreign_site = is_foreign_site(site_id.as_deref(), table);
            let tag = if foreign_site {
                "sensitive:external-label".into()
            } else {
                format!("sensitive:{}", tier_tag(tier))
            };
            out.push(ExternalSensitivityLabel {
                source: SensitivitySource::GoogleDrive,
                label_id: id.to_owned(),
                label_name: name.to_owned(),
                tier,
                parent_label_id: None,
                protection: ProtectionMarking::Unencrypted,
                policy_tag: Some(tag),
                advisory_only: false,
                site_id,
                foreign_site,
            });
        }
        Ok(out)
    }
}

impl LabelReaderPort for GoogleDriveLabelReader {
    fn source(&self) -> SensitivitySource {
        SensitivitySource::GoogleDrive
    }
    fn read_labels_with_table(
        &self,
        object_ref: &str,
        raw_metadata: &[u8],
        table: &OrgLabelTable,
    ) -> Result<Vec<ExternalSensitivityLabel>, CodedError> {
        Self::read_labels_with_table(self, object_ref, raw_metadata, table)
    }
}

fn is_foreign_site(site_id: Option<&str>, table: &OrgLabelTable) -> bool {
    if table.org_site_ids.is_empty() {
        return false;
    }
    match site_id {
        Some(sid) => !table.is_known_org_site(sid),
        None => true,
    }
}

fn extract_non_empty_lower(node: &Value, keys: &[&str]) -> Option<String> {
    for &key in keys {
        if let Some(raw) = node.get(key).and_then(Value::as_str) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_ascii_lowercase());
            }
        }
    }
    None
}

fn is_rms_encrypted_marker(suffix: &str, val: &str) -> bool {
    let low = val.to_ascii_lowercase();
    match suffix {
        "Protection" | "Rights" => !low.is_empty() && low != "none" && low != "false",
        "ContentBits" => {
            low.parse::<u32>().is_ok_and(|b| (b & 0x2) != 0) || low.contains("encrypt")
        }
        "Method" => low.contains("encrypt") || low.contains("rms"),
        _ => false,
    }
}

fn has_negated_public(lower: &str, tokens: &[&str]) -> bool {
    lower.contains("non-public")
        || lower.contains("nonpublic")
        || lower.contains("not public")
        || lower.contains("non-unrestricted")
        || lower.contains("not unrestricted")
        || tokens
            .windows(2)
            .any(|w| matches!(w, ["non" | "not" | "no", "public" | "unrestricted"]))
}

fn resolve_tier(label_id: &str, name: &str, table: &OrgLabelTable) -> SensitivityTier {
    if let Some(mapped) = table.lookup_guid_tier(label_id) {
        return mapped;
    }
    let lower = name.trim().to_ascii_lowercase();
    let tokens: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    let has = |t: &str| tokens.contains(&t);
    if has("pii") || has("hipaa") || has("pci") || has("regulated") || has("phi") || has("gdpr") {
        SensitivityTier::Regulated
    } else if lower.contains("highly confidential")
        || lower.contains("strictly private")
        || lower.contains("streng vertraulich")
        || has("secret")
        || has("restricted")
    {
        SensitivityTier::Secret
    } else if has("confidential") || has("vertraulich") || has("confidencial") {
        SensitivityTier::Confidential
    } else if has("internal") || has("general") {
        SensitivityTier::Internal
    } else if (has("unrestricted") || has("public")) && !has_negated_public(&lower, &tokens) {
        SensitivityTier::Public
    } else {
        SensitivityTier::Internal
    }
}

fn decode_bounded_utf8(raw: &[u8]) -> Result<&str, CodedError> {
    let cap = load_embedded_limits()
        .ok()
        .map(|l| l.endpoint.ipc.max_frame_bytes)
        .unwrap_or(MAX_LABEL_METADATA_BYTES);
    let max_bytes = MAX_LABEL_METADATA_BYTES.min(cap);
    if raw.len() > max_bytes {
        return Err(dlp_err(
            CODE_DLP_IO,
            format!("label metadata exceeds {max_bytes} bytes"),
        ));
    }
    std::str::from_utf8(raw).map_err(|_| dlp_err(CODE_DLP_IO, "label metadata is not valid UTF-8"))
}

fn decode_bounded_json(raw_metadata: &[u8]) -> Result<Value, CodedError> {
    let text = decode_bounded_utf8(raw_metadata)?;
    serde_json::from_str::<Value>(text)
        .map_err(|_| dlp_err(CODE_DLP_IO, "invalid JSON label metadata"))
}

const fn tier_tag(tier: SensitivityTier) -> &'static str {
    match tier {
        SensitivityTier::Public => "public",
        SensitivityTier::Internal => "internal",
        SensitivityTier::Confidential => "confidential",
        SensitivityTier::Secret => "secret",
        SensitivityTier::Regulated => "regulated",
    }
}
