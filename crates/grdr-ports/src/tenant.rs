// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;
use grdr_model::error::CODE_INVALID_INPUT;

pub const CODE_TENANT_WRITE_FORBIDDEN: &str = "GRDR-TENANT-0001";
pub const CODE_TENANT_SCOPE_MISMATCH: &str = "GRDR-TENANT-0002";
pub const CODE_TENANT_INVALID_ID: &str = "GRDR-TENANT-0003";
pub const CODE_BLOB_INVALID_PATH: &str = "GRDR-BLOB-0001";

const MAX_ORG_ID_LEN: usize = 128;
const MAX_REL_PATH_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    Embedded,
    Ha,
    Distributed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OrgId(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleCtx {
    organisation_id: OrgId,
    delegation_id: Option<String>,
    delegation_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetCtx {
    snapshot_id: String,
    organisation_ids: Vec<OrgId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantCtx {
    Single(SingleCtx),
    Set(SetCtx),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FencingToken(u64);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TenantRelPath(String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TenantPath {
    organisation_id: OrgId,
    relative: TenantRelPath,
}

impl ProfileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Ha => "ha",
            Self::Distributed => "distributed",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, CodedError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "embedded" => Ok(Self::Embedded),
            "ha" => Ok(Self::Ha),
            "distributed" => Ok(Self::Distributed),
            other => Err(CodedError::new(
                CODE_INVALID_INPUT,
                format!("Unsupported server storage profile `{other}`."),
                "Set server.profile to one of: embedded, ha, distributed.",
            )),
        }
    }
}

impl fmt::Display for ProfileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl OrgId {
    pub fn new(raw: impl Into<String>) -> Result<Self, CodedError> {
        let value = raw.into();
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_ORG_ID_LEN {
            return Err(CodedError::new(
                CODE_TENANT_INVALID_ID,
                "Organisation ID must be between 1 and 128 characters.",
                "Provide a valid organisation identifier.",
            ));
        }
        if trimmed == "." || trimmed == ".." || trimmed.contains("..") {
            return Err(CodedError::new(
                CODE_TENANT_INVALID_ID,
                "Organisation ID cannot contain path traversal segments.",
                "Use alphanumeric, hyphen, underscore, or dot characters only.",
            ));
        }
        let valid = trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !valid {
            return Err(CodedError::new(
                CODE_TENANT_INVALID_ID,
                format!("Organisation ID `{trimmed}` contains invalid characters."),
                "Use ASCII letters, digits, '-', '_', or '.'.",
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OrgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl SingleCtx {
    pub fn new(organisation_id: OrgId) -> Self {
        Self {
            organisation_id,
            delegation_id: None,
            delegation_epoch: None,
        }
    }

    pub fn with_delegation(
        organisation_id: OrgId,
        delegation_id: impl Into<String>,
        delegation_epoch: u64,
    ) -> Result<Self, CodedError> {
        let id = delegation_id.into();
        if id.trim().is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Delegation ID cannot be empty.",
                "Provide a non-empty delegation ID.",
            ));
        }
        Ok(Self {
            organisation_id,
            delegation_id: Some(id),
            delegation_epoch: Some(delegation_epoch),
        })
    }

    pub fn organisation_id(&self) -> &OrgId {
        &self.organisation_id
    }

    pub fn delegation_id(&self) -> Option<&str> {
        self.delegation_id.as_deref()
    }

    pub fn delegation_epoch(&self) -> Option<u64> {
        self.delegation_epoch
    }
}

impl SetCtx {
    pub fn new(
        snapshot_id: impl Into<String>,
        organisation_ids: Vec<OrgId>,
    ) -> Result<Self, CodedError> {
        let snap = snapshot_id.into();
        if snap.trim().is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Delegation snapshot ID cannot be empty.",
                "Mint SetCtx from a valid delegation snapshot.",
            ));
        }
        if organisation_ids.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "SetCtx must include at least one organisation.",
                "Provide one or more authorised organisation IDs.",
            ));
        }
        Ok(Self {
            snapshot_id: snap,
            organisation_ids,
        })
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    pub fn organisation_ids(&self) -> &[OrgId] {
        &self.organisation_ids
    }
}

impl TenantCtx {
    pub fn single(organisation_id: OrgId) -> Self {
        Self::Single(SingleCtx::new(organisation_id))
    }

    pub fn set(
        snapshot_id: impl Into<String>,
        organisation_ids: Vec<OrgId>,
    ) -> Result<Self, CodedError> {
        Ok(Self::Set(SetCtx::new(snapshot_id, organisation_ids)?))
    }

    pub fn as_single(&self) -> Result<&SingleCtx, CodedError> {
        match self {
            Self::Single(ctx) => Ok(ctx),
            Self::Set(_) => Err(CodedError::new(
                CODE_TENANT_WRITE_FORBIDDEN,
                "Read-only SetCtx cannot perform tenant write operations.",
                "Acquire a SingleCtx for the target organisation.",
            )),
        }
    }

    pub fn organisation_ids(&self) -> Vec<&OrgId> {
        match self {
            Self::Single(ctx) => vec![ctx.organisation_id()],
            Self::Set(ctx) => ctx.organisation_ids().iter().collect(),
        }
    }

    pub fn contains(&self, organisation_id: &OrgId) -> bool {
        match self {
            Self::Single(ctx) => ctx.organisation_id() == organisation_id,
            Self::Set(ctx) => ctx.organisation_ids().contains(organisation_id),
        }
    }
}

impl FencingToken {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for FencingToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TenantRelPath {
    pub fn parse(raw: &str) -> Result<Self, CodedError> {
        let normalized = validate_relative_path(raw, false)?;
        Ok(Self(normalized))
    }

    pub fn parse_prefix(raw: &str) -> Result<Self, CodedError> {
        let normalized = validate_relative_path(raw, true)?;
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|s| !s.is_empty())
    }
}

impl fmt::Display for TenantRelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TenantPath {
    pub fn new(ctx: &SingleCtx, relative: TenantRelPath) -> Self {
        Self {
            organisation_id: ctx.organisation_id().clone(),
            relative,
        }
    }

    pub fn parse(ctx: &SingleCtx, raw: &str) -> Result<Self, CodedError> {
        let relative = TenantRelPath::parse(raw)?;
        Ok(Self::new(ctx, relative))
    }

    pub fn for_org(organisation_id: OrgId, relative: TenantRelPath) -> Self {
        Self {
            organisation_id,
            relative,
        }
    }

    pub fn organisation_id(&self) -> &OrgId {
        &self.organisation_id
    }

    pub fn relative(&self) -> &TenantRelPath {
        &self.relative
    }

    pub fn scoped_key(&self) -> String {
        format!(
            "org={}/{}",
            self.organisation_id.as_str(),
            self.relative.as_str()
        )
    }
}

impl fmt::Display for TenantPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.scoped_key())
    }
}

fn validate_relative_path(raw: &str, allow_empty: bool) -> Result<String, CodedError> {
    if raw.len() > MAX_REL_PATH_LEN {
        return Err(CodedError::new(
            CODE_BLOB_INVALID_PATH,
            "Blob path exceeds maximum allowed length.",
            "Shorten the relative blob key path.",
        ));
    }
    if raw.contains('\0') || raw.contains('\\') || raw.contains(':') {
        return Err(CodedError::new(
            CODE_BLOB_INVALID_PATH,
            "Blob path contains forbidden characters.",
            "Use clean forward-slash relative path segments.",
        ));
    }
    let trimmed = raw.trim_matches('/');
    if trimmed.is_empty() {
        if allow_empty {
            return Ok(String::new());
        }
        return Err(CodedError::new(
            CODE_BLOB_INVALID_PATH,
            "Blob path cannot be empty.",
            "Provide a relative object path inside the tenant prefix.",
        ));
    }

    let mut clean_segments = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.starts_with('.') {
            return Err(CodedError::new(
                CODE_BLOB_INVALID_PATH,
                format!("Invalid blob path segment `{seg}`."),
                "Avoid empty, dot, or traversal segments in TenantPath.",
            ));
        }
        let safe = seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '='));
        if !safe {
            return Err(CodedError::new(
                CODE_BLOB_INVALID_PATH,
                format!("Blob path segment `{seg}` contains unsupported characters."),
                "Use ASCII letters, digits, '-', '_', '.', or '='.",
            ));
        }
        clean_segments.push(seg);
    }

    if let Some(first) = clean_segments.first()
        && first.starts_with("org=")
    {
        return Err(CodedError::new(
            CODE_BLOB_INVALID_PATH,
            "Relative TenantPath must not embed an `org=` prefix.",
            "Pass only the relative path; TenantPath scopes by TenantCtx.",
        ));
    }

    Ok(clean_segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_path_rejects_traversal_and_scopes_org() {
        let org = OrgId::new("org-alpha").unwrap();
        let ctx = SingleCtx::new(org);

        assert!(TenantPath::parse(&ctx, "../other/secret").is_err());
        assert!(TenantPath::parse(&ctx, "a/../b").is_err());
        assert!(TenantPath::parse(&ctx, "a\\b").is_err());
        assert!(TenantPath::parse(&ctx, ".hidden/file").is_err());
        assert!(TenantPath::parse(&ctx, "org=other/file").is_err());
        assert!(TenantPath::parse(&ctx, "").is_err());

        let path = TenantPath::parse(&ctx, "/class=decision/day=2026-11-24/part.parquet").unwrap();
        assert_eq!(
            path.scoped_key(),
            "org=org-alpha/class=decision/day=2026-11-24/part.parquet"
        );
    }

    #[test]
    fn set_ctx_cannot_mint_single_write_context() {
        let org_a = OrgId::new("org-a").unwrap();
        let org_b = OrgId::new("org-b").unwrap();
        let set = TenantCtx::set("snap-1", vec![org_a.clone(), org_b]).unwrap();
        assert!(set.contains(&org_a));
        assert!(set.as_single().is_err());
    }
}
