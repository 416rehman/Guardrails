// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Error codes and CompatError enum for `grdr-compat` (registered in `contracts/codes/registry.toml`).

use std::fmt;

pub const CODE_COMPAT_INVALID_SEMVER: &str = "GRDR-COMPAT-0001";
pub const CODE_COMPAT_INVALID_RANGE: &str = "GRDR-COMPAT-0002";
pub const CODE_COMPAT_UNSUPPORTED_VERSION: &str = "GRDR-COMPAT-0003";
pub const CODE_COMPAT_FORBIDDEN_JUMP: &str = "GRDR-COMPAT-0004";
pub const CODE_COMPAT_INVALID_CONTRACT: &str = "GRDR-COMPAT-0005";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatError {
    InvalidSemVer(String),
    InvalidRange { component: String },
    UnsupportedVersion(String),
    ForbiddenUpgradeJump(String),
    InvalidSupportContract(String),
}

impl CompatError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidSemVer(_) => CODE_COMPAT_INVALID_SEMVER,
            Self::InvalidRange { .. } => CODE_COMPAT_INVALID_RANGE,
            Self::UnsupportedVersion(_) => CODE_COMPAT_UNSUPPORTED_VERSION,
            Self::ForbiddenUpgradeJump(_) => CODE_COMPAT_FORBIDDEN_JUMP,
            Self::InvalidSupportContract(_) => CODE_COMPAT_INVALID_CONTRACT,
        }
    }
}

impl fmt::Display for CompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSemVer(raw) => {
                write!(
                    f,
                    "{CODE_COMPAT_INVALID_SEMVER}: invalid semantic version `{raw}`"
                )
            }
            Self::InvalidRange { component } => {
                write!(
                    f,
                    "{CODE_COMPAT_INVALID_RANGE}: invalid version range for {component}"
                )
            }
            Self::UnsupportedVersion(detail) => {
                write!(
                    f,
                    "{CODE_COMPAT_UNSUPPORTED_VERSION}: unsupported component or protocol version: {detail}"
                )
            }
            Self::ForbiddenUpgradeJump(detail) => {
                write!(
                    f,
                    "{CODE_COMPAT_FORBIDDEN_JUMP}: forbidden upgrade jump: {detail}"
                )
            }
            Self::InvalidSupportContract(detail) => {
                write!(
                    f,
                    "{CODE_COMPAT_INVALID_CONTRACT}: invalid support contract: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for CompatError {}
