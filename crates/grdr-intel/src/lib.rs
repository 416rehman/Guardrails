// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Layer 1 threat intelligence, pack validation, 24-bit fuse index, codecs, and k-anonymous sightings (`D-32`).

use std::sync::OnceLock;

use grdr_model::CodedError;
use grdr_schema::limits::{LimitsConfig, load_embedded_limits};

pub(crate) mod breaker;
pub mod canonical;
pub mod codecs;
pub mod feeds;
pub mod fuse;
pub(crate) mod gov_io;
pub mod governance;
pub mod index;
pub mod pack;
pub mod record;
pub mod semver;
pub mod sightings;
pub(crate) mod stix_pattern;
pub(crate) mod validators;

pub const CODE_INTEL_NON_RESTRICTIVE: &str = "GRDR-INTEL-0001";
pub const CODE_INTEL_INVALID_RECORD: &str = "GRDR-INTEL-0002";
pub const CODE_INTEL_CORRUPT_FILTER: &str = "GRDR-INTEL-0003";
pub const CODE_INTEL_CODEC_PARSE: &str = "GRDR-INTEL-0004";
pub const CODE_INTEL_BREAKER_OPEN: &str = "GRDR-INTEL-0005";
pub const CODE_INTEL_COHORT_SMALL: &str = "GRDR-INTEL-0006";
pub const CODE_INTEL_SIGHTING_REJECTED: &str = "GRDR-INTEL-0007";

static EMBEDDED_LIMITS: OnceLock<Result<LimitsConfig, &'static str>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntelError {
    #[error("GRDR-INTEL-0001: intel pack violated restrict-only contract: {0}")]
    NonRestrictivePack(String),
    #[error("GRDR-INTEL-0002: invalid threat intel record or GRDRI identifier: {0}")]
    InvalidRecord(String),
    #[error("GRDR-INTEL-0003: corrupt or failed binary fuse index: {0}")]
    CorruptFilter(String),
    #[error("GRDR-INTEL-0004: invalid threat intel codec payload: {0}")]
    CodecParse(String),
    #[error("GRDR-INTEL-0005: intel block circuit breaker tripped: {0}")]
    BreakerOpen(String),
    #[error("GRDR-INTEL-0006: sightings privacy cohort below k={0} minimum")]
    CohortTooSmall(u32),
    #[error("GRDR-INTEL-0007: sighting rejected by public-artefact or cohort policy: {0}")]
    SightingRejected(String),
}

impl From<IntelError> for CodedError {
    fn from(err: IntelError) -> Self {
        let code = match &err {
            IntelError::NonRestrictivePack(_) => CODE_INTEL_NON_RESTRICTIVE,
            IntelError::InvalidRecord(_) => CODE_INTEL_INVALID_RECORD,
            IntelError::CorruptFilter(_) => CODE_INTEL_CORRUPT_FILTER,
            IntelError::CodecParse(_) => CODE_INTEL_CODEC_PARSE,
            IntelError::BreakerOpen(_) => CODE_INTEL_BREAKER_OPEN,
            IntelError::CohortTooSmall(_) => CODE_INTEL_COHORT_SMALL,
            IntelError::SightingRejected(_) => CODE_INTEL_SIGHTING_REJECTED,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Threat intelligence feeds are restrict-only and treat unknown observables as unrated.",
        )
    }
}

pub(crate) fn embedded_limits() -> Result<&'static LimitsConfig, &'static str> {
    match EMBEDDED_LIMITS
        .get_or_init(|| load_embedded_limits().map_err(|_| "failed loading embedded schema limits"))
    {
        Ok(cfg) => Ok(cfg),
        Err(msg) => Err(*msg),
    }
}
