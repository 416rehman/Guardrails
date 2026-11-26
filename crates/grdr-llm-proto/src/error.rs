// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("GRDR-LLM-0001: invalid protocol JSON payload: {0}")]
    Parse(String),
    #[error("GRDR-LLM-0002: failed serializing protocol payload: {0}")]
    Serialize(String),
    #[error("GRDR-LLM-0003: JSON nesting depth exceeds limit")]
    DepthLimitExceeded,
    #[error("GRDR-LLM-0004: payload exceeds size limit")]
    PayloadTooLarge,
    #[error("GRDR-LLM-0005: decompression bomb or unsupported encoding: {0}")]
    DecompressionRejected(&'static str),
    #[error("GRDR-LLM-0006: duplicate JSON key rejected")]
    DuplicateJsonKey,
}

impl ProtoError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Parse(_) => "GRDR-LLM-0001",
            Self::Serialize(_) => "GRDR-LLM-0002",
            Self::DepthLimitExceeded => "GRDR-LLM-0003",
            Self::PayloadTooLarge => "GRDR-LLM-0004",
            Self::DecompressionRejected(_) => "GRDR-LLM-0005",
            Self::DuplicateJsonKey => "GRDR-LLM-0006",
        }
    }
}
