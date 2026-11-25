// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Sandboxed, networkless advisory detector host enforcing P2 restrict-only invariants.

pub mod advisory;
pub mod detector;
pub mod framing;
pub mod ipc;

use grdr_model::CodedError;

pub const CODE_INFER_INPUT: &str = "GRDR-INFER-0001";
pub const CODE_INFER_PERMISSIVE_OUTPUT: &str = "GRDR-INFER-0002";
pub const CODE_INFER_UNGROUNDED_QUOTE: &str = "GRDR-INFER-0003";
pub const CODE_INFER_FRAME_TAMPERED: &str = "GRDR-INFER-0004";
pub const CODE_INFER_CRYPTO_RANDOM: &str = "GRDR-INFER-0005";
pub const CODE_INFER_IPC: &str = "GRDR-INFER-0006";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InferError {
    #[error("GRDR-INFER-0001: invalid detector input: {0}")]
    InvalidInput(String),
    #[error("GRDR-INFER-0002: model output attempted non-restrictive action `{0}`")]
    PermissiveOutputRejected(String),
    #[error("GRDR-INFER-0003: finding quote missing from verified input record")]
    UngroundedQuote(String),
    #[error("GRDR-INFER-0004: delimited record HMAC verification failed: {0}")]
    FrameTampered(String),
    #[error("GRDR-INFER-0005: entropy or cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("GRDR-INFER-0006: wire IPC or verification failure: {0}")]
    Ipc(String),
}

impl From<InferError> for CodedError {
    fn from(err: InferError) -> Self {
        let code = match &err {
            InferError::InvalidInput(_) => CODE_INFER_INPUT,
            InferError::PermissiveOutputRejected(_) => CODE_INFER_PERMISSIVE_OUTPUT,
            InferError::UngroundedQuote(_) => CODE_INFER_UNGROUNDED_QUOTE,
            InferError::FrameTampered(_) => CODE_INFER_FRAME_TAMPERED,
            InferError::Crypto(_) => CODE_INFER_CRYPTO_RANDOM,
            InferError::Ipc(_) => CODE_INFER_IPC,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Advisory inference runs restrict-only; treat failures as unavailable.",
        )
    }
}
