// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Dual stdio + Streamable HTTP MCP security broker enforcing manifest pinning,
//! poisoning/shadowing rejection, MCP 2025/2026 headers, and D-14 fail-closed bounds.

pub mod decision;
pub mod pinning;
pub mod revisions;
pub mod transport;

use grdr_model::CodedError;

pub const CODE_MCP_PIN_DRIFT: &str = "GRDR-MCP-0001";
pub const CODE_MCP_TOOL_POISONING: &str = "GRDR-MCP-0002";
pub const CODE_MCP_TOOL_SHADOWING: &str = "GRDR-MCP-0003";
pub const CODE_MCP_HEADER_MISMATCH: &str = "GRDR-MCP-0004";
pub const CODE_MCP_SESSION_MISMATCH: &str = "GRDR-MCP-0005";
pub const CODE_MCP_FLOOR_UNTRUSTED: &str = "GRDR-MCP-0006";
pub const CODE_MCP_BROKER_TRANSPORT: &str = "GRDR-MCP-0007";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpBrokerError {
    #[error("GRDR-MCP-0001: manifest or tool pin drift detected for `{tool}`: {detail}")]
    PinDrift { tool: String, detail: String },
    #[error("GRDR-MCP-0002: tool poisoning detected on `{tool}`: {detail}")]
    ToolPoisoning { tool: String, detail: String },
    #[error("GRDR-MCP-0003: cross-server or homoglyph tool shadowing detected for `{tool}`")]
    ToolShadowing {
        tool: String,
        conflicts_with: String,
    },
    #[error("GRDR-MCP-0004: MCP protocol header mismatch: {0}")]
    HeaderMismatch(String),
    #[error("GRDR-MCP-0005: MCP session or origin binding failed: {0}")]
    SessionBinding(String),
    #[error("GRDR-MCP-0006: signed compiled floor verification failed")]
    FloorUntrusted,
    #[error("GRDR-MCP-0007: MCP transport or daemon broker error: {0}")]
    Transport(String),
}

impl From<McpBrokerError> for CodedError {
    fn from(err: McpBrokerError) -> Self {
        let code = match &err {
            McpBrokerError::PinDrift { .. } => CODE_MCP_PIN_DRIFT,
            McpBrokerError::ToolPoisoning { .. } => CODE_MCP_TOOL_POISONING,
            McpBrokerError::ToolShadowing { .. } => CODE_MCP_TOOL_SHADOWING,
            McpBrokerError::HeaderMismatch(_) => CODE_MCP_HEADER_MISMATCH,
            McpBrokerError::SessionBinding(_) => CODE_MCP_SESSION_MISMATCH,
            McpBrokerError::FloorUntrusted => CODE_MCP_FLOOR_UNTRUSTED,
            McpBrokerError::Transport(_) => CODE_MCP_BROKER_TRANSPORT,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Verify approved MCP manifest pins, session headers, and signed policy floor.",
        )
    }
}
