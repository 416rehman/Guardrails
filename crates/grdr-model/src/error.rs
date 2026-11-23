// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;

pub const CODE_INVALID_INPUT: &str = "GRDR-MODEL-0001";
pub const CODE_NOT_FOUND: &str = "GRDR-API-0404";
pub const CODE_CONFLICT: &str = "GRDR-API-0409";
pub const CODE_STORE_IO: &str = "GRDR-STORE-0001";
pub const CODE_STORE_CORRUPT: &str = "GRDR-STORE-0002";
pub const CODE_POLICY_DENIED: &str = "GRDR-POLICY-0001";
pub const CODE_POLICY_STEP_UP: &str = "GRDR-POLICY-0002";
pub const CODE_KILL_SWITCH_ACTIVE: &str = "GRDR-RESPONSE-0001";
pub const CODE_DAEMON_UNREACHABLE: &str = "GRDR-DAEMON-0001";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error)]
#[error("{code}: {message}")]
pub struct CodedError {
    pub code: String,
    pub message: String,
    pub next_step: String,
}

impl CodedError {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        next_step: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            next_step: next_step.into(),
        }
    }

    pub fn display_line(&self) -> String {
        format!(
            "{} - {} (next: {})",
            self.code, self.message, self.next_step
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidInput,
    NotFound,
    Conflict,
    StoreIo,
    DaemonUnreachable,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => f.write_str(CODE_INVALID_INPUT),
            Self::NotFound => f.write_str(CODE_NOT_FOUND),
            Self::Conflict => f.write_str(CODE_CONFLICT),
            Self::StoreIo => f.write_str(CODE_STORE_IO),
            Self::DaemonUnreachable => f.write_str(CODE_DAEMON_UNREACHABLE),
        }
    }
}
