// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod endpoint;
pub mod transport;
#[cfg(unix)]
pub mod unix_domain;
#[cfg(windows)]
pub mod windows_pipe;

use grdr_model::CodedError;

pub use endpoint::{
    EndpointKind, LocalEndpointAddress, MACOS_SUN_PATH_LIMIT, PipeClientAccessPolicy,
    PipeImpersonationLevel, TargetOsKind, WindowsPipeOpenPolicy, resolve_endpoint_address,
    validate_endpoint_address,
};
pub use transport::{
    Acceptor, Connector, FixedTimestampSource, IpcDeadline, Link, MAX_CALL_DEADLINE_MS,
    MAX_FIRST_FRAME_DEADLINE_MS, MAX_LOCAL_IPC_FRAME_BYTES, StreamLink, SystemConnector,
    TimestampSource,
};
#[cfg(unix)]
pub use unix_domain::{UnixDomainAcceptor, UnixDomainConnector, UnixDomainLink};
#[cfg(windows)]
pub use windows_pipe::{WindowsNamedPipeConnector, WindowsNamedPipeLink};

pub const CODE_IPC_INVALID_ADDRESS: &str = "GRDR-IPC-0001";
pub const CODE_IPC_DEADLINE_EXCEEDED: &str = "GRDR-IPC-0002";
pub const CODE_IPC_UNAVAILABLE: &str = "GRDR-IPC-0003";
pub const CODE_IPC_FRAME_INVALID: &str = "GRDR-IPC-0004";
pub const CODE_IPC_IO: &str = "GRDR-IPC-0005";
pub const CODE_IPC_STOPPED: &str = "GRDR-IPC-0006";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpcError {
    #[error("GRDR-IPC-0001: invalid local endpoint address: {0}")]
    InvalidAddress(String),
    #[error("GRDR-IPC-0002: local IPC operation timed out after {timeout_ms} ms")]
    DeadlineExceeded { timeout_ms: u64 },
    #[error("GRDR-IPC-0003: local IPC endpoint unavailable: {0}")]
    Unavailable(String),
    #[error("GRDR-IPC-0004: invalid wire frame on local IPC link: {0}")]
    FrameInvalid(String),
    #[error("GRDR-IPC-0005: local IPC I/O error: {0}")]
    Io(String),
    #[error("GRDR-IPC-0006: local IPC acceptor is stopped")]
    Stopped,
}

impl From<IpcError> for CodedError {
    fn from(err: IpcError) -> Self {
        let code = match &err {
            IpcError::InvalidAddress(_) => CODE_IPC_INVALID_ADDRESS,
            IpcError::DeadlineExceeded { .. } => CODE_IPC_DEADLINE_EXCEEDED,
            IpcError::Unavailable(_) => CODE_IPC_UNAVAILABLE,
            IpcError::FrameInvalid(_) => CODE_IPC_FRAME_INVALID,
            IpcError::Io(_) => CODE_IPC_IO,
            IpcError::Stopped => CODE_IPC_STOPPED,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Verify daemon endpoint availability and peer permissions.",
        )
    }
}
