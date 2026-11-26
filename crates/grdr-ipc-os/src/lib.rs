// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod duplex_pipe;
pub mod endpoint;
pub mod proto_io;
pub mod transport;
#[cfg(unix)]
pub mod unix_domain;
#[cfg(unix)]
mod unix_domain_bind;
#[cfg(windows)]
pub mod windows_pipe;
#[cfg(windows)]
pub mod windows_pipe_server;

use grdr_model::CodedError;

pub use endpoint::{
    EndpointKind, LocalEndpointAddress, MACOS_SUN_PATH_LIMIT, PipeClientAccessPolicy,
    PipeImpersonationLevel, TargetOsKind, WindowsPipeOpenPolicy, resolve_endpoint_address,
    validate_endpoint_address,
};
pub use transport::{
    Acceptor, Connector, FixedTimestampSource, IpcDeadline, Link, MAX_CALL_DEADLINE_MS,
    MAX_FIRST_FRAME_DEADLINE_MS, StreamLink, SystemConnector, TimestampSource, local_frame_cap,
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

/// Clone inherited standard input/output OS handles into unbuffered `File` streams
/// so `PeekNamedPipe` and `poll` readiness strictly reflects unread kernel pipe bytes.
pub fn inherited_stdio_pipe() -> std::io::Result<proto_io::DuplexPipe<std::fs::File, std::fs::File>>
{
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle as _;
        let stdin = std::io::stdin().as_handle().try_clone_to_owned()?;
        let stdout = std::io::stdout().as_handle().try_clone_to_owned()?;
        Ok(proto_io::DuplexPipe::new(
            std::fs::File::from(stdin),
            std::fs::File::from(stdout),
        ))
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsFd as _;
        let stdin = std::io::stdin().as_fd().try_clone_to_owned()?;
        let stdout = std::io::stdout().as_fd().try_clone_to_owned()?;
        Ok(proto_io::DuplexPipe::new(
            std::fs::File::from(stdin),
            std::fs::File::from(stdout),
        ))
    }
    #[cfg(not(any(windows, unix)))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "inherited stdio handles unsupported on this OS",
        ))
    }
}
