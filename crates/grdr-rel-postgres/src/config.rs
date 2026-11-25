// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;

pub const CODE_PG_IO: &str = "GRDR-PG-0001";
pub const CODE_PG_MIGRATION: &str = "GRDR-PG-0002";
pub const CODE_PG_CODEC: &str = "GRDR-PG-0003";
pub const CODE_PG_CONFIG: &str = "GRDR-PG-0004";
pub const CODE_PG_WIRE: &str = "GRDR-PG-0005";
pub const CODE_PG_RLS: &str = "GRDR-PG-0006";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresSslMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PostgresTransport {
    OfflineEmbedded,
    TcpWire {
        endpoint: String,
        database: String,
        user: String,
        password: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresConfig {
    pub transport: PostgresTransport,
    pub ssl_mode: PostgresSslMode,
    pub application_name: String,
    pub statement_timeout_ms: u32,
    pub connect_timeout_ms: u32,
}

impl PostgresSslMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Prefer => "prefer",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, CodedError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "disable" => Ok(Self::Disable),
            "prefer" => Ok(Self::Prefer),
            "require" => Ok(Self::Require),
            "verify-ca" => Ok(Self::VerifyCa),
            "verify-full" => Ok(Self::VerifyFull),
            other => Err(CodedError::new(
                CODE_PG_CONFIG,
                format!("Unsupported PostgreSQL sslmode `{other}`."),
                "Set sslmode to disable, prefer, require, verify-ca, or verify-full.",
            )),
        }
    }
}

impl PostgresConfig {
    pub fn offline() -> Self {
        Self {
            transport: PostgresTransport::OfflineEmbedded,
            ssl_mode: PostgresSslMode::Prefer,
            application_name: "grdr-server".into(),
            statement_timeout_ms: 30_000,
            connect_timeout_ms: 5_000,
        }
    }

    pub fn parse_dsn(dsn: &str) -> Result<Self, CodedError> {
        let trimmed = dsn.trim();
        let rest = trimmed
            .strip_prefix("postgres://")
            .or_else(|| trimmed.strip_prefix("postgresql://"))
            .ok_or_else(|| {
                CodedError::new(
                    CODE_PG_CONFIG,
                    "PostgreSQL DSN must start with postgres:// or postgresql://.",
                    "Provide a valid PostgreSQL 18 connection URI.",
                )
            })?;

        let (authority_and_path, query) = match rest.split_once('?') {
            Some((left, q)) => (left, Some(q)),
            None => (rest, None),
        };
        let (authority, db_raw) = authority_and_path.split_once('/').ok_or_else(|| {
            CodedError::new(
                CODE_PG_CONFIG,
                "PostgreSQL DSN must include a database path.",
                "Format DSN as postgres://user@host:port/database.",
            )
        })?;
        let database = db_raw.trim();
        validate_dsn_token("database", database, true)?;

        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let endpoint = normalize_hostport(hostport)?;
        let (user, password) = match userinfo {
            Some(ui) => match ui.split_once(':') {
                Some((u, p)) => (u.trim().to_string(), Some(p.to_string())),
                None => (ui.trim().to_string(), None),
            },
            None => ("grdr".to_string(), None),
        };
        validate_dsn_token("user", &user, true)?;
        if let Some(ref pw) = password {
            validate_dsn_token("password", pw, false)?;
        }

        let mut ssl_mode = PostgresSslMode::Require;
        if let Some(q) = query {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=')
                    && k.eq_ignore_ascii_case("sslmode")
                {
                    ssl_mode = PostgresSslMode::parse(v)?;
                }
            }
        }

        Ok(Self {
            transport: PostgresTransport::TcpWire {
                endpoint,
                database: database.to_string(),
                user,
                password,
            },
            ssl_mode,
            application_name: "grdr-server".into(),
            statement_timeout_ms: 30_000,
            connect_timeout_ms: 5_000,
        })
    }

    pub fn validate(&self) -> Result<(), CodedError> {
        validate_dsn_token("application_name", &self.application_name, true)?;
        if let PostgresTransport::TcpWire {
            endpoint,
            database,
            user,
            password,
        } = &self.transport
        {
            validate_dsn_token("endpoint", endpoint, true)?;
            validate_dsn_token("database", database, true)?;
            validate_dsn_token("user", user, true)?;
            if let Some(pw) = password {
                validate_dsn_token("password", pw, false)?;
            }
        }
        Ok(())
    }
}

fn validate_dsn_token(field: &str, value: &str, reject_whitespace: bool) -> Result<(), CodedError> {
    if value.trim().is_empty() {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            format!("PostgreSQL {field} cannot be empty."),
            "Provide a valid PostgreSQL connection configuration.",
        ));
    }
    let bad = value
        .chars()
        .any(|c| c == '\0' || c.is_control() || (reject_whitespace && c.is_whitespace()));
    if bad {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            format!("PostgreSQL {field} contains invalid control or whitespace characters."),
            "Remove control, NUL, or whitespace characters from PostgreSQL DSN parameters.",
        ));
    }
    Ok(())
}

fn normalize_hostport(raw: &str) -> Result<String, CodedError> {
    let trimmed = raw.trim();
    validate_dsn_token("host", trimmed, true)?;
    if let Some(after_open) = trimmed.strip_prefix('[') {
        let (host, rest) = after_open.split_once(']').ok_or_else(|| {
            CodedError::new(
                CODE_PG_CONFIG,
                "Invalid IPv6 host literal in PostgreSQL DSN.",
                "Use [addr]:port format for IPv6 hosts.",
            )
        })?;
        if host.is_empty() {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                "PostgreSQL IPv6 host cannot be empty.",
                "Provide a valid IPv6 host address.",
            ));
        }
        if rest.is_empty() {
            return Ok(format!("[{host}]:5432"));
        }
        let port_str = rest.strip_prefix(':').ok_or_else(|| {
            CodedError::new(
                CODE_PG_CONFIG,
                "Unexpected suffix after IPv6 host in PostgreSQL DSN.",
                "Use [addr]:port format.",
            )
        })?;
        validate_port(port_str)?;
        return Ok(format!("[{host}]:{port_str}"));
    }

    if let Some((host, port_str)) = trimmed.split_once(':') {
        if host.is_empty() || port_str.contains(':') {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                "Invalid host:port in PostgreSQL DSN.",
                "Format PostgreSQL host as host:port.",
            ));
        }
        validate_port(port_str)?;
        Ok(format!("{host}:{port_str}"))
    } else {
        Ok(format!("{trimmed}:5432"))
    }
}

fn validate_port(raw: &str) -> Result<u16, CodedError> {
    let port: u16 = raw.parse().map_err(|_| {
        CodedError::new(
            CODE_PG_CONFIG,
            format!("Invalid PostgreSQL port `{raw}`."),
            "Specify a numeric TCP port between 1 and 65535.",
        )
    })?;
    if port == 0 {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            "PostgreSQL port cannot be zero.",
            "Specify a numeric TCP port between 1 and 65535.",
        ));
    }
    Ok(port)
}
