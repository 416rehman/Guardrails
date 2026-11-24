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
        if database.is_empty() {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                "PostgreSQL DSN database name cannot be empty.",
                "Specify the target database name in the DSN.",
            ));
        }

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
        if user.is_empty() {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                "PostgreSQL DSN user cannot be empty.",
                "Provide a valid PostgreSQL role in the DSN.",
            ));
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
        if self.application_name.trim().is_empty() {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                "PostgreSQL application_name cannot be empty.",
                "Set a non-empty application_name.",
            ));
        }
        if let PostgresTransport::TcpWire {
            endpoint,
            database,
            user,
            ..
        } = &self.transport
            && (endpoint.trim().is_empty() || database.trim().is_empty() || user.trim().is_empty())
        {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                "PostgreSQL endpoint, database, and user must be non-empty.",
                "Inspect PostgreSQL connection configuration.",
            ));
        }
        Ok(())
    }
}

fn normalize_hostport(raw: &str) -> Result<String, CodedError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            "PostgreSQL host cannot be empty.",
            "Include host and port in the PostgreSQL DSN.",
        ));
    }
    if trimmed.contains(':') {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("{trimmed}:5432"))
    }
}
