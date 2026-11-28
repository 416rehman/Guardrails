// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;
use std::fs::{self, File};
use std::io::Read;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use grdr_model::CodedError;

pub const CODE_PG_IO: &str = "GRDR-PG-0001";
pub const CODE_PG_MIGRATION: &str = "GRDR-PG-0002";
pub const CODE_PG_CODEC: &str = "GRDR-PG-0003";
pub const CODE_PG_CONFIG: &str = "GRDR-PG-0004";
pub const CODE_PG_WIRE: &str = "GRDR-PG-0005";
pub const CODE_PG_RLS: &str = "GRDR-PG-0006";
const DEFAULT_POOL_SIZE: u16 = 8;
pub(crate) const MAX_CA_PEM_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresSslMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PostgresTransport {
    OfflineEmbedded,
    TcpWire {
        endpoint: String,
        database: String,
        user: String,
        #[serde(default, with = "opt_zeroizing_serde")]
        password: Option<Zeroizing<String>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresConfig {
    pub transport: PostgresTransport,
    pub ssl_mode: PostgresSslMode,
    pub application_name: String,
    pub statement_timeout_ms: u32,
    pub connect_timeout_ms: u32,
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    #[serde(default = "default_pool_size")]
    pub max_pool_size: u16,
}

impl fmt::Debug for PostgresTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OfflineEmbedded => write!(f, "OfflineEmbedded"),
            Self::TcpWire {
                endpoint,
                database,
                user,
                password,
            } => f
                .debug_struct("TcpWire")
                .field("endpoint", endpoint)
                .field("database", database)
                .field("user", user)
                .field("password", &password.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
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
            ssl_mode: PostgresSslMode::VerifyFull,
            application_name: "grdr-server".into(),
            statement_timeout_ms: 30_000,
            connect_timeout_ms: 5_000,
            ca_cert_pem: None,
            max_pool_size: DEFAULT_POOL_SIZE,
        }
    }

    pub fn with_ca_cert_pem(mut self, pem: impl Into<String>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    pub fn with_max_pool_size(mut self, max_pool_size: u16) -> Self {
        self.max_pool_size = max_pool_size.max(1);
        self
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
        if rest.contains('#') {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                "PostgreSQL DSN cannot contain URI #fragment.",
                "Remove #fragment from the PostgreSQL connection URI.",
            ));
        }

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
        if database.contains('/') || database.contains('#') {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                "PostgreSQL database path cannot contain extra '/' or '#' segments.",
                "Format DSN as postgres://user@host:port/database.",
            ));
        }

        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let endpoint = normalize_hostport(hostport)?;
        let (user, password) = match userinfo {
            Some(ui) => match ui.split_once(':') {
                Some((u, p)) => (u.trim().to_string(), Some(Zeroizing::new(p.to_string()))),
                None => (ui.trim().to_string(), None),
            },
            None => ("grdr".to_string(), None),
        };
        validate_dsn_token("user", &user, true)?;
        if let Some(ref pw) = password {
            validate_dsn_token("password", pw, false)?;
        }

        let mut ssl_mode = PostgresSslMode::VerifyFull;
        let mut ca_cert_pem: Option<String> = None;
        let mut max_pool_size = DEFAULT_POOL_SIZE;
        if let Some(q) = query {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k.eq_ignore_ascii_case("sslmode") {
                        ssl_mode = PostgresSslMode::parse(v)?;
                    } else if k.eq_ignore_ascii_case("sslrootcert") && !v.trim().is_empty() {
                        ca_cert_pem = Some(read_ca_pem_file(v.trim())?);
                    } else if k.eq_ignore_ascii_case("pool_size") {
                        let parsed = v.trim().parse::<u16>().map_err(|_| {
                            CodedError::new(
                                CODE_PG_CONFIG,
                                format!("Invalid PostgreSQL pool_size `{v}`."),
                                "Specify a numeric pool_size between 1 and 64.",
                            )
                        })?;
                        if parsed == 0 || parsed > 64 {
                            return Err(CodedError::new(
                                CODE_PG_CONFIG,
                                format!("PostgreSQL pool_size {parsed} must be between 1 and 64."),
                                "Specify pool_size between 1 and 64.",
                            ));
                        }
                        max_pool_size = parsed;
                    }
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
            ca_cert_pem,
            max_pool_size,
        })
    }

    pub fn validate(&self) -> Result<(), CodedError> {
        validate_dsn_token("application_name", &self.application_name, true)?;
        if self.max_pool_size == 0 || self.max_pool_size > 64 {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                format!(
                    "PostgreSQL max_pool_size {} must be between 1 and 64.",
                    self.max_pool_size
                ),
                "Configure a bounded connection pool size between 1 and 64.",
            ));
        }
        if let Some(ref pem) = self.ca_cert_pem {
            let _ = crate::tls::validate_ca_pem(pem)?;
        }
        if let PostgresTransport::TcpWire {
            endpoint,
            database,
            user,
            password,
        } = &self.transport
        {
            validate_explicit_hostport(endpoint)?;
            validate_dsn_token("database", database, true)?;
            if database.contains('/') || database.contains('#') {
                return Err(CodedError::new(
                    CODE_PG_CONFIG,
                    "PostgreSQL database name cannot contain '/' or '#'.",
                    "Specify a single valid PostgreSQL database name.",
                ));
            }
            validate_dsn_token("user", user, true)?;
            if let Some(pw) = password {
                validate_dsn_token("password", pw, false)?;
            }
        }
        Ok(())
    }
}

const fn default_pool_size() -> u16 {
    DEFAULT_POOL_SIZE
}

fn read_ca_pem_file(path_str: &str) -> Result<String, CodedError> {
    validate_dsn_token("sslrootcert", path_str, false)?;
    let meta = fs::symlink_metadata(path_str).map_err(|e| {
        CodedError::new(
            CODE_PG_CONFIG,
            format!("Cannot read PostgreSQL sslrootcert `{path_str}`: {e}"),
            "Provide an accessible PEM certificate file for sslrootcert.",
        )
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            format!("PostgreSQL sslrootcert `{path_str}` must be a regular file, not a symlink."),
            "Point sslrootcert directly to a PEM certificate file.",
        ));
    }
    if meta.len() > MAX_CA_PEM_BYTES as u64 {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            format!("PostgreSQL sslrootcert `{path_str}` exceeds {MAX_CA_PEM_BYTES} byte limit."),
            "Provide a concise PEM CA bundle.",
        ));
    }
    let file = File::open(path_str).map_err(|e| {
        CodedError::new(
            CODE_PG_CONFIG,
            format!("Failed opening PostgreSQL sslrootcert `{path_str}`: {e}"),
            "Provide a readable UTF-8 PEM certificate bundle.",
        )
    })?;
    let cap_u64 = u64::try_from(MAX_CA_PEM_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
    let mut raw = Vec::new();
    file.take(cap_u64).read_to_end(&mut raw).map_err(|e| {
        CodedError::new(
            CODE_PG_CONFIG,
            format!("Failed reading PostgreSQL sslrootcert `{path_str}`: {e}"),
            "Provide a readable UTF-8 PEM certificate bundle.",
        )
    })?;
    if raw.len() > MAX_CA_PEM_BYTES {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            format!("PostgreSQL sslrootcert `{path_str}` exceeds {MAX_CA_PEM_BYTES} byte limit."),
            "Provide a concise PEM CA bundle.",
        ));
    }
    let pem = String::from_utf8(raw).map_err(|_| {
        CodedError::new(
            CODE_PG_CONFIG,
            format!("PostgreSQL sslrootcert `{path_str}` is not valid UTF-8."),
            "Provide a UTF-8 PEM certificate bundle.",
        )
    })?;
    let _ = crate::tls::validate_ca_pem(&pem)?;
    Ok(pem)
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

fn validate_explicit_hostport(raw: &str) -> Result<(), CodedError> {
    let trimmed = raw.trim();
    validate_dsn_token("endpoint", trimmed, true)?;
    if let Some(after_open) = trimmed.strip_prefix('[') {
        let (host, rest) = after_open.split_once(']').ok_or_else(|| {
            CodedError::new(
                CODE_PG_CONFIG,
                "Invalid IPv6 host literal in PostgreSQL endpoint.",
                "Use [addr]:port format for IPv6 hosts.",
            )
        })?;
        let port_str = rest.strip_prefix(':').ok_or_else(|| {
            CodedError::new(
                CODE_PG_CONFIG,
                "PostgreSQL IPv6 endpoint must include :port.",
                "Use [addr]:port format.",
            )
        })?;
        if host.is_empty() {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                "PostgreSQL IPv6 host cannot be empty.",
                "Provide a valid IPv6 host address.",
            ));
        }
        let _ = validate_port(port_str)?;
        return Ok(());
    }
    let (host, port_str) = trimmed.split_once(':').ok_or_else(|| {
        CodedError::new(
            CODE_PG_CONFIG,
            "PostgreSQL endpoint must be in host:port form.",
            "Format PostgreSQL endpoint as host:port.",
        )
    })?;
    if host.is_empty() || port_str.contains(':') || host.contains('/') || host.contains('#') {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            "Invalid host:port in PostgreSQL endpoint.",
            "Format PostgreSQL endpoint as host:port.",
        ));
    }
    let _ = validate_port(port_str)?;
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

mod opt_zeroizing_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(value: &Option<Zeroizing<String>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(secret) => serializer.serialize_some(secret.as_str()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Zeroizing<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer).map(|opt| opt.map(Zeroizing::new))
    }
}
