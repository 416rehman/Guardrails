// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::IdentityError;
use crate::broker_types::BrokeredToken;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCredentialQuery {
    pub protocol: String,
    pub host: String,
    pub path: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerCredentialQuery {
    #[serde(rename = "ServerURL")]
    pub server_url: String,
    #[serde(rename = "Username", default)]
    pub username: Option<String>,
}

#[derive(Serialize)]
struct AwsCredentialProcessOutput<'a> {
    #[serde(rename = "Version")]
    version: u8,
    #[serde(rename = "AccessKeyId")]
    access_key_id: &'a str,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: &'a str,
    #[serde(rename = "SessionToken")]
    session_token: &'a str,
    #[serde(rename = "Expiration")]
    expiration: String,
}

#[derive(Deserialize)]
struct StsSecretJson {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
}

#[derive(Serialize)]
struct GcpExecutableCredentialResponse<'a> {
    version: u8,
    success: bool,
    token_type: &'a str,
    subject_token: &'a str,
    expiration_time: i64,
}

#[derive(Serialize)]
struct DockerCredentialResponse<'a> {
    #[serde(rename = "ServerURL")]
    server_url: &'a str,
    #[serde(rename = "Username")]
    username: &'a str,
    #[serde(rename = "Secret")]
    secret: &'a str,
}

#[derive(Serialize)]
struct KubeExecCredential<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    status: KubeExecStatus<'a>,
}

#[derive(Serialize)]
struct KubeExecStatus<'a> {
    #[serde(rename = "expirationTimestamp")]
    expiration_timestamp: String,
    token: &'a str,
}

const MAX_GIT_CREDENTIAL_STDIN_BYTES: usize = 16 * 1024;
const MAX_GIT_CREDENTIAL_LINES: usize = 64;

pub fn parse_git_credential_stdin(raw: &str) -> Result<GitCredentialQuery, IdentityError> {
    if raw.len() > MAX_GIT_CREDENTIAL_STDIN_BYTES {
        return Err(IdentityError::CredentialHelper(
            "git credential input exceeds 16KiB limit".to_string(),
        ));
    }
    let mut protocol = None;
    let mut host = None;
    let mut path = None;
    let mut username = None;

    for (line_idx, line) in raw.lines().enumerate() {
        if line_idx >= MAX_GIT_CREDENTIAL_LINES {
            return Err(IdentityError::CredentialHelper(
                "git credential input exceeds 64 line limit".to_string(),
            ));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if trimmed.chars().any(|c| c == '\0' || c.is_control()) {
            return Err(IdentityError::CredentialHelper(
                "git credential input contains control character".to_string(),
            ));
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            return Err(IdentityError::CredentialHelper(format!(
                "malformed git credential entry at line {}",
                line_idx.saturating_add(1)
            )));
        };
        match k {
            "protocol" => protocol = Some(v.to_string()),
            "host" => host = Some(v.to_string()),
            "path" => path = Some(v.to_string()),
            "username" => username = Some(v.to_string()),
            _ => {}
        }
    }

    Ok(GitCredentialQuery {
        protocol: protocol.ok_or_else(|| {
            IdentityError::CredentialHelper("git credential query missing protocol".to_string())
        })?,
        host: host.ok_or_else(|| {
            IdentityError::CredentialHelper("git credential query missing host".to_string())
        })?,
        path,
        username,
    })
}

pub fn format_git_credential_reply(
    query: &GitCredentialQuery,
    username: &str,
    token: &BrokeredToken,
) -> Result<Zeroizing<String>, IdentityError> {
    for part in [
        &query.protocol,
        &query.host,
        username,
        token.token_value.as_str(),
    ] {
        if part.contains('\n') || part.contains('\r') || part.contains('\0') {
            return Err(IdentityError::CredentialHelper(
                "git credential reply field contains newline or NUL".to_string(),
            ));
        }
    }
    Ok(Zeroizing::new(format!(
        "protocol={}\nhost={}\nusername={username}\npassword={}\n\n",
        query.protocol,
        query.host,
        token.token_value.as_str()
    )))
}

pub fn format_aws_credential_process(
    token: &BrokeredToken,
) -> Result<Zeroizing<String>, IdentityError> {
    let parsed: StsSecretJson = serde_json::from_str(&token.token_value).map_err(|e| {
        IdentityError::CredentialHelper(format!("expected AWS STS JSON secret in lease token: {e}"))
    })?;
    let out = AwsCredentialProcessOutput {
        version: 1,
        access_key_id: &parsed.access_key_id,
        secret_access_key: &parsed.secret_access_key,
        session_token: &parsed.session_token,
        expiration: format_rfc3339(token.expires_at),
    };
    serde_json::to_string(&out)
        .map(Zeroizing::new)
        .map_err(|e| IdentityError::CredentialHelper(format!("serialize aws output: {e}")))
}

pub fn format_gcp_external_account(
    token: &BrokeredToken,
) -> Result<Zeroizing<String>, IdentityError> {
    let out = GcpExecutableCredentialResponse {
        version: 1,
        success: true,
        token_type: "urn:ietf:params:oauth:token-type:access_token",
        subject_token: &token.token_value,
        expiration_time: token.expires_at.as_second(),
    };
    serde_json::to_string(&out)
        .map(Zeroizing::new)
        .map_err(|e| IdentityError::CredentialHelper(format!("serialize gcp output: {e}")))
}

pub fn format_docker_credential_get(
    server_url: &str,
    username: &str,
    token: &BrokeredToken,
) -> Result<Zeroizing<String>, IdentityError> {
    let clean = server_url.trim();
    if clean.is_empty() || clean.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(IdentityError::CredentialHelper(
            "invalid Docker server URL".to_string(),
        ));
    }
    if username.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(IdentityError::CredentialHelper(
            "Docker credential username contains control character".to_string(),
        ));
    }
    let out = DockerCredentialResponse {
        server_url: clean,
        username,
        secret: &token.token_value,
    };
    serde_json::to_string(&out)
        .map(Zeroizing::new)
        .map_err(|e| IdentityError::CredentialHelper(format!("serialize docker output: {e}")))
}

pub fn format_kube_exec_credential(
    token: &BrokeredToken,
) -> Result<Zeroizing<String>, IdentityError> {
    let out = KubeExecCredential {
        api_version: "client.authentication.k8s.io/v1",
        kind: "ExecCredential",
        status: KubeExecStatus {
            expiration_timestamp: format_rfc3339(token.expires_at),
            token: &token.token_value,
        },
    };
    serde_json::to_string(&out)
        .map(Zeroizing::new)
        .map_err(|e| IdentityError::CredentialHelper(format!("serialize kube output: {e}")))
}

pub fn format_gh_credential_token(
    token: &BrokeredToken,
) -> Result<Zeroizing<String>, IdentityError> {
    let raw = token.token_value.as_str();
    if raw.trim().is_empty() || raw.contains('\n') || raw.contains('\r') || raw.contains('\0') {
        return Err(IdentityError::CredentialHelper(
            "gh credential token must be single-line non-empty".to_string(),
        ));
    }
    Ok(Zeroizing::new(raw.to_owned()))
}

pub fn format_npm_userconfig(
    registry_host: &str,
    token: &BrokeredToken,
) -> Result<Zeroizing<String>, IdentityError> {
    let raw_url = registry_host.trim().trim_end_matches('/');
    if raw_url.is_empty()
        || raw_url.contains("${")
        || raw_url.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(IdentityError::CredentialHelper(
            "invalid npm registry URL".to_string(),
        ));
    }
    let parsed = crate::http_security::validate_exact_endpoint_url(raw_url, false)?;
    let val = token.token_value.as_str();
    if val.trim().is_empty()
        || val.contains("${")
        || val.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(IdentityError::CredentialHelper(
            "npm token contains invalid characters".to_string(),
        ));
    }
    let host = parsed.host_str().ok_or_else(|| {
        IdentityError::CredentialHelper("npm registry URL missing host".to_string())
    })?;
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Ok(Zeroizing::new(format!("//{authority}/:_authToken={val}\n")))
}

pub fn format_pypi_twine_env(
    repository_url: &str,
    token: &BrokeredToken,
) -> Result<Zeroizing<String>, IdentityError> {
    let raw_url = repository_url.trim();
    if raw_url.is_empty()
        || raw_url.contains("${")
        || raw_url.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(IdentityError::CredentialHelper(
            "invalid PyPI repository URL".to_string(),
        ));
    }
    let parsed = crate::http_security::validate_exact_endpoint_url(raw_url, false)?;
    let val = token.token_value.as_str();
    if val.trim().is_empty()
        || val.contains("${")
        || val.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(IdentityError::CredentialHelper(
            "PyPI token contains invalid characters".to_string(),
        ));
    }
    Ok(Zeroizing::new(format!(
        "TWINE_USERNAME=__token__\nTWINE_REPOSITORY_URL={}\nTWINE_PASSWORD={val}\n",
        parsed.as_str()
    )))
}

fn format_rfc3339(ts: Timestamp) -> String {
    ts.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_token(val: &str) -> BrokeredToken {
        BrokeredToken {
            jti: "jti_1".into(),
            lease_id: "lse_1".into(),
            mode: crate::broker_types::CredentialMode::Release,
            token_value: Zeroizing::new(val.into()),
            non_transferable: true,
            bound_session_id: "ses_1".into(),
            bound_instance_spiffe_id: "spiffe://org/agi/1".into(),
            bound_device_id: "dev_1".into(),
            dpop_jkt: None,
            scope_digest: "abc".into(),
            issued_at: Timestamp::from_second(1_760_000_000).unwrap(),
            expires_at: Timestamp::from_second(1_760_000_900).unwrap(),
            session_label: Some(grdr_model::SessionLabel::CredentialAccessed),
        }
    }

    #[test]
    fn formats_all_five_credential_helper_protocols_and_blocks_newline_injection() {
        let q =
            parse_git_credential_stdin("protocol=https\nhost=github.com\npath=org/repo.git\n\n")
                .expect("git query");
        let bad_tok = dummy_token("tok\nevil=1");
        assert!(format_git_credential_reply(&q, "grdr", &bad_tok).is_err());

        let ok_tok = dummy_token("tok_safe_1");
        let git_out = format_git_credential_reply(&q, "grdr", &ok_tok).expect("git reply");
        assert!(
            git_out
                .contains("protocol=https\nhost=github.com\nusername=grdr\npassword=tok_safe_1\n")
        );

        let gcp_out = format_gcp_external_account(&ok_tok).expect("gcp");
        assert!(gcp_out.contains("\"success\":true"));
        assert!(gcp_out.contains("1760000900"));

        let docker_out =
            format_docker_credential_get("ghcr.io", "grdr-bot", &ok_tok).expect("docker");
        assert!(docker_out.contains("\"ServerURL\":\"ghcr.io\""));

        let kube_out = format_kube_exec_credential(&ok_tok).expect("kube");
        assert!(kube_out.contains("\"kind\":\"ExecCredential\""));
        assert!(kube_out.contains("client.authentication.k8s.io/v1"));

        let sts_json =
            r#"{"access_key_id":"ASIATESTKEY","secret_access_key":"sec","session_token":"sess"}"#;
        let aws_out = format_aws_credential_process(&dummy_token(sts_json)).expect("aws");
        assert!(aws_out.contains("\"Version\":1"));
        assert!(aws_out.contains("ASIATESTKEY"));
    }
}
