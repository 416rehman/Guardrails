// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::sync::Arc;

use jiff::Timestamp;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::IdentityError;
use crate::broker_types::{BrokerRequest, CredentialBinding};
use crate::http_security::{
    pinned_client_for_url, read_bounded_response_text, validate_endpoint_url,
    validate_exact_endpoint_url,
};
use crate::issuer_helpers::{
    JwtAssertionSigner, build_aws_inline_session_policy, build_no_redirect_http_client,
    encode_form_pairs, mint_github_app_jwt, parse_aws_sts_xml_response, sanitize_role_session_name,
    validate_numeric_id,
};
use crate::secret_store::BoxFuture;

const MAX_AWS_STS_DURATION_SECS: i64 = 43_200;
const MAX_GITHUB_TOKEN_TTL_SECS: i64 = 3_600;

pub struct IssuedCredential {
    pub secret_material: Zeroizing<String>,
    pub upstream_public_id: Option<String>,
    pub revocation_handle: Option<Zeroizing<String>>,
    pub expires_at: Timestamp,
}

pub trait CredentialIssuer: Send + Sync {
    fn issuer_name(&self) -> &'static str;
    fn min_ttl_secs(&self) -> i64;
    fn supports_revocation(&self) -> bool;
    fn issue_credential<'a>(
        &'a self,
        binding: &'a CredentialBinding,
        req: &'a BrokerRequest,
        ttl_secs: i64,
        subject_token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<IssuedCredential, IdentityError>>;
    fn revoke_credential<'a>(
        &'a self,
        revocation_handle: &'a str,
    ) -> BoxFuture<'a, Result<(), IdentityError>>;
}

#[derive(Debug, Clone)]
pub struct AwsStsIssuer {
    http: Client,
    sts_endpoint: Url,
    source_identity: Option<String>,
    allow_insecure_loopback: bool,
}

#[derive(Clone)]
pub struct GitHubAppIssuer {
    http: Client,
    api_base: Url,
    app_id: String,
    installation_id: String,
    repositories: Vec<String>,
    permissions: BTreeMap<String, String>,
    signer: Arc<dyn JwtAssertionSigner>,
    allow_insecure_loopback: bool,
}

#[derive(Serialize)]
struct GitHubTokenRequest<'a> {
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    repositories: &'a [String],
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    permissions: &'a BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct GitHubTokenResponse {
    token: String,
    expires_at: Option<String>,
}

impl std::fmt::Debug for IssuedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCredential")
            .field("upstream_public_id", &self.upstream_public_id)
            .field("has_revocation_handle", &self.revocation_handle.is_some())
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for GitHubAppIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubAppIssuer")
            .field("api_base", &self.api_base.as_str())
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .finish_non_exhaustive()
    }
}

impl AwsStsIssuer {
    pub fn new(
        sts_endpoint: &str,
        source_identity: Option<String>,
        allow_insecure_loopback: bool,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            http: build_no_redirect_http_client(allow_insecure_loopback)?,
            sts_endpoint: validate_exact_endpoint_url(sts_endpoint, allow_insecure_loopback)?,
            source_identity,
            allow_insecure_loopback,
        })
    }
}

impl CredentialIssuer for AwsStsIssuer {
    fn issuer_name(&self) -> &'static str {
        "aws-sts"
    }

    fn min_ttl_secs(&self) -> i64 {
        900
    }

    fn supports_revocation(&self) -> bool {
        false
    }

    fn issue_credential<'a>(
        &'a self,
        _binding: &'a CredentialBinding,
        req: &'a BrokerRequest,
        ttl_secs: i64,
        subject_token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<IssuedCredential, IdentityError>> {
        Box::pin(async move {
            let web_token = subject_token.filter(|t| !t.is_empty()).ok_or_else(|| {
                IdentityError::IssuerError(
                    "AWS STS AssumeRoleWithWebIdentity requires subject_token".into(),
                )
            })?;
            validate_aws_role_arn(&req.requested_resource)?;
            if ttl_secs < self.min_ttl_secs() {
                return Err(IdentityError::ReleaseUnsupportedByUpstream);
            }
            let duration = ttl_secs.min(MAX_AWS_STS_DURATION_SECS);
            let role_session_name = sanitize_role_session_name(&req.session_id);
            let mut form_fields = vec![
                ("Action", "AssumeRoleWithWebIdentity".to_string()),
                ("Version", "2011-06-15".to_string()),
                ("RoleArn", req.requested_resource.clone()),
                ("RoleSessionName", role_session_name),
                ("DurationSeconds", duration.to_string()),
                ("WebIdentityToken", web_token.to_string()),
            ];
            let source_id = self
                .source_identity
                .clone()
                .unwrap_or_else(|| sanitize_role_session_name(&req.session_id));
            form_fields.push(("SourceIdentity", source_id));
            if let Some(ceiling) = &req.ceiling {
                form_fields.push(("Policy", build_aws_inline_session_policy(ceiling)?));
            }

            let client =
                pinned_client_for_url(&self.sts_endpoint, &self.http, self.allow_insecure_loopback)
                    .await?;
            let pair_refs: Vec<(&str, &str)> =
                form_fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let encoded = encode_form_pairs(&pair_refs);
            let resp = client
                .post(self.sts_endpoint.clone())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(encoded.as_str().to_owned())
                .send()
                .await
                .map_err(|e| IdentityError::IssuerError(format!("AWS STS request failed: {e}")))?;
            if !resp.status().is_success() {
                return Err(IdentityError::IssuerError(format!(
                    "AWS STS returned HTTP {}",
                    resp.status()
                )));
            }
            let body = read_bounded_response_text(resp, "AWS STS").await?;
            let now = Timestamp::now();
            let ceiling_exp =
                Timestamp::from_second(now.as_second().saturating_add(duration)).unwrap_or(now);
            let (secret_material, access_key_id, raw_exp) =
                parse_aws_sts_xml_response(&body, ceiling_exp)?;
            let expires_at = raw_exp.min(ceiling_exp);
            if expires_at <= now {
                return Err(IdentityError::IssuerError(
                    "AWS STS returned expired credentials".to_string(),
                ));
            }

            Ok(IssuedCredential {
                secret_material,
                upstream_public_id: Some(access_key_id),
                revocation_handle: None,
                expires_at,
            })
        })
    }

    fn revoke_credential<'a>(
        &'a self,
        _revocation_handle: &'a str,
    ) -> BoxFuture<'a, Result<(), IdentityError>> {
        Box::pin(async { Err(IdentityError::ReleaseUnsupportedByUpstream) })
    }
}

impl GitHubAppIssuer {
    pub fn new(
        api_base: &str,
        app_id: impl Into<String>,
        installation_id: impl Into<String>,
        repositories: Vec<String>,
        permissions: BTreeMap<String, String>,
        signer: Arc<dyn JwtAssertionSigner>,
        allow_insecure_loopback: bool,
    ) -> Result<Self, IdentityError> {
        let app_id_val = app_id.into();
        let inst_id_val = installation_id.into();
        validate_numeric_id("GitHub app_id", &app_id_val)?;
        validate_numeric_id("GitHub installation_id", &inst_id_val)?;
        Ok(Self {
            http: build_no_redirect_http_client(allow_insecure_loopback)?,
            api_base: validate_endpoint_url(api_base, allow_insecure_loopback)?,
            app_id: app_id_val,
            installation_id: inst_id_val,
            repositories,
            permissions,
            signer,
            allow_insecure_loopback,
        })
    }
}

impl CredentialIssuer for GitHubAppIssuer {
    fn issuer_name(&self) -> &'static str {
        "github-app"
    }

    fn min_ttl_secs(&self) -> i64 {
        60
    }

    fn supports_revocation(&self) -> bool {
        true
    }

    fn issue_credential<'a>(
        &'a self,
        _binding: &'a CredentialBinding,
        _req: &'a BrokerRequest,
        ttl_secs: i64,
        _subject_token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<IssuedCredential, IdentityError>> {
        Box::pin(async move {
            let effective_ttl = ttl_secs.clamp(1, MAX_GITHUB_TOKEN_TTL_SECS);
            let now = Timestamp::now();
            let jwt = mint_github_app_jwt(&self.app_id, self.signer.as_ref(), now.as_second())?;
            let url = self
                .api_base
                .join(&format!(
                    "app/installations/{}/access_tokens",
                    self.installation_id
                ))
                .map_err(|e| IdentityError::InvalidHttpEndpoint(e.to_string()))?;

            let client =
                pinned_client_for_url(&url, &self.http, self.allow_insecure_loopback).await?;
            let resp = client
                .post(url)
                .header("Authorization", format!("Bearer {}", jwt.as_str()))
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "guardrails-adr-broker")
                .json(&GitHubTokenRequest {
                    repositories: &self.repositories,
                    permissions: &self.permissions,
                })
                .send()
                .await
                .map_err(|e| {
                    IdentityError::IssuerError(format!("GitHub App token request: {e}"))
                })?;
            if !resp.status().is_success() {
                return Err(IdentityError::IssuerError(format!(
                    "GitHub App token endpoint returned HTTP {}",
                    resp.status()
                )));
            }
            let raw_text = read_bounded_response_text(resp, "GitHub App token").await?;
            let parsed: GitHubTokenResponse = serde_json::from_str(&raw_text)
                .map_err(|e| IdentityError::IssuerError(format!("GitHub response parse: {e}")))?;
            if parsed.token.trim().is_empty() {
                return Err(IdentityError::IssuerError(
                    "GitHub App token endpoint returned empty token".to_string(),
                ));
            }
            let ceiling_exp = Timestamp::from_second(now.as_second().saturating_add(effective_ttl))
                .unwrap_or(now);
            let raw_exp = parsed
                .expires_at
                .as_deref()
                .and_then(|s| s.parse::<Timestamp>().ok())
                .unwrap_or(ceiling_exp);
            let expires_at = raw_exp.min(ceiling_exp);
            if expires_at <= now {
                return Err(IdentityError::IssuerError(
                    "GitHub App returned already-expired token".to_string(),
                ));
            }
            let tok = Zeroizing::new(parsed.token);
            Ok(IssuedCredential {
                revocation_handle: Some(tok.clone()),
                secret_material: tok,
                upstream_public_id: Some(format!("gh-inst:{}", self.installation_id)),
                expires_at,
            })
        })
    }

    fn revoke_credential<'a>(
        &'a self,
        revocation_handle: &'a str,
    ) -> BoxFuture<'a, Result<(), IdentityError>> {
        Box::pin(async move {
            let url = self
                .api_base
                .join("installation/token")
                .map_err(|e| IdentityError::InvalidHttpEndpoint(e.to_string()))?;
            let client =
                pinned_client_for_url(&url, &self.http, self.allow_insecure_loopback).await?;
            let resp = client
                .delete(url)
                .header("Authorization", format!("Bearer {revocation_handle}"))
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "guardrails-adr-broker")
                .send()
                .await
                .map_err(|e| {
                    IdentityError::IssuerError(format!("GitHub token revoke failed: {e}"))
                })?;
            if !resp.status().is_success() {
                return Err(IdentityError::IssuerError(format!(
                    "GitHub token revoke returned HTTP {}",
                    resp.status()
                )));
            }
            Ok(())
        })
    }
}

fn validate_aws_role_arn(arn: &str) -> Result<(), IdentityError> {
    let valid_prefix = arn.starts_with("arn:aws:iam::")
        || arn.starts_with("arn:aws-us-gov:iam::")
        || arn.starts_with("arn:aws-cn:iam::");
    if !valid_prefix || !arn.contains(":role/") {
        return Err(IdentityError::IssuerError(
            "AWS STS requires valid IAM role ARN as requested_resource".to_string(),
        ));
    }
    Ok(())
}
