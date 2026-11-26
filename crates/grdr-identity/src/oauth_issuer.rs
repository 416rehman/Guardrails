// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use jiff::Timestamp;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::IdentityError;
use crate::broker_types::{BrokerRequest, CredentialBinding};
use crate::http_security::{
    pinned_client_for_url, read_bounded_response_text, validate_exact_endpoint_url,
};
use crate::issuer::{CredentialIssuer, IssuedCredential};
use crate::issuer_helpers::{build_no_redirect_http_client, encode_form_pairs};
use crate::secret_store::BoxFuture;

#[derive(Debug, Clone)]
pub struct GcpStsIssuer {
    http: Client,
    sts_endpoint: Url,
    audience: String,
    scopes: Vec<String>,
    allow_insecure_loopback: bool,
}

#[derive(Debug, Clone)]
pub struct OAuth2Rfc8693Issuer {
    http: Client,
    token_endpoint: Url,
    revocation_endpoint: Option<Url>,
    client_id: String,
    min_ttl_secs_val: i64,
    actor_token: Option<Zeroizing<String>>,
    allow_insecure_loopback: bool,
}

#[derive(Serialize)]
struct GcpStsExchangeRequest<'a> {
    grant_type: &'a str,
    audience: &'a str,
    scope: &'a str,
    requested_token_type: &'a str,
    subject_token: &'a str,
    subject_token_type: &'a str,
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    expires_in: Option<i64>,
}

impl GcpStsIssuer {
    pub fn new(
        sts_endpoint: &str,
        audience: impl Into<String>,
        scopes: Vec<String>,
        allow_insecure_loopback: bool,
    ) -> Result<Self, IdentityError> {
        let aud = audience.into();
        if aud.trim().is_empty() {
            return Err(IdentityError::IssuerError(
                "GCP STS audience must be non-empty".to_string(),
            ));
        }
        Ok(Self {
            http: build_no_redirect_http_client(allow_insecure_loopback)?,
            sts_endpoint: validate_exact_endpoint_url(sts_endpoint, allow_insecure_loopback)?,
            audience: aud,
            scopes,
            allow_insecure_loopback,
        })
    }
}

impl CredentialIssuer for GcpStsIssuer {
    fn issuer_name(&self) -> &'static str {
        "gcp-sts"
    }

    fn min_ttl_secs(&self) -> i64 {
        300
    }

    fn supports_revocation(&self) -> bool {
        false
    }

    fn issue_credential<'a>(
        &'a self,
        _binding: &'a CredentialBinding,
        _req: &'a BrokerRequest,
        ttl_secs: i64,
        subject_token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<IssuedCredential, IdentityError>> {
        Box::pin(async move {
            let subj = subject_token.filter(|s| !s.is_empty()).ok_or_else(|| {
                IdentityError::IssuerError("GCP STS exchange requires subject_token".into())
            })?;
            if ttl_secs < self.min_ttl_secs() {
                return Err(IdentityError::ReleaseUnsupportedByUpstream);
            }
            let client =
                pinned_client_for_url(&self.sts_endpoint, &self.http, self.allow_insecure_loopback)
                    .await?;
            let scope_joined = self.scopes.join(" ");
            let resp = client
                .post(self.sts_endpoint.clone())
                .json(&GcpStsExchangeRequest {
                    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
                    audience: &self.audience,
                    scope: &scope_joined,
                    requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
                    subject_token: subj,
                    subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
                })
                .send()
                .await
                .map_err(|e| IdentityError::IssuerError(format!("GCP STS request failed: {e}")))?;
            if !resp.status().is_success() {
                return Err(IdentityError::IssuerError(format!(
                    "GCP STS returned HTTP {}",
                    resp.status()
                )));
            }
            let raw_text = read_bounded_response_text(resp, "GCP STS").await?;
            let parsed: OAuthTokenResponse = serde_json::from_str(&raw_text)
                .map_err(|e| IdentityError::IssuerError(format!("GCP STS parse: {e}")))?;
            if parsed.access_token.trim().is_empty() {
                return Err(IdentityError::IssuerError(
                    "GCP STS returned empty access_token".to_string(),
                ));
            }
            let life = validate_clamped_expires_in(parsed.expires_in, ttl_secs, "GCP STS")?;
            let now = Timestamp::now();
            let exp = Timestamp::from_second(now.as_second().saturating_add(life)).unwrap_or(now);
            Ok(IssuedCredential {
                secret_material: Zeroizing::new(parsed.access_token),
                upstream_public_id: Some(self.audience.clone()),
                revocation_handle: None,
                expires_at: exp,
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

impl OAuth2Rfc8693Issuer {
    pub fn new(
        token_endpoint: &str,
        revocation_endpoint: Option<&str>,
        client_id: impl Into<String>,
        min_ttl_secs_val: i64,
        actor_token: Option<String>,
        allow_insecure_loopback: bool,
    ) -> Result<Self, IdentityError> {
        let client_id_val = client_id.into();
        if client_id_val.trim().is_empty() {
            return Err(IdentityError::IssuerError(
                "OAuth2 client_id must be non-empty".to_string(),
            ));
        }
        let rev_url = revocation_endpoint
            .map(|r| validate_exact_endpoint_url(r, allow_insecure_loopback))
            .transpose()?;
        Ok(Self {
            http: build_no_redirect_http_client(allow_insecure_loopback)?,
            token_endpoint: validate_exact_endpoint_url(token_endpoint, allow_insecure_loopback)?,
            revocation_endpoint: rev_url,
            client_id: client_id_val,
            min_ttl_secs_val,
            actor_token: actor_token.map(Zeroizing::new),
            allow_insecure_loopback,
        })
    }
}

impl CredentialIssuer for OAuth2Rfc8693Issuer {
    fn issuer_name(&self) -> &'static str {
        "oauth2-rfc8693"
    }

    fn min_ttl_secs(&self) -> i64 {
        self.min_ttl_secs_val
    }

    fn supports_revocation(&self) -> bool {
        self.revocation_endpoint.is_some()
    }

    fn issue_credential<'a>(
        &'a self,
        _binding: &'a CredentialBinding,
        req: &'a BrokerRequest,
        ttl_secs: i64,
        subject_token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<IssuedCredential, IdentityError>> {
        Box::pin(async move {
            let subj = subject_token.filter(|s| !s.is_empty()).ok_or_else(|| {
                IdentityError::IssuerError("RFC 8693 exchange requires subject_token".into())
            })?;
            if !self.supports_revocation() && ttl_secs < self.min_ttl_secs_val {
                return Err(IdentityError::ReleaseUnsupportedByUpstream);
            }
            let mut form = vec![
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("client_id", &self.client_id),
                ("subject_token", subj),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                ("resource", &req.requested_resource),
                ("scope", &req.requested_action),
            ];
            if let Some(act) = &self.actor_token {
                form.push(("actor_token", act.as_str()));
                form.push((
                    "actor_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ));
            }
            let client = pinned_client_for_url(
                &self.token_endpoint,
                &self.http,
                self.allow_insecure_loopback,
            )
            .await?;
            let encoded = encode_form_pairs(&form);
            let resp = client
                .post(self.token_endpoint.clone())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(encoded.as_str().to_owned())
                .send()
                .await
                .map_err(|e| IdentityError::IssuerError(format!("RFC 8693 exchange: {e}")))?;
            if !resp.status().is_success() {
                return Err(IdentityError::IssuerError(format!(
                    "RFC 8693 endpoint returned HTTP {}",
                    resp.status()
                )));
            }
            let raw_text = read_bounded_response_text(resp, "RFC 8693").await?;
            let parsed: OAuthTokenResponse = serde_json::from_str(&raw_text)
                .map_err(|e| IdentityError::IssuerError(format!("RFC 8693 parse: {e}")))?;
            if parsed.access_token.trim().is_empty() {
                return Err(IdentityError::IssuerError(
                    "RFC 8693 endpoint returned empty access_token".to_string(),
                ));
            }
            let life = validate_clamped_expires_in(parsed.expires_in, ttl_secs, "RFC 8693")?;
            let now = Timestamp::now();
            let exp = Timestamp::from_second(now.as_second().saturating_add(life)).unwrap_or(now);
            let tok = Zeroizing::new(parsed.access_token);
            let rev_handle = self.revocation_endpoint.as_ref().map(|_| tok.clone());
            Ok(IssuedCredential {
                secret_material: tok,
                upstream_public_id: Some(self.client_id.clone()),
                revocation_handle: rev_handle,
                expires_at: exp,
            })
        })
    }

    fn revoke_credential<'a>(
        &'a self,
        revocation_handle: &'a str,
    ) -> BoxFuture<'a, Result<(), IdentityError>> {
        Box::pin(async move {
            let Some(rev_url) = &self.revocation_endpoint else {
                return Err(IdentityError::ReleaseUnsupportedByUpstream);
            };
            let client =
                pinned_client_for_url(rev_url, &self.http, self.allow_insecure_loopback).await?;
            let encoded =
                encode_form_pairs(&[("token", revocation_handle), ("client_id", &self.client_id)]);
            let resp = client
                .post(rev_url.clone())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(encoded.as_str().to_owned())
                .send()
                .await
                .map_err(|e| IdentityError::IssuerError(format!("RFC 7009 revoke: {e}")))?;
            if !resp.status().is_success() {
                return Err(IdentityError::IssuerError(format!(
                    "RFC 7009 revoke returned HTTP {}",
                    resp.status()
                )));
            }
            Ok(())
        })
    }
}

fn validate_clamped_expires_in(
    expires_in: Option<i64>,
    ttl_secs: i64,
    label: &str,
) -> Result<i64, IdentityError> {
    if let Some(exp_in) = expires_in
        && exp_in <= 0
    {
        return Err(IdentityError::IssuerError(format!(
            "{label} returned non-positive expires_in ({exp_in})"
        )));
    }
    let ceiling_ttl = ttl_secs.max(1);
    Ok(expires_in.unwrap_or(ceiling_ttl).min(ceiling_ttl))
}
