// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use grdr_crypto::hmac_sha256;
use jiff::Timestamp;
use reqwest::Client;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::IdentityError;
use crate::broker_types::Ceiling;

const DEFAULT_ISSUER_TIMEOUT_SECS: u64 = 10;

pub type JwtSignerCallback = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, IdentityError> + Send + Sync>;

pub trait JwtAssertionSigner: Send + Sync {
    fn alg(&self) -> &str;
    fn sign_input(&self, signing_input: &[u8]) -> Result<Vec<u8>, IdentityError>;
}

#[derive(Clone)]
pub struct Hs256JwtSigner {
    secret: Zeroizing<Vec<u8>>,
}

pub struct CallbackJwtSigner {
    alg_name: String,
    signer_fn: JwtSignerCallback,
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    typ: &'a str,
}

#[derive(Serialize)]
struct GitHubAppJwtClaims<'a> {
    iat: i64,
    exp: i64,
    iss: &'a str,
}

#[derive(Serialize)]
struct AwsPolicyStatement<'a> {
    #[serde(rename = "Effect")]
    effect: &'a str,
    #[serde(rename = "Action")]
    action: Vec<&'a str>,
    #[serde(rename = "Resource")]
    resource: Vec<String>,
}

#[derive(Serialize)]
struct AwsSessionPolicyDoc<'a> {
    #[serde(rename = "Version")]
    version: &'a str,
    #[serde(rename = "Statement")]
    statement: Vec<AwsPolicyStatement<'a>>,
}

#[derive(Serialize)]
struct StsSecretPayload<'a> {
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: &'a str,
}

impl std::fmt::Debug for Hs256JwtSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hs256JwtSigner").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for CallbackJwtSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackJwtSigner")
            .field("alg_name", &self.alg_name)
            .finish_non_exhaustive()
    }
}

impl Hs256JwtSigner {
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: Zeroizing::new(secret.into()),
        }
    }
}

impl JwtAssertionSigner for Hs256JwtSigner {
    fn alg(&self) -> &str {
        "HS256"
    }

    fn sign_input(&self, signing_input: &[u8]) -> Result<Vec<u8>, IdentityError> {
        Ok(hmac_sha256(&self.secret, signing_input).to_vec())
    }
}

impl CallbackJwtSigner {
    pub fn new(
        alg_name: impl Into<String>,
        signer_fn: impl Fn(&[u8]) -> Result<Vec<u8>, IdentityError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            alg_name: alg_name.into(),
            signer_fn: Arc::new(signer_fn),
        }
    }
}

impl JwtAssertionSigner for CallbackJwtSigner {
    fn alg(&self) -> &str {
        &self.alg_name
    }

    fn sign_input(&self, signing_input: &[u8]) -> Result<Vec<u8>, IdentityError> {
        (self.signer_fn)(signing_input)
    }
}

pub(crate) fn build_no_redirect_http_client(
    allow_insecure_loopback: bool,
) -> Result<Client, IdentityError> {
    Client::builder()
        .https_only(!allow_insecure_loopback)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(DEFAULT_ISSUER_TIMEOUT_SECS))
        .build()
        .map_err(|e| IdentityError::IssuerError(format!("HTTP issuer client init failed: {e}")))
}

pub(crate) fn encode_form_pairs(pairs: &[(&str, &str)]) -> Zeroizing<String> {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    Zeroizing::new(ser.finish())
}

pub(crate) fn validate_numeric_id(label: &str, raw: &str) -> Result<(), IdentityError> {
    if raw.is_empty() || raw.len() > 32 || !raw.chars().all(|c| c.is_ascii_digit()) {
        return Err(IdentityError::IssuerError(format!(
            "{label} must be 1..=32 ASCII digits"
        )));
    }
    Ok(())
}

pub(crate) fn mint_github_app_jwt(
    app_id: &str,
    signer: &dyn JwtAssertionSigner,
    now_secs: i64,
) -> Result<Zeroizing<String>, IdentityError> {
    validate_numeric_id("GitHub app_id", app_id)?;
    let alg = signer.alg();
    if !matches!(alg, "RS256" | "ES256" | "EdDSA" | "HS256") {
        return Err(IdentityError::IssuerError(format!(
            "unsupported JWT signing algorithm `{alg}`"
        )));
    }
    let hdr = serde_json::to_vec(&JwtHeader { alg, typ: "JWT" })
        .map_err(|e| IdentityError::IssuerError(format!("JWT header encode failed: {e}")))?;
    let claims = serde_json::to_vec(&GitHubAppJwtClaims {
        iat: now_secs.saturating_sub(30),
        exp: now_secs.saturating_add(540),
        iss: app_id,
    })
    .map_err(|e| IdentityError::IssuerError(format!("JWT claims encode failed: {e}")))?;

    let signing_input = format!("{}.{}", B64_URL.encode(hdr), B64_URL.encode(claims));
    let sig = signer.sign_input(signing_input.as_bytes())?;
    Ok(Zeroizing::new(format!(
        "{signing_input}.{}",
        B64_URL.encode(sig)
    )))
}

pub(crate) fn build_aws_inline_session_policy(ceiling: &Ceiling) -> Result<String, IdentityError> {
    if ceiling.allowed_actions.is_empty() || ceiling.allowed_resource_prefixes.is_empty() {
        return Err(IdentityError::IssuerError(
            "AWS session ceiling requires non-empty allowed_actions and allowed_resource_prefixes"
                .to_string(),
        ));
    }
    let actions: Vec<&str> = ceiling.allowed_actions.iter().map(String::as_str).collect();
    if actions.iter().any(|a| a.trim().is_empty() || *a == "*") {
        return Err(IdentityError::IssuerError(
            "AWS session ceiling rejects empty or global wildcard action".to_string(),
        ));
    }
    let mut resources = Vec::with_capacity(ceiling.allowed_resource_prefixes.len());
    for prefix in &ceiling.allowed_resource_prefixes {
        let trimmed = prefix.trim();
        if trimmed.is_empty() || trimmed == "*" {
            return Err(IdentityError::IssuerError(
                "AWS session ceiling rejects empty or global wildcard resource".to_string(),
            ));
        }
        if trimmed.ends_with('*') {
            resources.push(trimmed.to_string());
        } else {
            resources.push(format!("{trimmed}*"));
        }
    }
    let doc = AwsSessionPolicyDoc {
        version: "2012-10-17",
        statement: vec![AwsPolicyStatement {
            effect: "Allow",
            action: actions,
            resource: resources,
        }],
    };
    serde_json::to_string(&doc)
        .map_err(|e| IdentityError::IssuerError(format!("AWS policy JSON failed: {e}")))
}

pub(crate) fn parse_aws_sts_xml_response(
    xml: &str,
    fallback_expiry: Timestamp,
) -> Result<(Zeroizing<String>, String, Timestamp), IdentityError> {
    let upper = xml.to_ascii_uppercase();
    if upper.contains("<!DOCTYPE")
        || upper.contains("<!ENTITY")
        || upper.contains("<![CDATA[")
        || xml.contains("<!--")
    {
        return Err(IdentityError::IssuerError(
            "AWS STS XML contains forbidden DTD, CDATA, or comment construct".to_string(),
        ));
    }
    if extract_xml_tag_strict(xml, "ErrorResponse").is_some()
        || extract_xml_tag_strict(xml, "Error").is_some()
    {
        let code = extract_xml_tag_strict(xml, "Code").unwrap_or_else(|| "Unknown".into());
        return Err(IdentityError::IssuerError(format!(
            "AWS STS returned ErrorResponse ({code})"
        )));
    }
    let access_key = extract_xml_tag_strict(xml, "AccessKeyId").ok_or_else(|| {
        IdentityError::IssuerError("AWS STS response missing <AccessKeyId>".to_string())
    })?;
    let secret_key = Zeroizing::new(extract_xml_tag_strict(xml, "SecretAccessKey").ok_or_else(
        || IdentityError::IssuerError("AWS STS response missing <SecretAccessKey>".to_string()),
    )?);
    let session_tok =
        Zeroizing::new(extract_xml_tag_strict(xml, "SessionToken").ok_or_else(|| {
            IdentityError::IssuerError("AWS STS response missing <SessionToken>".to_string())
        })?);
    if access_key.is_empty() || secret_key.is_empty() || session_tok.is_empty() {
        return Err(IdentityError::IssuerError(
            "AWS STS returned empty credential field".to_string(),
        ));
    }
    let expires_at = extract_xml_tag_strict(xml, "Expiration")
        .and_then(|s| s.parse::<Timestamp>().ok())
        .unwrap_or(fallback_expiry);

    let payload = StsSecretPayload {
        access_key_id: &access_key,
        secret_access_key: secret_key.as_str(),
        session_token: session_tok.as_str(),
    };
    let serialized = Zeroizing::new(serde_json::to_string(&payload).map_err(|e| {
        IdentityError::IssuerError(format!("AWS STS secret serialize failed: {e}"))
    })?);
    Ok((serialized, access_key, expires_at))
}

pub(crate) fn sanitize_role_session_name(session_id: &str) -> String {
    let mut out = String::from("grdr-");
    for ch in session_id.chars() {
        if out.len() >= 64 {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '@' | '=' | ',' | '-') {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    out
}

fn extract_xml_tag_strict(xml: &str, tag: &str) -> Option<String> {
    let prefix = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut search_from = 0usize;
    while let Some(rel) = xml.get(search_from..)?.find(&prefix) {
        let start = search_from.saturating_add(rel);
        let after_name = start.saturating_add(prefix.len());
        let next_ch = xml.get(after_name..)?.chars().next()?;
        if next_ch == '>' || next_ch.is_ascii_whitespace() {
            let rest = xml.get(after_name..)?;
            let gt = rest.find('>')?;
            let body_start = after_name.saturating_add(gt).saturating_add(1);
            let close_rel = xml.get(body_start..)?.find(&close)?;
            let inner = xml.get(body_start..body_start.saturating_add(close_rel))?;
            if inner.contains('<') && !matches!(tag, "ErrorResponse" | "Error") {
                return None;
            }
            return Some(inner.trim().to_string());
        }
        search_from = after_name;
    }
    None
}
