// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! RFC 9421 Web Bot Auth request signing & verification (`ed25519`, RFC 9530 Content-Digest) via `grdr-crypto`.

use axum::http::HeaderMap;
use axum::http::header::{HeaderName, HeaderValue};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use url::Url;

use grdr_crypto::{SigningKeypair, sha256_digest, verify_ed25519_raw};
use grdr_os_clock::{Clock, SystemClock};

use crate::ProxyError;

pub const WEB_BOT_AUTH_DOMAIN: &str = "grdr.web-bot-auth.v1";
pub const WEB_BOT_AUTH_TTL_S: i64 = 300;
const MAX_WEB_BOT_AUTH_WINDOW_S: i64 = 900;
const MAX_CLOCK_SKEW_S: i64 = 60;
const REQUIRED_COVERED: &str = "(\"@method\" \"@authority\" \"@path\" \"content-digest\")";

#[derive(Clone)]
pub struct WebBotAuthSigner {
    keypair: SigningKeypair,
    signature_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedWebBotHeaders {
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
    pub key_id: String,
}

impl std::fmt::Debug for WebBotAuthSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebBotAuthSigner")
            .field("key_id", &self.keypair.key_id())
            .field("signature_agent", &self.signature_agent)
            .finish()
    }
}

impl WebBotAuthSigner {
    #[must_use]
    pub fn new(keypair: SigningKeypair, signature_agent: Option<String>) -> Self {
        Self {
            keypair,
            signature_agent: signature_agent
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        }
    }

    pub fn from_env(env_var: &str, signature_agent: Option<String>) -> Result<Self, ProxyError> {
        let raw = zeroize::Zeroizing::new(std::env::var(env_var).map_err(|_| {
            ProxyError::CredentialDenied(format!("Web Bot Auth seed env `{env_var}` is unset"))
        })?);
        let kp = SigningKeypair::from_seed_b64(&raw)
            .map_err(|e| ProxyError::CredentialDenied(format!("invalid Ed25519 seed: {e}")))?;
        Ok(Self::new(kp, signature_agent))
    }

    #[must_use]
    pub fn public_key_b64(&self) -> String {
        self.keypair.public_key_b64()
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        self.keypair.key_id()
    }

    pub fn sign_outbound_request(
        &self,
        method: &str,
        target_url: &str,
        body: &[u8],
        headers: &mut HeaderMap,
    ) -> Result<SignedWebBotHeaders, ProxyError> {
        let parsed = Url::parse(target_url).map_err(|e| {
            ProxyError::Sr39Rejected(format!("invalid URL for RFC 9421 signing: {e}"))
        })?;
        let host = parsed
            .host_str()
            .ok_or_else(|| ProxyError::Sr39Rejected("missing host for RFC 9421 signing".into()))?;
        let authority = match parsed.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        let path_q = match parsed.query() {
            Some(q) => format!("{}?{q}", parsed.path()),
            None => parsed.path().to_string(),
        };
        let clean_method = sanitize_param(method)?;
        let clean_authority = sanitize_param(&authority)?;
        let clean_path_q = sanitize_param(&path_q)?;
        let created = SystemClock::new()
            .now_wall()
            .map_err(|e| ProxyError::Transport(format!("wall clock unavailable: {e}")))?
            .as_second();
        let expires = created.saturating_add(WEB_BOT_AUTH_TTL_S);
        let content_digest = compute_rfc9530_digest(body);
        let keyid = sanitize_param(self.keypair.key_id())?;
        let nonce_hex = random_nonce_hex()?;
        let params = format!(
            "{REQUIRED_COVERED};created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\";nonce=\"{nonce_hex}\";tag=\"web-bot-auth\""
        );
        let signature_base = build_signature_base(
            &clean_method,
            &clean_authority,
            &clean_path_q,
            &content_digest,
            &params,
        );
        let sig_raw = self.keypair.sign_ed25519_raw(signature_base.as_bytes());
        let sig_b64 = STANDARD.encode(sig_raw);
        let sig_input = format!("sig1={params}");
        let sig_hdr = format!("sig1=:{sig_b64}:");

        set_single_header(headers, "content-digest", &content_digest)?;
        set_single_header(headers, "signature-input", &sig_input)?;
        set_single_header(headers, "signature", &sig_hdr)?;
        if let Some(agent_uri) = &self.signature_agent {
            let clean_agent = sanitize_param(agent_uri)?;
            set_single_header(headers, "signature-agent", &clean_agent)?;
        }

        Ok(SignedWebBotHeaders {
            content_digest,
            signature_input: sig_input,
            signature: sig_hdr,
            key_id: keyid,
        })
    }
}

pub fn verify_web_bot_auth_signature(
    public_key_b64: &str,
    method: &str,
    authority: &str,
    path_and_query: &str,
    content_digest: &str,
    signature_input_header: &str,
    signature_header: &str,
) -> Result<(), ProxyError> {
    let clean_method = sanitize_param(method)?;
    let clean_authority = sanitize_param(authority)?;
    let clean_path = sanitize_param(path_and_query)?;
    let clean_digest = sanitize_param(content_digest)?;
    let clean_params = sanitize_param(
        signature_input_header
            .strip_prefix("sig1=")
            .ok_or_else(|| {
                ProxyError::CredentialDenied("missing sig1= in Signature-Input".into())
            })?,
    )?;
    validate_rfc9421_params(&clean_params)?;

    let sig_b64 = signature_header
        .strip_prefix("sig1=:")
        .and_then(|s| s.strip_suffix(':'))
        .ok_or_else(|| ProxyError::CredentialDenied("malformed Signature header".into()))?;
    let pub_bytes = STANDARD.decode(public_key_b64.trim()).map_err(|_| {
        ProxyError::CredentialDenied("invalid Web Bot Auth public key base64".into())
    })?;
    let pub_arr: [u8; 32] = pub_bytes.try_into().map_err(|_| {
        ProxyError::CredentialDenied("Web Bot Auth public key must be 32 bytes".into())
    })?;
    let sig_bytes = STANDARD.decode(sig_b64.trim()).map_err(|_| {
        ProxyError::CredentialDenied("invalid Web Bot Auth signature base64".into())
    })?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        ProxyError::CredentialDenied("Web Bot Auth signature must be 64 bytes".into())
    })?;

    let base = build_signature_base(
        &clean_method,
        &clean_authority,
        &clean_path,
        &clean_digest,
        &clean_params,
    );
    verify_ed25519_raw(&pub_arr, base.as_bytes(), &sig_arr)
        .map_err(|e| ProxyError::CredentialDenied(format!("Web Bot Auth verify failed: {e}")))
}

fn validate_rfc9421_params(params: &str) -> Result<(), ProxyError> {
    if !params.starts_with(REQUIRED_COVERED) {
        return Err(ProxyError::CredentialDenied(
            "RFC 9421 Signature-Input missing required covered components".into(),
        ));
    }
    let now_s = SystemClock::new()
        .now_wall()
        .map_err(|e| ProxyError::Transport(format!("wall clock unavailable: {e}")))?
        .as_second();

    let rest = params.get(REQUIRED_COVERED.len()..).unwrap_or("");
    let (mut created, mut expires, mut keyid, mut alg, mut nonce, mut tag) =
        (None, None, None, None, None, None);
    for seg in rest.split(';').filter(|s| !s.is_empty()) {
        let Some((k, v)) = seg.split_once('=') else {
            return Err(ProxyError::CredentialDenied(
                "malformed RFC 9421 signature parameter".into(),
            ));
        };
        let unquoted = v.trim_matches('"');
        match k.trim() {
            "created" => created = v.parse::<i64>().ok(),
            "expires" => expires = v.parse::<i64>().ok(),
            "keyid" => keyid = (!unquoted.is_empty()).then_some(unquoted),
            "alg" => alg = Some(unquoted),
            "nonce" => nonce = (!unquoted.is_empty()).then_some(unquoted),
            "tag" => tag = Some(unquoted),
            _ => {}
        }
    }
    let (Some(c), Some(e)) = (created, expires) else {
        return Err(ProxyError::CredentialDenied(
            "RFC 9421 Signature-Input missing created or expires".into(),
        ));
    };
    if e <= c || e.saturating_sub(c) > MAX_WEB_BOT_AUTH_WINDOW_S {
        return Err(ProxyError::CredentialDenied(
            "RFC 9421 created/expires lifetime out of bounds".into(),
        ));
    }
    if c > now_s.saturating_add(MAX_CLOCK_SKEW_S) || now_s > e.saturating_add(MAX_CLOCK_SKEW_S) {
        return Err(ProxyError::CredentialDenied(
            "RFC 9421 signature expired or not yet valid".into(),
        ));
    }
    if alg != Some("ed25519") || tag != Some("web-bot-auth") || keyid.is_none() || nonce.is_none() {
        return Err(ProxyError::CredentialDenied(
            "RFC 9421 Web Bot Auth missing required alg=ed25519, tag=web-bot-auth, keyid, or nonce"
                .into(),
        ));
    }
    Ok(())
}

#[must_use]
pub fn compute_rfc9530_digest(body: &[u8]) -> String {
    let digest = sha256_digest(body);
    format!("sha-256=:{}:", STANDARD.encode(digest))
}

fn build_signature_base(
    method: &str,
    authority: &str,
    path_and_query: &str,
    content_digest: &str,
    params: &str,
) -> String {
    format!(
        "\"@method\": {method}\n\"@authority\": {authority}\n\"@path\": {path_and_query}\n\"content-digest\": {content_digest}\n\"@signature-params\": {params}"
    )
}

fn sanitize_param(raw: &str) -> Result<String, ProxyError> {
    if raw.is_empty() || raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ProxyError::CredentialDenied(
            "invalid control characters in RFC 9421 field".into(),
        ));
    }
    Ok(raw.to_owned())
}

fn random_nonce_hex() -> Result<String, ProxyError> {
    let mut raw = [0_u8; 16];
    grdr_crypto::fill_random(&mut raw).map_err(|e| ProxyError::Transport(e.to_string()))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for b in raw {
        if let (Some(&c1), Some(&c2)) =
            (HEX.get(usize::from(b >> 4)), HEX.get(usize::from(b & 0x0f)))
        {
            out.push(char::from(c1));
            out.push(char::from(c2));
        }
    }
    Ok(out)
}

fn set_single_header(headers: &mut HeaderMap, name: &str, val: &str) -> Result<(), ProxyError> {
    let hdr_name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|e| ProxyError::Transport(format!("invalid header `{name}`: {e}")))?;
    let hdr_val = HeaderValue::from_str(val)
        .map_err(|e| ProxyError::Transport(format!("invalid header value `{name}`: {e}")))?;
    while headers.remove(&hdr_name).is_some() {}
    headers.insert(hdr_name, hdr_val);
    Ok(())
}
