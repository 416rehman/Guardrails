// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

use crate::CryptoError;

const TOKEN_FORMAT_VERSION: u8 = 1;
const XNONCE_LEN: usize = 24;
const AEAD_DOMAIN_PREFIX: &[u8] = b"grdr.aead.v1\0";
const AEAD_SUBKEY_PREFIX: &[u8] = b"grdr.aead.subkey.v1\0";

#[derive(Clone)]
pub struct AeadKey {
    bytes: [u8; 32],
}

impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl AeadKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes = random_array::<32>()?;
        Ok(Self { bytes })
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn derive_subkey(&self, domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(AEAD_SUBKEY_PREFIX);
        hasher.update(domain.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.bytes);
        let digest: [u8; 32] = hasher.finalize().into();
        Self { bytes: digest }
    }
}

pub fn seal_token(
    key: &AeadKey,
    domain: &str,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<String, CryptoError> {
    let nonce_bytes = random_array::<XNONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.bytes));
    let nonce = XNonce::from_slice(&nonce_bytes);
    let effective_aad = domain_separated_aad(domain, aad);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &effective_aad,
            },
        )
        .map_err(|_| CryptoError::AeadEncrypt("XChaCha20-Poly1305 encryption failed".into()))?;

    let mut framed = Vec::with_capacity(
        1usize
            .saturating_add(XNONCE_LEN)
            .saturating_add(ciphertext.len()),
    );
    framed.push(TOKEN_FORMAT_VERSION);
    framed.extend_from_slice(&nonce_bytes);
    framed.extend_from_slice(&ciphertext);
    Ok(B64_URL.encode(framed))
}

pub fn open_token(
    key: &AeadKey,
    domain: &str,
    aad: &[u8],
    token: &str,
) -> Result<Vec<u8>, CryptoError> {
    let framed = B64_URL
        .decode(token.trim())
        .map_err(|_| CryptoError::InvalidToken)?;
    let Some(version) = framed.first().copied() else {
        return Err(CryptoError::InvalidToken);
    };
    if version != TOKEN_FORMAT_VERSION {
        return Err(CryptoError::InvalidToken);
    }
    let Some(nonce_slice) = framed.get(1..1usize.saturating_add(XNONCE_LEN)) else {
        return Err(CryptoError::InvalidToken);
    };
    let Some(ciphertext) = framed.get(1usize.saturating_add(XNONCE_LEN)..) else {
        return Err(CryptoError::InvalidToken);
    };
    let nonce = XNonce::from_slice(nonce_slice);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.bytes));
    let effective_aad = domain_separated_aad(domain, aad);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &effective_aad,
            },
        )
        .map_err(|_| CryptoError::InvalidToken)
}

fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = Vec::with_capacity(N);
    while out.len() < N {
        let chunk = getrandom::u64().map_err(|e| CryptoError::Entropy(e.to_string()))?;
        let remaining = N.saturating_sub(out.len());
        let take = remaining.min(8);
        let bytes = chunk.to_le_bytes();
        let Some(slice) = bytes.get(..take) else {
            return Err(CryptoError::Entropy("entropy slice out of bounds".into()));
        };
        out.extend_from_slice(slice);
    }
    out.try_into()
        .map_err(|_| CryptoError::Entropy("unexpected random array length".into()))
}

fn domain_separated_aad(domain: &str, aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        AEAD_DOMAIN_PREFIX
            .len()
            .saturating_add(domain.len())
            .saturating_add(1)
            .saturating_add(aad.len()),
    );
    out.extend_from_slice(AEAD_DOMAIN_PREFIX);
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    out.extend_from_slice(aad);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningKeypair;

    #[test]
    fn sealed_token_roundtrips_and_binds_aad_and_domain() {
        let root = AeadKey::generate().unwrap();
        let page_key = root.derive_subkey("page_token");
        let plaintext = br#"{"cursor":"row_42","exp":1900000000}"#;
        let aad = b"tenant=default|method=ListDevices|filter=|order=id asc";

        let sealed = seal_token(&page_key, "cursor-domain", aad, plaintext).unwrap();
        let opened = open_token(&page_key, "cursor-domain", aad, &sealed).unwrap();
        assert_eq!(opened, plaintext);

        // Wrong AAD (e.g. altered filter) fails verification.
        assert!(matches!(
            open_token(
                &page_key,
                "cursor-domain",
                b"tenant=default|method=ListDevices|filter=mode=block|order=id asc",
                &sealed
            ),
            Err(CryptoError::InvalidToken)
        ));

        // Wrong domain fails verification.
        assert!(matches!(
            open_token(&page_key, "other.domain", aad, &sealed),
            Err(CryptoError::InvalidToken)
        ));

        // Wrong derived subkey fails verification.
        let other_key = root.derive_subkey("other_key");
        assert!(matches!(
            open_token(&other_key, "cursor-domain", aad, &sealed),
            Err(CryptoError::InvalidToken)
        ));

        // Tampered token string fails verification.
        let mut chars: Vec<char> = sealed.chars().collect();
        let last = chars.len().saturating_sub(1);
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(matches!(
            open_token(&page_key, "cursor-domain", aad, &tampered),
            Err(CryptoError::InvalidToken)
        ));
    }

    #[test]
    fn malformed_tokens_fail_cleanly() {
        let key = SigningKeypair::generate()
            .unwrap()
            .derive_aead_key("test-cursor");
        for bad in ["", "not-base64!!!", "AQ", "AAECAw"] {
            assert!(matches!(
                open_token(&key, "cursor-domain", b"aad", bad),
                Err(CryptoError::InvalidToken)
            ));
        }
    }
}
