// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::fs::{self, OpenOptions};
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, Zeroizing};

mod aead;
pub use aead::{AeadKey, open_token, seal_token};

pub const SHA256_DIGEST_LEN: usize = 32;
pub const SHA256_HEX_LEN: usize = 64;
const HMAC_BLOCK_BYTES: usize = 64;
const HASH_DOMAIN_PREFIX: &[u8] = b"grdr.hash.v1\0";
const SIGNATURE_DOMAIN_PREFIX: &[u8] = b"grdr.sig.v1\0";
const SIGNATURE_V2_DOMAIN_PREFIX: &[u8] = b"grdr.sig.v2\0";

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("GRDR-CRYPTO-0001: OS entropy generation failed: {0}")]
    Entropy(String),
    #[error("GRDR-CRYPTO-0002: invalid Ed25519 key material: {0}")]
    InvalidKey(String),
    #[error("GRDR-CRYPTO-0003: invalid Ed25519 signature encoding: {0}")]
    InvalidSignature(String),
    #[error("GRDR-CRYPTO-0004: signature verification failed")]
    VerificationFailed,
    #[error("GRDR-CRYPTO-0005: canonical payload serialization failed: {0}")]
    Serialization(String),
    #[error("GRDR-CRYPTO-0006: key storage I/O failed: {0}")]
    Io(String),
    #[error("GRDR-CRYPTO-0007: token encryption failed: {0}")]
    AeadEncrypt(String),
    #[error("GRDR-CRYPTO-0008: invalid or tampered sealed token")]
    InvalidToken,
}

#[derive(Clone)]
pub struct SigningKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    key_id: String,
}

#[derive(Default)]
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Drop for SigningKeypair {
    fn drop(&mut self) {
        self.key_id.zeroize();
    }
}

impl Sha256Hasher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    #[must_use]
    pub fn finalize_digest(self) -> [u8; SHA256_DIGEST_LEN] {
        self.inner.finalize().into()
    }

    #[must_use]
    pub fn finalize_hex(self) -> String {
        let digest = self.finalize_digest();
        encode_lower_hex(&digest)
    }
}

impl SigningKeypair {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        fill_random(&mut seed)?;
        let out = Self::from_seed(seed);
        seed.zeroize();
        Ok(out)
    }

    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let key_id = compute_key_id(verifying_key.as_bytes());
        Self {
            signing_key,
            verifying_key,
            key_id,
        }
    }

    pub fn from_seed_b64(raw: &str) -> Result<Self, CryptoError> {
        let bytes = Zeroizing::new(
            B64.decode(raw.trim())
                .map_err(|e| CryptoError::InvalidKey(format!("base64 decode failed: {e}")))?,
        );
        let mut seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("seed must be 32 bytes".into()))?;
        let kp = Self::from_seed(seed);
        seed.zeroize();
        Ok(kp)
    }

    pub fn seed_b64(&self) -> String {
        let mut raw = self.signing_key.to_bytes();
        let encoded = B64.encode(raw);
        raw.zeroize();
        encoded
    }

    #[must_use]
    pub fn derive_aead_key(&self, domain: &str) -> AeadKey {
        let mut raw = self.signing_key.to_bytes();
        let key = AeadKey::from_bytes(raw).derive_subkey(domain);
        raw.zeroize();
        key
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.verifying_key.as_bytes())
    }

    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    #[must_use]
    pub fn sign_ed25519_raw(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    #[must_use]
    pub fn sign_bytes(&self, domain: &str, payload: &[u8]) -> String {
        let message = signature_message(domain, payload);
        let sig = self.signing_key.sign(&message);
        B64.encode(sig.to_bytes())
    }
}

pub fn fill_random(dest: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(dest).map_err(|e| CryptoError::Entropy(e.to_string()))
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    Sha256::digest(bytes).into()
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256_digest(bytes);
    encode_lower_hex(&digest)
}

#[must_use]
pub fn domain_sha256_digest(domain: &str, payload: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut hasher = Sha256Hasher::new();
    hasher.update(HASH_DOMAIN_PREFIX);
    let domain_len = u64::try_from(domain.len())
        .unwrap_or(u64::MAX)
        .to_le_bytes();
    hasher.update(&domain_len);
    hasher.update(domain.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(payload);
    hasher.finalize_digest()
}

#[must_use]
pub fn domain_sha256_hex(domain: &str, payload: &[u8]) -> String {
    let digest = domain_sha256_digest(domain, payload);
    encode_lower_hex(&digest)
}

#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut padded_key = [0u8; HMAC_BLOCK_BYTES];
    if key.len() > HMAC_BLOCK_BYTES {
        let mut hashed = sha256_digest(key);
        for (dst, src) in padded_key.iter_mut().zip(hashed.iter()) {
            *dst = *src;
        }
        hashed.zeroize();
    } else {
        for (dst, src) in padded_key.iter_mut().zip(key.iter()) {
            *dst = *src;
        }
    }

    let mut ipad = [0x36u8; HMAC_BLOCK_BYTES];
    let mut opad = [0x5cu8; HMAC_BLOCK_BYTES];
    for (dst, k) in ipad.iter_mut().zip(padded_key.iter()) {
        *dst ^= *k;
    }
    for (dst, k) in opad.iter_mut().zip(padded_key.iter()) {
        *dst ^= *k;
    }

    let mut inner = Sha256Hasher::new();
    inner.update(&ipad);
    inner.update(data);
    let mut inner_digest = inner.finalize_digest();

    let mut outer = Sha256Hasher::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    let mac = outer.finalize_digest();

    padded_key.zeroize();
    ipad.zeroize();
    opad.zeroize();
    inner_digest.zeroize();
    mac
}

#[must_use]
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let mac = hmac_sha256(key, data);
    encode_lower_hex(&mac)
}

#[must_use]
pub fn domain_hmac_sha256(key: &[u8], domain: &str, data: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let msg = domain_separated_message(HASH_DOMAIN_PREFIX, domain, data);
    hmac_sha256(key, &msg)
}

#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

#[must_use]
pub fn encode_lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

pub fn load_or_create_keypair(path: &Path) -> Result<SigningKeypair, CryptoError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(CryptoError::Io(format!(
                    "refusing symlink or non-regular key file {}",
                    path.display()
                )));
            }
            let raw = Zeroizing::new(
                fs::read_to_string(path)
                    .map_err(|e| CryptoError::Io(format!("read {}: {e}", path.display())))?,
            );
            return SigningKeypair::from_seed_b64(&raw);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(CryptoError::Io(format!("stat {}: {err}", path.display())));
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CryptoError::Io(format!("create {}: {e}", parent.display())))?;
    }
    let kp = SigningKeypair::generate()?;
    let tmp = path.with_extension("key.tmp");
    if let Ok(meta) = fs::symlink_metadata(&tmp) {
        if meta.file_type().is_symlink() {
            return Err(CryptoError::Io(format!(
                "refusing symlink temporary key path {}",
                tmp.display()
            )));
        }
        let _ = fs::remove_file(&tmp);
    }

    let seed_b64 = Zeroizing::new(kp.seed_b64());
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts
        .open(&tmp)
        .map_err(|e| CryptoError::Io(format!("create {}: {e}", tmp.display())))?;
    file.write_all(seed_b64.as_bytes())
        .map_err(|e| CryptoError::Io(format!("write {}: {e}", tmp.display())))?;
    drop(file);

    fs::rename(&tmp, path)
        .map_err(|e| CryptoError::Io(format!("rename {}: {e}", path.display())))?;
    Ok(kp)
}

fn decode_verifying_key(public_key_b64: &str) -> Result<VerifyingKey, CryptoError> {
    let pk_bytes = B64
        .decode(public_key_b64.trim())
        .map_err(|e| CryptoError::InvalidKey(format!("base64 decode failed: {e}")))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| CryptoError::InvalidKey(format!("invalid Ed25519 public key: {e}")))
}

pub fn validate_public_key_b64(public_key_b64: &str) -> Result<(), CryptoError> {
    decode_verifying_key(public_key_b64)?;
    Ok(())
}

pub fn verify_bytes(
    public_key_b64: &str,
    domain: &str,
    payload: &[u8],
    signature_b64: &str,
) -> Result<(), CryptoError> {
    let verifying_key = decode_verifying_key(public_key_b64)?;

    let sig_bytes = B64
        .decode(signature_b64.trim())
        .map_err(|e| CryptoError::InvalidSignature(format!("base64 decode failed: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_arr);

    let message = signature_message(domain, payload);
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

pub fn verify_ed25519_raw(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| CryptoError::InvalidKey(format!("invalid Ed25519 public key: {e}")))?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

fn signature_message(domain: &str, payload: &[u8]) -> Vec<u8> {
    // Keep v1 framing for nul-free domains (matches pinned pack signatures) and switch
    // to length-prefixed v2 whenever a domain contains NUL so (domain, payload) pairs stay injective.
    if domain.as_bytes().contains(&0) {
        return domain_separated_message(SIGNATURE_V2_DOMAIN_PREFIX, domain, payload);
    }
    let mut out = Vec::with_capacity(
        SIGNATURE_DOMAIN_PREFIX
            .len()
            .saturating_add(domain.len())
            .saturating_add(1)
            .saturating_add(payload.len()),
    );
    out.extend_from_slice(SIGNATURE_DOMAIN_PREFIX);
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    out.extend_from_slice(payload);
    out
}

fn domain_separated_message(prefix: &[u8], domain: &str, payload: &[u8]) -> Vec<u8> {
    let domain_len = u64::try_from(domain.len())
        .unwrap_or(u64::MAX)
        .to_le_bytes();
    let mut out = Vec::with_capacity(
        prefix
            .len()
            .saturating_add(domain_len.len())
            .saturating_add(domain.len())
            .saturating_add(1)
            .saturating_add(payload.len()),
    );
    out.extend_from_slice(prefix);
    out.extend_from_slice(&domain_len);
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    out.extend_from_slice(payload);
    out
}

fn compute_key_id(public_key: &[u8; 32]) -> String {
    let hex = sha256_hex(public_key);
    let prefix: String = hex.chars().take(16).collect();
    format!("kid_{prefix}")
}

fn hex_nibble(value: u8) -> char {
    match value & 0x0f {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_streaming_and_one_shot_match_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hasher.finalize_hex(), sha256_hex(b"abc"));
        assert_ne!(
            domain_sha256_digest("dom-a", b"bc"),
            domain_sha256_digest("dom-ab", b"c")
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_and_constant_time_eq() {
        let mac = hmac_sha256_hex(&[0x0bu8; 20], b"Hi There");
        assert_eq!(
            mac,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let long_key_mac = hmac_sha256_hex(
            &[0xaau8; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            long_key_mac,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn ed25519_bytes_signing_verifies_and_detects_tampering() {
        let kp = SigningKeypair::generate().unwrap();
        let sig = kp.sign_bytes("grdr.test.v1", b"payload");
        assert!(verify_bytes(&kp.public_key_b64(), "grdr.test.v1", b"payload", &sig).is_ok());
        assert!(verify_bytes(&kp.public_key_b64(), "grdr.other.v1", b"payload", &sig).is_err());
        assert!(verify_bytes(&kp.public_key_b64(), "grdr.test.v1", b"tamper", &sig).is_err());

        let nul_sig = kp.sign_bytes("a\0b", b"c");
        assert!(verify_bytes(&kp.public_key_b64(), "a\0b", b"c", &nul_sig).is_ok());
        assert!(verify_bytes(&kp.public_key_b64(), "a", b"b\0c", &nul_sig).is_err());

        let raw_sig = kp.sign_ed25519_raw(b"rfc7515-input");
        let pk = kp.public_key_bytes();
        assert!(verify_ed25519_raw(&pk, b"rfc7515-input", &raw_sig).is_ok());
        assert!(verify_ed25519_raw(&pk, b"tampered", &raw_sig).is_err());
    }

    #[test]
    fn keypair_persists_and_reloads_from_disk() {
        let dir = std::env::temp_dir().join(format!("grdr-crypto-test-{}", std::process::id()));
        let key_path = dir.join("signing.key");
        let _ = fs::remove_dir_all(&dir);

        let kp1 = load_or_create_keypair(&key_path).unwrap();
        let kp2 = load_or_create_keypair(&key_path).unwrap();
        assert_eq!(kp1.key_id(), kp2.key_id());
        assert_eq!(kp1.public_key_b64(), kp2.public_key_b64());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
