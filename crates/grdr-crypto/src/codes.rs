// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Registered cryptographic error codes (`contracts/codes/registry.toml`, `ARCH-017`).

use std::fmt;

pub const CODE_CRYPTO_ENTROPY: &str = "GRDR-CRYPTO-0001";
pub const CODE_CRYPTO_INVALID_KEY: &str = "GRDR-CRYPTO-0002";
pub const CODE_CRYPTO_INVALID_SIGNATURE: &str = "GRDR-CRYPTO-0003";
pub const CODE_CRYPTO_VERIFICATION_FAILED: &str = "GRDR-CRYPTO-0004";
pub const CODE_CRYPTO_SERIALIZATION: &str = "GRDR-CRYPTO-0005";
pub const CODE_CRYPTO_IO: &str = "GRDR-CRYPTO-0006";
pub const CODE_CRYPTO_AEAD_ENCRYPT: &str = "GRDR-CRYPTO-0007";
pub const CODE_CRYPTO_INVALID_TOKEN: &str = "GRDR-CRYPTO-0008";

#[derive(Debug)]
pub enum CryptoError {
    Entropy(String),
    InvalidKey(String),
    InvalidSignature(String),
    VerificationFailed,
    Serialization(String),
    Io(String),
    AeadEncrypt(String),
    InvalidToken,
}

impl CryptoError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Entropy(_) => CODE_CRYPTO_ENTROPY,
            Self::InvalidKey(_) => CODE_CRYPTO_INVALID_KEY,
            Self::InvalidSignature(_) => CODE_CRYPTO_INVALID_SIGNATURE,
            Self::VerificationFailed => CODE_CRYPTO_VERIFICATION_FAILED,
            Self::Serialization(_) => CODE_CRYPTO_SERIALIZATION,
            Self::Io(_) => CODE_CRYPTO_IO,
            Self::AeadEncrypt(_) => CODE_CRYPTO_AEAD_ENCRYPT,
            Self::InvalidToken => CODE_CRYPTO_INVALID_TOKEN,
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(detail) => {
                write!(
                    f,
                    "{CODE_CRYPTO_ENTROPY}: OS entropy generation failed: {detail}"
                )
            }
            Self::InvalidKey(detail) => {
                write!(
                    f,
                    "{CODE_CRYPTO_INVALID_KEY}: invalid Ed25519 key material: {detail}"
                )
            }
            Self::InvalidSignature(detail) => {
                write!(
                    f,
                    "{CODE_CRYPTO_INVALID_SIGNATURE}: invalid Ed25519 signature encoding: {detail}"
                )
            }
            Self::VerificationFailed => {
                write!(
                    f,
                    "{CODE_CRYPTO_VERIFICATION_FAILED}: signature verification failed"
                )
            }
            Self::Serialization(detail) => {
                write!(
                    f,
                    "{CODE_CRYPTO_SERIALIZATION}: canonical payload serialization failed: {detail}"
                )
            }
            Self::Io(detail) => write!(f, "{CODE_CRYPTO_IO}: key storage I/O failed: {detail}"),
            Self::AeadEncrypt(detail) => {
                write!(
                    f,
                    "{CODE_CRYPTO_AEAD_ENCRYPT}: token encryption failed: {detail}"
                )
            }
            Self::InvalidToken => {
                write!(
                    f,
                    "{CODE_CRYPTO_INVALID_TOKEN}: invalid or tampered sealed token"
                )
            }
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_error_codes_match_registry_toml() {
        let reg = include_str!("../../../contracts/codes/registry.toml");
        for code in [
            CODE_CRYPTO_ENTROPY,
            CODE_CRYPTO_INVALID_KEY,
            CODE_CRYPTO_INVALID_SIGNATURE,
            CODE_CRYPTO_VERIFICATION_FAILED,
            CODE_CRYPTO_SERIALIZATION,
            CODE_CRYPTO_IO,
            CODE_CRYPTO_AEAD_ENCRYPT,
            CODE_CRYPTO_INVALID_TOKEN,
        ] {
            assert!(
                reg.contains(&format!("{code} =")),
                "{code} missing from contracts/codes/registry.toml"
            );
        }
        assert_eq!(
            CryptoError::VerificationFailed.code(),
            CODE_CRYPTO_VERIFICATION_FAILED
        );
        assert_eq!(CryptoError::InvalidToken.code(), CODE_CRYPTO_INVALID_TOKEN);
    }
}
