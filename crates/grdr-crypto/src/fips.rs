// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Startup cryptographic self-test and FIPS 140-3 platform compliance probes (`E5.5`).

use std::env::VarError;

use crate::{
    AeadKey, CryptoError, SigningKeypair, constant_time_eq, hmac_sha256_hex, open_token,
    seal_token, sha256_hex, verify_bytes,
};

pub const FIPS_REQUIRE_VALIDATED_ENV: &str = "GRDR_FIPS_REQUIRE_VALIDATED_MODULE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsBuildProfile {
    Standard,
    Fips,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsStartupMode {
    BestEffort,
    RequireValidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsPlatformEligibility {
    SupportedLinux,
    SupportedWindows,
    UnsupportedMacOs,
    UnsupportedOther,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsValidationState {
    ValidatedModuleActive,
    SelfTestPassedNonFipsModule,
    UnsupportedPlatform,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCipherSuite {
    Tls13Aes256GcmSha384,
    Tls13Aes128GcmSha256,
    Tls13Chacha20Poly1305Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsKeyExchangeGroup {
    Secp256r1,
    Secp384r1,
    X25519,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsTlsPolicy {
    pub startup_mode: FipsStartupMode,
    pub allowed_cipher_suites: Vec<TlsCipherSuite>,
    pub allowed_kx_groups: Vec<TlsKeyExchangeGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsSelfTestReport {
    pub profile: FipsBuildProfile,
    pub startup_mode: FipsStartupMode,
    pub target_os: &'static str,
    pub platform_eligibility: FipsPlatformEligibility,
    pub state: FipsValidationState,
    pub awslc_version: Option<&'static str>,
    pub fips_module_version: Option<u32>,
    pub fips_runtime_mode: bool,
    pub passed_kats: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsSbomClaim {
    pub module_name: String,
    pub module_version: u32,
    pub target_os: String,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeCryptoProbe {
    target_os: &'static str,
    profile: FipsBuildProfile,
    awslc_version: Option<&'static str>,
    fips_module_version: Option<u32>,
    fips_runtime_mode: bool,
    backend_self_test_ok: bool,
}

impl FipsBuildProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Fips => "fips",
        }
    }
}

impl FipsPlatformEligibility {
    #[must_use]
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::SupportedLinux | Self::SupportedWindows)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SupportedLinux => "supported_linux",
            Self::SupportedWindows => "supported_windows",
            Self::UnsupportedMacOs => "unsupported_macos_no_fips_claim",
            Self::UnsupportedOther => "unsupported_other",
        }
    }
}

impl FipsValidationState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidatedModuleActive => "validated_module_active",
            Self::SelfTestPassedNonFipsModule => "self_test_passed_non_fips_module",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Failed => "failed",
        }
    }
}

impl TlsCipherSuite {
    #[must_use]
    pub const fn is_fips_approved(self) -> bool {
        matches!(
            self,
            Self::Tls13Aes256GcmSha384 | Self::Tls13Aes128GcmSha256
        )
    }
}

impl TlsKeyExchangeGroup {
    #[must_use]
    pub const fn is_fips_approved(self) -> bool {
        matches!(self, Self::Secp256r1 | Self::Secp384r1)
    }
}

impl FipsTlsPolicy {
    #[must_use]
    pub fn for_startup_mode(mode: FipsStartupMode) -> Self {
        let all_suites = [
            TlsCipherSuite::Tls13Aes256GcmSha384,
            TlsCipherSuite::Tls13Aes128GcmSha256,
            TlsCipherSuite::Tls13Chacha20Poly1305Sha256,
        ];
        let all_groups = [
            TlsKeyExchangeGroup::Secp256r1,
            TlsKeyExchangeGroup::Secp384r1,
            TlsKeyExchangeGroup::X25519,
        ];
        let allowed_cipher_suites = match mode {
            FipsStartupMode::RequireValidated => all_suites
                .into_iter()
                .filter(|suite| suite.is_fips_approved())
                .collect(),
            FipsStartupMode::BestEffort => all_suites.to_vec(),
        };
        let allowed_kx_groups = match mode {
            FipsStartupMode::RequireValidated => all_groups
                .into_iter()
                .filter(|group| group.is_fips_approved())
                .collect(),
            FipsStartupMode::BestEffort => all_groups.to_vec(),
        };
        Self {
            startup_mode: mode,
            allowed_cipher_suites,
            allowed_kx_groups,
        }
    }
}

#[must_use]
pub const fn compiled_fips_profile() -> FipsBuildProfile {
    if cfg!(feature = "fips") {
        FipsBuildProfile::Fips
    } else {
        FipsBuildProfile::Standard
    }
}

pub fn parse_fips_startup_mode(raw: Option<&str>) -> Result<FipsStartupMode, CryptoError> {
    let Some(value) = raw else {
        return Ok(FipsStartupMode::BestEffort);
    };
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("0")
        || trimmed.eq_ignore_ascii_case("false")
        || trimmed.eq_ignore_ascii_case("no")
    {
        Ok(FipsStartupMode::BestEffort)
    } else if trimmed.eq_ignore_ascii_case("1")
        || trimmed.eq_ignore_ascii_case("true")
        || trimmed.eq_ignore_ascii_case("yes")
    {
        Ok(FipsStartupMode::RequireValidated)
    } else {
        Err(CryptoError::FipsModuleUnavailable(format!(
            "unrecognized {FIPS_REQUIRE_VALIDATED_ENV} value '{trimmed}' (expected 1/true/yes or 0/false/no)"
        )))
    }
}

pub fn startup_fips_mode_from_env() -> Result<FipsStartupMode, CryptoError> {
    match std::env::var(FIPS_REQUIRE_VALIDATED_ENV) {
        Ok(raw) => parse_fips_startup_mode(Some(&raw)),
        Err(VarError::NotPresent) => Ok(FipsStartupMode::BestEffort),
        Err(VarError::NotUnicode(_)) => Err(CryptoError::FipsModuleUnavailable(format!(
            "{FIPS_REQUIRE_VALIDATED_ENV} contains non-UTF-8 data"
        ))),
    }
}

pub fn startup_crypto_self_test_from_env() -> Result<FipsSelfTestReport, CryptoError> {
    let mode = startup_fips_mode_from_env()?;
    run_startup_crypto_self_test(mode)
}

pub fn run_startup_crypto_self_test(
    mode: FipsStartupMode,
) -> Result<FipsSelfTestReport, CryptoError> {
    let probe = collect_runtime_probe();
    evaluate_startup_self_test(probe, mode)
}

pub fn filter_tls_cipher_suites(
    mode: FipsStartupMode,
    candidates: &[TlsCipherSuite],
) -> Result<Vec<TlsCipherSuite>, CryptoError> {
    let filtered: Vec<TlsCipherSuite> = match mode {
        FipsStartupMode::RequireValidated => candidates
            .iter()
            .copied()
            .filter(|suite| suite.is_fips_approved())
            .collect(),
        FipsStartupMode::BestEffort => candidates.to_vec(),
    };
    if mode == FipsStartupMode::RequireValidated && filtered.is_empty() {
        return Err(CryptoError::FipsModuleUnavailable(
            "no FIPS-approved TLS 1.3 cipher suite remained after filtering".to_string(),
        ));
    }
    Ok(filtered)
}

pub fn filter_tls_kx_groups(
    mode: FipsStartupMode,
    candidates: &[TlsKeyExchangeGroup],
) -> Result<Vec<TlsKeyExchangeGroup>, CryptoError> {
    let filtered: Vec<TlsKeyExchangeGroup> = match mode {
        FipsStartupMode::RequireValidated => candidates
            .iter()
            .copied()
            .filter(|group| group.is_fips_approved())
            .collect(),
        FipsStartupMode::BestEffort => candidates.to_vec(),
    };
    if mode == FipsStartupMode::RequireValidated && filtered.is_empty() {
        return Err(CryptoError::FipsModuleUnavailable(
            "no FIPS-approved TLS key-exchange group remained after filtering".to_string(),
        ));
    }
    Ok(filtered)
}

#[must_use]
pub fn evaluate_sbom_fips_claim(
    report: &FipsSelfTestReport,
    module_name: &str,
) -> Option<FipsSbomClaim> {
    if !report.platform_eligibility.is_eligible() {
        return None;
    }
    if report.state != FipsValidationState::ValidatedModuleActive || !report.fips_runtime_mode {
        return None;
    }
    let module_version = report.fips_module_version?;
    if module_name.trim().is_empty() {
        return None;
    }
    Some(FipsSbomClaim {
        module_name: module_name.trim().to_string(),
        module_version,
        target_os: report.target_os.to_string(),
    })
}

fn collect_runtime_probe() -> RuntimeCryptoProbe {
    #[cfg(feature = "fips")]
    {
        RuntimeCryptoProbe {
            target_os: std::env::consts::OS,
            profile: FipsBuildProfile::Fips,
            awslc_version: Some(aws_lc_rs::awslc_version()),
            fips_module_version: aws_lc_rs::fips_version(),
            fips_runtime_mode: aws_lc_rs::try_fips_mode().is_ok(),
            backend_self_test_ok: aws_lc_rs::try_fips_self_test().is_ok(),
        }
    }
    #[cfg(not(feature = "fips"))]
    {
        RuntimeCryptoProbe {
            target_os: std::env::consts::OS,
            profile: FipsBuildProfile::Standard,
            awslc_version: None,
            fips_module_version: None,
            fips_runtime_mode: false,
            backend_self_test_ok: true,
        }
    }
}

fn classify_platform(target_os: &str) -> FipsPlatformEligibility {
    match target_os {
        "linux" => FipsPlatformEligibility::SupportedLinux,
        "windows" => FipsPlatformEligibility::SupportedWindows,
        "macos" => FipsPlatformEligibility::UnsupportedMacOs,
        _ => FipsPlatformEligibility::UnsupportedOther,
    }
}

fn run_primitive_kats() -> Result<Vec<&'static str>, CryptoError> {
    const NIST_SHA256_ABC: &str =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const RFC4231_TC1_HEX: &str =
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    let digest = sha256_hex(b"abc");
    if digest != NIST_SHA256_ABC {
        return Err(CryptoError::FipsSelfTestFailed(
            "SHA-256 NIST KAT mismatch".to_string(),
        ));
    }

    let mac = hmac_sha256_hex(&[0x0bu8; 20], b"Hi There");
    if mac != RFC4231_TC1_HEX {
        return Err(CryptoError::FipsSelfTestFailed(
            "HMAC-SHA256 RFC 4231 KAT mismatch".to_string(),
        ));
    }

    if !constant_time_eq(b"grdr-kat", b"grdr-kat") || constant_time_eq(b"grdr-kat", b"grdr-bad") {
        return Err(CryptoError::FipsSelfTestFailed(
            "constant-time equality KAT mismatch".to_string(),
        ));
    }

    let kp = SigningKeypair::from_seed([0x42u8; 32]);
    let sig = kp.sign_bytes("grdr.kat.v1", b"kat-payload");
    verify_bytes(&kp.public_key_b64(), "grdr.kat.v1", b"kat-payload", &sig)
        .map_err(|e| CryptoError::FipsSelfTestFailed(format!("Ed25519 KAT verify: {e}")))?;
    if verify_bytes(&kp.public_key_b64(), "grdr.kat.v1", b"tampered", &sig).is_ok() {
        return Err(CryptoError::FipsSelfTestFailed(
            "Ed25519 KAT accepted tampered payload".to_string(),
        ));
    }

    let aead_key = AeadKey::from_bytes([0x24u8; 32]);
    let token = seal_token(&aead_key, "grdr.kat.token", b"kat-aad", b"kat-secret")
        .map_err(|e| CryptoError::FipsSelfTestFailed(format!("AEAD KAT seal: {e}")))?;
    let plain = open_token(&aead_key, "grdr.kat.token", b"kat-aad", &token)
        .map_err(|e| CryptoError::FipsSelfTestFailed(format!("AEAD KAT open: {e}")))?;
    if plain.as_slice() != b"kat-secret" {
        return Err(CryptoError::FipsSelfTestFailed(
            "AEAD KAT plaintext mismatch".to_string(),
        ));
    }
    if open_token(&aead_key, "grdr.kat.token", b"wrong-aad", &token).is_ok() {
        return Err(CryptoError::FipsSelfTestFailed(
            "AEAD KAT accepted wrong AAD".to_string(),
        ));
    }

    Ok(vec![
        "sha256-nist-kat",
        "hmac-sha256-rfc4231-kat",
        "constant-time-eq-kat",
        "ed25519-sign-verify-kat",
        "aead-seal-open-kat",
    ])
}

fn evaluate_startup_self_test(
    probe: RuntimeCryptoProbe,
    mode: FipsStartupMode,
) -> Result<FipsSelfTestReport, CryptoError> {
    let mut passed_kats = run_primitive_kats()?;
    if !probe.backend_self_test_ok {
        return Err(CryptoError::FipsSelfTestFailed(
            "AWS-LC power-on cryptographic self-test failed".to_string(),
        ));
    }
    if probe.profile == FipsBuildProfile::Fips {
        passed_kats.push("aws-lc-boringssl-self-test");
    }

    let platform_eligibility = classify_platform(probe.target_os);
    let state = if !platform_eligibility.is_eligible() {
        FipsValidationState::UnsupportedPlatform
    } else if probe.profile == FipsBuildProfile::Fips
        && probe.fips_runtime_mode
        && probe.fips_module_version.is_some()
    {
        FipsValidationState::ValidatedModuleActive
    } else {
        FipsValidationState::SelfTestPassedNonFipsModule
    };

    if mode == FipsStartupMode::RequireValidated {
        if !platform_eligibility.is_eligible() {
            return Err(CryptoError::FipsModuleUnavailable(format!(
                "FIPS validation has no supported CMVP module claim on OS '{}'",
                probe.target_os
            )));
        }
        if state != FipsValidationState::ValidatedModuleActive {
            return Err(CryptoError::FipsModuleUnavailable(format!(
                "strict FIPS mode requires active CMVP module (awslc={:?}, fips_version={:?}, runtime_mode={})",
                probe.awslc_version, probe.fips_module_version, probe.fips_runtime_mode
            )));
        }
    }

    Ok(FipsSelfTestReport {
        profile: probe.profile,
        startup_mode: mode,
        target_os: probe.target_os,
        platform_eligibility,
        state,
        awslc_version: probe.awslc_version,
        fips_module_version: probe.fips_module_version,
        fips_runtime_mode: probe.fips_runtime_mode,
        passed_kats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_crypto_self_test_runs_kats_and_matches_compiled_profile() {
        let report = run_startup_crypto_self_test(FipsStartupMode::BestEffort).unwrap();
        assert_eq!(report.profile, compiled_fips_profile());
        assert!(report.passed_kats.contains(&"sha256-nist-kat"));
        assert!(report.passed_kats.contains(&"hmac-sha256-rfc4231-kat"));
        assert!(report.passed_kats.contains(&"ed25519-sign-verify-kat"));
        assert!(report.passed_kats.contains(&"aead-seal-open-kat"));
        #[cfg(feature = "fips")]
        {
            assert!(report.awslc_version.is_some());
            assert!(report.passed_kats.contains(&"aws-lc-boringssl-self-test"));
        }
    }

    #[test]
    fn strict_mode_rejects_macos_and_never_emits_macos_sbom_claim() {
        let macos_probe = RuntimeCryptoProbe {
            target_os: "macos",
            profile: FipsBuildProfile::Fips,
            awslc_version: Some("1.70.0"),
            fips_module_version: Some(4),
            fips_runtime_mode: true,
            backend_self_test_ok: true,
        };
        let err = evaluate_startup_self_test(macos_probe, FipsStartupMode::RequireValidated)
            .expect_err("strict FIPS must reject macOS");
        assert!(err.to_string().contains("GRDR-CRYPTO-0010"));

        let best_effort =
            evaluate_startup_self_test(macos_probe, FipsStartupMode::BestEffort).unwrap();
        assert_eq!(best_effort.state, FipsValidationState::UnsupportedPlatform);
        assert_eq!(
            evaluate_sbom_fips_claim(&best_effort, "aws-lc-fips"),
            None,
            "macOS must carry zero FIPS SBOM claim"
        );
    }

    #[test]
    fn linux_and_windows_validated_modules_emit_sbom_claim_while_non_fips_module_fails_strict() {
        for os in ["linux", "windows"] {
            let validated_probe = RuntimeCryptoProbe {
                target_os: os,
                profile: FipsBuildProfile::Fips,
                awslc_version: Some("1.70.0"),
                fips_module_version: Some(4),
                fips_runtime_mode: true,
                backend_self_test_ok: true,
            };
            let report =
                evaluate_startup_self_test(validated_probe, FipsStartupMode::RequireValidated)
                    .unwrap();
            assert_eq!(report.state, FipsValidationState::ValidatedModuleActive);
            let claim = evaluate_sbom_fips_claim(&report, "aws-lc-fips")
                .expect("Linux/Windows validated build should emit FIPS SBOM claim");
            assert_eq!(claim.module_version, 4);
            assert_eq!(claim.target_os, os);
        }

        let non_fips_probe = RuntimeCryptoProbe {
            target_os: "linux",
            profile: FipsBuildProfile::Fips,
            awslc_version: Some("1.70.0"),
            fips_module_version: None,
            fips_runtime_mode: false,
            backend_self_test_ok: true,
        };
        let err = evaluate_startup_self_test(non_fips_probe, FipsStartupMode::RequireValidated)
            .expect_err("strict FIPS must fail when FIPS_mode is inactive");
        assert!(err.to_string().contains("GRDR-CRYPTO-0010"));

        let best_effort =
            evaluate_startup_self_test(non_fips_probe, FipsStartupMode::BestEffort).unwrap();
        assert_eq!(
            best_effort.state,
            FipsValidationState::SelfTestPassedNonFipsModule
        );
        assert_eq!(evaluate_sbom_fips_claim(&best_effort, "aws-lc-fips"), None);
    }

    #[test]
    fn failed_backend_self_test_aborts_before_strict_checks() {
        let failed_probe = RuntimeCryptoProbe {
            target_os: "linux",
            profile: FipsBuildProfile::Fips,
            awslc_version: Some("1.70.0"),
            fips_module_version: Some(4),
            fips_runtime_mode: true,
            backend_self_test_ok: false,
        };
        let err = evaluate_startup_self_test(failed_probe, FipsStartupMode::BestEffort)
            .expect_err("failed backend self-test must fail closed");
        assert!(err.to_string().contains("GRDR-CRYPTO-0009"));
    }

    #[test]
    fn startup_mode_parser_fails_closed_on_unrecognized_values() {
        assert_eq!(
            parse_fips_startup_mode(None).unwrap(),
            FipsStartupMode::BestEffort
        );
        assert_eq!(
            parse_fips_startup_mode(Some("")).unwrap(),
            FipsStartupMode::BestEffort
        );
        assert_eq!(
            parse_fips_startup_mode(Some("false")).unwrap(),
            FipsStartupMode::BestEffort
        );
        assert_eq!(
            parse_fips_startup_mode(Some("1")).unwrap(),
            FipsStartupMode::RequireValidated
        );
        assert_eq!(
            parse_fips_startup_mode(Some("yes")).unwrap(),
            FipsStartupMode::RequireValidated
        );
        for unrecognized in ["strict", "required", "maybe"] {
            let err = parse_fips_startup_mode(Some(unrecognized))
                .expect_err("unrecognized FIPS strictness mode must fail closed");
            assert!(err.to_string().contains("GRDR-CRYPTO-0010"));
        }
    }

    #[test]
    fn strict_tls_policy_filters_non_fips_suites_and_groups() {
        let strict_policy = FipsTlsPolicy::for_startup_mode(FipsStartupMode::RequireValidated);
        assert!(
            !strict_policy
                .allowed_cipher_suites
                .contains(&TlsCipherSuite::Tls13Chacha20Poly1305Sha256)
        );
        assert!(
            !strict_policy
                .allowed_kx_groups
                .contains(&TlsKeyExchangeGroup::X25519)
        );

        let filtered_suites = filter_tls_cipher_suites(
            FipsStartupMode::RequireValidated,
            &[
                TlsCipherSuite::Tls13Chacha20Poly1305Sha256,
                TlsCipherSuite::Tls13Aes256GcmSha384,
            ],
        )
        .unwrap();
        assert_eq!(filtered_suites, vec![TlsCipherSuite::Tls13Aes256GcmSha384]);

        let filtered_groups = filter_tls_kx_groups(
            FipsStartupMode::RequireValidated,
            &[TlsKeyExchangeGroup::X25519, TlsKeyExchangeGroup::Secp256r1],
        )
        .unwrap();
        assert_eq!(filtered_groups, vec![TlsKeyExchangeGroup::Secp256r1]);

        let empty_suite_err = filter_tls_cipher_suites(
            FipsStartupMode::RequireValidated,
            &[TlsCipherSuite::Tls13Chacha20Poly1305Sha256],
        )
        .expect_err("rejecting all offered suites must fail closed");
        assert!(empty_suite_err.to_string().contains("GRDR-CRYPTO-0010"));
    }

    #[test]
    fn non_cmvp_runtime_probe_never_claims_validated_module() {
        let report = run_startup_crypto_self_test(FipsStartupMode::BestEffort).unwrap();
        assert_ne!(report.state, FipsValidationState::ValidatedModuleActive);
        assert_eq!(evaluate_sbom_fips_claim(&report, "aws-lc-fips"), None);
    }
}
