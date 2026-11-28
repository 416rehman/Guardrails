// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

use crate::fs_safe;
use crate::server_preflight::der_parse::{ParsedCertSummary, parse_x509_der_strict};
use crate::server_preflight::probe_types::{
    ErrCodeSlot, PreflightThresholds, ProbeOutcomeKind, RawProbeResult,
};

pub const MAX_CERT_PEM_BYTES: u64 = 2 * 1024 * 1024;
const SECS_PER_DAY: i64 = 86_400;
const MAX_CA_CHAIN_DEPTH: usize = 8;

pub fn load_pem_certs_strict(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let bytes = fs_safe::read_bounded_regular(path, MAX_CERT_PEM_BYTES)
        .map_err(|e| format!("Failed reading certificate `{}`: {e}", path.display()))?;
    let pem = std::str::from_utf8(&bytes).map_err(|_| {
        format!(
            "Certificate file `{}` is not valid UTF-8 PEM.",
            path.display()
        )
    })?;
    extract_pem_cert_blocks(pem)
        .map_err(|e| format!("Invalid PEM certificate in `{}`: {e}", path.display()))
}

pub fn extract_pem_cert_blocks(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(BEGIN) {
        let Some(after_begin) = rest.get(start.saturating_add(BEGIN.len())..) else {
            return Err("Truncated PEM BEGIN marker.".into());
        };
        let Some(end) = after_begin.find(END) else {
            return Err("Unclosed -----BEGIN CERTIFICATE----- block without matching END.".into());
        };
        let body = after_begin
            .get(..end)
            .ok_or_else(|| "Invalid PEM block boundary.".to_string())?;
        if body.contains(BEGIN) {
            return Err("Nested -----BEGIN CERTIFICATE----- inside PEM block.".into());
        }
        let cleaned: Vec<u8> = body.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        if cleaned.is_empty() {
            return Err("Empty PEM CERTIFICATE block.".into());
        }
        let der = B64_STD
            .decode(&cleaned)
            .map_err(|e| format!("Invalid Base64 in PEM block: {e}"))?;
        out.push(CertificateDer::from(der));
        rest = after_begin
            .get(end.saturating_add(END.len())..)
            .unwrap_or("");
    }
    if rest.contains(END) {
        return Err("Orphan -----END CERTIFICATE----- marker.".into());
    }
    if out.is_empty() {
        return Err("No PEM CERTIFICATE blocks present.".into());
    }
    Ok(out)
}

fn is_verified_self_signed_ca(
    der: &CertificateDer<'_>,
    summary: &ParsedCertSummary<'_>,
    sig_algs: &[&dyn SignatureVerificationAlgorithm],
) -> bool {
    if !summary.is_ca || summary.issuer_full != summary.subject_full {
        return false;
    }
    let Ok(ee) = EndEntityCert::try_from(der) else {
        return false;
    };
    sig_algs.iter().any(|alg| {
        ee.verify_signature(*alg, summary.tbs_full, summary.sig_bytes)
            .is_ok()
    })
}

pub fn probe_pem_certificates(
    cert_files: &[PathBuf],
    thresholds: &PreflightThresholds,
    now_unix_s: i64,
) -> Vec<RawProbeResult> {
    probe_pem_certificates_with_roots(
        cert_files,
        webpki_root_certs::TLS_SERVER_ROOT_CERTS,
        thresholds,
        now_unix_s,
    )
}

pub(crate) fn probe_pem_certificates_with_roots(
    cert_files: &[PathBuf],
    builtin_roots: &[CertificateDer<'static>],
    thresholds: &PreflightThresholds,
    now_unix_s: i64,
) -> Vec<RawProbeResult> {
    let mut out = Vec::new();
    let sig_algs = default_provider().signature_verification_algorithms.all;
    let mut loaded_files: Vec<(String, Vec<CertificateDer<'static>>)> = Vec::new();
    let mut extra_ca_pool: Vec<CertificateDer<'static>> = Vec::new();
    let mut anchors: Vec<TrustAnchor<'static>> = builtin_roots
        .iter()
        .filter_map(|der| anchor_from_trusted_cert(der).ok().map(|a| a.to_owned()))
        .collect();

    for path in cert_files {
        let label = path.display().to_string();
        match load_pem_certs_strict(path) {
            Ok(blocks) => {
                for der in &blocks {
                    if let Ok(summary) = parse_x509_der_strict(der.as_ref())
                        && summary.is_ca
                    {
                        if is_verified_self_signed_ca(der, &summary, sig_algs)
                            && let Ok(anchor) = anchor_from_trusted_cert(der)
                        {
                            anchors.push(anchor.to_owned());
                        }
                        extra_ca_pool.push(der.clone());
                    }
                }
                loaded_files.push((label, blocks));
            }
            Err(detail) => out.push(cert_res(
                "PF-09",
                ProbeOutcomeKind::Fail,
                detail,
                Some("Provide a valid non-symlink PEM certificate file."),
            )),
        }
    }

    if let Ok(ssl_file) = std::env::var("SSL_CERT_FILE")
        && !ssl_file.trim().is_empty()
        && let Ok(blocks) = load_pem_certs_strict(&PathBuf::from(ssl_file.trim()))
    {
        for der in &blocks {
            if let Ok(summary) = parse_x509_der_strict(der.as_ref())
                && summary.is_ca
            {
                if is_verified_self_signed_ca(der, &summary, sig_algs)
                    && let Ok(anchor) = anchor_from_trusted_cert(der)
                {
                    anchors.push(anchor.to_owned());
                }
                extra_ca_pool.push(der.clone());
            }
        }
    }

    for (label, blocks) in &loaded_files {
        let mut intermediates: Vec<CertificateDer<'_>> = Vec::new();
        for b in blocks {
            if let Ok(s) = parse_x509_der_strict(b.as_ref())
                && s.is_ca
                && s.issuer_full != s.subject_full
            {
                intermediates.push(b.as_ref().into());
            }
        }
        for (idx, der) in blocks.iter().enumerate() {
            verify_cert_entry(
                der,
                idx,
                label,
                &anchors,
                &intermediates,
                &extra_ca_pool,
                builtin_roots,
                sig_algs,
                thresholds,
                now_unix_s,
                &mut out,
            );
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn verify_cert_entry(
    der: &CertificateDer<'_>,
    idx: usize,
    label: &str,
    anchors: &[TrustAnchor<'_>],
    intermediates: &[CertificateDer<'_>],
    ca_pool: &[CertificateDer<'static>],
    builtin_roots: &[CertificateDer<'static>],
    sig_algs: &[&dyn SignatureVerificationAlgorithm],
    thresholds: &PreflightThresholds,
    now_unix_s: i64,
    out: &mut Vec<RawProbeResult>,
) {
    let summary = match parse_x509_der_strict(der.as_ref()) {
        Ok(s) => s,
        Err(reason) => {
            out.push(cert_res(
                "PF-09",
                ProbeOutcomeKind::Fail,
                format!("Malformed X.509 certificate #{idx} in `{label}`: {reason}"),
                Some("Reissue valid RFC 5280 DER X.509 certificate."),
            ));
            return;
        }
    };
    let Ok(ee) = EndEntityCert::try_from(der) else {
        out.push(cert_res(
            "PF-09",
            ProbeOutcomeKind::Fail,
            format!("Certificate #{idx} in `{label}` rejected by webpki X.509 parser."),
            Some("Verify X.509 v3 constraints and signature structure."),
        ));
        return;
    };

    if summary.is_ca {
        if summary.issuer_full == summary.subject_full {
            let self_ok = sig_algs.iter().any(|alg| {
                ee.verify_signature(*alg, summary.tbs_full, summary.sig_bytes)
                    .is_ok()
            });
            if !self_ok {
                out.push(cert_res(
                    "PF-09",
                    ProbeOutcomeKind::Fail,
                    format!("Self-signed CA certificate #{idx} in `{label}` has invalid cryptographic signature."),
                    Some("Replace tampered or corrupted CA certificate."),
                ));
                return;
            }
        } else if !verify_intermediate_ca_to_root(der, &summary, ca_pool, builtin_roots, sig_algs) {
            out.push(cert_res(
                "PF-09",
                ProbeOutcomeKind::Fail,
                format!(
                    "Intermediate CA certificate #{idx} in `{label}` failed issuer signature chain verification."
                ),
                Some("Include a validly signed root CA matching this intermediate CA."),
            ));
            return;
        }
    } else {
        let now_u64 = u64::try_from(now_unix_s).unwrap_or(0);
        let chain_res = ee.verify_for_usage(
            sig_algs,
            anchors,
            intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(now_u64)),
            KeyUsage::server_auth(),
            None,
            None,
        );
        if let Err(err) = chain_res {
            out.push(cert_res(
                "PF-09",
                ProbeOutcomeKind::Fail,
                format!("Certificate #{idx} in `{label}` failed chain/EKU verification: {err:?}"),
                Some("Include full CA/intermediate chain and serverAuth EKU in --cert."),
            ));
            return;
        }
    }

    check_cert_dates(
        idx,
        label,
        summary.not_before_s,
        summary.not_after_s,
        thresholds,
        now_unix_s,
        out,
    );
}

fn verify_intermediate_ca_to_root(
    start_der: &CertificateDer<'_>,
    start_summary: &ParsedCertSummary<'_>,
    ca_pool: &[CertificateDer<'static>],
    builtin_roots: &[CertificateDer<'static>],
    sig_algs: &[&dyn SignatureVerificationAlgorithm],
) -> bool {
    let mut visited: Vec<&[u8]> = vec![start_der.as_ref()];
    let mut cur_issuer = start_summary.issuer_full;
    let mut cur_tbs = start_summary.tbs_full;
    let mut cur_sig = start_summary.sig_bytes;

    for _ in 0..MAX_CA_CHAIN_DEPTH {
        for root in builtin_roots {
            let Ok(root_sum) = parse_x509_der_strict(root.as_ref()) else {
                continue;
            };
            if root_sum.subject_full != cur_issuer {
                continue;
            }
            let Ok(root_ee) = EndEntityCert::try_from(root) else {
                continue;
            };
            if sig_algs
                .iter()
                .any(|alg| root_ee.verify_signature(*alg, cur_tbs, cur_sig).is_ok())
            {
                return true;
            }
        }
        let mut advanced = false;
        for cand in ca_pool {
            if visited.contains(&cand.as_ref()) {
                continue;
            }
            let Ok(cand_sum) = parse_x509_der_strict(cand.as_ref()) else {
                continue;
            };
            if !cand_sum.is_ca || cand_sum.subject_full != cur_issuer {
                continue;
            }
            let Ok(cand_ee) = EndEntityCert::try_from(cand) else {
                continue;
            };
            let sig_ok = sig_algs
                .iter()
                .any(|alg| cand_ee.verify_signature(*alg, cur_tbs, cur_sig).is_ok());
            if !sig_ok {
                continue;
            }
            if is_verified_self_signed_ca(cand, &cand_sum, sig_algs) {
                return true;
            }
            visited.push(cand.as_ref());
            cur_issuer = cand_sum.issuer_full;
            cur_tbs = cand_sum.tbs_full;
            cur_sig = cand_sum.sig_bytes;
            advanced = true;
            break;
        }
        if !advanced {
            break;
        }
    }
    false
}

fn check_cert_dates(
    idx: usize,
    label: &str,
    not_before_s: i64,
    not_after_s: i64,
    thresholds: &PreflightThresholds,
    now_unix_s: i64,
    out: &mut Vec<RawProbeResult>,
) {
    if now_unix_s < not_before_s {
        out.push(cert_res(
            "PF-09",
            ProbeOutcomeKind::Fail,
            format!("Certificate #{idx} in `{label}` is not yet valid."),
            Some("Check host clock or replace premature certificate."),
        ));
        return;
    }
    let remaining_s = not_after_s.saturating_sub(now_unix_s);
    let min_s = i64::try_from(thresholds.cert_min_validity_days)
        .unwrap_or(14)
        .saturating_mul(SECS_PER_DAY);
    if remaining_s <= 0 {
        out.push(cert_res(
            "PF-09",
            ProbeOutcomeKind::Fail,
            format!("Certificate #{idx} in `{label}` has expired."),
            Some("Rotate expired certificate immediately (RB-11)."),
        ));
    } else if remaining_s < min_s {
        let days_left = remaining_s / SECS_PER_DAY;
        out.push(cert_res(
            "PF-09",
            ProbeOutcomeKind::Fail,
            format!(
                "Certificate #{idx} in `{label}` expires in {days_left}d (< {}d minimum).",
                thresholds.cert_min_validity_days
            ),
            Some("Renew certificate before rotation threshold (RB-11)."),
        ));
    } else {
        let days_left = remaining_s / SECS_PER_DAY;
        out.push(RawProbeResult {
            id: "PF-09",
            name: "tls_certificate_validity",
            kind: ProbeOutcomeKind::Pass,
            err_slot: ErrCodeSlot::None,
            detail: format!("Certificate #{idx} in `{label}` verified and valid for {days_left}d."),
            remedy: None,
        });
    }
}

fn cert_res(
    id: &'static str,
    kind: ProbeOutcomeKind,
    detail: String,
    remedy: Option<&'static str>,
) -> RawProbeResult {
    RawProbeResult {
        id,
        name: "tls_certificate_validity",
        kind,
        err_slot: ErrCodeSlot::Storage,
        detail,
        remedy,
    }
}
