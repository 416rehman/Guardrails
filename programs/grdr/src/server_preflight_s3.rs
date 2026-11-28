// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;

use reqwest::blocking::Client;

use crate::server_preflight::probe_types::{
    PreflightThresholds, ProbeOutcomeKind, RawProbeResult, S3AddressingStyle,
};
use crate::server_preflight::s3_auth::{
    LifecycleAssessment, ObjectLockAssessment, S3Credentials, assess_lifecycle_xml,
    assess_object_lock_xml, build_bucket_url, sanitize_s3_xml, validate_s3_endpoint_url,
    xml_contains_tag_value,
};
use crate::server_preflight::s3_http::{
    build_s3_client, execute_signed_get, probe_http_date_skew, s3_res,
};

pub fn probe_s3_object_store(
    endpoint: &str,
    lake_bucket: Option<&str>,
    backup_bucket: Option<&str>,
    style: S3AddressingStyle,
    cert_files: &[PathBuf],
    thresholds: &PreflightThresholds,
    now_unix_s: i64,
) -> Vec<RawProbeResult> {
    let mut out = Vec::new();
    if let Err(msg) = validate_s3_endpoint_url(endpoint) {
        out.push(s3_res(
            "PF-04",
            "object_store_endpoint_reachability",
            ProbeOutcomeKind::Fail,
            msg.to_string(),
            Some("Provide a valid https:// --object-store-endpoint URL without credentials."),
        ));
        return out;
    }
    let creds = match S3Credentials::from_env() {
        Ok(c) => c,
        Err(msg) => {
            out.push(s3_res(
                "PF-04",
                "object_store_endpoint_reachability",
                ProbeOutcomeKind::Fail,
                msg,
                Some("Set both access key and secret key or clear partial S3 credentials."),
            ));
            return out;
        }
    };
    let client = match build_s3_client(cert_files) {
        Ok(c) => c,
        Err(detail) => {
            out.push(s3_res(
                "PF-04",
                "object_store_endpoint_reachability",
                ProbeOutcomeKind::Fail,
                detail,
                Some("Check local CA bundle and --cert PEM files."),
            ));
            return out;
        }
    };

    probe_http_date_skew(
        &client,
        endpoint.trim(),
        creds.as_ref(),
        thresholds,
        now_unix_s,
        &mut out,
    );
    if let Some(bucket_url) = resolve_bucket_target(
        "PF-04",
        "object_store_bucket_versioning",
        "--object-store-bucket",
        endpoint,
        lake_bucket,
        style,
        &mut out,
    ) {
        let b = lake_bucket.map(str::trim).unwrap_or("");
        out.push(query_versioning(
            &client,
            "object_store_bucket_versioning",
            b,
            &bucket_url,
            creds.as_ref(),
            now_unix_s,
        ));
        out.push(query_lifecycle(
            &client,
            b,
            &bucket_url,
            creds.as_ref(),
            now_unix_s,
        ));
    }
    if let Some(backup_url) = resolve_bucket_target(
        "PF-05",
        "backup_bucket_object_lock",
        "--backup-bucket",
        endpoint,
        backup_bucket,
        style,
        &mut out,
    ) {
        let b = backup_bucket.map(str::trim).unwrap_or("");
        out.push(query_versioning(
            &client,
            "backup_bucket_versioning",
            b,
            &backup_url,
            creds.as_ref(),
            now_unix_s,
        ));
        out.push(query_object_lock(
            &client,
            b,
            &backup_url,
            creds.as_ref(),
            thresholds.pitr_window_days,
            now_unix_s,
        ));
    }
    out
}

fn resolve_bucket_target(
    id: &'static str,
    name: &'static str,
    flag: &str,
    endpoint: &str,
    bucket: Option<&str>,
    style: S3AddressingStyle,
    out: &mut Vec<RawProbeResult>,
) -> Option<String> {
    let Some(clean) = bucket.map(str::trim).filter(|b| !b.is_empty()) else {
        out.push(s3_res(
            id,
            name,
            ProbeOutcomeKind::Fail,
            format!("Missing {flag} when --object-store-endpoint is set."),
            Some("Specify both --object-store-bucket and --backup-bucket."),
        ));
        return None;
    };
    match build_bucket_url(endpoint, clean, style) {
        Ok(url) => Some(url),
        Err(detail) => {
            let remedy = if detail.contains("--object-store-path-style") {
                "Pass --object-store-path-style for IP S3 endpoints."
            } else {
                "Supply a valid DNS-compliant S3 bucket name."
            };
            out.push(s3_res(
                id,
                name,
                ProbeOutcomeKind::Fail,
                format!("{flag}: {detail}"),
                Some(remedy),
            ));
            None
        }
    }
}

fn query_versioning(
    client: &Client,
    check_name: &'static str,
    bucket: &str,
    bucket_url: &str,
    creds: Option<&S3Credentials>,
    now_unix_s: i64,
) -> RawProbeResult {
    let url = format!("{bucket_url}?versioning");
    match execute_signed_get(client, &url, creds, now_unix_s) {
        Ok((401 | 403, _)) => s3_res(
            "PF-04",
            check_name,
            ProbeOutcomeKind::Fail,
            format!(
                "Bucket `{bucket}` versioning returned HTTP 401/403; credentials/IAM rejected."
            ),
            Some("Provide credentials with s3:GetBucketVersioning to verify bucket state."),
        ),
        Ok((status, _)) if status >= 400 => s3_res(
            "PF-04",
            check_name,
            ProbeOutcomeKind::Fail,
            format!("Bucket `{bucket}` versioning query returned HTTP {status}."),
            Some("Ensure bucket exists and object versioning is enabled."),
        ),
        Ok((_, body)) => match sanitize_s3_xml(&body) {
            Ok(clean)
                if clean.contains("<VersioningConfiguration")
                    && xml_contains_tag_value(&clean, "Status", "Enabled") =>
            {
                s3_res(
                    "PF-04",
                    check_name,
                    ProbeOutcomeKind::Pass,
                    format!("Bucket `{bucket}` has Versioning Enabled."),
                    None,
                )
            }
            Ok(_) => s3_res(
                "PF-04",
                check_name,
                ProbeOutcomeKind::Fail,
                format!("Bucket `{bucket}` is unversioned or Suspended."),
                Some("Enable bucket versioning before deploying HA/backup storage."),
            ),
            Err(msg) => s3_res(
                "PF-04",
                check_name,
                ProbeOutcomeKind::Fail,
                format!("Bucket `{bucket}` versioning response invalid: {msg}"),
                Some("Verify S3 gateway returns valid XML without DTD declarations."),
            ),
        },
        Err(err) => s3_res(
            "PF-04",
            check_name,
            ProbeOutcomeKind::Fail,
            format!("Bucket `{bucket}` versioning request failed: {err}"),
            Some("Check path-style vs virtual-host addressing and bucket connectivity."),
        ),
    }
}

fn query_lifecycle(
    client: &Client,
    bucket: &str,
    bucket_url: &str,
    creds: Option<&S3Credentials>,
    now_unix_s: i64,
) -> RawProbeResult {
    let url = format!("{bucket_url}?lifecycle");
    match execute_signed_get(client, &url, creds, now_unix_s) {
        Ok((401 | 403, _)) => s3_res(
            "PF-04",
            "object_store_bucket_lifecycle",
            ProbeOutcomeKind::Fail,
            format!("Bucket `{bucket}` lifecycle returned HTTP 401/403; IAM rejected."),
            Some("Grant s3:GetLifecycleConfiguration to verify retention expiry rules."),
        ),
        Ok((status, _)) if status != 200 => s3_res(
            "PF-04",
            "object_store_bucket_lifecycle",
            ProbeOutcomeKind::Fail,
            format!("Bucket `{bucket}` lifecycle query returned HTTP {status}."),
            Some("Configure Enabled Expiration or NoncurrentVersionExpiration rules."),
        ),
        Ok((_, body)) => match assess_lifecycle_xml(&body) {
            LifecycleAssessment::Valid => s3_res(
                "PF-04",
                "object_store_bucket_lifecycle",
                ProbeOutcomeKind::Pass,
                format!("Bucket `{bucket}` has an Enabled lifecycle expiration rule."),
                None,
            ),
            LifecycleAssessment::Invalid(reason) => s3_res(
                "PF-04",
                "object_store_bucket_lifecycle",
                ProbeOutcomeKind::Fail,
                format!("Bucket `{bucket}` lifecycle invalid: {reason}"),
                Some("Configure an Enabled noncurrent/expiration lifecycle rule."),
            ),
        },
        Err(err) => s3_res(
            "PF-04",
            "object_store_bucket_lifecycle",
            ProbeOutcomeKind::Fail,
            format!("Bucket `{bucket}` lifecycle request failed: {err}"),
            Some("Verify S3 lifecycle configuration endpoint reachability."),
        ),
    }
}

fn query_object_lock(
    client: &Client,
    bucket: &str,
    bucket_url: &str,
    creds: Option<&S3Credentials>,
    min_retention_days: u64,
    now_unix_s: i64,
) -> RawProbeResult {
    let url = format!("{bucket_url}?object-lock");
    match execute_signed_get(client, &url, creds, now_unix_s) {
        Ok((401 | 403, _)) => s3_res(
            "PF-05",
            "backup_bucket_object_lock",
            ProbeOutcomeKind::Fail,
            format!("Backup bucket `{bucket}` object-lock returned HTTP 401/403; IAM rejected."),
            Some("Grant s3:GetObjectLockConfiguration on backup bucket."),
        ),
        Ok((status, _)) if status != 200 => s3_res(
            "PF-05",
            "backup_bucket_object_lock",
            ProbeOutcomeKind::Fail,
            format!("Backup bucket `{bucket}` lacks S3 Object Lock (HTTP {status})."),
            Some("Recreate backup bucket with S3 Object Lock COMPLIANCE default retention."),
        ),
        Ok((_, body)) => match assess_object_lock_xml(&body, min_retention_days) {
            ObjectLockAssessment::Valid { mode, days } => s3_res(
                "PF-05",
                "backup_bucket_object_lock",
                ProbeOutcomeKind::Pass,
                format!("Backup bucket `{bucket}` enforces Object Lock {mode} mode ({days}d)."),
                None,
            ),
            ObjectLockAssessment::Invalid(reason) => s3_res(
                "PF-05",
                "backup_bucket_object_lock",
                ProbeOutcomeKind::Fail,
                format!("Backup bucket `{bucket}` Object Lock rejected: {reason}"),
                Some("Configure default retention mode = COMPLIANCE with >= pitr_window_days."),
            ),
        },
        Err(err) => s3_res(
            "PF-05",
            "backup_bucket_object_lock",
            ProbeOutcomeKind::Fail,
            format!("Backup bucket `{bucket}` object-lock request failed: {err}"),
            Some("Verify backup bucket connectivity and Object Lock API support."),
        ),
    }
}
