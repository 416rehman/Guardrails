// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;
use zeroize::Zeroizing;

use grdr_crypto::{encode_lower_hex, hmac_sha256, sha256_hex};
use grdr_model::CodedError;
use grdr_ports::CODE_BLOB_IO;

use crate::s3_config::S3Credentials;

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const SECS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedS3Headers {
    pub(crate) amz_date: String,
    pub(crate) content_sha256: String,
    pub(crate) authorization: String,
}

pub(crate) struct SigV4SignInput<'a> {
    pub(crate) method: &'a str,
    pub(crate) canonical_uri: &'a str,
    pub(crate) query_params: &'a [(&'a str, &'a str)],
    pub(crate) host_header: &'a str,
    pub(crate) extra_headers: &'a [(&'a str, &'a str)],
    pub(crate) payload: &'a [u8],
    pub(crate) credentials: &'a S3Credentials,
    pub(crate) region: &'a str,
    pub(crate) now: Timestamp,
}

pub(crate) fn sign_s3_request(input: &SigV4SignInput<'_>) -> Result<SignedS3Headers, CodedError> {
    let method = input.method;
    let canonical_uri = input.canonical_uri;
    let query_params = input.query_params;
    let host_header = input.host_header;
    let extra_headers = input.extra_headers;
    let payload = input.payload;
    let credentials = input.credentials;
    let region = input.region;
    let now = input.now;
    let (amz_date, date_stamp) = format_amz_datetime(now);
    let content_sha256 = sha256_hex(payload);

    let canonical_qs = build_canonical_query_string(query_params);
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    grouped.insert("host".into(), vec![host_header.trim().to_string()]);
    grouped.insert("x-amz-content-sha256".into(), vec![content_sha256.clone()]);
    grouped.insert("x-amz-date".into(), vec![amz_date.clone()]);
    if let Some(ref token) = credentials.session_token {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            grouped.insert("x-amz-security-token".into(), vec![trimmed.to_string()]);
        }
    }
    for (k, v) in extra_headers {
        let lower = k.trim().to_ascii_lowercase();
        if is_reserved_sigv4_header(&lower) {
            return Err(CodedError::new(
                CODE_BLOB_IO,
                format!("Forbidden override of reserved S3 SigV4 header `{lower}`."),
                "Do not override host, authorization, or x-amz-* headers in extra_headers.",
            ));
        }
        grouped.entry(lower).or_default().push(collapse_ws(v));
    }

    let mut canonical_headers = String::new();
    let mut signed_header_names = Vec::with_capacity(grouped.len());
    for (k, vals) in &grouped {
        canonical_headers.push_str(k);
        canonical_headers.push(':');
        canonical_headers.push_str(&vals.join(","));
        canonical_headers.push('\n');
        signed_header_names.push(k.as_str());
    }
    let signed_headers = signed_header_names.join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_qs}\n{canonical_headers}\n{signed_headers}\n{content_sha256}"
    );
    let scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let canonical_hash = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");

    let signing_key = derive_signing_key(
        credentials.secret_access_key.as_bytes(),
        &date_stamp,
        region,
    );
    let signature_bytes = hmac_sha256(&*signing_key, string_to_sign.as_bytes());
    let signature_hex = encode_lower_hex(&signature_bytes);

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature_hex}",
        credentials.access_key_id
    );

    Ok(SignedS3Headers {
        amz_date,
        content_sha256,
        authorization,
    })
}

pub(crate) fn is_reserved_sigv4_header(lower_name: &str) -> bool {
    lower_name == "host" || lower_name == "authorization" || lower_name.starts_with("x-amz-")
}

pub(crate) fn aws_uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        let is_unreserved = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (!encode_slash && b == b'/');
        if is_unreserved {
            out.push(char::from(b));
        } else {
            out.push('%');
            let hi = usize::from((b >> 4) & 0x0f);
            let lo = usize::from(b & 0x0f);
            out.push(char::from(*HEX_UPPER.get(hi).unwrap_or(&b'0')));
            out.push(char::from(*HEX_UPPER.get(lo).unwrap_or(&b'0')));
        }
    }
    out
}

pub(crate) fn build_canonical_query_string(pairs: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (aws_uri_encode(k, true), aws_uri_encode(v, true)))
        .collect();
    encoded.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub(crate) fn format_amz_datetime(ts: Timestamp) -> (String, String) {
    let secs = ts.as_second();
    let days = secs.div_euclid(SECS_PER_DAY);
    let secs_of_day = secs.rem_euclid(SECS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    let date_stamp = format!("{year:04}{month:02}{day:02}");
    let amz_date = format!("{date_stamp}T{hour:02}{minute:02}{second:02}Z");
    (amz_date, date_stamp)
}

fn derive_signing_key(secret: &[u8], date_stamp: &str, region: &str) -> Zeroizing<[u8; 32]> {
    let mut aws4_secret = Zeroizing::new(Vec::with_capacity(4usize.saturating_add(secret.len())));
    aws4_secret.extend_from_slice(b"AWS4");
    aws4_secret.extend_from_slice(secret);

    let k_date = Zeroizing::new(hmac_sha256(&aws4_secret, date_stamp.as_bytes()));
    let k_region = Zeroizing::new(hmac_sha256(&*k_date, region.as_bytes()));
    let k_service = Zeroizing::new(hmac_sha256(&*k_region, b"s3"));
    Zeroizing::new(hmac_sha256(&*k_service, b"aws4_request"))
}

fn collapse_ws(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn civil_from_days(days_since_unix: i64) -> (i64, u32, u32) {
    let z = days_since_unix.saturating_add(719_468);
    let era = if z >= 0 { z } else { z.saturating_sub(146_096) } / 146_097;
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = (doe
        .saturating_sub(doe / 1_460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096))
        / 365;
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(
        365i64
            .saturating_mul(yoe)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = (5i64.saturating_mul(doy).saturating_add(2)) / 153;
    let d = doy
        .saturating_sub((153i64.saturating_mul(mp).saturating_add(2)) / 5)
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let final_y = if m <= 2 { y.saturating_add(1) } else { y };
    (
        final_y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigv4_comma_joins_duplicate_headers_and_forbids_reserved_overrides() {
        let creds = S3Credentials::new("AKIDTEST", "SECRETKEY").with_session_token(" tok \n");
        let err = sign_s3_request(&SigV4SignInput {
            method: "PUT",
            canonical_uri: "/b/k",
            query_params: &[],
            host_header: "s3.internal",
            extra_headers: &[("Authorization", "evil")],
            payload: b"hi",
            credentials: &creds,
            region: "us-east-1",
            now: Timestamp::UNIX_EPOCH,
        })
        .unwrap_err();
        assert_eq!(err.code, CODE_BLOB_IO);

        let creds_clean = S3Credentials::new("AKIDTEST", "SECRETKEY").with_session_token("  tok  ");
        let single = sign_s3_request(&SigV4SignInput {
            method: "GET",
            canonical_uri: "/b/k",
            query_params: &[],
            host_header: "s3.internal",
            extra_headers: &[("x-custom", "a,b")],
            payload: b"",
            credentials: &creds_clean,
            region: "us-east-1",
            now: Timestamp::UNIX_EPOCH,
        })
        .unwrap();
        let dup = sign_s3_request(&SigV4SignInput {
            method: "GET",
            canonical_uri: "/b/k",
            query_params: &[],
            host_header: "s3.internal",
            extra_headers: &[("x-custom", "a"), ("X-Custom", "b")],
            payload: b"",
            credentials: &creds_clean,
            region: "us-east-1",
            now: Timestamp::UNIX_EPOCH,
        })
        .unwrap();
        assert_eq!(single.authorization, dup.authorization);
    }
}
