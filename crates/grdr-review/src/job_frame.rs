// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Per-job HMAC48 `<rec id="...">` JSON-escaped record framing and verification.

use serde::{Deserialize, Serialize};

use grdr_crypto::{constant_time_eq, domain_hmac_sha256, encode_lower_hex, sha256_digest};
use grdr_model::{CodedError, DataClass};
use grdr_schema::limits::load_embedded_limits;

use crate::reducer::{
    ReducedTranscript, ReviewRecordKind, SourceSegment, append_len_prefixed,
    salted_class_commitment,
};

pub const CODE_REV_FRAMING_INVALID: &str = "GRDR-REV-0004";

const FRAMING_MAC_DOMAIN: &str = "grdr.review.job-frame.v2";
const FRAMING_TAG_ID_DOMAIN: &str = "grdr.review.tag-id48.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FramedJobRecord {
    pub job_id: String,
    pub record_index: u64,
    pub record_id: String,
    pub keyed_rec_id: String,
    pub kind: ReviewRecordKind,
    pub data_class: DataClass,
    pub envelope_text: String,
    pub mac_hex: String,
    pub class_commitment_sha256: String,
}

/// Seals a source record in per-job HMAC48 `<rec id="..." kind="..." trust="..." class="...">`
/// JSON-escaped framing with salted class commitment inside the MAC (`ARCH-006`).
pub fn seal_job_record(
    job_mac_key: &[u8; 32],
    job_id: &str,
    record_index: u64,
    class_salt: &[u8; 32],
    segment: &SourceSegment,
) -> Result<FramedJobRecord, CodedError> {
    let class_commitment_sha256 = salted_class_commitment(
        class_salt,
        &segment.record_id,
        segment.data_class,
        &segment.text,
    );
    seal_job_record_with_commitment(
        job_mac_key,
        job_id,
        record_index,
        &class_commitment_sha256,
        segment,
    )
}

/// Seals a source or reduced record using a precomputed original-text salted class commitment.
pub fn seal_job_record_with_commitment(
    job_mac_key: &[u8; 32],
    job_id: &str,
    record_index: u64,
    class_commitment_sha256: &str,
    segment: &SourceSegment,
) -> Result<FramedJobRecord, CodedError> {
    validate_identifier(job_id, "job_id")?;
    validate_identifier(&segment.record_id, "record_id")?;
    if !is_lower_hex_len(class_commitment_sha256, 64) {
        return Err(framing_err("invalid class_commitment_sha256 format"));
    }
    let max_frame_bytes = load_embedded_limits()
        .map(|l| l.endpoint.ipc.max_frame_bytes)
        .unwrap_or(1_048_576);
    if segment.text.len() > max_frame_bytes {
        return Err(framing_err("source segment exceeds max_frame_bytes"));
    }

    let text_digest = sha256_digest(segment.text.as_bytes());
    let keyed_rec_id = compute_hmac48_tag_id(job_mac_key, record_index, &text_digest);
    let escaped_json_body = encode_escaped_json_body(&segment.text)?;
    let envelope_text = format!(
        "<rec id=\"{keyed_rec_id}\" kind=\"{}\" trust=\"{}\" class=\"{}\">{escaped_json_body}</rec>",
        segment.kind.as_str(),
        segment.kind.trust_label(),
        segment.data_class.as_str()
    );
    let mac_hex = compute_frame_mac_hex(
        job_mac_key,
        job_id,
        record_index,
        &segment.record_id,
        &keyed_rec_id,
        segment.kind,
        segment.data_class,
        class_commitment_sha256,
        &envelope_text,
    );

    Ok(FramedJobRecord {
        job_id: job_id.to_owned(),
        record_index,
        record_id: segment.record_id.clone(),
        keyed_rec_id,
        kind: segment.kind,
        data_class: segment.data_class,
        envelope_text,
        mac_hex,
        class_commitment_sha256: class_commitment_sha256.to_owned(),
    })
}

/// Seals all records of a `ReducedTranscript` binding each frame to its full-text commitment in `offset_map`.
pub fn seal_reduced_transcript(
    job_mac_key: &[u8; 32],
    job_id: &str,
    reduced: &ReducedTranscript,
) -> Result<Vec<FramedJobRecord>, CodedError> {
    let mut framed = Vec::with_capacity(reduced.reduced_records.len());
    for (idx, seg) in reduced.reduced_records.iter().enumerate() {
        let mut commit: Option<&str> = None;
        for entry in reduced
            .offset_map
            .iter()
            .filter(|e| e.record_id == seg.record_id)
        {
            match commit {
                None => commit = Some(entry.class_commitment_sha256.as_str()),
                Some(prev) if prev != entry.class_commitment_sha256 => {
                    return Err(framing_err(
                        "inconsistent class commitments in reduced offset_map",
                    ));
                }
                Some(_) => {}
            }
        }
        let commitment = commit
            .ok_or_else(|| framing_err("reduced record missing offset_map class commitment"))?;
        let record_index =
            u64::try_from(idx).map_err(|_| framing_err("reduced record index overflows u64"))?;
        framed.push(seal_job_record_with_commitment(
            job_mac_key,
            job_id,
            record_index,
            commitment,
            seg,
        )?);
    }
    Ok(framed)
}

/// Verifies per-job HMAC framing, `expected_job_id`, keyed tag ID, strict `<rec>` structure,
/// and JSON-escaped body, returning the decoded plain text on success.
pub fn verify_job_record(
    job_mac_key: &[u8; 32],
    expected_job_id: &str,
    framed: &FramedJobRecord,
) -> Result<String, CodedError> {
    validate_identifier(expected_job_id, "expected_job_id")?;
    validate_identifier(&framed.job_id, "job_id")?;
    validate_identifier(&framed.record_id, "record_id")?;
    if framed.job_id != expected_job_id {
        return Err(framing_err("job_id mismatch on framed record"));
    }
    if !is_lower_hex_len(&framed.keyed_rec_id, 12)
        || !is_lower_hex_len(&framed.mac_hex, 64)
        || !is_lower_hex_len(&framed.class_commitment_sha256, 64)
    {
        return Err(framing_err("invalid hex identifier or MAC format"));
    }

    let open_prefix = format!(
        "<rec id=\"{}\" kind=\"{}\" trust=\"{}\" class=\"{}\">",
        framed.keyed_rec_id,
        framed.kind.as_str(),
        framed.kind.trust_label(),
        framed.data_class.as_str()
    );
    let after_open = framed
        .envelope_text
        .strip_prefix(&open_prefix)
        .ok_or_else(|| framing_err("malformed or tampered opening <rec> tag"))?;
    let json_body = after_open
        .strip_suffix("</rec>")
        .ok_or_else(|| framing_err("missing closing </rec> tag"))?;
    if json_body.contains('<') || json_body.contains('>') || json_body.contains('&') {
        return Err(framing_err(
            "unescaped XML metacharacter inside framed body",
        ));
    }

    let expected_mac = compute_frame_mac_hex(
        job_mac_key,
        &framed.job_id,
        framed.record_index,
        &framed.record_id,
        &framed.keyed_rec_id,
        framed.kind,
        framed.data_class,
        &framed.class_commitment_sha256,
        &framed.envelope_text,
    );
    if !constant_time_eq(framed.mac_hex.as_bytes(), expected_mac.as_bytes()) {
        return Err(framing_err("HMAC verification failed on framed record"));
    }

    let plain_text: String = serde_json::from_str(json_body)
        .map_err(|_| framing_err("framed body is not a valid JSON string"))?;
    let text_digest = sha256_digest(plain_text.as_bytes());
    let expected_tag_id = compute_hmac48_tag_id(job_mac_key, framed.record_index, &text_digest);
    if !constant_time_eq(framed.keyed_rec_id.as_bytes(), expected_tag_id.as_bytes()) {
        return Err(framing_err("keyed record tag ID mismatch"));
    }
    Ok(plain_text)
}

fn compute_hmac48_tag_id(key: &[u8; 32], record_index: u64, digest: &[u8; 32]) -> String {
    let mut msg = Vec::with_capacity(48);
    msg.extend_from_slice(&record_index.to_le_bytes());
    append_len_prefixed(&mut msg, digest);
    let mac = domain_hmac_sha256(key, FRAMING_TAG_ID_DOMAIN, &msg);
    let prefix = mac.get(..6).unwrap_or(&mac);
    encode_lower_hex(prefix)
}

#[allow(clippy::too_many_arguments)]
fn compute_frame_mac_hex(
    job_mac_key: &[u8; 32],
    job_id: &str,
    record_index: u64,
    record_id: &str,
    keyed_rec_id: &str,
    kind: ReviewRecordKind,
    data_class: DataClass,
    class_commitment_sha256: &str,
    envelope_text: &str,
) -> String {
    let mut payload = Vec::new();
    append_len_prefixed(&mut payload, job_id.as_bytes());
    payload.extend_from_slice(&record_index.to_le_bytes());
    append_len_prefixed(&mut payload, record_id.as_bytes());
    append_len_prefixed(&mut payload, keyed_rec_id.as_bytes());
    append_len_prefixed(&mut payload, kind.as_str().as_bytes());
    append_len_prefixed(&mut payload, data_class.as_str().as_bytes());
    append_len_prefixed(&mut payload, class_commitment_sha256.as_bytes());
    append_len_prefixed(&mut payload, envelope_text.as_bytes());
    let mac = domain_hmac_sha256(job_mac_key, FRAMING_MAC_DOMAIN, &payload);
    encode_lower_hex(&mac)
}

fn encode_escaped_json_body(raw: &str) -> Result<String, CodedError> {
    let json = serde_json::to_string(raw)
        .map_err(|_| framing_err("failed to JSON-encode framed record text"))?;
    Ok(json
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026"))
}

fn validate_identifier(val: &str, label: &str) -> Result<(), CodedError> {
    if val.is_empty()
        || val.len() > 64
        || !val
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(framing_err(&format!("invalid `{label}` identifier format")));
    }
    Ok(())
}

fn is_lower_hex_len(raw: &str, expected_len: usize) -> bool {
    raw.len() == expected_len
        && raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn framing_err(msg: &str) -> CodedError {
    CodedError::new(
        CODE_REV_FRAMING_INVALID,
        msg.to_owned(),
        "Treat tampered job frame as could_not_look.",
    )
}
