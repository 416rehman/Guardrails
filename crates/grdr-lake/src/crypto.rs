// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use grdr_crypto::{AeadKey, SigningKeypair, open_token, seal_token};
use grdr_model::CodedError;
use grdr_ports::{CODE_LAKE_IO, LakeRecord, OrgId, RetentionClass};

use crate::schema::lake_sql_err;

const SESSION_KEY_DOMAIN: &str = "lake.session_key.v1";
const CONTENT_SEAL_DOMAIN: &str = "lake.content.v1";
const ARCHIVE_SEAL_DOMAIN: &str = "lake.archive.v1";
const MIN_LAKE_YEAR: i16 = 1970;
const MAX_LAKE_YEAR: i16 = 9999;

#[derive(Debug, Clone)]
pub(crate) enum SessionKeyLookup {
    Active(AeadKey),
    Destroyed,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SealedBlobEnvelope {
    pub(crate) schema_rev: u32,
    pub(crate) data_key_id: String,
    pub(crate) ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ArchivePayload {
    pub(crate) lane: String,
    pub(crate) day: String,
    pub(crate) records: Vec<LakeRecord>,
    pub(crate) raw_archive_b64: Option<String>,
    pub(crate) reduced_sessions: Vec<String>,
}

pub(crate) fn ensure_session_key(
    conn: &Connection,
    org_kek: &AeadKey,
    org_id: &OrgId,
    root_session_id: &str,
    now_ms: i64,
) -> Result<SessionKeyLookup, CodedError> {
    let existing: Option<(String, String)> = conn
        .query_row(
            "SELECT state, wrapped_key FROM lake_content_keys
             WHERE organisation_id = ?1 AND root_session_id = ?2",
            rusqlite::params![org_id.as_str(), root_session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(lake_sql_err)?;

    if let Some((state, wrapped)) = existing {
        if state == "destroyed" {
            return Ok(SessionKeyLookup::Destroyed);
        }
        let key = unwrap_session_key(org_kek, org_id, root_session_id, &wrapped)?;
        return Ok(SessionKeyLookup::Active(key));
    }

    let kp = SigningKeypair::generate().map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Failed generating session content key: {e}"),
            "Verify OS entropy availability.",
        )
    })?;
    let seed_b64 = Zeroizing::new(kp.seed_b64());
    let aad = build_aad(&[org_id.as_str(), root_session_id]);
    let wrapped =
        seal_token(org_kek, SESSION_KEY_DOMAIN, &aad, seed_b64.as_bytes()).map_err(|e| {
            CodedError::new(
                CODE_LAKE_IO,
                format!("Failed wrapping session content key: {e}"),
                "Check organisation KEK configuration.",
            )
        })?;
    let key_id = format!("sck-{}", kp.key_id());
    let destroy_after_ms = now_ms.saturating_add(RetentionClass::Content.retention_ms());
    conn.execute(
        "INSERT INTO lake_content_keys (
            organisation_id, root_session_id, key_id, wrapped_key,
            created_at_ms, destroy_after_ms, state, destroyed_at_ms, destruction_record_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', NULL, NULL)",
        rusqlite::params![
            org_id.as_str(),
            root_session_id,
            key_id,
            wrapped,
            now_ms,
            destroy_after_ms
        ],
    )
    .map_err(lake_sql_err)?;

    Ok(SessionKeyLookup::Active(
        kp.derive_aead_key(CONTENT_SEAL_DOMAIN),
    ))
}

pub(crate) fn load_session_key(
    conn: &Connection,
    org_kek: &AeadKey,
    org_id: &OrgId,
    root_session_id: &str,
) -> Result<SessionKeyLookup, CodedError> {
    let existing: Option<(String, String)> = conn
        .query_row(
            "SELECT state, wrapped_key FROM lake_content_keys
             WHERE organisation_id = ?1 AND root_session_id = ?2",
            rusqlite::params![org_id.as_str(), root_session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(lake_sql_err)?;
    match existing {
        None => Ok(SessionKeyLookup::Missing),
        Some((state, _)) if state == "destroyed" => Ok(SessionKeyLookup::Destroyed),
        Some((_, wrapped)) => {
            let key = unwrap_session_key(org_kek, org_id, root_session_id, &wrapped)?;
            Ok(SessionKeyLookup::Active(key))
        }
    }
}

pub(crate) fn seal_content_fields(
    session_key: &AeadKey,
    org_id: &OrgId,
    event_id: &str,
    plaintext: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, CodedError> {
    let mut out = BTreeMap::new();
    for (field_path, val) in plaintext {
        let aad = build_aad(&[org_id.as_str(), event_id, field_path]);
        let sealed =
            seal_token(session_key, CONTENT_SEAL_DOMAIN, &aad, val.as_bytes()).map_err(|e| {
                CodedError::new(
                    CODE_LAKE_IO,
                    format!("Failed sealing content field `{field_path}`: {e}"),
                    "Check session AEAD key state.",
                )
            })?;
        out.insert(field_path.clone(), sealed);
    }
    Ok(out)
}

pub(crate) fn open_content_fields(
    session_key: &AeadKey,
    org_id: &OrgId,
    event_id: &str,
    sealed: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, CodedError> {
    let mut out = BTreeMap::new();
    for (field_path, token) in sealed {
        let aad = build_aad(&[org_id.as_str(), event_id, field_path]);
        let bytes = Zeroizing::new(
            open_token(session_key, CONTENT_SEAL_DOMAIN, &aad, token).map_err(|e| {
                CodedError::new(
                    CODE_LAKE_IO,
                    format!("Failed unsealing content field `{field_path}`: {e}"),
                    "Session key may have rotated or token was tampered.",
                )
            })?,
        );
        let text = String::from_utf8(bytes.to_vec()).map_err(|e| {
            CodedError::new(
                CODE_LAKE_IO,
                format!("Unsealed content field `{field_path}` is not valid UTF-8: {e}"),
                "Inspect sealed content integrity.",
            )
        })?;
        out.insert(field_path.clone(), text);
    }
    Ok(out)
}

pub(crate) fn derive_segment_dek(
    org_kek: &AeadKey,
    org_id: &OrgId,
    class_label: &str,
    day: &str,
) -> (String, AeadKey) {
    let key_id = format!("dek-{}-{class_label}-{day}", org_id.as_str());
    let domain = format!(
        "lake.dek.v1.{}:{}.{}:{}.{}:{}",
        org_id.as_str().len(),
        org_id.as_str(),
        class_label.len(),
        class_label,
        day.len(),
        day
    );
    (key_id, org_kek.derive_subkey(&domain))
}

pub(crate) fn seal_envelope(
    dek: &AeadKey,
    data_key_id: &str,
    domain: &str,
    aad_parts: &[&str],
    plaintext: &[u8],
) -> Result<Vec<u8>, CodedError> {
    let aad = build_aad(aad_parts);
    let ciphertext = seal_token(dek, domain, &aad, plaintext).map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Failed encrypting lake object: {e}"),
            "Check organisation KEK configuration.",
        )
    })?;
    let envelope = SealedBlobEnvelope {
        schema_rev: 1,
        data_key_id: data_key_id.to_string(),
        ciphertext,
    };
    serde_json::to_vec(&envelope).map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Failed serializing lake envelope: {e}"),
            "Inspect lake object serializer.",
        )
    })
}

pub(crate) fn open_envelope(
    dek: &AeadKey,
    domain: &str,
    aad_parts: &[&str],
    envelope_bytes: &[u8],
) -> Result<Vec<u8>, CodedError> {
    let envelope: SealedBlobEnvelope = serde_json::from_slice(envelope_bytes).map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Corrupt sealed lake envelope: {e}"),
            "Verify lake segment object integrity.",
        )
    })?;
    let aad = build_aad(aad_parts);
    open_token(dek, domain, &aad, &envelope.ciphertext).map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Failed decrypting lake object: {e}"),
            "Verify organisation KEK and object integrity.",
        )
    })
}

pub(crate) fn archive_seal_domain() -> &'static str {
    ARCHIVE_SEAL_DOMAIN
}

pub(crate) use grdr_crypto::sha256_hex;

pub(crate) fn day_from_ms(ms: i64) -> Result<String, CodedError> {
    if ms < 0 {
        return Err(CodedError::new(
            CODE_LAKE_IO,
            format!("Lake timestamp `{ms}` cannot be negative."),
            "Supply non-negative UTC millisecond timestamps.",
        ));
    }
    let secs = ms.div_euclid(1_000);
    let ts = Timestamp::from_second(secs).map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Invalid lake timestamp `{ms}`: {e}"),
            "Supply UTC millisecond timestamps within valid date bounds.",
        )
    })?;
    let iso = ts.to_string();
    let Some(day) = iso.get(..10) else {
        return Err(CodedError::new(
            CODE_LAKE_IO,
            format!("Unexpected timestamp format `{iso}`."),
            "Supply UTC millisecond timestamps within 1970..=9999.",
        ));
    };
    let year: i16 = day.get(..4).and_then(|y| y.parse().ok()).ok_or_else(|| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Lake timestamp year `{day}` out of valid range."),
            "Supply UTC millisecond timestamps within 1970..=9999.",
        )
    })?;
    if !(MIN_LAKE_YEAR..=MAX_LAKE_YEAR).contains(&year) {
        return Err(CodedError::new(
            CODE_LAKE_IO,
            format!("Lake timestamp year `{year}` out of valid range."),
            "Supply UTC millisecond timestamps within 1970..=9999.",
        ));
    }
    Ok(day.to_string())
}

pub(crate) fn build_aad(parts: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        let len_bytes = u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes();
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(part.as_bytes());
    }
    out
}

fn unwrap_session_key(
    org_kek: &AeadKey,
    org_id: &OrgId,
    root_session_id: &str,
    wrapped: &str,
) -> Result<AeadKey, CodedError> {
    let aad = build_aad(&[org_id.as_str(), root_session_id]);
    let seed_bytes = Zeroizing::new(
        open_token(org_kek, SESSION_KEY_DOMAIN, &aad, wrapped).map_err(|e| {
            CodedError::new(
                CODE_LAKE_IO,
                format!("Failed unwrapping session content key: {e}"),
                "Check organisation KEK consistency.",
            )
        })?,
    );
    let seed_str = Zeroizing::new(String::from_utf8(seed_bytes.to_vec()).map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Invalid UTF-8 in wrapped session key: {e}"),
            "Inspect lake_content_keys table.",
        )
    })?);
    let kp = SigningKeypair::from_seed_b64(&seed_str).map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Invalid unwrapped session key seed: {e}"),
            "Inspect lake_content_keys table.",
        )
    })?;
    Ok(kp.derive_aead_key(CONTENT_SEAL_DOMAIN))
}
