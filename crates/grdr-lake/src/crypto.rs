// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use grdr_crypto::{AeadKey, SigningKeypair, open_token, seal_token};
use grdr_model::CodedError;
use grdr_ports::{CODE_LAKE_IO, OrgId, RetentionClass};

use crate::schema::lake_sql_err;

const SESSION_KEY_DOMAIN: &str = "lake.session_key.v1";
const CONTENT_SEAL_DOMAIN: &str = "lake.content.v1";

#[derive(Debug, Clone)]
pub(crate) enum SessionKeyLookup {
    Active(AeadKey),
    Destroyed,
    Missing,
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
    let seed_b64 = kp.seed_b64();
    let aad = format!("{}|{root_session_id}", org_id.as_str());
    let wrapped = seal_token(
        org_kek,
        SESSION_KEY_DOMAIN,
        aad.as_bytes(),
        seed_b64.as_bytes(),
    )
    .map_err(|e| {
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
        let aad = format!("{}|{event_id}|{field_path}", org_id.as_str());
        let sealed = seal_token(
            session_key,
            CONTENT_SEAL_DOMAIN,
            aad.as_bytes(),
            val.as_bytes(),
        )
        .map_err(|e| {
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
        let aad = format!("{}|{event_id}|{field_path}", org_id.as_str());
        let bytes =
            open_token(session_key, CONTENT_SEAL_DOMAIN, aad.as_bytes(), token).map_err(|e| {
                CodedError::new(
                    CODE_LAKE_IO,
                    format!("Failed unsealing content field `{field_path}`: {e}"),
                    "Session key may have rotated or token was tampered.",
                )
            })?;
        let text = String::from_utf8(bytes).map_err(|e| {
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

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub(crate) fn day_from_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1_000);
    let ts = Timestamp::from_second(secs).unwrap_or(Timestamp::UNIX_EPOCH);
    ts.to_string().get(..10).unwrap_or("1970-01-01").to_string()
}

fn unwrap_session_key(
    org_kek: &AeadKey,
    org_id: &OrgId,
    root_session_id: &str,
    wrapped: &str,
) -> Result<AeadKey, CodedError> {
    let aad = format!("{}|{root_session_id}", org_id.as_str());
    let seed_bytes =
        open_token(org_kek, SESSION_KEY_DOMAIN, aad.as_bytes(), wrapped).map_err(|e| {
            CodedError::new(
                CODE_LAKE_IO,
                format!("Failed unwrapping session content key: {e}"),
                "Check organisation KEK consistency.",
            )
        })?;
    let seed_str = String::from_utf8(seed_bytes).map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Invalid UTF-8 in wrapped session key: {e}"),
            "Inspect lake_content_keys table.",
        )
    })?;
    let kp = SigningKeypair::from_seed_b64(&seed_str).map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Invalid unwrapped session key seed: {e}"),
            "Inspect lake_content_keys table.",
        )
    })?;
    Ok(kp.derive_aead_key(CONTENT_SEAL_DOMAIN))
}
