// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use grdr_crypto::{AeadKey, open_token, seal_token};
use grdr_model::CodedError;
use grdr_ports::{BlobPort, ByteRange, LakeRecord, OrgId, RetentionClass, TenantCtx, TenantPath};

use crate::crypto::build_aad;
use crate::parquet_codec::{
    LAKE_COLUMNS, ParquetColumnExtent, decode_file_metadata, encode_column_data_page,
    encode_file_metadata, encode_standard_par1, parquet_err, reconstruct_records,
};

pub(crate) const PARQUET_MAGIC_PARE: &[u8; 4] = b"PARE";
const PARQUET_COL_DOMAIN: &str = "grdr.lake.parquet.col.v1";
const PARQUET_FOOTER_DOMAIN: &str = "grdr.lake.parquet.footer.v1";
const MAX_PARE_HEADER_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PARE_FOOTER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PARE_COL_CHUNK_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SealedParquetSliceHeader {
    pub(crate) version: u32,
    pub(crate) retention_class: RetentionClass,
    pub(crate) day: String,
    pub(crate) data_key_id: String,
    pub(crate) num_rows: u64,
    pub(crate) min_observed_ms: i64,
    pub(crate) max_observed_ms: i64,
    pub(crate) column_offsets: BTreeMap<String, (u64, u64)>,
    pub(crate) footer_offset: u64,
    pub(crate) footer_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedColumnChunk {
    column: String,
    token: String,
}

pub(crate) struct ParquetSliceDecryptCtx<'a> {
    pub(crate) org_id: &'a OrgId,
    pub(crate) class: RetentionClass,
    pub(crate) day: &'a str,
    pub(crate) rel_key: &'a str,
    pub(crate) day_dek: &'a AeadKey,
}

pub(crate) fn seal_modular_parquet(
    org_id: &OrgId,
    class: RetentionClass,
    day: &str,
    rel_key: &str,
    data_key_id: &str,
    day_dek: &AeadKey,
    records: &[LakeRecord],
) -> Result<Vec<u8>, CodedError> {
    let mut kv = BTreeMap::new();
    kv.insert("grdr.org_id".into(), org_id.as_str().to_string());
    kv.insert("grdr.retention_class".into(), class.as_str().into());
    kv.insert("grdr.day".into(), day.to_string());
    kv.insert("grdr.data_key_id".into(), data_key_id.to_string());

    let mut min_obs = i64::MAX;
    let mut max_obs = i64::MIN;
    for r in records {
        min_obs = min_obs.min(r.observed_time_ms);
        max_obs = max_obs.max(r.observed_time_ms);
    }
    if records.is_empty() {
        min_obs = 0;
        max_obs = 0;
    }

    let mut out = Vec::new();
    out.extend_from_slice(PARQUET_MAGIC_PARE);
    let mut extents = Vec::with_capacity(LAKE_COLUMNS.len());
    let mut column_offsets = BTreeMap::new();

    for col in LAKE_COLUMNS {
        let page = encode_column_data_page(col, records)?;
        let aad = build_aad(&[org_id.as_str(), class.as_str(), day, rel_key, col.name]);
        let token = seal_token(day_dek, PARQUET_COL_DOMAIN, &aad, &page.bytes)
            .map_err(|e| parquet_err(&format!("column encrypt failed: {e}")))?;
        let chunk_bytes = serde_json::to_vec(&SealedColumnChunk {
            column: col.name.to_string(),
            token,
        })
        .map_err(|e| parquet_err(&e.to_string()))?;
        let offset = u64::try_from(out.len()).unwrap_or(0);
        let len = u64::try_from(chunk_bytes.len()).unwrap_or(0);
        out.extend_from_slice(&chunk_bytes);
        column_offsets.insert(col.name.to_string(), (offset, len));
        extents.push(ParquetColumnExtent {
            name: col.name.to_string(),
            file_offset: offset,
            compressed_size: len,
            min_i64: page.min_i64,
            max_i64: page.max_i64,
        });
    }

    let footer_meta = encode_file_metadata(records.len(), &extents, &kv);
    let footer_aad = build_aad(&[org_id.as_str(), class.as_str(), day, rel_key, "footer"]);
    let sealed_footer = seal_token(day_dek, PARQUET_FOOTER_DOMAIN, &footer_aad, &footer_meta)
        .map_err(|e| parquet_err(&format!("footer encrypt failed: {e}")))?;

    let footer_offset = u64::try_from(out.len()).unwrap_or(0);
    let footer_len = u64::try_from(sealed_footer.len()).unwrap_or(0);
    out.extend_from_slice(sealed_footer.as_bytes());

    let hdr = SealedParquetSliceHeader {
        version: 1,
        retention_class: class,
        day: day.to_string(),
        data_key_id: data_key_id.to_string(),
        num_rows: u64::try_from(records.len()).unwrap_or(0),
        min_observed_ms: min_obs,
        max_observed_ms: max_obs,
        column_offsets,
        footer_offset,
        footer_len,
    };
    let hdr_bytes = serde_json::to_vec(&hdr).map_err(|e| parquet_err(&e.to_string()))?;
    let hdr_len = u32::try_from(hdr_bytes.len())
        .map_err(|_| parquet_err("header envelope length exceeds u32"))?;
    out.extend_from_slice(&hdr_bytes);
    out.extend_from_slice(&hdr_len.to_le_bytes());
    out.extend_from_slice(PARQUET_MAGIC_PARE);
    Ok(out)
}

pub(crate) fn parse_pare_header(bytes: &[u8]) -> Result<SealedParquetSliceHeader, CodedError> {
    if bytes.len() < 12 {
        return Err(parquet_err("PARE file shorter than 12 bytes"));
    }
    if bytes.get(..4) != Some(PARQUET_MAGIC_PARE)
        || bytes.get(bytes.len().saturating_sub(4)..) != Some(PARQUET_MAGIC_PARE)
    {
        return Err(parquet_err("invalid PARE modular encryption magic"));
    }
    let len_end = bytes.len().saturating_sub(4);
    let len_start = len_end.saturating_sub(4);
    let len_arr: [u8; 4] = bytes
        .get(len_start..len_end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| parquet_err("missing PARE header length"))?;
    let hdr_len = usize::try_from(u32::from_le_bytes(len_arr))
        .map_err(|_| parquet_err("PARE header length overflow"))?;
    let hdr_start = len_start
        .checked_sub(hdr_len)
        .ok_or_else(|| parquet_err("PARE header length out of bounds"))?;
    let hdr_slice = bytes
        .get(hdr_start..len_start)
        .ok_or_else(|| parquet_err("corrupt PARE header slice"))?;
    serde_json::from_slice(hdr_slice).map_err(|e| parquet_err(&e.to_string()))
}

pub(crate) fn open_modular_parquet(
    org_id: &OrgId,
    class: RetentionClass,
    day: &str,
    rel_key: &str,
    day_dek: &AeadKey,
    bytes: &[u8],
    projected_cols: Option<&[&str]>,
) -> Result<Vec<LakeRecord>, CodedError> {
    let hdr = parse_pare_header(bytes)?;
    let f_start =
        usize::try_from(hdr.footer_offset).map_err(|_| parquet_err("footer offset overflow"))?;
    let f_len = usize::try_from(hdr.footer_len).map_err(|_| parquet_err("footer len overflow"))?;
    let f_end = f_start
        .checked_add(f_len)
        .ok_or_else(|| parquet_err("footer slice offset overflow"))?;
    let sealed_footer = std::str::from_utf8(
        bytes
            .get(f_start..f_end)
            .ok_or_else(|| parquet_err("footer slice out of bounds"))?,
    )
    .map_err(|_| parquet_err("non-UTF-8 sealed footer"))?;
    let footer_aad = build_aad(&[org_id.as_str(), class.as_str(), day, rel_key, "footer"]);
    let footer_plain = open_token(day_dek, PARQUET_FOOTER_DOMAIN, &footer_aad, sealed_footer)
        .map_err(|_| parquet_err("footer authentication failed"))?;
    let meta = decode_file_metadata(&footer_plain)?;
    if meta
        .key_value_metadata
        .get("grdr.org_id")
        .map(String::as_str)
        != Some(org_id.as_str())
    {
        return Err(parquet_err("parquet footer org_id metadata mismatch"));
    }
    let num_rows = meta.num_rows;

    let want_col = |name: &str| projected_cols.is_none_or(|list| list.contains(&name));
    let mut col_pages: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for extent in &meta.columns {
        if !want_col(&extent.name) {
            continue;
        }
        let start = usize::try_from(extent.file_offset)
            .map_err(|_| parquet_err("column offset overflow"))?;
        let col_len = usize::try_from(extent.compressed_size)
            .map_err(|_| parquet_err("column size overflow"))?;
        let end = start
            .checked_add(col_len)
            .ok_or_else(|| parquet_err("column slice offset overflow"))?;
        let chunk_slice = bytes
            .get(start..end)
            .ok_or_else(|| parquet_err("column chunk slice out of bounds"))?;
        let page_plain = decrypt_column_chunk(
            org_id,
            class,
            day,
            rel_key,
            day_dek,
            &extent.name,
            chunk_slice,
        )?;
        col_pages.insert(extent.name.clone(), page_plain);
    }

    reconstruct_records(num_rows, &col_pages)
}

pub(crate) fn read_modular_parquet_projected<B: BlobPort>(
    blobs: &B,
    ctx: &TenantCtx,
    path: &TenantPath,
    size_hint: u64,
    decrypt: &ParquetSliceDecryptCtx<'_>,
    projected_cols: Option<&[&str]>,
) -> Result<Option<(Vec<LakeRecord>, u64)>, CodedError> {
    let org_id = decrypt.org_id;
    let class = decrypt.class;
    let day = decrypt.day;
    let rel_key = decrypt.rel_key;
    let day_dek = decrypt.day_dek;
    if projected_cols.is_none() || size_hint < 128 {
        let Some(blob) = blobs.get(ctx, path)? else {
            return Ok(None);
        };
        let bytes_read = u64::try_from(blob.bytes.len()).unwrap_or(0);
        let recs = open_modular_parquet(
            org_id,
            class,
            day,
            rel_key,
            day_dek,
            &blob.bytes,
            projected_cols,
        )?;
        return Ok(Some((recs, bytes_read)));
    }

    let tail_len = size_hint.min(1_024);
    let tail_offset = size_hint.saturating_sub(tail_len);
    let Some(tail_bytes) = blobs.get_range(
        ctx,
        path,
        ByteRange {
            offset: tail_offset,
            length: tail_len,
        },
    )?
    else {
        return Ok(None);
    };
    let mut total_read = u64::try_from(tail_bytes.len()).unwrap_or(0);
    if tail_bytes.get(tail_bytes.len().saturating_sub(4)..) != Some(PARQUET_MAGIC_PARE) {
        let Some(blob) = blobs.get(ctx, path)? else {
            return Ok(None);
        };
        let bytes_read = u64::try_from(blob.bytes.len()).unwrap_or(0);
        let recs = open_modular_parquet(
            org_id,
            class,
            day,
            rel_key,
            day_dek,
            &blob.bytes,
            projected_cols,
        )?;
        return Ok(Some((recs, bytes_read)));
    }

    let len_end = tail_bytes.len().saturating_sub(4);
    let len_start = len_end.saturating_sub(4);
    let hdr_len_arr: [u8; 4] = tail_bytes
        .get(len_start..len_end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| parquet_err("missing PARE header length in tail"))?;
    let hdr_len = u64::from(u32::from_le_bytes(hdr_len_arr));
    if hdr_len == 0 || hdr_len > MAX_PARE_HEADER_BYTES {
        return Err(parquet_err("PARE header length out of bounds"));
    }
    let hdr_abs_start = size_hint
        .saturating_sub(8)
        .checked_sub(hdr_len)
        .ok_or_else(|| parquet_err("PARE header offset invalid"))?;

    let hdr_bytes = if hdr_abs_start >= tail_offset {
        let rel_s = usize::try_from(hdr_abs_start.saturating_sub(tail_offset)).unwrap_or(0);
        let rel_e = len_start;
        tail_bytes
            .get(rel_s..rel_e)
            .ok_or_else(|| parquet_err("PARE header tail slice invalid"))?
            .to_vec()
    } else {
        let Some(fetched) = blobs.get_range(
            ctx,
            path,
            ByteRange {
                offset: hdr_abs_start,
                length: hdr_len,
            },
        )?
        else {
            return Ok(None);
        };
        total_read = total_read.saturating_add(u64::try_from(fetched.len()).unwrap_or(0));
        fetched
    };
    let hdr: SealedParquetSliceHeader =
        serde_json::from_slice(&hdr_bytes).map_err(|e| parquet_err(&e.to_string()))?;

    if hdr.footer_len == 0 || hdr.footer_len > MAX_PARE_FOOTER_BYTES {
        return Err(parquet_err("PARE footer length out of bounds"));
    }
    let footer_end = hdr
        .footer_offset
        .checked_add(hdr.footer_len)
        .ok_or_else(|| parquet_err("PARE footer range overflow"))?;
    if footer_end > size_hint {
        return Err(parquet_err("PARE footer exceeds segment size"));
    }
    let footer_bytes = if hdr.footer_offset >= tail_offset && footer_end <= size_hint {
        let rel_s = usize::try_from(hdr.footer_offset.saturating_sub(tail_offset)).unwrap_or(0);
        let rel_e = usize::try_from(footer_end.saturating_sub(tail_offset)).unwrap_or(0);
        tail_bytes
            .get(rel_s..rel_e)
            .ok_or_else(|| parquet_err("PARE footer tail slice invalid"))?
            .to_vec()
    } else {
        let Some(fetched) = blobs.get_range(
            ctx,
            path,
            ByteRange {
                offset: hdr.footer_offset,
                length: hdr.footer_len,
            },
        )?
        else {
            return Ok(None);
        };
        total_read = total_read.saturating_add(u64::try_from(fetched.len()).unwrap_or(0));
        fetched
    };
    let sealed_footer =
        std::str::from_utf8(&footer_bytes).map_err(|_| parquet_err("non-UTF-8 footer range"))?;
    let footer_aad = build_aad(&[org_id.as_str(), class.as_str(), day, rel_key, "footer"]);
    let footer_plain = open_token(day_dek, PARQUET_FOOTER_DOMAIN, &footer_aad, sealed_footer)
        .map_err(|_| parquet_err("footer authentication failed"))?;
    let meta = decode_file_metadata(&footer_plain)?;
    if meta
        .key_value_metadata
        .get("grdr.org_id")
        .map(String::as_str)
        != Some(org_id.as_str())
    {
        return Err(parquet_err("parquet footer org_id metadata mismatch"));
    }
    let want_col = |name: &str| projected_cols.is_none_or(|list| list.contains(&name));

    let mut col_pages: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for extent in &meta.columns {
        if !want_col(&extent.name) {
            continue;
        }
        if extent.compressed_size == 0 || extent.compressed_size > MAX_PARE_COL_CHUNK_BYTES {
            return Err(parquet_err("PARE column chunk length out of bounds"));
        }
        let col_end = extent
            .file_offset
            .checked_add(extent.compressed_size)
            .ok_or_else(|| parquet_err("PARE column range overflow"))?;
        if col_end > size_hint {
            return Err(parquet_err("PARE column chunk exceeds segment size"));
        }
        let Some(chunk_bytes) = blobs.get_range(
            ctx,
            path,
            ByteRange {
                offset: extent.file_offset,
                length: extent.compressed_size,
            },
        )?
        else {
            return Ok(None);
        };
        total_read = total_read.saturating_add(u64::try_from(chunk_bytes.len()).unwrap_or(0));
        let page_plain = decrypt_column_chunk(
            org_id,
            class,
            day,
            rel_key,
            day_dek,
            &extent.name,
            &chunk_bytes,
        )?;
        col_pages.insert(extent.name.clone(), page_plain);
    }

    let records = reconstruct_records(meta.num_rows, &col_pages)?;
    Ok(Some((records, total_read)))
}

pub(crate) fn export_decrypted_par1(
    org_id: &OrgId,
    class: RetentionClass,
    day: &str,
    rel_key: &str,
    day_dek: &AeadKey,
    pare_bytes: &[u8],
) -> Result<Vec<u8>, CodedError> {
    let records = open_modular_parquet(org_id, class, day, rel_key, day_dek, pare_bytes, None)?;
    let mut kv = BTreeMap::new();
    kv.insert("grdr.org_id".into(), org_id.as_str().to_string());
    kv.insert("grdr.retention_class".into(), class.as_str().into());
    kv.insert("grdr.day".into(), day.to_string());
    encode_standard_par1(&records, &kv)
}

fn decrypt_column_chunk(
    org_id: &OrgId,
    class: RetentionClass,
    day: &str,
    rel_key: &str,
    day_dek: &AeadKey,
    col_name: &str,
    chunk_slice: &[u8],
) -> Result<Vec<u8>, CodedError> {
    let chunk: SealedColumnChunk = serde_json::from_slice(chunk_slice)
        .map_err(|e| parquet_err(&format!("corrupt column chunk: {e}")))?;
    let col_aad = build_aad(&[org_id.as_str(), class.as_str(), day, rel_key, col_name]);
    open_token(day_dek, PARQUET_COL_DOMAIN, &col_aad, &chunk.token)
        .map_err(|_| parquet_err(&format!("column `{col_name}` authentication failed")))
}
