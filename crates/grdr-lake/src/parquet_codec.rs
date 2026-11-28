// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::CodedError;
use grdr_ports::{LakeObservable, LakeRecord, RetentionClass};

pub(crate) use crate::parquet_schema::{
    LAKE_COLUMNS, LakeColKind, LakeColumnSpec, MAX_PARQUET_ROWS, ParquetColumnExtent,
    decode_file_metadata, encode_file_metadata, parquet_err,
};
use crate::thrift_compact::{CT_I32, CT_STRUCT, CompactReader, CompactWriter};

pub(crate) const PARQUET_MAGIC_PAR1: &[u8; 4] = b"PAR1";
const PARQUET_PAGE_TYPE_DATA: i32 = 0;
const PARQUET_ENCODING_PLAIN: i32 = 0;
const PARQUET_ENCODING_RLE: i32 = 3;

#[derive(Debug, Clone)]
pub(crate) struct EncodedColumnPage {
    pub(crate) bytes: Vec<u8>,
    pub(crate) min_i64: Option<i64>,
    pub(crate) max_i64: Option<i64>,
}

#[derive(Debug, Clone)]
enum DecodedColumnValues {
    Str(Vec<String>),
    I64(Vec<i64>),
    OptStr(Vec<Option<String>>),
}

pub(crate) fn encode_column_data_page(
    col: &LakeColumnSpec,
    records: &[LakeRecord],
) -> Result<EncodedColumnPage, CodedError> {
    let mut payload = Vec::new();
    let mut min_i64: Option<i64> = None;
    let mut max_i64: Option<i64> = None;

    match col.kind {
        LakeColKind::Str => {
            for rec in records {
                let s = extract_str_col(col.name, rec)?;
                write_plain_byte_array(&mut payload, s.as_bytes())?;
            }
        }
        LakeColKind::I64 => {
            for rec in records {
                let v = extract_i64_col(col.name, rec);
                min_i64 = Some(min_i64.map_or(v, |cur| cur.min(v)));
                max_i64 = Some(max_i64.map_or(v, |cur| cur.max(v)));
                payload.extend_from_slice(&v.to_le_bytes());
            }
        }
        LakeColKind::OptStr => {
            let mut def_bits = Vec::new();
            let mut defined_vals = Vec::new();
            let mut cur_byte = 0u8;
            let mut bit_idx = 0u8;
            for rec in records {
                if let Some(val) = rec.tool_call_id.as_deref() {
                    cur_byte |= 1u8 << bit_idx;
                    defined_vals.push(val);
                }
                bit_idx = bit_idx.saturating_add(1);
                if bit_idx == 8 {
                    def_bits.push(cur_byte);
                    cur_byte = 0;
                    bit_idx = 0;
                }
            }
            if bit_idx > 0 {
                def_bits.push(cur_byte);
            }
            let rle_len = u32::try_from(def_bits.len())
                .map_err(|_| parquet_err("definition levels length exceeds u32"))?;
            payload.extend_from_slice(&rle_len.to_le_bytes());
            payload.extend_from_slice(&def_bits);
            for val in defined_vals {
                write_plain_byte_array(&mut payload, val.as_bytes())?;
            }
        }
    }

    let hdr = encode_data_page_header(records.len(), payload.len())?;
    let mut out = Vec::with_capacity(hdr.len().saturating_add(payload.len()));
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&payload);
    Ok(EncodedColumnPage {
        bytes: out,
        min_i64,
        max_i64,
    })
}

pub(crate) fn encode_standard_par1(
    records: &[LakeRecord],
    kv: &BTreeMap<String, String>,
) -> Result<Vec<u8>, CodedError> {
    let mut out = Vec::new();
    out.extend_from_slice(PARQUET_MAGIC_PAR1);
    let mut extents = Vec::with_capacity(LAKE_COLUMNS.len());
    for col in LAKE_COLUMNS {
        let offset = u64::try_from(out.len()).unwrap_or(0);
        let page = encode_column_data_page(col, records)?;
        let size = u64::try_from(page.bytes.len()).unwrap_or(0);
        out.extend_from_slice(&page.bytes);
        extents.push(ParquetColumnExtent {
            name: col.name.to_string(),
            file_offset: offset,
            compressed_size: size,
            min_i64: page.min_i64,
            max_i64: page.max_i64,
        });
    }
    let meta = encode_file_metadata(records.len(), &extents, kv);
    let meta_len =
        u32::try_from(meta.len()).map_err(|_| parquet_err("PAR1 metadata exceeds u32 length"))?;
    out.extend_from_slice(&meta);
    out.extend_from_slice(&meta_len.to_le_bytes());
    out.extend_from_slice(PARQUET_MAGIC_PAR1);
    Ok(out)
}

#[cfg(test)]
pub(crate) fn decode_par1_footer(
    bytes: &[u8],
) -> Result<crate::parquet_schema::DecodedParquetMeta, CodedError> {
    if bytes.len() < 12
        || bytes.get(..4) != Some(PARQUET_MAGIC_PAR1)
        || bytes.get(bytes.len().saturating_sub(4)..) != Some(PARQUET_MAGIC_PAR1)
    {
        return Err(parquet_err("invalid PAR1 magic header/footer"));
    }
    let len_end = bytes.len().saturating_sub(4);
    let len_start = len_end.saturating_sub(4);
    let len_arr: [u8; 4] = bytes
        .get(len_start..len_end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| parquet_err("missing PAR1 footer length"))?;
    let meta_len = usize::try_from(u32::from_le_bytes(len_arr))
        .map_err(|_| parquet_err("PAR1 footer length overflow"))?;
    let meta_start = len_start
        .checked_sub(meta_len)
        .ok_or_else(|| parquet_err("PAR1 footer length out of bounds"))?;
    let meta_slice = bytes
        .get(meta_start..len_start)
        .ok_or_else(|| parquet_err("corrupt PAR1 metadata slice"))?;
    decode_file_metadata(meta_slice)
}

pub(crate) fn reconstruct_records(
    num_rows: usize,
    col_pages: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<LakeRecord>, CodedError> {
    if num_rows > MAX_PARQUET_ROWS {
        return Err(parquet_err("Parquet row count exceeds limit"));
    }
    let mut decoded = BTreeMap::new();
    for spec in LAKE_COLUMNS {
        if let Some(page_bytes) = col_pages.get(spec.name) {
            decoded.insert(spec.name, decode_column_page(spec, num_rows, page_bytes)?);
        }
    }

    let mut out = Vec::with_capacity(num_rows);
    for idx in 0..num_rows {
        let rc_str = get_str(&decoded, "retention_class", idx);
        let retention_class = RetentionClass::parse(&rc_str).unwrap_or(RetentionClass::Activity);
        let fields_raw = get_str(&decoded, "fields_json", idx);
        let fields: BTreeMap<String, String> = if fields_raw.is_empty() {
            BTreeMap::new()
        } else {
            serde_json::from_str(&fields_raw).map_err(|e| parquet_err(&e.to_string()))?
        };
        let content_raw = get_str(&decoded, "content_fields_json", idx);
        let content_fields: BTreeMap<String, String> = if content_raw.is_empty() {
            BTreeMap::new()
        } else {
            serde_json::from_str(&content_raw).map_err(|e| parquet_err(&e.to_string()))?
        };
        let obs_raw = get_str(&decoded, "observables_json", idx);
        let observables: Vec<LakeObservable> = if obs_raw.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(&obs_raw).map_err(|e| parquet_err(&e.to_string()))?
        };

        out.push(LakeRecord {
            event_id: get_str(&decoded, "event_id", idx),
            device_id: get_str(&decoded, "device_id", idx),
            epoch: u64::try_from(get_i64(&decoded, "epoch", idx)).unwrap_or(0),
            lane: get_str(&decoded, "lane", idx),
            seq: u64::try_from(get_i64(&decoded, "seq", idx)).unwrap_or(0),
            retention_class,
            category: get_str(&decoded, "category", idx),
            root_session_id: get_str(&decoded, "root_session_id", idx),
            session_id: get_str(&decoded, "session_id", idx),
            tool_call_id: get_opt_str(&decoded, "tool_call_id", idx),
            observed_time_ms: get_i64(&decoded, "observed_time_ms", idx),
            monotonic_ns: u64::try_from(get_i64(&decoded, "monotonic_ns", idx)).unwrap_or(0),
            received_at_ms: get_i64(&decoded, "received_at_ms", idx),
            schema_rev: u32::try_from(get_i64(&decoded, "schema_rev", idx)).unwrap_or(1),
            fields,
            content_fields,
            observables,
        });
    }
    Ok(out)
}

fn encode_data_page_header(num_rows: usize, payload_len: usize) -> Result<Vec<u8>, CodedError> {
    let sz_i32 =
        i32::try_from(payload_len).map_err(|_| parquet_err("data page exceeds i32 size"))?;
    let rows_i32 =
        i32::try_from(num_rows).map_err(|_| parquet_err("data page row count exceeds i32"))?;
    let mut w = CompactWriter::new();
    w.begin_struct();
    w.write_i32_field(1, PARQUET_PAGE_TYPE_DATA);
    w.write_i32_field(2, sz_i32);
    w.write_i32_field(3, sz_i32);
    w.write_field_header(5, CT_STRUCT);
    w.begin_struct();
    w.write_i32_field(1, rows_i32);
    w.write_i32_field(2, PARQUET_ENCODING_PLAIN);
    w.write_i32_field(3, PARQUET_ENCODING_RLE);
    w.write_i32_field(4, PARQUET_ENCODING_RLE);
    w.end_struct();
    w.end_struct();
    Ok(w.into_bytes())
}

fn decode_column_page(
    spec: &LakeColumnSpec,
    expected_rows: usize,
    page_bytes: &[u8],
) -> Result<DecodedColumnValues, CodedError> {
    let mut r = CompactReader::new(page_bytes);
    r.begin_struct();
    let mut num_values = expected_rows;
    let mut compressed_size = 0usize;
    while let Some((fid, ft)) = r.read_field_header()? {
        match fid {
            1 => {
                if ft != CT_I32 {
                    return Err(parquet_err("invalid Parquet page type field"));
                }
                let pt = r.read_i32()?;
                if pt != PARQUET_PAGE_TYPE_DATA {
                    return Err(parquet_err("unexpected Parquet page type"));
                }
            }
            3 => {
                if ft != CT_I32 {
                    return Err(parquet_err("invalid Parquet compressed_page_size field"));
                }
                compressed_size = usize::try_from(r.read_i32()?)
                    .map_err(|_| parquet_err("negative page size"))?;
            }
            5 => {
                if ft != CT_STRUCT {
                    return Err(parquet_err("invalid Parquet data_page_header field"));
                }
                r.begin_struct();
                while let Some((dfid, dft)) = r.read_field_header()? {
                    if dfid == 1 {
                        if dft != CT_I32 {
                            return Err(parquet_err("invalid Parquet num_values field"));
                        }
                        num_values = usize::try_from(r.read_i32()?)
                            .map_err(|_| parquet_err("negative page num_values"))?;
                    } else {
                        r.skip_field(dft)?;
                    }
                }
                r.end_struct();
            }
            _ => r.skip_field(ft)?,
        }
    }
    r.end_struct();

    if num_values != expected_rows || num_values > MAX_PARQUET_ROWS {
        return Err(parquet_err(
            "Parquet column page row count mismatch or exceeded limit",
        ));
    }

    let payload_start = r.position();
    let payload_end = payload_start
        .checked_add(compressed_size)
        .ok_or_else(|| parquet_err("column page size overflow"))?;
    let data = page_bytes
        .get(payload_start..payload_end)
        .ok_or_else(|| parquet_err("truncated column data page"))?;

    match spec.kind {
        LakeColKind::Str => {
            if data.len() / 4 < num_values {
                return Err(parquet_err("truncated string column page"));
            }
            let mut vals = Vec::with_capacity(num_values);
            let mut off = 0usize;
            for _ in 0..num_values {
                vals.push(read_plain_utf8(data, &mut off)?);
            }
            Ok(DecodedColumnValues::Str(vals))
        }
        LakeColKind::I64 => {
            let needed = num_values
                .checked_mul(8)
                .ok_or_else(|| parquet_err("INT64 column byte count overflow"))?;
            if data.len() < needed {
                return Err(parquet_err("truncated INT64 column page"));
            }
            let mut vals = Vec::with_capacity(num_values);
            let mut off = 0usize;
            for _ in 0..num_values {
                let end = off.saturating_add(8);
                let arr: [u8; 8] = data
                    .get(off..end)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| parquet_err("truncated INT64 column page"))?;
                off = end;
                vals.push(i64::from_le_bytes(arr));
            }
            Ok(DecodedColumnValues::I64(vals))
        }
        LakeColKind::OptStr => {
            let rle_len_bytes: [u8; 4] = data
                .get(..4)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| parquet_err("missing definition levels length"))?;
            let rle_len = usize::try_from(u32::from_le_bytes(rle_len_bytes))
                .map_err(|_| parquet_err("definition levels overflow"))?;
            if rle_len < num_values.div_ceil(8) {
                return Err(parquet_err("truncated definition levels bitmap"));
            }
            let mut off = 4usize
                .checked_add(rle_len)
                .ok_or_else(|| parquet_err("definition levels offset overflow"))?;
            let def_bits = data
                .get(4..off)
                .ok_or_else(|| parquet_err("truncated definition levels"))?;
            let mut vals = Vec::with_capacity(num_values);
            for idx in 0..num_values {
                let present = def_bits
                    .get(idx / 8)
                    .is_some_and(|b| ((b >> (idx % 8)) & 1) == 1);
                if present {
                    vals.push(Some(read_plain_utf8(data, &mut off)?));
                } else {
                    vals.push(None);
                }
            }
            Ok(DecodedColumnValues::OptStr(vals))
        }
    }
}

fn write_plain_byte_array(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CodedError> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| parquet_err("BYTE_ARRAY value exceeds u32"))?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
    Ok(())
}

fn read_plain_utf8(data: &[u8], off: &mut usize) -> Result<String, CodedError> {
    let len_end = off.saturating_add(4);
    let len_arr: [u8; 4] = data
        .get(*off..len_end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| parquet_err("truncated BYTE_ARRAY length"))?;
    let len = usize::try_from(u32::from_le_bytes(len_arr))
        .map_err(|_| parquet_err("BYTE_ARRAY length overflow"))?;
    let val_end = len_end.saturating_add(len);
    let slice = data
        .get(len_end..val_end)
        .ok_or_else(|| parquet_err("truncated BYTE_ARRAY value"))?;
    *off = val_end;
    std::str::from_utf8(slice)
        .map(ToString::to_string)
        .map_err(|_| parquet_err("invalid UTF-8 column value"))
}

fn extract_str_col(name: &str, rec: &LakeRecord) -> Result<String, CodedError> {
    match name {
        "event_id" => Ok(rec.event_id.clone()),
        "device_id" => Ok(rec.device_id.clone()),
        "lane" => Ok(rec.lane.clone()),
        "retention_class" => Ok(rec.retention_class.as_str().to_string()),
        "category" => Ok(rec.category.clone()),
        "root_session_id" => Ok(rec.root_session_id.clone()),
        "session_id" => Ok(rec.session_id.clone()),
        "fields_json" => {
            serde_json::to_string(&rec.fields).map_err(|e| parquet_err(&e.to_string()))
        }
        "content_fields_json" => {
            serde_json::to_string(&rec.content_fields).map_err(|e| parquet_err(&e.to_string()))
        }
        "observables_json" => {
            serde_json::to_string(&rec.observables).map_err(|e| parquet_err(&e.to_string()))
        }
        other => Err(parquet_err(&format!("unknown string column `{other}`"))),
    }
}

fn extract_i64_col(name: &str, rec: &LakeRecord) -> i64 {
    match name {
        "epoch" => i64::try_from(rec.epoch).unwrap_or(i64::MAX),
        "seq" => i64::try_from(rec.seq).unwrap_or(i64::MAX),
        "observed_time_ms" => rec.observed_time_ms,
        "monotonic_ns" => i64::try_from(rec.monotonic_ns).unwrap_or(i64::MAX),
        "received_at_ms" => rec.received_at_ms,
        "schema_rev" => i64::from(rec.schema_rev),
        _ => 0,
    }
}

fn get_str(map: &BTreeMap<&'static str, DecodedColumnValues>, key: &str, idx: usize) -> String {
    match map.get(key) {
        Some(DecodedColumnValues::Str(v)) => v.get(idx).cloned().unwrap_or_default(),
        _ => String::new(),
    }
}

fn get_i64(map: &BTreeMap<&'static str, DecodedColumnValues>, key: &str, idx: usize) -> i64 {
    match map.get(key) {
        Some(DecodedColumnValues::I64(v)) => v.get(idx).copied().unwrap_or(0),
        _ => 0,
    }
}

fn get_opt_str(
    map: &BTreeMap<&'static str, DecodedColumnValues>,
    key: &str,
    idx: usize,
) -> Option<String> {
    match map.get(key) {
        Some(DecodedColumnValues::OptStr(v)) => v.get(idx).cloned().flatten(),
        _ => None,
    }
}
