// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::CodedError;
use grdr_ports::CODE_LAKE_IO;

use crate::thrift_compact::{
    CT_BINARY, CT_I32, CT_I64, CT_LIST, CT_STRUCT, CompactReader, CompactWriter,
};

const MAX_PARQUET_ROW_GROUPS: usize = 10_000;
const MAX_PARQUET_COLUMNS: usize = 1_024;
const MAX_PARQUET_KV: usize = 4_096;
const MAX_PARQUET_PATH_LEN: usize = 64;
pub(crate) const MAX_PARQUET_ROWS: usize = 1_000_000;

const PARQUET_TYPE_INT64: i32 = 2;
const PARQUET_TYPE_BYTE_ARRAY: i32 = 6;
const PARQUET_REPETITION_REQUIRED: i32 = 0;
const PARQUET_REPETITION_OPTIONAL: i32 = 1;
const PARQUET_CONVERTED_UTF8: i32 = 0;
const PARQUET_ENCODING_PLAIN: i32 = 0;
const PARQUET_ENCODING_RLE: i32 = 3;
const PARQUET_CODEC_UNCOMPRESSED: i32 = 0;

pub(crate) const LAKE_COLUMNS: &[LakeColumnSpec] = &[
    LakeColumnSpec {
        name: "event_id",
        kind: LakeColKind::Str,
    },
    LakeColumnSpec {
        name: "device_id",
        kind: LakeColKind::Str,
    },
    LakeColumnSpec {
        name: "epoch",
        kind: LakeColKind::I64,
    },
    LakeColumnSpec {
        name: "lane",
        kind: LakeColKind::Str,
    },
    LakeColumnSpec {
        name: "seq",
        kind: LakeColKind::I64,
    },
    LakeColumnSpec {
        name: "retention_class",
        kind: LakeColKind::Str,
    },
    LakeColumnSpec {
        name: "category",
        kind: LakeColKind::Str,
    },
    LakeColumnSpec {
        name: "root_session_id",
        kind: LakeColKind::Str,
    },
    LakeColumnSpec {
        name: "session_id",
        kind: LakeColKind::Str,
    },
    LakeColumnSpec {
        name: "tool_call_id",
        kind: LakeColKind::OptStr,
    },
    LakeColumnSpec {
        name: "observed_time_ms",
        kind: LakeColKind::I64,
    },
    LakeColumnSpec {
        name: "monotonic_ns",
        kind: LakeColKind::I64,
    },
    LakeColumnSpec {
        name: "received_at_ms",
        kind: LakeColKind::I64,
    },
    LakeColumnSpec {
        name: "schema_rev",
        kind: LakeColKind::I64,
    },
    LakeColumnSpec {
        name: "fields_json",
        kind: LakeColKind::Str,
    },
    LakeColumnSpec {
        name: "content_fields_json",
        kind: LakeColKind::Str,
    },
    LakeColumnSpec {
        name: "observables_json",
        kind: LakeColKind::Str,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LakeColKind {
    Str,
    I64,
    OptStr,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LakeColumnSpec {
    pub(crate) name: &'static str,
    pub(crate) kind: LakeColKind,
}

#[derive(Debug, Clone)]
pub(crate) struct ParquetColumnExtent {
    pub(crate) name: String,
    pub(crate) file_offset: u64,
    pub(crate) compressed_size: u64,
    pub(crate) min_i64: Option<i64>,
    pub(crate) max_i64: Option<i64>,
}

#[derive(Debug, Clone)]
pub(crate) struct DecodedParquetMeta {
    pub(crate) num_rows: usize,
    pub(crate) columns: Vec<ParquetColumnExtent>,
    pub(crate) key_value_metadata: BTreeMap<String, String>,
}

pub(crate) fn find_column_spec(name: &str) -> Option<&'static LakeColumnSpec> {
    LAKE_COLUMNS.iter().find(|c| c.name == name)
}

pub(crate) fn encode_file_metadata(
    num_rows: usize,
    columns: &[ParquetColumnExtent],
    key_value_metadata: &BTreeMap<String, String>,
) -> Vec<u8> {
    let mut w = CompactWriter::new();
    w.begin_struct();
    w.write_i32_field(1, 1);

    let schema_count = 1usize.saturating_add(LAKE_COLUMNS.len());
    w.write_list_header(2, CT_STRUCT, schema_count);
    write_schema_root(&mut w);
    for spec in LAKE_COLUMNS {
        write_schema_leaf(&mut w, spec);
    }

    let num_rows_i64 = i64::try_from(num_rows).unwrap_or(i64::MAX);
    w.write_i64_field(3, num_rows_i64);

    w.write_list_header(4, CT_STRUCT, 1);
    write_row_group(&mut w, num_rows_i64, columns);

    if !key_value_metadata.is_empty() {
        w.write_list_header(5, CT_STRUCT, key_value_metadata.len());
        for (k, v) in key_value_metadata {
            w.begin_struct();
            w.write_str_field(1, k);
            w.write_str_field(2, v);
            w.end_struct();
        }
    }

    w.write_str_field(6, "Guardrails ADR grdr-lake");
    w.end_struct();
    w.into_bytes()
}

pub(crate) fn decode_file_metadata(bytes: &[u8]) -> Result<DecodedParquetMeta, CodedError> {
    let mut r = CompactReader::new(bytes);
    r.begin_struct();
    let mut num_rows: usize = 0;
    let mut columns = Vec::new();
    let mut kv = BTreeMap::new();

    while let Some((fid, ft)) = r.read_field_header()? {
        match fid {
            3 => {
                if ft != CT_I64 {
                    return Err(parquet_err("invalid Parquet num_rows field type"));
                }
                let n = r.read_i64()?;
                num_rows = usize::try_from(n).map_err(|_| parquet_err("negative num_rows"))?;
                if num_rows > MAX_PARQUET_ROWS {
                    return Err(parquet_err("Parquet num_rows exceeds limit"));
                }
            }
            4 => {
                if ft != CT_LIST {
                    return Err(parquet_err("invalid Parquet row_groups field type"));
                }
                let (et, rg_count) = r.read_list_header()?;
                if et != CT_STRUCT
                    || rg_count > MAX_PARQUET_ROW_GROUPS
                    || rg_count > r.remaining_bytes()
                {
                    return Err(parquet_err(
                        "invalid Parquet row_groups count or element type",
                    ));
                }
                for idx in 0..rg_count {
                    let rg_cols = read_row_group(&mut r)?;
                    if idx == 0 {
                        columns = rg_cols;
                    }
                }
            }
            5 => {
                if ft != CT_LIST {
                    return Err(parquet_err("invalid Parquet key_value_metadata field type"));
                }
                let (et, kv_count) = r.read_list_header()?;
                if et != CT_STRUCT || kv_count > MAX_PARQUET_KV || kv_count > r.remaining_bytes() {
                    return Err(parquet_err(
                        "invalid Parquet key_value_metadata count or element type",
                    ));
                }
                for _ in 0..kv_count {
                    let (k, v) = read_key_value(&mut r)?;
                    kv.insert(k, v);
                }
            }
            _ => r.skip_field(ft)?,
        }
    }
    r.end_struct();
    Ok(DecodedParquetMeta {
        num_rows,
        columns,
        key_value_metadata: kv,
    })
}

pub(crate) fn parquet_err(detail: &str) -> CodedError {
    CodedError::new(
        CODE_LAKE_IO,
        format!("Parquet codec error: {detail}."),
        "Inspect Parquet segment integrity and schema revision.",
    )
}

fn write_schema_root(w: &mut CompactWriter) {
    w.begin_struct();
    w.write_str_field(4, "grdr_lake_schema");
    w.write_i32_field(5, i32::try_from(LAKE_COLUMNS.len()).unwrap_or(0));
    w.end_struct();
}

fn write_schema_leaf(w: &mut CompactWriter, spec: &LakeColumnSpec) {
    w.begin_struct();
    let physical = match spec.kind {
        LakeColKind::I64 => PARQUET_TYPE_INT64,
        LakeColKind::Str | LakeColKind::OptStr => PARQUET_TYPE_BYTE_ARRAY,
    };
    let rep = match spec.kind {
        LakeColKind::OptStr => PARQUET_REPETITION_OPTIONAL,
        LakeColKind::Str | LakeColKind::I64 => PARQUET_REPETITION_REQUIRED,
    };
    w.write_i32_field(1, physical);
    w.write_i32_field(3, rep);
    w.write_str_field(4, spec.name);
    if !matches!(spec.kind, LakeColKind::I64) {
        w.write_i32_field(6, PARQUET_CONVERTED_UTF8);
    }
    w.end_struct();
}

fn write_row_group(w: &mut CompactWriter, num_rows_i64: i64, columns: &[ParquetColumnExtent]) {
    w.begin_struct();
    w.write_list_header(1, CT_STRUCT, columns.len());
    let mut total_bytes = 0i64;
    for col in columns {
        total_bytes = total_bytes.saturating_add(i64::try_from(col.compressed_size).unwrap_or(0));
        write_column_chunk(w, num_rows_i64, col);
    }
    w.write_i64_field(2, total_bytes);
    w.write_i64_field(3, num_rows_i64);
    w.end_struct();
}

fn write_column_chunk(w: &mut CompactWriter, num_rows_i64: i64, col: &ParquetColumnExtent) {
    let spec = find_column_spec(&col.name);
    let physical = match spec.map(|s| s.kind) {
        Some(LakeColKind::I64) => PARQUET_TYPE_INT64,
        _ => PARQUET_TYPE_BYTE_ARRAY,
    };
    let sz_i64 = i64::try_from(col.compressed_size).unwrap_or(0);
    let off_i64 = i64::try_from(col.file_offset).unwrap_or(0);

    w.begin_struct();
    w.write_i64_field(2, off_i64);
    w.write_field_header(3, CT_STRUCT);
    w.begin_struct();
    w.write_i32_field(1, physical);
    w.write_list_header(2, CT_I32, 2);
    w.write_i32_elem(PARQUET_ENCODING_PLAIN);
    w.write_i32_elem(PARQUET_ENCODING_RLE);
    w.write_list_header(3, CT_BINARY, 1);
    w.write_binary(col.name.as_bytes());
    w.write_i32_field(4, PARQUET_CODEC_UNCOMPRESSED);
    w.write_i64_field(5, num_rows_i64);
    w.write_i64_field(6, sz_i64);
    w.write_i64_field(7, sz_i64);
    w.write_i64_field(9, off_i64);
    if col.min_i64.is_some() || col.max_i64.is_some() {
        w.write_field_header(12, CT_STRUCT);
        w.begin_struct();
        if let Some(mx) = col.max_i64 {
            w.write_bytes_field(5, &mx.to_le_bytes());
        }
        if let Some(mn) = col.min_i64 {
            w.write_bytes_field(6, &mn.to_le_bytes());
        }
        w.end_struct();
    }
    w.end_struct();
    w.end_struct();
}

fn read_row_group(r: &mut CompactReader<'_>) -> Result<Vec<ParquetColumnExtent>, CodedError> {
    r.begin_struct();
    let mut cols = Vec::new();
    while let Some((fid, ft)) = r.read_field_header()? {
        if fid == 1 {
            if ft != CT_LIST {
                return Err(parquet_err("invalid Parquet columns field type"));
            }
            let (et, count) = r.read_list_header()?;
            if et != CT_STRUCT || count > MAX_PARQUET_COLUMNS || count > r.remaining_bytes() {
                return Err(parquet_err("invalid Parquet columns count or element type"));
            }
            for _ in 0..count {
                cols.push(read_column_chunk(r)?);
            }
        } else {
            r.skip_field(ft)?;
        }
    }
    r.end_struct();
    Ok(cols)
}

fn read_column_chunk(r: &mut CompactReader<'_>) -> Result<ParquetColumnExtent, CodedError> {
    r.begin_struct();
    let mut file_offset = 0u64;
    let mut name = String::new();
    let mut compressed_size = 0u64;
    let mut min_i64 = None;
    let mut max_i64 = None;

    while let Some((fid, ft)) = r.read_field_header()? {
        match fid {
            2 => {
                if ft != CT_I64 {
                    return Err(parquet_err("invalid column file_offset field type"));
                }
                file_offset = u64::try_from(r.read_i64()?)
                    .map_err(|_| parquet_err("negative column file_offset"))?;
            }
            3 => {
                if ft != CT_STRUCT {
                    return Err(parquet_err("invalid column metadata field type"));
                }
                r.begin_struct();
                while let Some((mfid, mft)) = r.read_field_header()? {
                    match mfid {
                        3 => {
                            if mft != CT_LIST {
                                return Err(parquet_err("invalid column path field type"));
                            }
                            let (et, plen) = r.read_list_header()?;
                            if et != CT_BINARY
                                || plen > MAX_PARQUET_PATH_LEN
                                || plen > r.remaining_bytes()
                            {
                                return Err(parquet_err(
                                    "invalid column path count or element type",
                                ));
                            }
                            for idx in 0..plen {
                                let part = r.read_string()?;
                                if idx == 0 {
                                    name = part;
                                }
                            }
                        }
                        7 => {
                            if mft != CT_I64 {
                                return Err(parquet_err("invalid column compressed_size type"));
                            }
                            compressed_size = u64::try_from(r.read_i64()?)
                                .map_err(|_| parquet_err("negative column compressed_size"))?;
                        }
                        12 => {
                            if mft != CT_STRUCT {
                                return Err(parquet_err("invalid column stats field type"));
                            }
                            r.begin_struct();
                            while let Some((sfid, sft)) = r.read_field_header()? {
                                match sfid {
                                    5 => {
                                        if sft != CT_BINARY {
                                            return Err(parquet_err("invalid max_value stat type"));
                                        }
                                        max_i64 = decode_i64_stat(r.read_binary()?);
                                    }
                                    6 => {
                                        if sft != CT_BINARY {
                                            return Err(parquet_err("invalid min_value stat type"));
                                        }
                                        min_i64 = decode_i64_stat(r.read_binary()?);
                                    }
                                    _ => r.skip_field(sft)?,
                                }
                            }
                            r.end_struct();
                        }
                        _ => r.skip_field(mft)?,
                    }
                }
                r.end_struct();
            }
            _ => r.skip_field(ft)?,
        }
    }
    r.end_struct();
    Ok(ParquetColumnExtent {
        name,
        file_offset,
        compressed_size,
        min_i64,
        max_i64,
    })
}

fn read_key_value(r: &mut CompactReader<'_>) -> Result<(String, String), CodedError> {
    r.begin_struct();
    let mut key = String::new();
    let mut val = String::new();
    while let Some((fid, ft)) = r.read_field_header()? {
        match fid {
            1 => {
                if ft != CT_BINARY {
                    return Err(parquet_err("invalid key_value key field type"));
                }
                key = r.read_string()?;
            }
            2 => {
                if ft != CT_BINARY {
                    return Err(parquet_err("invalid key_value val field type"));
                }
                val = r.read_string()?;
            }
            _ => r.skip_field(ft)?,
        }
    }
    r.end_struct();
    Ok((key, val))
}

fn decode_i64_stat(bytes: &[u8]) -> Option<i64> {
    let arr: [u8; 8] = bytes.try_into().ok()?;
    Some(i64::from_le_bytes(arr))
}
