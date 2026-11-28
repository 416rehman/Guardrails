// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use grdr_model::CodedError;
use grdr_ports::CODE_BLOB_IO;

const MAX_S3_XML_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct S3ListEntry {
    pub(crate) key: String,
    pub(crate) size_bytes: u64,
    pub(crate) etag: String,
    pub(crate) last_modified_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct S3ListPage {
    pub(crate) entries: Vec<S3ListEntry>,
    pub(crate) is_truncated: bool,
    pub(crate) next_continuation_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct S3XmlError {
    pub(crate) code: String,
    pub(crate) message: String,
}

pub(crate) fn parse_list_objects_v2(xml: &str) -> Result<S3ListPage, CodedError> {
    reject_dtd_and_entities(xml)?;
    let is_truncated = match extract_tag_text(xml, "IsTruncated") {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.eq_ignore_ascii_case("true") {
                true
            } else if trimmed.eq_ignore_ascii_case("false") {
                false
            } else {
                return Err(xml_malformed_err("invalid <IsTruncated> boolean value"));
            }
        }
        None => false,
    };
    let next_continuation_token = match extract_tag_text(xml, "NextContinuationToken") {
        Some(raw) => {
            let val = unescape_xml(raw)?;
            (!val.is_empty()).then_some(val)
        }
        None => None,
    };

    let mut entries = Vec::new();
    for block in extract_all_blocks(xml, "Contents") {
        let raw_key =
            extract_tag_text(block, "Key").ok_or_else(|| xml_malformed_err("missing <Key>"))?;
        let key = unescape_xml(raw_key)?;
        let raw_size =
            extract_tag_text(block, "Size").ok_or_else(|| xml_malformed_err("missing <Size>"))?;
        let size_text = unescape_xml(raw_size)?;
        let size_bytes = size_text
            .trim()
            .parse::<u64>()
            .map_err(|_| xml_malformed_err("malformed <Size> integer in ListObjectsV2"))?;
        let etag = match extract_tag_text(block, "ETag") {
            Some(raw) => unescape_xml(raw)?.trim_matches('"').to_string(),
            None => String::new(),
        };
        let last_modified_ms = match extract_tag_text(block, "LastModified") {
            Some(raw) => {
                let text = unescape_xml(raw)?;
                text.trim()
                    .parse::<Timestamp>()
                    .map_err(|_| xml_malformed_err("malformed <LastModified> timestamp"))?
                    .as_millisecond()
            }
            None => 0,
        };
        entries.push(S3ListEntry {
            key,
            size_bytes,
            etag,
            last_modified_ms,
        });
    }

    Ok(S3ListPage {
        entries,
        is_truncated,
        next_continuation_token,
    })
}

pub(crate) fn parse_versioning_status(xml: &str) -> Result<Option<String>, CodedError> {
    reject_dtd_and_entities(xml)?;
    match extract_tag_text(xml, "Status") {
        Some(raw) => Ok(Some(unescape_xml(raw)?.trim().to_string())),
        None => Ok(None),
    }
}

pub(crate) fn parse_lifecycle_present(xml: &str) -> Result<bool, CodedError> {
    reject_dtd_and_entities(xml)?;
    Ok(extract_tag_text(xml, "Rule").is_some())
}

pub(crate) fn parse_s3_error(xml: &str) -> Option<S3XmlError> {
    if reject_dtd_and_entities(xml).is_err() {
        return None;
    }
    let raw_code = extract_tag_text(xml, "Code")?;
    let code = unescape_xml(raw_code).ok()?;
    let message = match extract_tag_text(xml, "Message") {
        Some(raw) => unescape_xml(raw).ok()?,
        None => String::new(),
    };
    Some(S3XmlError { code, message })
}

fn reject_dtd_and_entities(xml: &str) -> Result<(), CodedError> {
    if xml.len() > MAX_S3_XML_BYTES {
        return Err(CodedError::new(
            CODE_BLOB_IO,
            format!("S3 XML response exceeded {MAX_S3_XML_BYTES} byte limit."),
            "Paginate S3 responses within XML size limits.",
        ));
    }
    let lower = xml.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err(CodedError::new(
            CODE_BLOB_IO,
            "Rejected S3 XML response containing DOCTYPE or ENTITY declaration.",
            "Ensure object store returns standard S3 XML without external entities.",
        ));
    }
    Ok(())
}

fn xml_malformed_err(detail: &str) -> CodedError {
    CodedError::new(
        CODE_BLOB_IO,
        format!("Malformed S3 XML payload: {detail}."),
        "Verify S3-compatible XML response syntax.",
    )
}

fn extract_tag_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    extract_all_blocks(xml, tag).into_iter().next()
}

fn extract_all_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let prefix = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut results = Vec::new();
    let mut cursor = 0usize;
    while let Some(haystack) = xml.get(cursor..) {
        let Some(rel_start) = haystack.find(&prefix) else {
            break;
        };
        let after_name_idx = cursor
            .saturating_add(rel_start)
            .saturating_add(prefix.len());
        let Some(after_name) = xml.get(after_name_idx..) else {
            break;
        };
        let Some(next_ch) = after_name.chars().next() else {
            break;
        };
        if next_ch != '>' && !next_ch.is_ascii_whitespace() {
            cursor = after_name_idx;
            continue;
        }
        let Some(gt_rel) = find_opening_tag_end(after_name) else {
            break;
        };
        let content_start = after_name_idx.saturating_add(gt_rel).saturating_add(1);
        if after_name
            .get(..gt_rel)
            .is_some_and(|s| s.trim_end().ends_with('/'))
        {
            cursor = content_start;
            continue;
        }
        let Some(after_open) = xml.get(content_start..) else {
            break;
        };
        let Some(rel_end) = after_open.find(&close) else {
            break;
        };
        let content_end = content_start.saturating_add(rel_end);
        if let Some(inner) = xml.get(content_start..content_end) {
            results.push(inner);
        }
        cursor = content_end.saturating_add(close.len());
    }
    results
}

fn find_opening_tag_end(after_name: &str) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (idx, &b) in after_name.as_bytes().iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(idx),
            None => {}
        }
    }
    None
}

fn unescape_xml(raw: &str) -> Result<String, CodedError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(cdata_start) = rest.find("<![CDATA[") {
        if let Some(before) = rest.get(..cdata_start) {
            unescape_entities_into(before, &mut out)?;
        }
        let after_marker = rest
            .get(cdata_start.saturating_add(9)..)
            .ok_or_else(|| xml_malformed_err("truncated CDATA section"))?;
        let Some(cdata_end) = after_marker.find("]]>") else {
            return Err(xml_malformed_err("unterminated CDATA section"));
        };
        let inner = after_marker
            .get(..cdata_end)
            .ok_or_else(|| xml_malformed_err("invalid CDATA bounds"))?;
        if inner.contains('\0') {
            return Err(xml_malformed_err("NUL byte inside CDATA section"));
        }
        out.push_str(inner);
        rest = after_marker
            .get(cdata_end.saturating_add(3)..)
            .unwrap_or("");
    }
    unescape_entities_into(rest, &mut out)?;
    Ok(out)
}

fn unescape_entities_into(raw: &str, out: &mut String) -> Result<(), CodedError> {
    let mut rest = raw;
    while let Some(amp_idx) = rest.find('&') {
        if let Some(prefix) = rest.get(..amp_idx) {
            out.push_str(prefix);
        }
        let Some(after_amp) = rest.get(amp_idx.saturating_add(1)..) else {
            out.push('&');
            return Ok(());
        };
        if let Some(semi_idx) = after_amp.find(';')
            && semi_idx <= 12
            && let Some(entity) = after_amp.get(..semi_idx)
        {
            match entity {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                _ if entity.starts_with('#') => {
                    let decoded = decode_numeric_entity(entity)?;
                    out.push(decoded);
                }
                _ => {
                    out.push('&');
                    out.push_str(entity);
                    out.push(';');
                }
            }
            rest = after_amp.get(semi_idx.saturating_add(1)..).unwrap_or("");
        } else {
            out.push('&');
            rest = after_amp;
        }
    }
    out.push_str(rest);
    Ok(())
}

fn decode_numeric_entity(entity: &str) -> Result<char, CodedError> {
    let code_opt = if let Some(hex_str) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        u32::from_str_radix(hex_str, 16).ok()
    } else if let Some(dec_str) = entity.strip_prefix('#') {
        dec_str.parse::<u32>().ok()
    } else {
        None
    };
    let Some(code) = code_opt else {
        return Err(xml_malformed_err("invalid XML numeric character reference"));
    };
    if code == 0 {
        return Err(xml_malformed_err("forbidden NUL numeric XML entity"));
    }
    char::from_u32(code).ok_or_else(|| xml_malformed_err("invalid Unicode scalar in XML entity"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_handles_attributes_cdata_and_rejects_malformed_size_or_nul_entities() {
        let xml = r#"<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false</IsTruncated><Contents attr="1"><Key xml:space="preserve"><![CDATA[org=o1/raw&key.parquet]]></Key><Size>42</Size><ETag>"abc"</ETag></Contents></ListBucketResult>"#;
        let page = parse_list_objects_v2(xml).unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries.first().unwrap().key, "org=o1/raw&key.parquet");
        assert_eq!(page.entries.first().unwrap().size_bytes, 42);

        let bad_size = "<ListBucketResult><Contents><Key>a</Key><Size>not-num</Size></Contents></ListBucketResult>";
        assert!(parse_list_objects_v2(bad_size).is_err());

        let nul_entity = "<ListBucketResult><Contents><Key>a&#0;b</Key><Size>1</Size></Contents></ListBucketResult>";
        assert!(parse_list_objects_v2(nul_entity).is_err());

        let nul_hex = "<ListBucketResult><Contents><Key>a&#x0;b</Key><Size>1</Size></Contents></ListBucketResult>";
        assert!(parse_list_objects_v2(nul_hex).is_err());

        let dtd = "<!DOCTYPE foo><ListBucketResult></ListBucketResult>";
        assert!(parse_list_objects_v2(dtd).is_err());
    }
}
