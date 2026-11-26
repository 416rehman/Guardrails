// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Bounded binary cursor and rule decoding helpers for `GRDRFLT1` floor tables (`crates/grdr-wire`).

use grdr_fastpath::{FastActionClass, FastVerdict};

use crate::floor_bin::{FloorBinError, FloorMatchKind, FloorRuleRecord};

pub(crate) const MAX_RULE_ID_LEN: usize = 256;
pub(crate) const MAX_PATTERN_LEN: usize = 1024;
pub(crate) const MAX_AGENTS_PER_RULE: usize = 32;

pub(crate) struct Cursor<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) offset: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], FloorBinError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(FloorBinError::Truncated {
                offset: self.offset,
            })?;
        let slice = self
            .buf
            .get(self.offset..end)
            .ok_or(FloorBinError::Truncated {
                offset: self.offset,
            })?;
        self.offset = end;
        Ok(slice)
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, FloorBinError> {
        let bytes = self.take(1)?;
        bytes.first().copied().ok_or(FloorBinError::Truncated {
            offset: self.offset,
        })
    }

    pub(crate) fn read_u16_le(&mut self) -> Result<u16, FloorBinError> {
        let bytes = self.take(2)?;
        let arr: [u8; 2] = bytes.try_into().map_err(|_| FloorBinError::Truncated {
            offset: self.offset,
        })?;
        Ok(u16::from_le_bytes(arr))
    }

    pub(crate) fn read_u32_le(&mut self) -> Result<u32, FloorBinError> {
        let bytes = self.take(4)?;
        let arr: [u8; 4] = bytes.try_into().map_err(|_| FloorBinError::Truncated {
            offset: self.offset,
        })?;
        Ok(u32::from_le_bytes(arr))
    }

    pub(crate) fn read_u64_le(&mut self) -> Result<u64, FloorBinError> {
        let bytes = self.take(8)?;
        let arr: [u8; 8] = bytes.try_into().map_err(|_| FloorBinError::Truncated {
            offset: self.offset,
        })?;
        Ok(u64::from_le_bytes(arr))
    }

    pub(crate) fn read_i64_le(&mut self) -> Result<i64, FloorBinError> {
        let bytes = self.take(8)?;
        let arr: [u8; 8] = bytes.try_into().map_err(|_| FloorBinError::Truncated {
            offset: self.offset,
        })?;
        Ok(i64::from_le_bytes(arr))
    }

    pub(crate) fn read_optional_string(
        &mut self,
        max_len: usize,
        allow_whitespace: bool,
    ) -> Result<String, FloorBinError> {
        let len = usize::from(self.read_u16_le()?);
        if len == 0 {
            return Ok(String::new());
        }
        self.read_str_payload(len, max_len, allow_whitespace)
    }

    pub(crate) fn read_nonempty_string(
        &mut self,
        max_len: usize,
        allow_whitespace: bool,
    ) -> Result<String, FloorBinError> {
        let len = usize::from(self.read_u16_le()?);
        if len == 0 || len > max_len {
            return Err(FloorBinError::MalformedField {
                detail: format!("string length {len} outside 1..={max_len}"),
            });
        }
        self.read_str_payload(len, max_len, allow_whitespace)
    }

    fn read_str_payload(
        &mut self,
        len: usize,
        max_len: usize,
        allow_whitespace: bool,
    ) -> Result<String, FloorBinError> {
        if len > max_len {
            return Err(FloorBinError::MalformedField {
                detail: format!("string length {len} exceeds {max_len}"),
            });
        }
        let raw = self.take(len)?;
        let text = std::str::from_utf8(raw).map_err(|_| FloorBinError::MalformedField {
            detail: "non-utf8 field".to_string(),
        })?;
        if !allow_whitespace && text.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(FloorBinError::MalformedField {
                detail: "unexpected whitespace in identifier/signature".to_string(),
            });
        }
        Ok(text.to_string())
    }
}

pub(crate) fn ascii_starts_with_icase(haystack: &str, needle: &str) -> bool {
    let hb = haystack.as_bytes();
    let nb = needle.as_bytes();
    if nb.len() > hb.len() {
        return false;
    }
    hb.get(..nb.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(nb))
}

pub(crate) fn ascii_contains_icase(haystack: &str, needle: &str) -> bool {
    let hb = haystack.as_bytes();
    let nb = needle.as_bytes();
    if nb.is_empty() {
        return true;
    }
    hb.windows(nb.len()).any(|win| win.eq_ignore_ascii_case(nb))
}

pub(crate) fn decode_floor_rule(cursor: &mut Cursor<'_>) -> Result<FloorRuleRecord, FloorBinError> {
    let action_class = decode_action_class(cursor.read_u8()?)?;
    let verdict = decode_verdict(cursor.read_u8()?)?;
    let match_kind = decode_match_kind(cursor.read_u8()?)?;
    let rule_id = cursor.read_nonempty_string(MAX_RULE_ID_LEN, true)?;
    let pattern = match match_kind {
        FloorMatchKind::Any => {
            let pat = cursor.read_optional_string(MAX_PATTERN_LEN, true)?;
            if !pat.is_empty() {
                return Err(FloorBinError::MalformedField {
                    detail: "Any floor rule must carry empty pattern".to_string(),
                });
            }
            pat
        }
        FloorMatchKind::Contains | FloorMatchKind::Prefix => {
            cursor.read_nonempty_string(MAX_PATTERN_LEN, true)?
        }
    };
    let agent_count = usize::from(cursor.read_u16_le()?);
    if agent_count > MAX_AGENTS_PER_RULE {
        return Err(FloorBinError::MalformedField {
            detail: format!("floor rule agent count {agent_count} exceeds {MAX_AGENTS_PER_RULE}"),
        });
    }
    let min_agent_bytes = agent_count.saturating_mul(3);
    if cursor.remaining() < min_agent_bytes {
        return Err(FloorBinError::Truncated {
            offset: cursor.offset,
        });
    }
    let mut agents = Vec::with_capacity(agent_count);
    for _ in 0..agent_count {
        agents.push(cursor.read_nonempty_string(MAX_RULE_ID_LEN, false)?);
    }
    Ok(FloorRuleRecord {
        action_class,
        verdict,
        match_kind,
        rule_id,
        pattern,
        agents,
    })
}

fn decode_action_class(raw: u8) -> Result<FastActionClass, FloorBinError> {
    FastActionClass::from_u8(raw).ok_or_else(|| FloorBinError::MalformedField {
        detail: format!("unknown floor action class {raw}"),
    })
}

fn decode_match_kind(raw: u8) -> Result<FloorMatchKind, FloorBinError> {
    match raw {
        0 => Ok(FloorMatchKind::Contains),
        1 => Ok(FloorMatchKind::Prefix),
        2 => Ok(FloorMatchKind::Any),
        other => Err(FloorBinError::MalformedField {
            detail: format!("unknown floor match kind {other}"),
        }),
    }
}

fn decode_verdict(raw: u8) -> Result<FastVerdict, FloorBinError> {
    match raw {
        0 => Ok(FastVerdict::Allow),
        1 => Ok(FastVerdict::StepUp),
        2 => Ok(FastVerdict::Deny),
        other => Err(FloorBinError::MalformedField {
            detail: format!("unknown floor verdict {other}"),
        }),
    }
}
