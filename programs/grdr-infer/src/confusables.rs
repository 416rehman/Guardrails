// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Unicode confusable, invisible, combining-mark, whitespace, and escape helpers.

use unicode_normalization::char::canonical_combining_class;

#[path = "confusables_tables.rs"]
mod confusables_tables;

use confusables_tables::COMBINING_MN_ME_RANGES;

const MAX_ANSI_SEQ_BYTES: usize = 256;

#[must_use]
pub(crate) fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

#[must_use]
pub(crate) fn is_tag_char(ch: char) -> bool {
    ('\u{E0000}'..='\u{E007F}').contains(&ch)
}

#[must_use]
pub(crate) fn is_zero_width_or_invisible(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{070F}'
            | '\u{08E2}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0080}'..='\u{E00FF}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

#[must_use]
pub(crate) fn is_combining_mark_to_strip(ch: char) -> bool {
    if canonical_combining_class(ch) != 0 {
        return true;
    }
    let cp = u32::from(ch);
    COMBINING_MN_ME_RANGES
        .binary_search_by(|&(lo, hi)| {
            if cp < lo {
                std::cmp::Ordering::Greater
            } else if cp > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

#[must_use]
pub(crate) fn is_obfuscation_combining_mark(ch: char) -> bool {
    matches!(ch, '\u{0334}'..='\u{0338}' | '\u{034F}')
}

#[must_use]
pub(crate) fn is_safe_quote_char(ch: char) -> bool {
    !ch.is_control()
        && !is_bidi_control(ch)
        && !is_tag_char(ch)
        && !is_zero_width_or_invisible(ch)
        && !is_obfuscation_combining_mark(ch)
}

#[must_use]
pub(crate) fn is_normalizable_whitespace(ch: char) -> bool {
    ch.is_whitespace()
}

#[must_use]
pub(crate) fn is_visible_quote_char(ch: char) -> bool {
    is_safe_quote_char(ch) && !is_normalizable_whitespace(ch) && !is_combining_mark_to_strip(ch)
}

#[must_use]
pub(crate) fn is_c1_escape_introducer(ch: char) -> bool {
    matches!(
        ch,
        '\u{009B}' | '\u{009D}' | '\u{0090}' | '\u{0098}' | '\u{009E}' | '\u{009F}'
    )
}

#[must_use]
pub(crate) fn fold_homoglyph_and_case(ch: char) -> (char, bool) {
    let mapped = match ch {
        'A'..='Z' => return (ch.to_ascii_lowercase(), false),
        'а' | 'А' | 'α' | 'Α' | 'ᴀ' | '\u{0251}' => 'a',
        'в' | 'В' | 'β' | 'Β' | 'ʙ' | 'ь' | 'Ь' => 'b',
        'с' | 'С' | 'ϲ' | 'Ϲ' | 'ᴄ' | 'ҫ' => 'c',
        'ԁ' | 'Ԁ' | 'ᴅ' => 'd',
        'е' | 'Е' | 'ε' | 'Ε' | 'є' | 'Є' | 'ҽ' | 'ᴇ' => 'e',
        'ғ' | 'Ғ' | 'ꜰ' => 'f',
        'ɡ' | 'ɢ' | 'ց' => 'g',
        'н' | 'Н' | 'η' | 'Η' | 'һ' | 'Һ' | 'ʜ' | '\u{0570}' => 'h',
        'і' | 'І' | 'ι' | 'Ι' | 'ӏ' | 'Ӏ' | 'ı' | 'ɪ' => 'i',
        'ј' | 'Ј' | 'ʝ' | 'ᴊ' | '\u{0237}' => 'j',
        'к' | 'К' | 'κ' | 'Κ' | 'қ' | 'Қ' | 'ᴋ' => 'k',
        'ʟ' | 'ł' => 'l',
        'м' | 'М' | 'μ' | 'Μ' | 'ᴍ' => 'm',
        'Ν' | 'ո' | 'ɴ' => 'n',
        'о' | 'О' | 'ο' | 'Ο' | 'ᴏ' | 'օ' => 'o',
        'р' | 'Р' | 'ρ' | 'Ρ' | 'ᴘ' => 'p',
        'ԛ' | 'Ԛ' => 'q',
        'ʀ' | 'ᴦ' => 'r',
        'ѕ' | 'Ѕ' | 'ς' | 'ꜱ' => 's',
        'т' | 'Т' | 'τ' | 'Τ' | 'ᴛ' => 't',
        'ᴜ' | 'ս' => 'u',
        'ν' | 'ᴠ' | 'ѵ' | 'Ѵ' => 'v',
        'ԝ' | 'Ԝ' | 'ᴡ' | 'ա' => 'w',
        'х' | 'Х' | 'χ' | 'Χ' | '×' => 'x',
        'у' | 'У' | 'υ' | 'Υ' | 'ү' | 'Ү' | 'ʏ' => 'y',
        'ᴢ' | '\u{0396}' => 'z',
        other => return (other.to_ascii_lowercase(), false),
    };
    (mapped, true)
}

/// Strips validated CSI or ST-terminated escape sequences without hiding trailing text on
/// unterminated sequences (falls back to stripping only the escape introducer).
#[must_use]
pub(crate) fn advance_escape_sequence(raw: &str, bytes: &[u8], start: usize, intro: char) -> usize {
    if intro != '\u{001B}' {
        let after_c1 = start.saturating_add(intro.len_utf8());
        let end = match intro {
            '\u{009B}' => scan_csi_body(bytes, after_c1).unwrap_or(after_c1),
            '\u{009D}' | '\u{0090}' | '\u{0098}' | '\u{009E}' | '\u{009F}' => {
                scan_st_terminated_body(raw, bytes, after_c1).unwrap_or(after_c1)
            }
            _ => after_c1,
        };
        return ensure_char_boundary(raw, end, after_c1);
    }

    let after_esc = start.saturating_add(1);
    let Some(&second) = bytes.get(after_esc) else {
        return raw.len();
    };
    let intro_two = after_esc.saturating_add(1);
    let end = match second {
        b'[' => scan_csi_body(bytes, intro_two).unwrap_or(intro_two),
        b']' | b'P' | b'X' | b'^' | b'_' => {
            scan_st_terminated_body(raw, bytes, intro_two).unwrap_or(intro_two)
        }
        0x40..=0x5F => intro_two,
        _ => after_esc,
    };
    ensure_char_boundary(raw, end, after_esc)
}

fn scan_csi_body(bytes: &[u8], body_start: usize) -> Option<usize> {
    let limit = bytes
        .len()
        .min(body_start.saturating_add(MAX_ANSI_SEQ_BYTES));
    let mut cursor = body_start;
    while cursor < limit {
        let &b = bytes.get(cursor)?;
        if (0x40..=0x7E).contains(&b) {
            return Some(cursor.saturating_add(1));
        }
        if !(0x20..=0x3F).contains(&b) {
            return None;
        }
        cursor = cursor.saturating_add(1);
    }
    None
}

fn scan_st_terminated_body(raw: &str, bytes: &[u8], body_start: usize) -> Option<usize> {
    let limit = bytes
        .len()
        .min(body_start.saturating_add(MAX_ANSI_SEQ_BYTES));
    let mut cursor = body_start;
    while cursor < limit {
        let &b = bytes.get(cursor)?;
        if b == 0x07 {
            return Some(cursor.saturating_add(1));
        }
        if b == 0x1B {
            if bytes.get(cursor.saturating_add(1)) == Some(&b'\\') {
                return Some(cursor.saturating_add(2));
            }
            return None;
        }
        if raw.is_char_boundary(cursor)
            && let Some(tail) = raw.get(cursor..)
            && let Some(ch) = tail.chars().next()
            && ch == '\u{009C}'
        {
            return Some(cursor.saturating_add(ch.len_utf8()));
        }
        cursor = cursor.saturating_add(1);
    }
    None
}

fn ensure_char_boundary(raw: &str, candidate: usize, fallback: usize) -> usize {
    if raw.is_char_boundary(candidate) {
        candidate
    } else if raw.is_char_boundary(fallback) {
        fallback
    } else {
        raw.len()
    }
}
