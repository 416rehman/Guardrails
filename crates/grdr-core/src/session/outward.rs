// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Doc 06 section 13 outward session identity (`sp_<16 base32>`), cloud tags,
//! git commit/patch-id receipts, and opt-in `refs/notes/grdr` push-refspec checks (`docs/design/06`).

use grdr_crypto::{domain_hmac_sha256, encode_lower_hex};
use grdr_model::CodedError;
use serde::{Deserialize, Serialize};

const OUTWARD_SP_HMAC_DOMAIN: &str = "grdr.session.outward.sp.v1";
const PATCH_ID_HMAC_DOMAIN: &str = "grdr.outward.git.patch-id.v1";
const BASE32_LOWER_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
pub const MIN_OUTWARD_HMAC_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutwardGrade {
    Tag,
    Receipt,
    Credential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutwardLaunchTags {
    pub aws_sdk_ua_app_id: String,
    pub tf_append_user_agent: String,
    pub grdr_session: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitOutwardReceipt {
    pub external_system: String,
    pub commit_id: String,
    pub patch_id_hmac: String,
    pub session_id: String,
    pub pseudonym: String,
    pub tool_call_id: String,
    pub grade: OutwardGrade,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitNotesPushAssessment {
    NotesNotTransferred,
    AllowedOrgNotesPush,
    PushOutsideOrgViolation,
}

struct GlobCharClass {
    negated: bool,
    ranges: Vec<(char, char)>,
}

pub fn format_session_pseudonym_sp(
    raw_session_id: &str,
    device_pseudonym_key: &[u8],
) -> Result<String, CodedError> {
    if device_pseudonym_key.len() < MIN_OUTWARD_HMAC_KEY_LEN {
        return Err(CodedError::new(
            "GRDR-SESS-0003",
            format!(
                "outward pseudonym HMAC key length {} below minimum {MIN_OUTWARD_HMAC_KEY_LEN}",
                device_pseudonym_key.len()
            ),
            "Provide a CSPRNG >= 32-byte per-device pseudonym key.",
        ));
    }
    let mac = domain_hmac_sha256(
        device_pseudonym_key,
        OUTWARD_SP_HMAC_DOMAIN,
        raw_session_id.as_bytes(),
    );
    let encoded = encode_base32_80bits(&mac);
    Ok(format!("sp_{encoded}"))
}

#[must_use]
pub fn outward_launch_tags(pseudonym_sp: &str) -> OutwardLaunchTags {
    OutwardLaunchTags {
        aws_sdk_ua_app_id: format!("grdr.{pseudonym_sp}"),
        tf_append_user_agent: format!("grdr/{pseudonym_sp}"),
        grdr_session: pseudonym_sp.to_string(),
    }
}

pub fn build_git_outward_receipt(
    commit_id: &str,
    stable_patch_id: &str,
    session_id: &str,
    pseudonym_sp: &str,
    tool_call_id: &str,
    device_hmac_key: &[u8],
) -> Result<GitOutwardReceipt, CodedError> {
    if device_hmac_key.len() < MIN_OUTWARD_HMAC_KEY_LEN {
        return Err(CodedError::new(
            "GRDR-SESS-0003",
            format!(
                "git patch-id HMAC key length {} below minimum {MIN_OUTWARD_HMAC_KEY_LEN}",
                device_hmac_key.len()
            ),
            "Provide a CSPRNG >= 32-byte per-device HMAC key.",
        ));
    }
    let mac = domain_hmac_sha256(
        device_hmac_key,
        PATCH_ID_HMAC_DOMAIN,
        stable_patch_id.trim().as_bytes(),
    );
    Ok(GitOutwardReceipt {
        external_system: "git".to_string(),
        commit_id: commit_id.to_string(),
        patch_id_hmac: encode_lower_hex(&mac),
        session_id: session_id.to_string(),
        pseudonym: pseudonym_sp.to_string(),
        tool_call_id: tool_call_id.to_string(),
        grade: OutwardGrade::Receipt,
    })
}

#[must_use]
pub fn assess_git_notes_push(
    git_args: &[&str],
    remote_in_org_allowlist: bool,
) -> GitNotesPushAssessment {
    let transfers_notes = git_args.iter().any(|arg| is_notes_transfer_arg(arg));
    if !transfers_notes {
        GitNotesPushAssessment::NotesNotTransferred
    } else if remote_in_org_allowlist {
        GitNotesPushAssessment::AllowedOrgNotesPush
    } else {
        GitNotesPushAssessment::PushOutsideOrgViolation
    }
}

fn is_notes_transfer_arg(arg: &str) -> bool {
    let lower = arg.trim().to_ascii_lowercase();
    if lower == "--mirror" || lower == "--all" {
        return true;
    }
    let clean = lower.trim_start_matches('+');
    let sides = match clean.split_once(':') {
        Some((lhs, rhs)) => [lhs, rhs],
        None => [clean, ""],
    };
    sides.iter().any(|side| {
        let s = side.trim_start_matches('+');
        !s.is_empty()
            && (s.contains("refs/notes/grdr") || refspec_glob_matches(s, "refs/notes/grdr"))
    })
}

fn refspec_glob_matches(pattern: &str, target: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = target.chars().collect();
    if pat.len() > 256 || txt.len() > 256 {
        return false;
    }
    let mut dp = vec![false; txt.len().saturating_add(1)];
    if let Some(first) = dp.first_mut() {
        *first = true;
    }
    let mut pi = 0usize;
    while pi < pat.len() {
        let mut next = vec![false; txt.len().saturating_add(1)];
        let ch = pat.get(pi).copied().unwrap_or('\0');
        if ch == '*' {
            let mut matched = false;
            for (ti, &val) in dp.iter().enumerate() {
                matched = matched || val;
                if let Some(slot) = next.get_mut(ti) {
                    *slot = matched;
                }
            }
            pi = pi.saturating_add(1);
        } else if ch == '[' {
            let Some((class_len, matched_fn)) = parse_glob_class(pat.get(pi..).unwrap_or(&[]))
            else {
                for ti in 0..txt.len() {
                    if dp.get(ti).copied().unwrap_or(false)
                        && txt.get(ti) == Some(&'[')
                        && let Some(slot) = next.get_mut(ti.saturating_add(1))
                    {
                        *slot = true;
                    }
                }
                dp = next;
                pi = pi.saturating_add(1);
                continue;
            };
            for (ti, &tc) in txt.iter().enumerate() {
                if dp.get(ti).copied().unwrap_or(false)
                    && class_matches(&matched_fn, tc)
                    && let Some(slot) = next.get_mut(ti.saturating_add(1))
                {
                    *slot = true;
                }
            }
            pi = pi.saturating_add(class_len);
        } else {
            for (ti, &tc) in txt.iter().enumerate() {
                if dp.get(ti).copied().unwrap_or(false)
                    && (ch == '?' || ch == tc)
                    && let Some(slot) = next.get_mut(ti.saturating_add(1))
                {
                    *slot = true;
                }
            }
            pi = pi.saturating_add(1);
        }
        dp = next;
    }
    dp.get(txt.len()).copied().unwrap_or(false)
}

fn parse_glob_class(slice: &[char]) -> Option<(usize, GlobCharClass)> {
    if slice.first() != Some(&'[') {
        return None;
    }
    let mut idx = 1usize;
    let negated = slice.get(idx).is_some_and(|c| *c == '!' || *c == '^');
    if negated {
        idx = idx.saturating_add(1);
    }
    let mut ranges = Vec::new();
    while let Some(&c) = slice.get(idx) {
        if c == ']' && !ranges.is_empty() {
            return Some((idx.saturating_add(1), GlobCharClass { negated, ranges }));
        }
        if slice.get(idx.saturating_add(1)) == Some(&'-')
            && let Some(&end_c) = slice.get(idx.saturating_add(2))
            && end_c != ']'
        {
            ranges.push((c.min(end_c), c.max(end_c)));
            idx = idx.saturating_add(3);
        } else {
            ranges.push((c, c));
            idx = idx.saturating_add(1);
        }
    }
    None
}

fn class_matches(spec: &GlobCharClass, ch: char) -> bool {
    let hit = spec.ranges.iter().any(|&(lo, hi)| ch >= lo && ch <= hi);
    if spec.negated { !hit } else { hit }
}

fn encode_base32_80bits(digest: &[u8]) -> String {
    let mut out = String::with_capacity(16);
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;
    for &byte in digest.iter().take(10) {
        buffer = (buffer << 8) | u32::from(byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            let idx = usize::try_from((buffer >> bits) & 0x1F).unwrap_or(0);
            if let Some(&ch) = BASE32_LOWER_ALPHABET.get(idx) {
                out.push(char::from(ch));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outward_sp_pseudonym_tags_and_git_notes_refspec_work() {
        let key = b"device-hmac-key-32-bytes-minimum";
        assert!(format_session_pseudonym_sp("sess-abc", b"").is_err());
        assert!(format_session_pseudonym_sp("sess-abc", b"short").is_err());

        let sp = format_session_pseudonym_sp("sess-abc", key).unwrap();
        assert!(sp.starts_with("sp_"));
        assert_eq!(sp.len(), 19);
        let tags = outward_launch_tags(&sp);
        assert!(tags.aws_sdk_ua_app_id.len() <= 50);
        assert_eq!(tags.aws_sdk_ua_app_id, format!("grdr.{sp}"));

        assert!(build_git_outward_receipt("c1", "p", "s1", &sp, "tc1", b"short").is_err());
        let r1 = build_git_outward_receipt("c1", "patch-stable-9", "s1", &sp, "tc1", key).unwrap();
        let r2 = build_git_outward_receipt("c2-rebased", "patch-stable-9", "s1", &sp, "tc1", key)
            .unwrap();
        assert_eq!(r1.patch_id_hmac, r2.patch_id_hmac);

        assert_eq!(
            assess_git_notes_push(&["push", "origin", "main"], false),
            GitNotesPushAssessment::NotesNotTransferred
        );
        assert_eq!(
            assess_git_notes_push(&["push", "--mirror", "evil"], false),
            GitNotesPushAssessment::PushOutsideOrgViolation
        );
        assert_eq!(
            assess_git_notes_push(&["push", "evil", "+refs/*:refs/*"], false),
            GitNotesPushAssessment::PushOutsideOrgViolation
        );
        assert_eq!(
            assess_git_notes_push(&["push", "org", "refs/notes/grdr"], true),
            GitNotesPushAssessment::AllowedOrgNotesPush
        );
    }
}
