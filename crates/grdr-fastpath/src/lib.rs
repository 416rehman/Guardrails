// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_std]
#![deny(clippy::arithmetic_side_effects)]

pub const FLOOR_FORMAT_MAGIC: &[u8; 8] = b"GRDRFLT1";
pub const FLOOR_FORMAT_VERSION: u32 = 1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastActionClass {
    Exec = 0,
    FileRead = 1,
    FileWrite = 2,
    FileDelete = 3,
    NetConnect = 4,
    NetRequest = 5,
    LlmRequest = 6,
    McpConnect = 7,
    McpCall = 8,
    CredUse = 9,
    AgentSpawn = 10,
    ConfigChange = 11,
    Elevate = 12,
    UiAct = 13,
    DataFlow = 14,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastVerdict {
    Allow = 0,
    StepUp = 1,
    Deny = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorRuleRef<'a> {
    pub rule_id: &'a str,
    pub action_mask: u32,
    pub prefixes: &'a [&'a str],
    pub contains: &'a [&'a str],
    pub agents: &'a [&'a str],
    pub verdict: FastVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorHit<'a> {
    pub rule_id: &'a str,
    pub verdict: FastVerdict,
}

impl FastActionClass {
    pub const fn bit(self) -> u32 {
        1u32 << (self as u8)
    }

    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Exec),
            1 => Some(Self::FileRead),
            2 => Some(Self::FileWrite),
            3 => Some(Self::FileDelete),
            4 => Some(Self::NetConnect),
            5 => Some(Self::NetRequest),
            6 => Some(Self::LlmRequest),
            7 => Some(Self::McpConnect),
            8 => Some(Self::McpCall),
            9 => Some(Self::CredUse),
            10 => Some(Self::AgentSpawn),
            11 => Some(Self::ConfigChange),
            12 => Some(Self::Elevate),
            13 => Some(Self::UiAct),
            14 => Some(Self::DataFlow),
            _ => None,
        }
    }
}

pub fn evaluate_floor_entries<'a>(
    entries: &[FloorRuleRef<'a>],
    action: FastActionClass,
    agent: &str,
    target: &str,
) -> Option<FloorHit<'a>> {
    let action_bit = action.bit();
    for entry in entries {
        if entry.action_mask != 0 && (entry.action_mask & action_bit) == 0 {
            continue;
        }
        if !entry.agents.is_empty() && !entry.agents.iter().any(|a| eq_ascii_icase(a, agent)) {
            continue;
        }
        if entry.prefixes.is_empty() && entry.contains.is_empty() {
            return Some(FloorHit {
                rule_id: entry.rule_id,
                verdict: entry.verdict,
            });
        }
        let prefix_hit = entry
            .prefixes
            .iter()
            .any(|p| starts_with_norm_icase(target, p));
        let contains_hit = entry
            .contains
            .iter()
            .any(|n| !n.is_empty() && contains_norm_icase(target, n));
        if prefix_hit || contains_hit {
            return Some(FloorHit {
                rule_id: entry.rule_id,
                verdict: entry.verdict,
            });
        }
    }
    None
}

fn norm_byte(byte: u8) -> u8 {
    if byte == b'\\' {
        b'/'
    } else {
        byte.to_ascii_lowercase()
    }
}

fn eq_ascii_icase(a: &str, b: &str) -> bool {
    let left = a.as_bytes();
    let right = b.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn starts_with_norm_icase(haystack: &str, prefix: &str) -> bool {
    let h = haystack.as_bytes();
    let p = prefix.as_bytes();
    if h.len() < p.len() {
        return false;
    }
    h.iter()
        .zip(p.iter())
        .all(|(x, y)| norm_byte(*x) == norm_byte(*y))
}

fn contains_norm_icase(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() {
        return true;
    }
    if h.len() < n.len() {
        return false;
    }
    h.windows(n.len()).any(|window| {
        window
            .iter()
            .zip(n.iter())
            .all(|(x, y)| norm_byte(*x) == norm_byte(*y))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_std_floor_table_matches_slash_and_case_variants() {
        let prefixes: [&str; 0] = [];
        let contains = [".claude/", ".claude.json"];
        let agents: [&str; 0] = [];
        let entries = [FloorRuleRef {
            rule_id: "essentials.agent-control-files",
            action_mask: FastActionClass::FileWrite.bit() | FastActionClass::FileDelete.bit(),
            prefixes: &prefixes,
            contains: &contains,
            agents: &agents,
            verdict: FastVerdict::Deny,
        }];

        let hit = evaluate_floor_entries(
            &entries,
            FastActionClass::FileWrite,
            "claude-code",
            r"C:\repo\.CLAUDE\settings.json",
        );
        assert_eq!(
            hit,
            Some(FloorHit {
                rule_id: "essentials.agent-control-files",
                verdict: FastVerdict::Deny,
            })
        );

        let safe = evaluate_floor_entries(
            &entries,
            FastActionClass::FileRead,
            "claude-code",
            ".claude/settings.json",
        );
        assert!(safe.is_none());
    }
}
