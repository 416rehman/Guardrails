// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Compiles and signs binary `GRDRFLT1` floor tables (`floor.bin` + `floor.pub`) in the
//! protected state directory and provides deny-wins in-memory `overload` fallback evaluation.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;

use grdr_crypto::{SigningKeypair, sha256_hex};
use grdr_fastpath::{FastActionClass, FastVerdict};
use grdr_model::eval::essentials_pack;
use grdr_model::{ActionClass, Mode, PolicyPack};
use grdr_peer_os::fs_open::{
    OpenNofollowAccess, check_no_ancestor_symlinks, open_nofollow_file, sync_parent_dir,
};
use grdr_wire::floor_bin::{
    FloorMatchKind, FloorRuleRecord, FloorTableDocument, encode_signed_floor_table,
    floor_verdict_rank,
};
use grdr_wire::messages::WireActionClass;
use thiserror::Error;

const FLOOR_TTL_SECS: i64 = 7 * 24 * 3600;
const ALL_FAST_ACTION_CLASSES: [FastActionClass; 15] = [
    FastActionClass::Exec,
    FastActionClass::FileRead,
    FastActionClass::FileWrite,
    FastActionClass::FileDelete,
    FastActionClass::NetConnect,
    FastActionClass::NetRequest,
    FastActionClass::LlmRequest,
    FastActionClass::McpConnect,
    FastActionClass::McpCall,
    FastActionClass::CredUse,
    FastActionClass::AgentSpawn,
    FastActionClass::ConfigChange,
    FastActionClass::Elevate,
    FastActionClass::UiAct,
    FastActionClass::DataFlow,
];

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FloorCompileError {
    #[error("GRDR-DAEM-0006: failed compiling or persisting binary floor table: {0}")]
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct CompiledFloorCache {
    pub epoch: u64,
    pub digest_hex: String,
    pub doc: FloorTableDocument,
}

impl CompiledFloorCache {
    pub fn compile_and_write(
        packs: &[PolicyPack],
        prior_rules: &[FloorRuleRecord],
        forced_deny_rule_ids: &BTreeSet<String>,
        epoch: u64,
        now_unix_s: i64,
        state_dir: &Path,
        signing_key: &SigningKeypair,
    ) -> Result<Self, FloorCompileError> {
        let essentials = essentials_pack();
        let mut combined: Vec<&PolicyPack> = Vec::with_capacity(packs.len().saturating_add(1));
        // Always prepend built-in essentials_pack so custom/remote packs sharing its ID cannot displace it.
        combined.push(&essentials);
        for pack in packs {
            if pack.id != essentials.id {
                combined.push(pack);
            }
        }

        let mut rules = Vec::new();
        for pack in combined {
            for rule in &pack.rules {
                if !rule.enabled || matches!(rule.mode, Mode::Off | Mode::Watch) {
                    continue;
                }
                let mut verdict = match rule.mode {
                    Mode::Ask => FastVerdict::StepUp,
                    Mode::Block => FastVerdict::Deny,
                    Mode::Off | Mode::Watch => continue,
                };
                if forced_deny_rule_ids.contains(&rule.id) {
                    verdict = FastVerdict::Deny;
                }
                let classes: Vec<FastActionClass> = if rule.matcher.action_classes.is_empty() {
                    ALL_FAST_ACTION_CLASSES.to_vec()
                } else {
                    rule.matcher
                        .action_classes
                        .iter()
                        .map(|&cls| map_action_class(cls))
                        .collect()
                };
                for fast_cls in classes {
                    let has_contains = rule
                        .matcher
                        .target_contains
                        .iter()
                        .any(|p| !p.trim().is_empty());
                    let has_prefixes = rule
                        .matcher
                        .target_prefixes
                        .iter()
                        .any(|p| !p.trim().is_empty());
                    for pat in &rule.matcher.target_contains {
                        if !pat.trim().is_empty() {
                            rules.push(FloorRuleRecord {
                                action_class: fast_cls,
                                verdict,
                                match_kind: FloorMatchKind::Contains,
                                rule_id: rule.id.clone(),
                                pattern: pat.clone(),
                                agents: rule.matcher.agents.clone(),
                            });
                        }
                    }
                    for pfx in &rule.matcher.target_prefixes {
                        if !pfx.trim().is_empty() {
                            rules.push(FloorRuleRecord {
                                action_class: fast_cls,
                                verdict,
                                match_kind: FloorMatchKind::Prefix,
                                rule_id: rule.id.clone(),
                                pattern: pfx.clone(),
                                agents: rule.matcher.agents.clone(),
                            });
                        }
                    }
                    if !has_contains && !has_prefixes {
                        rules.push(FloorRuleRecord {
                            action_class: fast_cls,
                            verdict,
                            match_kind: FloorMatchKind::Any,
                            rule_id: rule.id.clone(),
                            pattern: String::new(),
                            agents: rule.matcher.agents.clone(),
                        });
                    }
                }
            }
        }

        // Preserve monotonic floor non-weakening from prior compiled floor rules (`D-02`).
        for prior in prior_rules {
            let mut upgraded = prior.clone();
            if forced_deny_rule_ids.contains(&upgraded.rule_id) {
                upgraded.verdict = FastVerdict::Deny;
            }
            let covered = rules.iter().any(|cur| {
                cur.rule_id == upgraded.rule_id
                    && cur.action_class == upgraded.action_class
                    && cur.match_kind == upgraded.match_kind
                    && cur.pattern == upgraded.pattern
                    && cur.agents == upgraded.agents
                    && floor_verdict_rank(cur.verdict) >= floor_verdict_rank(upgraded.verdict)
            });
            if !covered {
                rules.push(upgraded);
            }
        }

        if rules.is_empty() {
            rules.push(FloorRuleRecord {
                action_class: FastActionClass::Exec,
                verdict: FastVerdict::Deny,
                match_kind: FloorMatchKind::Contains,
                rule_id: "FLOOR-BASELINE-RM".to_string(),
                pattern: "rm -rf /".to_string(),
                agents: Vec::new(),
            });
        }

        let doc = FloorTableDocument {
            epoch,
            expires_at_unix_s: now_unix_s.saturating_add(FLOOR_TTL_SECS),
            signer_key_id: signing_key.key_id().to_string(),
            rules,
        };
        let bytes = encode_signed_floor_table(&doc, signing_key)
            .map_err(|err| FloorCompileError::Failed(err.to_string()))?;
        let digest_hex = sha256_hex(&bytes);

        check_no_ancestor_symlinks(state_dir)
            .map_err(|err| FloorCompileError::Failed(err.to_string()))?;
        fs::create_dir_all(state_dir)
            .map_err(|err| FloorCompileError::Failed(format!("create state dir: {err}")))?;
        atomic_write_sync(state_dir, &state_dir.join("floor.bin"), &bytes)?;
        let pub_record = format!(
            "{}:{}\n",
            signing_key.key_id(),
            signing_key.public_key_b64()
        );
        atomic_write_sync(
            state_dir,
            &state_dir.join("floor.pub"),
            pub_record.as_bytes(),
        )?;

        Ok(Self {
            epoch,
            digest_hex,
            doc,
        })
    }

    #[must_use]
    pub fn evaluate_overload_fallback(
        &self,
        action_class_code: i32,
        agent: &str,
        target: &str,
        command_line: &str,
    ) -> (FastVerdict, String, String) {
        let Some(fast_cls) =
            WireActionClass::from_wire_i32(action_class_code).and_then(WireActionClass::to_fast)
        else {
            return (
                FastVerdict::Deny,
                "FLOOR-INVALID-ACTION".to_string(),
                "unspecified WireActionClass rejected under overload fallback".to_string(),
            );
        };
        let primary = if matches!(fast_cls, FastActionClass::Exec | FastActionClass::Elevate)
            && !command_line.trim().is_empty()
        {
            command_line
        } else {
            target
        };
        let mut best: Option<&FloorRuleRecord> = None;
        for rule in &self.doc.rules {
            let matched = rule.matches(fast_cls, agent, primary)
                || (primary != target && rule.matches(fast_cls, agent, target));
            if !matched {
                continue;
            }
            let replace = match best {
                None => true,
                Some(prev) => floor_verdict_rank(rule.verdict) > floor_verdict_rank(prev.verdict),
            };
            if replace {
                best = Some(rule);
            }
        }
        if let Some(hit) = best {
            let hit_id = hit.rule_id.clone();
            let msg = format!("floor fallback matched {hit_id} under overload");
            return (hit.verdict, hit_id, msg);
        }
        (
            FastVerdict::Allow,
            "FLOOR-OVERLOAD-ALLOW".to_string(),
            "no floor deny match under daemon overload fallback".to_string(),
        )
    }
}

fn atomic_write_sync(state_dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), FloorCompileError> {
    check_no_ancestor_symlinks(path).map_err(|err| FloorCompileError::Failed(err.to_string()))?;
    let suffix = grdr_wire::generate_nonce()
        .map(|s| s.chars().take(12).collect::<String>())
        .unwrap_or_else(|_| std::process::id().to_string());
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| FloorCompileError::Failed("invalid floor target path".to_string()))?;
    let tmp = path.with_file_name(format!(".{file_name}.tmp.{suffix}"));
    {
        let mut f = open_nofollow_file(&tmp, OpenNofollowAccess::TruncateCreate, 0o644)
            .map_err(|err| FloorCompileError::Failed(err.to_string()))?;
        f.write_all(bytes)
            .map_err(|err| FloorCompileError::Failed(format!("write tmp: {err}")))?;
        f.sync_all()
            .map_err(|err| FloorCompileError::Failed(format!("fsync tmp: {err}")))?;
    }
    fs::rename(&tmp, path)
        .map_err(|err| FloorCompileError::Failed(format!("rename floor file: {err}")))?;
    sync_parent_dir(state_dir).map_err(|err| FloorCompileError::Failed(err.to_string()))?;
    Ok(())
}

const fn map_action_class(cls: ActionClass) -> FastActionClass {
    match cls {
        ActionClass::Exec => FastActionClass::Exec,
        ActionClass::FileRead => FastActionClass::FileRead,
        ActionClass::FileWrite => FastActionClass::FileWrite,
        ActionClass::FileDelete => FastActionClass::FileDelete,
        ActionClass::NetConnect => FastActionClass::NetConnect,
        ActionClass::NetRequest => FastActionClass::NetRequest,
        ActionClass::LlmRequest => FastActionClass::LlmRequest,
        ActionClass::McpConnect => FastActionClass::McpConnect,
        ActionClass::McpCall => FastActionClass::McpCall,
        ActionClass::CredUse => FastActionClass::CredUse,
        ActionClass::AgentSpawn => FastActionClass::AgentSpawn,
        ActionClass::ConfigChange => FastActionClass::ConfigChange,
        ActionClass::Elevate => FastActionClass::Elevate,
        ActionClass::UiAct => FastActionClass::UiAct,
        ActionClass::DataFlow => FastActionClass::DataFlow,
    }
}
