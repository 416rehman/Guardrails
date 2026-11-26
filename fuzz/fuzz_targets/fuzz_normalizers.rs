// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use std::collections::BTreeMap;

use grdr_core::analyze::cmd::{ShellInput, canonicalise_shell, canonicalise_shell_plausible};
use grdr_core::analyze::content::{redact_sensitive_text, scan_deterministic_content};
use grdr_core::analyze::decode::decode_payload_layers;
use grdr_core::analyze::deflate::gunzip_bounded;
use grdr_core::analyze::mcp_diff::{McpDriftClass, McpToolSpec, diff_mcp_manifests};
use grdr_core::analyze::net::{HostClassifierConfig, classify_url_or_host};
use grdr_core::analyze::path::{OsKind, PathFacts, SymlinkResolution, VolumeCase, resolve_path};
use grdr_core::analyze::types::{Resolution, ShellDialect, ShellLimits};
use grdr_core::analyze::{
    canonicalize_path, classify_target, normalize_attempt_target, normalize_command,
};
use grdr_model::{ActionClass, CommandParseStatus};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 262_144 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let cmd = normalize_command(&text);
    assert!(cmd.segments.iter().all(|seg| !seg.is_empty()));
    let segments_free_of_shell_meta = !cmd.segments.is_empty()
        && cmd.segments.iter().all(|seg| {
            !seg.contains([
                '\\', '\'', '"', ';', '&', '|', '\n', '\r', '^', '`', '\u{2018}', '\u{2019}',
                '\u{201A}', '\u{201B}', '\u{201C}', '\u{201D}', '\u{201E}',
            ])
        });
    if cmd.status == CommandParseStatus::Resolved && segments_free_of_shell_meta {
        let again = normalize_command(&cmd.canonical_text);
        assert_eq!(again.status, CommandParseStatus::Resolved);
        assert!(!again.opaque);
        assert_eq!(again.canonical_text, cmd.canonical_text);
        assert_eq!(again.segments, cmd.segments);
    }

    let canon_path = canonicalize_path(&text);
    assert_eq!(canonicalize_path(&canon_path), canon_path);
    assert!(!canon_path.contains('\0'));

    let mut env = BTreeMap::new();
    env.insert(b"SAFE_CMD".to_vec(), b"echo".to_vec());
    if !data.is_empty() {
        let slice_len = data.len().min(64);
        if let Some(val) = data.get(..slice_len) {
            env.insert(b"FUZZ_VAR".to_vec(), val.to_vec());
        }
    }

    let limits = ShellLimits::from_schema();
    let max_clauses = usize::try_from(limits.words_max).unwrap_or(usize::MAX);
    for dialect in [
        ShellDialect::Posix,
        ShellDialect::PowerShell,
        ShellDialect::Cmd,
    ] {
        if let Resolution::Resolved(tree) = canonicalise_shell(
            &ShellInput {
                command: data.to_vec(),
                dialect,
                env: env.clone(),
            },
            &limits,
        ) {
            assert!(tree.clauses.len() <= max_clauses);
        }
    }

    if let Resolution::Resolved(tree) = canonicalise_shell_plausible(data, &env, &limits) {
        assert!(tree.clauses.len() <= max_clauses);
        assert!(
            !tree.canonical_lines.is_empty()
                || tree
                    .clauses
                    .iter()
                    .all(|c| c.argv.iter().all(String::is_empty))
        );
        for line in &tree.canonical_lines {
            assert!(!line.contains('\0'));
        }
    }

    let path_res = resolve_path(
        &text,
        Some(&PathFacts {
            os: OsKind::Windows,
            volume_case: VolumeCase::CaseInsensitive,
            symlink: SymlinkResolution::Direct,
            workspace_root: Some("C:/workspace".into()),
        }),
    );
    if text.contains('\0') {
        assert!(path_res.is_malformed());
    }

    let url_res = classify_url_or_host(&text, &HostClassifierConfig::default());
    if let Resolution::Resolved(norm) = url_res {
        assert!(!norm.canonical_host.is_empty());
    }

    let (layers, decoded) = decode_payload_layers(data);
    assert!(layers <= 3);
    assert!(decoded.iter().all(|v| v.len() <= 1_048_576));

    if let Ok(unpacked) = gunzip_bounded(data, 65_536) {
        assert!(unpacked.len() <= 65_536);
    }

    let content_rep = scan_deterministic_content(data);
    for m in &content_rep.matches {
        assert!(m.span.start <= m.span.end);
    }
    let redacted = redact_sensitive_text(&text);
    assert_eq!(redact_sensitive_text(&redacted), redacted);

    let pinned_spec = McpToolSpec {
        name: "pinned_tool".into(),
        description: "Baseline description".into(),
        input_schema: serde_json::json!({
            "type": "object",
            "required": ["q"],
            "properties": { "q": { "type": "string" } },
            "additionalProperties": false
        }),
        read_only_hint: true,
        destructive_hint: false,
    };
    let curr_spec = McpToolSpec {
        name: text.chars().take(64).collect(),
        description: text.chars().take(256).collect(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": { "q": { "type": "string" } }
        }),
        read_only_hint: true,
        destructive_hint: false,
    };
    let diff = diff_mcp_manifests(&[pinned_spec], &[curr_spec], &["pinned_tool".into()]);
    assert!(
        diff.drifts
            .iter()
            .all(|d| d.class != McpDriftClass::DuplicateToolName)
    );

    let exec_analysis = classify_target(ActionClass::Exec, &text);
    if cmd.status == CommandParseStatus::Malformed {
        assert_eq!(exec_analysis.command_status, CommandParseStatus::Malformed);
        assert!(
            exec_analysis
                .risk_tags
                .iter()
                .any(|t| t == "exec.malformed")
        );
        assert!(exec_analysis.risk_score >= 85);
    } else if cmd.status == CommandParseStatus::Unresolved {
        assert!(matches!(
            exec_analysis.command_status,
            CommandParseStatus::Unresolved | CommandParseStatus::Malformed
        ));
        assert!(
            exec_analysis
                .risk_tags
                .iter()
                .any(|t| t == "exec.opaque" || t == "exec.malformed")
        );
        assert!(exec_analysis.risk_score >= 65);
    }

    let bare_plausible = canonicalise_shell_plausible(text.as_bytes(), &BTreeMap::new(), &limits);
    match bare_plausible {
        Resolution::Malformed(_) => {
            assert_eq!(exec_analysis.command_status, CommandParseStatus::Malformed);
        }
        Resolution::Unresolved(_) => {
            assert!(matches!(
                exec_analysis.command_status,
                CommandParseStatus::Unresolved | CommandParseStatus::Malformed
            ));
        }
        Resolution::Resolved(_) => {}
    }

    for class in [
        ActionClass::FileRead,
        ActionClass::FileWrite,
        ActionClass::FileDelete,
        ActionClass::NetConnect,
        ActionClass::NetRequest,
        ActionClass::DataFlow,
        ActionClass::McpCall,
        ActionClass::Elevate,
    ] {
        let (norm, norm_status) = normalize_attempt_target(class, &text);
        let analysis = classify_target(class, &text);
        assert_eq!(analysis.normalized_target, norm);
        assert!(analysis.risk_score <= 100);
        if matches!(class, ActionClass::Elevate) {
            assert!(matches!(
                (norm_status, analysis.command_status),
                (CommandParseStatus::Resolved, _)
                    | (
                        CommandParseStatus::Unresolved,
                        CommandParseStatus::Unresolved | CommandParseStatus::Malformed
                    )
                    | (CommandParseStatus::Malformed, CommandParseStatus::Malformed)
            ));
        } else {
            assert_eq!(analysis.command_status, norm_status);
        }
        if analysis.command_status == CommandParseStatus::Malformed {
            assert!(analysis.risk_tags.iter().any(|t| t == "exec.malformed"));
        } else if analysis.command_status == CommandParseStatus::Unresolved {
            assert!(analysis.risk_tags.iter().any(|t| t == "exec.opaque"));
        }
    }
});
