// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod emit_contracts;
pub mod emit_i18n;
pub mod emit_rust;
pub mod emit_rust_extra;
pub mod emit_web;
pub mod loader;
pub mod loader_extra;
pub mod model;
pub mod toml_doc;
pub mod validate;
pub mod validate_extra;

use std::fs;
use std::path::{Path, PathBuf};

use crate::emit_contracts::{
    render_ansi_palette_json, render_cli_json, render_email_tokens_css, render_notifications_json,
    render_routes_json, render_rune_theme_json, render_shortcuts_json,
};
use crate::emit_i18n::render_i18n_generated_ts;
use crate::emit_rust::{render_grdr_messages, render_grdr_strings};
use crate::emit_web::{render_tokens_css, render_tokens_ts};
use crate::loader::load_interface_bundle;
use crate::model::{GenError, InterfaceBundle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    Write,
    Check,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedArtifact {
    pub relative_path: &'static str,
    pub content: String,
}

/// Renders all deterministic Rust, Web, and cross-surface contract artifacts from `InterfaceBundle`.
pub fn render_artifacts(bundle: &InterfaceBundle) -> Result<Vec<GeneratedArtifact>, GenError> {
    Ok(vec![
        GeneratedArtifact {
            relative_path: "crates/grdr-strings/src/generated.rs",
            content: render_grdr_strings(bundle),
        },
        GeneratedArtifact {
            relative_path: "crates/grdr-messages/src/generated.rs",
            content: render_grdr_messages(bundle),
        },
        GeneratedArtifact {
            relative_path: "web/packages/tokens/src/tokens.css",
            content: render_tokens_css(bundle),
        },
        GeneratedArtifact {
            relative_path: "web/packages/tokens/src/index.ts",
            content: render_tokens_ts(bundle),
        },
        GeneratedArtifact {
            relative_path: "web/packages/i18n/src/generated.ts",
            content: render_i18n_generated_ts(bundle),
        },
        GeneratedArtifact {
            relative_path: "contracts/interface/generated/rune-theme.json",
            content: render_rune_theme_json(bundle)?,
        },
        GeneratedArtifact {
            relative_path: "contracts/interface/generated/routes.json",
            content: render_routes_json(bundle)?,
        },
        GeneratedArtifact {
            relative_path: "contracts/interface/generated/cli-contract.json",
            content: render_cli_json(bundle)?,
        },
        GeneratedArtifact {
            relative_path: "contracts/interface/generated/shortcuts.json",
            content: render_shortcuts_json(bundle)?,
        },
        GeneratedArtifact {
            relative_path: "contracts/interface/generated/notifications.json",
            content: render_notifications_json(bundle)?,
        },
        GeneratedArtifact {
            relative_path: "contracts/interface/generated/ansi-palette.json",
            content: render_ansi_palette_json(bundle)?,
        },
        GeneratedArtifact {
            relative_path: "contracts/interface/generated/email-tokens.css",
            content: render_email_tokens_css(bundle),
        },
    ])
}

/// Runs generation (`RunMode::Write`) or drift verification (`RunMode::Check`) at `repo_root`.
pub fn run(repo_root: &Path, mode: RunMode) -> Result<Vec<PathBuf>, GenError> {
    let bundle = load_interface_bundle(repo_root)?;
    let artifacts = render_artifacts(&bundle)?;

    match mode {
        RunMode::Write => {
            let mut written = Vec::with_capacity(artifacts.len());
            for artifact in artifacts {
                let target = repo_root.join(artifact.relative_path);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|source| GenError::Io {
                        path: parent.to_path_buf(),
                        source,
                    })?;
                }
                fs::write(&target, artifact.content.as_bytes()).map_err(|source| GenError::Io {
                    path: target.clone(),
                    source,
                })?;
                written.push(target);
            }
            Ok(written)
        }
        RunMode::Check => {
            let mut drifted = Vec::new();
            let mut checked = Vec::with_capacity(artifacts.len());
            for artifact in artifacts {
                let target = repo_root.join(artifact.relative_path);
                let existing = match fs::read_to_string(&target) {
                    Ok(content) => normalize_lf(&content),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(source) => {
                        return Err(GenError::Io {
                            path: target,
                            source,
                        });
                    }
                };
                if existing != normalize_lf(&artifact.content) {
                    drifted.push(artifact.relative_path);
                }
                checked.push(target);
            }
            if !drifted.is_empty() {
                return Err(GenError::Drift {
                    count: drifted.len(),
                    files: drifted.join(", "),
                });
            }
            Ok(checked)
        }
    }
}

fn normalize_lf(raw: &str) -> String {
    raw.replace("\r\n", "\n")
}
