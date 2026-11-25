pub mod emit_rust;
pub mod emit_web;
pub mod loader;
pub mod model;
pub mod toml_doc;

use std::fs;
use std::path::{Path, PathBuf};

use crate::emit_rust::{render_grdr_messages, render_grdr_strings};
use crate::emit_web::{render_i18n_generated_ts, render_tokens_css, render_tokens_ts};
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

/// Renders all deterministic Rust and Web artifacts from the loaded `InterfaceBundle`.
#[must_use]
pub fn render_artifacts(bundle: &InterfaceBundle) -> Vec<GeneratedArtifact> {
    vec![
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
    ]
}

/// Runs generation (`RunMode::Write`) or drift verification (`RunMode::Check`) at `repo_root`.
pub fn run(repo_root: &Path, mode: RunMode) -> Result<Vec<PathBuf>, GenError> {
    let bundle = load_interface_bundle(repo_root)?;
    let artifacts = render_artifacts(&bundle);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> PathBuf {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("crate sits under <repo>/crates/grdr-interface-gen")
            .to_path_buf()
    }

    fn copy_dir_recursive(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).expect("create temp dir");
        for entry in fs::read_dir(src).expect("read dir") {
            let entry = entry.expect("dir entry");
            let ty = entry.file_type().expect("file type");
            let target = dst.join(entry.file_name());
            if ty.is_dir() {
                copy_dir_recursive(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), &target).expect("copy file");
            }
        }
    }

    #[test]
    fn loads_workspace_interface_and_matches_checked_in_artifacts_with_zero_drift() {
        let root = workspace_root();
        let checked = run(&root, RunMode::Check).expect("generated files must have zero drift");
        assert_eq!(checked.len(), 5);
    }

    #[test]
    fn write_and_check_round_trip_detects_drift_in_temp_workspace() {
        let root = workspace_root();
        let temp_root =
            std::env::temp_dir().join(format!("grdr-interface-gen-test-{}", std::process::id()));
        if temp_root.exists() {
            fs::remove_dir_all(&temp_root).expect("cleanup old temp");
        }
        copy_dir_recursive(
            &root.join("contracts/interface"),
            &temp_root.join("contracts/interface"),
        );

        let written = run(&temp_root, RunMode::Write).expect("write generated artifacts");
        assert_eq!(written.len(), 5);
        run(&temp_root, RunMode::Check).expect("freshly written files pass --check");

        let tokens_path = temp_root.join("web/packages/tokens/src/tokens.css");
        fs::write(&tokens_path, "/* drifted */\n").expect("inject drift");
        let err = run(&temp_root, RunMode::Check).expect_err("must detect drift");
        assert!(err.to_string().contains("GRDR-GEN-0006"));
        assert!(
            err.to_string()
                .contains("web/packages/tokens/src/tokens.css")
        );

        fs::remove_dir_all(&temp_root).expect("cleanup temp");
    }

    #[test]
    fn validation_rejects_forbidden_vocabulary_and_missing_references() {
        let root = workspace_root();
        let temp_root =
            std::env::temp_dir().join(format!("grdr-interface-gen-val-{}", std::process::id()));
        if temp_root.exists() {
            fs::remove_dir_all(&temp_root).expect("cleanup old temp");
        }
        copy_dir_recursive(
            &root.join("contracts/interface"),
            &temp_root.join("contracts/interface"),
        );

        let common_path = temp_root.join("contracts/interface/strings/src/common.mf2.toml");
        let original = fs::read_to_string(&common_path).expect("read common.mf2.toml");
        let bad = format!(
            "{original}\n[\"console.bad.example\"]\ndesc = \"Bad\"\nmax = 40\nrisk = \"normal\"\nmsg = \"Check device posture\"\n"
        );
        fs::write(&common_path, bad).expect("write forbidden term");
        let err = load_interface_bundle(&temp_root).expect_err("must reject forbidden vocabulary");
        assert!(err.to_string().contains("GRDR-GEN-0004"));
        assert!(err.to_string().contains("posture"));

        fs::write(&common_path, original).expect("restore common.mf2.toml");
        let pres_path = temp_root.join("contracts/interface/presentation.toml");
        let pres_orig = fs::read_to_string(&pres_path).expect("read presentation.toml");
        let bad_pres = format!(
            "{pres_orig}\n[[entry]]\nenum = \"Mode\"\nvalue = \"broken\"\nlabel = \"mode.off.label\"\nicon = \"missing.icon\"\ntone = \"neutral\"\n"
        );
        fs::write(&pres_path, bad_pres).expect("write missing icon ref");
        let icon_err = load_interface_bundle(&temp_root).expect_err("must reject missing icon");
        assert!(icon_err.to_string().contains("missing.icon"));

        fs::remove_dir_all(&temp_root).expect("cleanup temp");
    }
}
