// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};

use grdr_model::AssuranceLevel;

const EXACT_SENSITIVE_ENV_KEYS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "NPM_TOKEN",
    "DOCKER_PASSWORD",
];

const SENSITIVE_ENV_SUBSTRINGS: &[&str] = &[
    "_SECRET",
    "_TOKEN",
    "_API_KEY",
    "_PRIVATE_KEY",
    "_PASSWORD",
    "_CREDENTIAL",
];

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("GRDR-SANDBOX-0001: contained command program cannot be empty")]
    EmptyProgram,
    #[error("GRDR-SANDBOX-0002: working directory `{0}` does not exist or is not a directory")]
    InvalidWorkdir(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentMode {
    ObserveOnly,
    SanitizedEnv,
    WorkspaceContained,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub session_id: String,
    pub agent_name: String,
    pub mode: ContainmentMode,
    pub workdir: Option<PathBuf>,
    pub extra_allow_env: Vec<String>,
    pub strip_secret_env: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxReport {
    pub mode: ContainmentMode,
    pub effective_assurance: AssuranceLevel,
    pub stripped_env_vars: Vec<String>,
    pub workdir: Option<String>,
    pub partial_reason: Option<String>,
}

pub fn is_sensitive_env_key(key: &str) -> bool {
    let upper = key.trim().to_ascii_uppercase();
    if EXACT_SENSITIVE_ENV_KEYS.iter().any(|exact| upper == *exact) {
        return true;
    }
    SENSITIVE_ENV_SUBSTRINGS
        .iter()
        .any(|needle| upper.contains(needle))
}

pub fn prepare_contained_command(
    program: &str,
    args: &[String],
    spec: &SandboxSpec,
    inherited_env: &[(String, String)],
) -> Result<(Command, SandboxReport), SandboxError> {
    if program.trim().is_empty() {
        return Err(SandboxError::EmptyProgram);
    }

    let workdir_display = if let Some(dir) = &spec.workdir {
        if !dir.is_dir() {
            return Err(SandboxError::InvalidWorkdir(dir.display().to_string()));
        }
        Some(dir.display().to_string())
    } else {
        None
    };

    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(dir) = &spec.workdir {
        cmd.current_dir(dir);
    }

    let mut stripped_env_vars = Vec::new();
    if spec.mode != ContainmentMode::ObserveOnly && spec.strip_secret_env {
        cmd.env_clear();
        for (key, val) in inherited_env {
            let explicitly_allowed = spec
                .extra_allow_env
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(key));
            if is_sensitive_env_key(key) && !explicitly_allowed {
                stripped_env_vars.push(key.clone());
            } else {
                cmd.env(key, val);
            }
        }
        stripped_env_vars.sort();
    }

    cmd.env("GRDR_SESSION_ID", &spec.session_id);
    cmd.env("GRDR_AGENT_NAME", &spec.agent_name);
    if spec.mode != ContainmentMode::ObserveOnly {
        cmd.env("GRDR_CONTAINED", "1");
    }

    let (effective_assurance, partial_reason) = match spec.mode {
        ContainmentMode::ObserveOnly => (
            AssuranceLevel::Al1Observed,
            Some("observe-only launch without containment".into()),
        ),
        ContainmentMode::SanitizedEnv | ContainmentMode::WorkspaceContained => (
            AssuranceLevel::Al2Guided,
            Some(
                "engine-sandbox-partial: user-mode env/workdir isolation without kernel namespace"
                    .into(),
            ),
        ),
    };

    Ok((
        cmd,
        SandboxReport {
            mode: spec.mode,
            effective_assurance,
            stripped_env_vars,
            workdir: workdir_display,
            partial_reason,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_sensitive_env_vars_and_honors_allowlist() {
        let workdir = std::env::temp_dir();
        let spec = SandboxSpec {
            session_id: "sess-sb-1".into(),
            agent_name: "claude-code".into(),
            mode: ContainmentMode::WorkspaceContained,
            workdir: Some(workdir),
            extra_allow_env: vec!["OPENAI_API_KEY".into()],
            strip_secret_env: true,
        };
        let env = vec![
            ("PATH".into(), "/usr/bin".into()),
            ("GITHUB_TOKEN".into(), "ghp_secret_value_123".into()),
            ("CUSTOM_SECRET".into(), "top_secret".into()),
            ("OPENAI_API_KEY".into(), "sk-allowed".into()),
        ];

        let (cmd, report) =
            prepare_contained_command("git", &["status".into()], &spec, &env).unwrap();

        assert_eq!(report.effective_assurance, AssuranceLevel::Al2Guided);
        assert!(
            report
                .partial_reason
                .as_deref()
                .is_some_and(|r| r.contains("engine-sandbox-partial"))
        );
        assert_eq!(
            report.stripped_env_vars,
            vec!["CUSTOM_SECRET", "GITHUB_TOKEN"]
        );
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("ghp_secret_value_123"));

        let child_envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().to_string(),
                    v.map(|val| val.to_string_lossy().to_string()),
                )
            })
            .collect();
        assert!(
            child_envs
                .iter()
                .any(|(k, v)| k == "GRDR_CONTAINED" && v.as_deref() == Some("1"))
        );
        assert!(child_envs.iter().any(|(k, _)| k == "OPENAI_API_KEY"));
        assert!(!child_envs.iter().any(|(k, _)| k == "GITHUB_TOKEN"));
    }

    #[test]
    fn rejects_empty_program_and_missing_workdir() {
        let spec = SandboxSpec {
            session_id: "s1".into(),
            agent_name: "claude-code".into(),
            mode: ContainmentMode::SanitizedEnv,
            workdir: None,
            extra_allow_env: vec![],
            strip_secret_env: true,
        };
        assert!(matches!(
            prepare_contained_command("", &[], &spec, &[]),
            Err(SandboxError::EmptyProgram)
        ));

        let bad_dir = SandboxSpec {
            workdir: Some(PathBuf::from("this-dir-definitely-does-not-exist-grdr")),
            ..spec
        };
        assert!(matches!(
            prepare_contained_command("git", &[], &bad_dir, &[]),
            Err(SandboxError::InvalidWorkdir(_))
        ));
    }
}
