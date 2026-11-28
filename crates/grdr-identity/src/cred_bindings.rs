// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::IdentityError;

pub const MAX_AWS_UA_APP_ID_CHARS: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperTool {
    Git,
    Gh,
    Aws,
    Gcp,
    Docker,
    Kube,
    Npm,
    Pypi,
    Ssh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionGradeKind {
    Proxy,
    Tag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedBindingSpec {
    pub tool: HelperTool,
    pub env_vars: BTreeMap<String, String>,
    pub helper_args: Vec<String>,
    pub edits_user_dotfiles: bool,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperConfigConflict {
    pub tool: HelperTool,
    pub source_kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvMarkerInjection {
    pub grade: AttributionGradeKind,
    pub env_vars: BTreeMap<String, String>,
}

pub fn build_session_env_bindings(
    helper_bin: &str,
    ssh_socket_path: &str,
    session_config_dir: &str,
) -> Result<Vec<ManagedBindingSpec>, IdentityError> {
    validate_clean_path(helper_bin, "helper_bin")?;
    validate_clean_path(ssh_socket_path, "ssh_socket_path")?;
    validate_clean_path(session_config_dir, "session_config_dir")?;

    let mut out = Vec::new();
    out.push(ManagedBindingSpec {
        tool: HelperTool::Git,
        env_vars: BTreeMap::from([
            ("GIT_CONFIG_COUNT".to_string(), "3".to_string()),
            (
                "GIT_CONFIG_KEY_0".to_string(),
                "credential.helper".to_string(),
            ),
            ("GIT_CONFIG_VALUE_0".to_string(), String::new()),
            (
                "GIT_CONFIG_KEY_1".to_string(),
                "credential.helper".to_string(),
            ),
            (
                "GIT_CONFIG_VALUE_1".to_string(),
                format!("!{helper_bin} cred git"),
            ),
            (
                "GIT_CONFIG_KEY_2".to_string(),
                "user.useConfigOnly".to_string(),
            ),
            ("GIT_CONFIG_VALUE_2".to_string(), "true".to_string()),
        ]),
        helper_args: vec!["cred".to_string(), "git".to_string()],
        edits_user_dotfiles: false,
        note:
            "Resets existing helpers and binds via GIT_CONFIG_COUNT without modifying ~/.gitconfig."
                .to_string(),
    });
    out.push(ManagedBindingSpec {
        tool: HelperTool::Gh,
        env_vars: BTreeMap::from([(
            "GH_CONFIG_DIR".to_string(),
            format!("{session_config_dir}/gh"),
        )]),
        helper_args: vec!["cred".to_string(), "gh".to_string()],
        edits_user_dotfiles: false,
        note: "Routes gh authentication through session GH_CONFIG_DIR.".to_string(),
    });
    out.push(ManagedBindingSpec {
        tool: HelperTool::Aws,
        env_vars: BTreeMap::from([
            (
                "AWS_CONFIG_FILE".to_string(),
                format!("{session_config_dir}/aws/config"),
            ),
            (
                "AWS_SHARED_CREDENTIALS_FILE".to_string(),
                format!("{session_config_dir}/aws/credentials"),
            ),
        ]),
        helper_args: vec!["cred".to_string(), "aws".to_string()],
        edits_user_dotfiles: false,
        note: "Uses session AWS_CONFIG_FILE credential_process without touching ~/.aws/."
            .to_string(),
    });
    out.push(ManagedBindingSpec {
        tool: HelperTool::Gcp,
        env_vars: BTreeMap::from([
            (
                "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                format!("{session_config_dir}/gcp/external_account.json"),
            ),
            (
                "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES".to_string(),
                "1".to_string(),
            ),
        ]),
        helper_args: vec!["cred".to_string(), "gcp".to_string()],
        edits_user_dotfiles: false,
        note: "Points GOOGLE_APPLICATION_CREDENTIALS at executable-source session config."
            .to_string(),
    });
    out.push(ManagedBindingSpec {
        tool: HelperTool::Docker,
        env_vars: BTreeMap::from([(
            "DOCKER_CONFIG".to_string(),
            format!("{session_config_dir}/docker"),
        )]),
        helper_args: vec!["cred".to_string(), "docker".to_string()],
        edits_user_dotfiles: false,
        note: "Points DOCKER_CONFIG at session dir delegating to docker-credential-grdr."
            .to_string(),
    });
    out.push(ManagedBindingSpec {
        tool: HelperTool::Kube,
        env_vars: BTreeMap::from([(
            "KUBECONFIG".to_string(),
            format!("{session_config_dir}/kube/config"),
        )]),
        helper_args: vec!["cred".to_string(), "kube".to_string()],
        edits_user_dotfiles: false,
        note: "Points KUBECONFIG at exec-credential config backed by grdr broker.".to_string(),
    });
    out.push(ManagedBindingSpec {
        tool: HelperTool::Npm,
        env_vars: BTreeMap::from([(
            "NPM_CONFIG_USERCONFIG".to_string(),
            format!("{session_config_dir}/npm/.npmrc"),
        )]),
        helper_args: vec!["cred".to_string(), "npm".to_string()],
        edits_user_dotfiles: false,
        note: "Points NPM_CONFIG_USERCONFIG at session .npmrc without editing ~/.npmrc."
            .to_string(),
    });
    out.push(ManagedBindingSpec {
        tool: HelperTool::Pypi,
        env_vars: BTreeMap::from([
            ("TWINE_USERNAME".to_string(), "__token__".to_string()),
            (
                "PIP_CONFIG_FILE".to_string(),
                format!("{session_config_dir}/pip/pip.conf"),
            ),
        ]),
        helper_args: vec!["cred".to_string(), "pypi".to_string()],
        edits_user_dotfiles: false,
        note: "Configures session PyPI/Twine lookup without touching ~/.pypirc.".to_string(),
    });
    out.push(ManagedBindingSpec {
        tool: HelperTool::Ssh,
        env_vars: BTreeMap::from([("SSH_AUTH_SOCK".to_string(), ssh_socket_path.to_owned())]),
        helper_args: vec!["cred".to_string(), "ssh".to_string()],
        edits_user_dotfiles: false,
        note: "Exposes sign-only brokered SSH agent via session SSH_AUTH_SOCK.".to_string(),
    });

    Ok(out)
}

#[must_use]
pub fn detect_helper_config_conflicts(
    existing_env: &BTreeMap<String, String>,
    dotfile_paths_present: &[&str],
) -> Vec<HelperConfigConflict> {
    let mut conflicts = Vec::new();
    let static_env_rules = [
        (
            HelperTool::Gh,
            "GH_TOKEN",
            "Static GH_TOKEN shadows brokered gh helper",
        ),
        (
            HelperTool::Gh,
            "GITHUB_TOKEN",
            "Static GITHUB_TOKEN shadows brokered gh helper",
        ),
        (
            HelperTool::Aws,
            "AWS_SECRET_ACCESS_KEY",
            "Static AWS_SECRET_ACCESS_KEY overrides AWS credential_process",
        ),
        (
            HelperTool::Npm,
            "NPM_TOKEN",
            "Static NPM_TOKEN shadows session NPM_CONFIG_USERCONFIG",
        ),
        (
            HelperTool::Pypi,
            "TWINE_PASSWORD",
            "Static TWINE_PASSWORD shadows brokered PyPI helper",
        ),
        (
            HelperTool::Ssh,
            "SSH_AUTH_SOCK",
            "Existing SSH_AUTH_SOCK shadows broker sign-only agent",
        ),
    ];
    for (tool, key, detail) in static_env_rules {
        if existing_env.get(key).is_some_and(|v| !v.trim().is_empty()) {
            conflicts.push(HelperConfigConflict {
                tool,
                source_kind: format!("env:{key}"),
                detail: detail.to_string(),
            });
        }
    }

    let dotfile_rules = [
        (HelperTool::Git, ".git-credentials"),
        (HelperTool::Npm, ".npmrc"),
        (HelperTool::Pypi, ".pypirc"),
        (HelperTool::Aws, ".aws/credentials"),
        (HelperTool::Docker, ".docker/config.json"),
    ];
    for path in dotfile_paths_present {
        let norm = path.replace('\\', "/");
        for (tool, needle) in dotfile_rules {
            if norm.ends_with(needle) {
                conflicts.push(HelperConfigConflict {
                    tool,
                    source_kind: format!("dotfile:{norm}"),
                    detail: format!(
                        "User credential store `{norm}` present; adopt via grdr cred adopt"
                    ),
                });
            }
        }
    }
    conflicts
}

#[must_use]
pub fn build_tag_grade_env_markers(
    grade: AttributionGradeKind,
    agi_id: &str,
    session_id: &str,
    trace_id: &str,
) -> EnvMarkerInjection {
    let mut env_vars = BTreeMap::from([
        ("GRDR_AGENT_ID".to_string(), agi_id.to_owned()),
        ("GRDR_SESSION_ID".to_string(), session_id.to_owned()),
        ("GRDR_TRACE_ID".to_string(), trace_id.to_owned()),
    ]);
    if grade == AttributionGradeKind::Tag {
        env_vars.insert(
            "AWS_SDK_UA_APP_ID".to_string(),
            truncate_aws_ua_app_id(agi_id, session_id),
        );
    }
    EnvMarkerInjection { grade, env_vars }
}

#[must_use]
pub fn truncate_aws_ua_app_id(agi_id: &str, session_id: &str) -> String {
    let clean_agi: String = agi_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    let clean_ses: String = session_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    let combined = format!("grdr-{clean_agi}-{clean_ses}");
    combined.chars().take(MAX_AWS_UA_APP_ID_CHARS).collect()
}

fn validate_clean_path(raw: &str, field: &str) -> Result<(), IdentityError> {
    const FORBIDDEN_METACHARS: &[char] = &[';', '|', '&', '$', '`', '"', '\'', '(', ')', '<', '>'];
    if raw.trim().is_empty()
        || raw.chars().any(|c| {
            c == '\0'
                || c == '\n'
                || c == '\r'
                || c.is_control()
                || c.is_whitespace()
                || FORBIDDEN_METACHARS.contains(&c)
        })
    {
        return Err(IdentityError::CredentialHelper(format!(
            "{field} must be non-empty without whitespace, control chars, or shell metacharacters"
        )));
    }
    Ok(())
}
