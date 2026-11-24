// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use uuid::Uuid;

use grdr_model::{
    AuditEntry, BrowserAppPolicy, BrowserEvaluateRequest, BrowserEvaluateResponse,
    CODE_BROWSER_NOT_FOUND, CodedError, Mode, UpdateBrowserAppPolicyInput, Verdict,
    evaluate_browser_action,
};

use super::AppState;

pub(crate) fn demo_browser_policies() -> Vec<BrowserAppPolicy> {
    vec![
        BrowserAppPolicy {
            id: "chatgpt".into(),
            name: "ChatGPT".into(),
            domains: vec!["chatgpt.com".into(), "chat.openai.com".into()],
            mode: Mode::Block,
            block_file_uploads: true,
            block_secret_paste: true,
            managed_extension_only: true,
            events_24h: 142,
            blocked_24h: 11,
        },
        BrowserAppPolicy {
            id: "claude-web".into(),
            name: "Claude Web".into(),
            domains: vec!["claude.ai".into()],
            mode: Mode::Ask,
            block_file_uploads: true,
            block_secret_paste: true,
            managed_extension_only: true,
            events_24h: 96,
            blocked_24h: 2,
        },
        BrowserAppPolicy {
            id: "gemini".into(),
            name: "Google Gemini".into(),
            domains: vec!["gemini.google.com".into(), "aistudio.google.com".into()],
            mode: Mode::Watch,
            block_file_uploads: false,
            block_secret_paste: true,
            managed_extension_only: false,
            events_24h: 64,
            blocked_24h: 0,
        },
        BrowserAppPolicy {
            id: "perplexity".into(),
            name: "Perplexity".into(),
            domains: vec!["perplexity.ai".into()],
            mode: Mode::Block,
            block_file_uploads: true,
            block_secret_paste: true,
            managed_extension_only: true,
            events_24h: 38,
            blocked_24h: 7,
        },
        BrowserAppPolicy {
            id: "m365-copilot".into(),
            name: "Microsoft 365 Copilot".into(),
            domains: vec![
                "copilot.microsoft.com".into(),
                "m365.cloud.microsoft".into(),
            ],
            mode: Mode::Watch,
            block_file_uploads: false,
            block_secret_paste: true,
            managed_extension_only: true,
            events_24h: 118,
            blocked_24h: 0,
        },
    ]
}

impl AppState {
    pub async fn list_browser_policies(&self) -> Vec<BrowserAppPolicy> {
        let guard = self.inner.read().await;
        guard.browser_policies.clone()
    }

    pub async fn update_browser_policy(
        &self,
        id: &str,
        input: UpdateBrowserAppPolicyInput,
    ) -> Result<BrowserAppPolicy, CodedError> {
        let now = Timestamp::now();
        let mut guard = self.inner.write().await;
        let idx = guard
            .browser_policies
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_BROWSER_NOT_FOUND,
                    format!("Browser policy `{id}` was not found."),
                    "Refresh Browser AI policies and retry.",
                )
            })?;

        let updated = {
            let policy = guard.browser_policies.get_mut(idx).ok_or_else(|| {
                CodedError::new(CODE_BROWSER_NOT_FOUND, "Missing policy", "Retry")
            })?;
            if let Some(mode) = input.mode {
                policy.mode = mode;
            }
            if let Some(v) = input.block_file_uploads {
                policy.block_file_uploads = v;
            }
            if let Some(v) = input.block_secret_paste {
                policy.block_secret_paste = v;
            }
            if let Some(v) = input.managed_extension_only {
                policy.managed_extension_only = v;
            }
            policy.clone()
        };

        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                kind: "browser.policy.updated".into(),
                actor: "console-operator".into(),
                summary: format!(
                    "Updated browser policy `{}` to mode {:?}",
                    updated.name, updated.mode
                ),
                target: updated.id.clone(),
                timestamp: now,
            },
        );
        self.persist_store(&guard)?;
        Ok(updated)
    }

    pub async fn evaluate_browser(
        &self,
        req: BrowserEvaluateRequest,
    ) -> Result<BrowserEvaluateResponse, CodedError> {
        let mut guard = self.inner.write().await;
        let idx = guard
            .browser_policies
            .iter()
            .position(|p| p.id == req.app_id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_BROWSER_NOT_FOUND,
                    format!("Browser policy `{}` was not found.", req.app_id),
                    "Pick a configured browser AI app from Protect -> Browser AI.",
                )
            })?;

        let response = {
            let policy = guard.browser_policies.get_mut(idx).ok_or_else(|| {
                CodedError::new(CODE_BROWSER_NOT_FOUND, "Missing policy", "Retry")
            })?;
            let res = evaluate_browser_action(policy, &req);
            policy.events_24h = policy.events_24h.saturating_add(1);
            if res.verdict == Verdict::Deny {
                policy.blocked_24h = policy.blocked_24h.saturating_add(1);
            }
            res
        };

        self.persist_store(&guard)?;
        Ok(response)
    }
}
