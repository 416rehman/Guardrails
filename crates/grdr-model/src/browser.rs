// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::{Mode, Verdict};

pub const CODE_BROWSER_NOT_FOUND: &str = "GRDR-BROWSER-0001";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserDlpClass {
    FileUpload,
    PasteSecret,
    SourceCode,
    CustomerPii,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserAppPolicy {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub mode: Mode,
    pub block_file_uploads: bool,
    pub block_secret_paste: bool,
    pub managed_extension_only: bool,
    pub events_24h: u32,
    pub blocked_24h: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateBrowserAppPolicyInput {
    pub mode: Option<Mode>,
    pub block_file_uploads: Option<bool>,
    pub block_secret_paste: Option<bool>,
    pub managed_extension_only: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserEvaluateRequest {
    pub app_id: String,
    pub domain: String,
    pub dlp_class: BrowserDlpClass,
    pub file_extension: Option<String>,
    pub has_secret_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserEvaluateResponse {
    pub app_id: String,
    pub app_name: String,
    pub verdict: Verdict,
    pub rule_id: Option<String>,
    pub reason: String,
    pub dlp_class: BrowserDlpClass,
}

pub fn evaluate_browser_action(
    policy: &BrowserAppPolicy,
    req: &BrowserEvaluateRequest,
) -> BrowserEvaluateResponse {
    if policy.mode == Mode::Off {
        return BrowserEvaluateResponse {
            app_id: policy.id.clone(),
            app_name: policy.name.clone(),
            verdict: Verdict::Allow,
            rule_id: None,
            reason: format!("Browser policy is Off for {}.", policy.name),
            dlp_class: req.dlp_class,
        };
    }

    let triggered = match req.dlp_class {
        BrowserDlpClass::FileUpload => policy.block_file_uploads || req.has_secret_match,
        BrowserDlpClass::PasteSecret => policy.block_secret_paste || req.has_secret_match,
        BrowserDlpClass::SourceCode | BrowserDlpClass::CustomerPii => true,
    };

    if !triggered {
        return BrowserEvaluateResponse {
            app_id: policy.id.clone(),
            app_name: policy.name.clone(),
            verdict: Verdict::Allow,
            rule_id: None,
            reason: format!("Allowed by browser policy for {}.", policy.name),
            dlp_class: req.dlp_class,
        };
    }

    let ext_hint = req
        .file_extension
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!(" ({s})"))
        .unwrap_or_default();

    let (verdict, prefix) = match policy.mode {
        Mode::Off => (Verdict::Allow, "off"),
        Mode::Watch => (Verdict::Allow, "watch"),
        Mode::Ask => (Verdict::StepUp, "ask"),
        Mode::Block => (Verdict::Deny, "block"),
    };

    BrowserEvaluateResponse {
        app_id: policy.id.clone(),
        app_name: policy.name.clone(),
        verdict,
        rule_id: Some(format!("browser.{prefix}.{}", policy.id)),
        reason: format!(
            "{} triggered {prefix} on {}{ext_hint} for domain {}.",
            policy.name,
            dlp_label(req.dlp_class),
            req.domain
        ),
        dlp_class: req.dlp_class,
    }
}

fn dlp_label(cls: BrowserDlpClass) -> &'static str {
    match cls {
        BrowserDlpClass::FileUpload => "file upload",
        BrowserDlpClass::PasteSecret => "secret paste",
        BrowserDlpClass::SourceCode => "source code paste",
        BrowserDlpClass::CustomerPii => "customer PII paste",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy(mode: Mode) -> BrowserAppPolicy {
        BrowserAppPolicy {
            id: "chatgpt".into(),
            name: "ChatGPT".into(),
            domains: vec!["chatgpt.com".into(), "chat.openai.com".into()],
            mode,
            block_file_uploads: true,
            block_secret_paste: true,
            managed_extension_only: true,
            events_24h: 12,
            blocked_24h: 3,
        }
    }

    #[test]
    fn browser_evaluator_respects_mode_and_toggles() {
        let req = BrowserEvaluateRequest {
            app_id: "chatgpt".into(),
            domain: "chatgpt.com".into(),
            dlp_class: BrowserDlpClass::FileUpload,
            file_extension: Some(".env".into()),
            has_secret_match: true,
        };

        let deny_res = evaluate_browser_action(&sample_policy(Mode::Block), &req);
        assert_eq!(deny_res.verdict, Verdict::Deny);
        assert_eq!(deny_res.rule_id.as_deref(), Some("browser.block.chatgpt"));

        let ask_res = evaluate_browser_action(&sample_policy(Mode::Ask), &req);
        assert_eq!(ask_res.verdict, Verdict::StepUp);

        let watch_res = evaluate_browser_action(&sample_policy(Mode::Watch), &req);
        assert_eq!(watch_res.verdict, Verdict::Allow);
        assert_eq!(watch_res.rule_id.as_deref(), Some("browser.watch.chatgpt"));

        let off_res = evaluate_browser_action(&sample_policy(Mode::Off), &req);
        assert_eq!(off_res.verdict, Verdict::Allow);
        assert!(off_res.rule_id.is_none());

        let mut no_upload_block = sample_policy(Mode::Block);
        no_upload_block.block_file_uploads = false;
        let clean_upload = BrowserEvaluateRequest {
            has_secret_match: false,
            ..req
        };
        let allowed = evaluate_browser_action(&no_upload_block, &clean_upload);
        assert_eq!(allowed.verdict, Verdict::Allow);
        assert!(allowed.rule_id.is_none());
    }
}
