// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::sync::Mutex;

use grdr_crypto::{SigningKeypair, sha256_hex, verify_bytes};
use grdr_model::{DecisionReceipt, Verdict};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const EXPORT_DOMAIN: &str = "export_bundle";
const REDACT_MAX_CHARS: usize = 240;
const SECRET_MARKERS: &[&str] = &["sk-", "ghp_", "github_pat_", "AKIA", "Bearer ", "xoxb-"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExportError {
    #[error("GRDR-EXP-0001: failed serializing export record: {0}")]
    Serialization(String),
    #[error("GRDR-EXP-0002: failed signing export bundle: {0}")]
    SigningFailed(String),
    #[error("GRDR-EXP-0003: export bundle signature verification failed")]
    VerificationFailed,
    #[error("GRDR-EXP-0004: export sink unavailable: {0}")]
    SinkUnavailable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Ocsf19Jsonl,
    AuditJsonl,
    CefSyslog,
    SplunkHec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionPolicy {
    StrictP8,
    MetadataOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRecord {
    pub receipt_id: String,
    pub format: ExportFormat,
    pub line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExportBundle {
    pub bundle_id: String,
    pub format: ExportFormat,
    pub record_count: usize,
    pub created_at: Timestamp,
    pub records_jsonl: String,
    pub payload_sha256: String,
    pub key_id: String,
    pub signature: String,
}

pub trait ExportSink {
    fn sink_name(&self) -> &'static str;
    fn emit_bundle(&mut self, bundle: &SignedExportBundle) -> Result<(), ExportError>;
}

#[derive(Debug, Default)]
pub struct MemoryExportSink {
    bundles: Mutex<Vec<SignedExportBundle>>,
}

impl MemoryExportSink {
    #[must_use]
    pub fn drain_bundles(&self) -> Vec<SignedExportBundle> {
        match self.bundles.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(_) => Vec::new(),
        }
    }
}

impl ExportSink for MemoryExportSink {
    fn sink_name(&self) -> &'static str {
        "memory-export-sink"
    }

    fn emit_bundle(&mut self, bundle: &SignedExportBundle) -> Result<(), ExportError> {
        let mut guard = self
            .bundles
            .lock()
            .map_err(|_| ExportError::SinkUnavailable("memory sink lock poisoned".into()))?;
        guard.push(bundle.clone());
        Ok(())
    }
}

#[must_use]
pub fn redact_untrusted_text(raw: &str, policy: RedactionPolicy) -> String {
    if policy == RedactionPolicy::MetadataOnly {
        return format!("[redacted len={}]", raw.chars().count());
    }

    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(REDACT_MAX_CHARS)
        .collect();

    if SECRET_MARKERS.iter().any(|m| cleaned.contains(m)) {
        "[redacted secret material]".to_owned()
    } else {
        cleaned.trim().to_owned()
    }
}

#[must_use]
pub fn receipt_to_ocsf19(receipt: &DecisionReceipt, policy: RedactionPolicy) -> Value {
    let activity_id = match receipt.verdict {
        Verdict::Allow | Verdict::Modify => 1,
        Verdict::StepUp | Verdict::Defer => 3,
        Verdict::Deny => 2,
    };
    let severity_id = match receipt.verdict {
        Verdict::Allow => 1,
        Verdict::Modify => 2,
        Verdict::StepUp | Verdict::Defer => 3,
        Verdict::Deny => 4,
    };
    let class_uid = 2004_i64;
    let category_uid = 2_i64;
    let type_uid = class_uid.saturating_mul(100).saturating_add(activity_id);
    let epoch_ms = receipt.decided_at.as_millisecond();

    let safe_target = redact_untrusted_text(&receipt.target, policy);
    let safe_reason = redact_untrusted_text(&receipt.reason, policy);

    json!({
        "class_uid": class_uid,
        "category_uid": category_uid,
        "activity_id": activity_id,
        "type_uid": type_uid,
        "time": epoch_ms,
        "severity_id": severity_id,
        "metadata": {
            "version": "1.9.0",
            "product": {
                "name": "Guardrails ADR",
                "vendor_name": "Loonaro",
                "uid": "guardrails-adr"
            },
            "correlation_uid": receipt.receipt_id,
            "original_time": receipt.decided_at.to_string(),
        },
        "device": {
            "uid": receipt.device_id,
            "name": receipt.agent_name,
        },
        "resources": [
            {
                "name": safe_target,
                "type": format!("{:?}", receipt.action_class),
                "rule_id": receipt.rule_id,
                "reason": safe_reason,
            }
        ]
    })
}

pub fn format_receipt(
    receipt: &DecisionReceipt,
    format: ExportFormat,
    policy: RedactionPolicy,
) -> Result<String, ExportError> {
    match format {
        ExportFormat::Ocsf19Jsonl => {
            let val = receipt_to_ocsf19(receipt, policy);
            serde_json::to_string(&val).map_err(|e| ExportError::Serialization(e.to_string()))
        }
        ExportFormat::AuditJsonl => {
            let mut clean = receipt.clone();
            clean.target = redact_untrusted_text(&receipt.target, policy);
            clean.reason = redact_untrusted_text(&receipt.reason, policy);
            serde_json::to_string(&clean).map_err(|e| ExportError::Serialization(e.to_string()))
        }
        ExportFormat::CefSyslog => {
            let safe_target = redact_untrusted_text(&receipt.target, policy).replace('|', "/");
            let rule = receipt.rule_id.as_deref().unwrap_or("none");
            let sev = match receipt.verdict {
                Verdict::Deny => 8,
                Verdict::StepUp | Verdict::Defer => 6,
                Verdict::Modify => 4,
                Verdict::Allow => 2,
            };
            Ok(format!(
                "CEF:0|Loonaro|GuardrailsADR|1.0|{rule}|Agent Decision|{sev}|deviceId={} agent={} verdict={:?} act={:?} filePath={safe_target}",
                receipt.device_id, receipt.agent_name, receipt.verdict, receipt.action_class
            ))
        }
        ExportFormat::SplunkHec => {
            let ocsf = receipt_to_ocsf19(receipt, policy);
            let event = json!({
                "time": receipt.decided_at.as_second(),
                "source": "guardrails:adr",
                "sourcetype": "guardrails:ocsf:1.9",
                "event": ocsf,
            });
            serde_json::to_string(&event).map_err(|e| ExportError::Serialization(e.to_string()))
        }
    }
}

pub fn format_batch(
    receipts: &[DecisionReceipt],
    format: ExportFormat,
    policy: RedactionPolicy,
) -> Result<Vec<String>, ExportError> {
    let mut lines = Vec::with_capacity(receipts.len());
    for r in receipts {
        lines.push(format_receipt(r, format, policy)?);
    }
    Ok(lines)
}

pub fn sign_export_bundle(
    bundle_id: impl Into<String>,
    receipts: &[DecisionReceipt],
    format: ExportFormat,
    policy: RedactionPolicy,
    keypair: &SigningKeypair,
    created_at: Timestamp,
) -> Result<SignedExportBundle, ExportError> {
    let lines = format_batch(receipts, format, policy)?;
    let records_jsonl = lines.join("\n");
    let payload_sha256 = sha256_hex(records_jsonl.as_bytes());
    let signature = keypair.sign_bytes(EXPORT_DOMAIN, records_jsonl.as_bytes());

    Ok(SignedExportBundle {
        bundle_id: bundle_id.into(),
        format,
        record_count: receipts.len(),
        created_at,
        records_jsonl,
        payload_sha256,
        key_id: keypair.key_id().to_owned(),
        signature,
    })
}

pub fn verify_export_bundle(
    bundle: &SignedExportBundle,
    public_key_b64: &str,
) -> Result<(), ExportError> {
    let actual_hash = sha256_hex(bundle.records_jsonl.as_bytes());
    if actual_hash != bundle.payload_sha256 {
        return Err(ExportError::VerificationFailed);
    }
    verify_bytes(
        public_key_b64,
        EXPORT_DOMAIN,
        bundle.records_jsonl.as_bytes(),
        &bundle.signature,
    )
    .map_err(|_| ExportError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::{ActionClass, ControlPoint, Mode};
    use grdr_schema::{SchemaKind, schema_for, validate_json};

    fn sample_receipt(target: &str) -> DecisionReceipt {
        DecisionReceipt {
            receipt_id: "rcpt-1".into(),
            attempt_id: "att-1".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            agent_name: "Claude Code".into(),
            action_class: ActionClass::NetRequest,
            control_point: ControlPoint::Proxy,
            target: target.into(),
            verdict: Verdict::Deny,
            would_be: None,
            rule_id: Some("essentials.egress-secrets".into()),
            pack_id: Some("pack-essentials".into()),
            mode_applied: Some(Mode::Block),
            grant_id: None,
            reason: "Secret token blocked before egress".into(),
            next_step: "Tell user".into(),
            receipt_digest: "deadbeef".into(),
            decided_at: Timestamp::UNIX_EPOCH,
            key_id: None,
            signature: None,
            signature_verified: None,
        }
    }

    #[test]
    fn ocsf19_validates_against_grdr_schema_and_scrubs_secrets() {
        let r = sample_receipt("Bearer sk-secret-token-value");
        let val = receipt_to_ocsf19(&r, RedactionPolicy::StrictP8);
        assert!(validate_json(&schema_for(SchemaKind::OcsfEvent), &val).is_ok());
        let text = serde_json::to_string(&val).expect("serialize");
        assert!(!text.contains("sk-secret-token-value"));
        assert!(text.contains("[redacted secret material]"));
    }

    #[test]
    fn signed_export_bundle_verifies_and_detects_tampering() {
        let kp = SigningKeypair::generate().expect("keypair");
        let receipts = vec![sample_receipt("https://api.example.com/v1/status")];
        let mut bundle = sign_export_bundle(
            "bundle-1",
            &receipts,
            ExportFormat::Ocsf19Jsonl,
            RedactionPolicy::StrictP8,
            &kp,
            Timestamp::UNIX_EPOCH,
        )
        .expect("sign bundle");

        assert!(verify_export_bundle(&bundle, &kp.public_key_b64()).is_ok());

        bundle.records_jsonl.push_str("\ntampered");
        assert!(verify_export_bundle(&bundle, &kp.public_key_b64()).is_err());

        let mut sink = MemoryExportSink::default();
        sink.emit_bundle(&bundle).expect("emit");
        assert_eq!(sink.drain_bundles().len(), 1);
    }
}
