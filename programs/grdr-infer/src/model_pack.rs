// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Signed offline ONNX model-pack verification, `DetectorAdapter`, `DetectorPort`,
//! and agent-process classification (`docs/design/16`, `docs/design/19`, `P2`).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use grdr_crypto::{SigningKeypair, constant_time_eq, sha256_hex, verify_bytes};
use grdr_model::{CodedError, TrustedKeyInfo};
use grdr_ports::dlp::{
    CaptureScope, DetectedSpan, DetectorCoverageStatus, DetectorFact, DetectorInput,
    DetectorOutput, DetectorPort, FactOrigin, MAX_MODEL_DETECTOR_RISK, ModelFactKind,
};

use crate::InferError;
use crate::advisory::{
    AdvisoryAction, AdvisoryLabel, AdvisorySeverityCap, BoundedRiskScore, FindingCandidate,
    ModelAdvisorySignal, UnavailableReason, VerifiedAdvisory, validate_evaluator_id,
};
use crate::detector::{DetectFuture, DetectorAdapter};
use crate::framing::{MAX_FRAMED_RECORD_BYTES, VerifiedRecord};
use crate::model_pack_io::{
    MAX_MANIFEST_BYTES, MAX_VOCAB_BYTES, canonical_pack_dir, finite_prob_to_u16_scaled,
    read_pack_member_bounded,
};
use crate::onnx_proto::MAX_ONNX_MODEL_BYTES;
use crate::onnx_runtime::{OnnxSession, OnnxVocab, TensorData, TensorValue};
use crate::quote_extract::longest_safe_mapped_run;

pub const MODEL_PACK_DOMAIN: &str = "grdr.infer.model-pack.v1";
pub const ONNX_JUDGE_EVALUATOR_ID: &str = "grdr-infer.onnx-judge.v1";
pub const ONNX_DLP_PORT_ID: &str = "grdr-infer.onnx-dlp.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelPackRole {
    ContentInjection,
    AgentProcess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPackManifest {
    pub pack_id: String,
    pub version: String,
    pub role: ModelPackRole,
    pub model_file: String,
    #[serde(default)]
    pub vocab_file: Option<String>,
    pub onnx_sha256: String,
    #[serde(default)]
    pub vocab_sha256: Option<String>,
    pub max_bytes: usize,
    pub threshold_bps: u16,
    pub signer_key_id: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize)]
struct ManifestSignBody<'a> {
    pack_id: &'a str,
    version: &'a str,
    role: ModelPackRole,
    model_file: &'a str,
    vocab_file: Option<&'a str>,
    onnx_sha256: &'a str,
    vocab_sha256: Option<&'a str>,
    max_bytes: usize,
    threshold_bps: u16,
    signer_key_id: &'a str,
}

#[derive(Debug, Clone)]
pub struct VerifiedModelPack {
    pub manifest: ModelPackManifest,
    pub session: Arc<OnnxSession>,
    pub vocab: Option<Arc<OnnxVocab>>,
}

#[derive(Debug, Clone)]
pub struct OnnxJudgeDetector {
    evaluator_id: String,
    session: Option<Arc<OnnxSession>>,
    vocab: Option<Arc<OnnxVocab>>,
    threshold_bps: u16,
}

#[derive(Debug, Clone)]
pub struct OnnxDetectorPort {
    session: Option<Arc<OnnxSession>>,
    vocab: Option<Arc<OnnxVocab>>,
    threshold_bps: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProcessAdvisory {
    pub risk_score: BoundedRiskScore,
    pub suspected_agent: bool,
    pub evaluator_id: String,
}

#[derive(Debug, Clone)]
pub struct OnnxAgentProcessClassifier {
    evaluator_id: String,
    session: Arc<OnnxSession>,
    threshold_bps: u16,
}

impl ModelPackManifest {
    /// Signs manifest fields deterministically for pack distribution/testing.
    pub fn sign(&mut self, keypair: &SigningKeypair) -> Result<(), InferError> {
        self.signer_key_id = keypair.key_id().to_owned();
        let payload = canonical_sign_body(self)?;
        self.signature_b64 = keypair.sign_bytes(MODEL_PACK_DOMAIN, &payload);
        Ok(())
    }
}

impl VerifiedModelPack {
    /// Verifies manifest Ed25519 signature BEFORE opening weight/vocab files on disk.
    pub fn load_and_verify(
        pack_dir: &Path,
        trusted_keys: &[TrustedKeyInfo],
    ) -> Result<Self, InferError> {
        let canon_dir = canonical_pack_dir(pack_dir)?;
        let manifest_raw =
            read_pack_member_bounded(&canon_dir, "manifest.json", MAX_MANIFEST_BYTES)?;
        let manifest: ModelPackManifest = serde_json::from_slice(&manifest_raw)
            .map_err(|e| InferError::InvalidInput(format!("malformed model manifest: {e}")))?;
        verify_manifest_signature(&manifest, trusted_keys)?;
        let onnx_bytes =
            read_pack_member_bounded(&canon_dir, &manifest.model_file, manifest.max_bytes)?;
        let vocab_bytes = match &manifest.vocab_file {
            Some(rel) => Some(read_pack_member_bounded(&canon_dir, rel, MAX_VOCAB_BYTES)?),
            None => None,
        };
        Self::verify_from_bytes(manifest, &onnx_bytes, vocab_bytes.as_deref(), trusted_keys)
    }

    /// Verifies signed manifest + ONNX + optional vocab byte slices purely in memory.
    pub fn verify_from_bytes(
        manifest: ModelPackManifest,
        onnx_bytes: &[u8],
        vocab_bytes: Option<&[u8]>,
        trusted_keys: &[TrustedKeyInfo],
    ) -> Result<Self, InferError> {
        verify_manifest_signature(&manifest, trusted_keys)?;
        if onnx_bytes.is_empty() || onnx_bytes.len() > manifest.max_bytes {
            return Err(InferError::InvalidInput(
                "ONNX payload exceeds declared max_bytes".into(),
            ));
        }
        let actual_onnx_sha = sha256_hex(onnx_bytes);
        if !constant_time_eq(actual_onnx_sha.as_bytes(), manifest.onnx_sha256.as_bytes()) {
            return Err(InferError::Crypto(
                "ONNX weight SHA-256 digest mismatch".into(),
            ));
        }

        let vocab = match (vocab_bytes, &manifest.vocab_sha256) {
            (Some(vb), Some(expected_sha)) => {
                if vb.len() > MAX_VOCAB_BYTES {
                    return Err(InferError::InvalidInput(
                        "vocab payload exceeds maximum bound".into(),
                    ));
                }
                let actual_v_sha = sha256_hex(vb);
                if !constant_time_eq(actual_v_sha.as_bytes(), expected_sha.as_bytes()) {
                    return Err(InferError::Crypto("vocab SHA-256 digest mismatch".into()));
                }
                let parsed: OnnxVocab = serde_json::from_slice(vb)
                    .map_err(|e| InferError::InvalidInput(format!("invalid vocab JSON: {e}")))?;
                Some(Arc::new(parsed))
            }
            (None, None) => None,
            _ => {
                return Err(InferError::InvalidInput(
                    "vocab file/digest pairing mismatch".into(),
                ));
            }
        };

        let session = Arc::new(OnnxSession::from_bytes(onnx_bytes)?);
        Ok(Self {
            manifest,
            session,
            vocab,
        })
    }
}

fn verify_manifest_signature(
    manifest: &ModelPackManifest,
    trusted_keys: &[TrustedKeyInfo],
) -> Result<(), InferError> {
    if manifest.max_bytes == 0 || manifest.max_bytes > MAX_ONNX_MODEL_BYTES {
        return Err(InferError::InvalidInput(
            "manifest max_bytes out of range".into(),
        ));
    }
    let signer = trusted_keys
        .iter()
        .find(|k| k.key_id == manifest.signer_key_id)
        .ok_or_else(|| InferError::Crypto("untrusted model pack signer key_id".into()))?;
    let body = canonical_sign_body(manifest)?;
    verify_bytes(
        &signer.public_key_b64,
        MODEL_PACK_DOMAIN,
        &body,
        &manifest.signature_b64,
    )
    .map_err(|e| InferError::Crypto(format!("model pack signature invalid: {e}")))
}

impl OnnxJudgeDetector {
    pub fn from_verified_pack(pack: VerifiedModelPack) -> Result<Self, InferError> {
        if pack.manifest.role != ModelPackRole::ContentInjection {
            return Err(InferError::InvalidInput(
                "pack role is not content_injection".into(),
            ));
        }
        let vocab = pack.vocab.ok_or_else(|| {
            InferError::InvalidInput("content injection model requires vocab".into())
        })?;
        Ok(Self {
            evaluator_id: ONNX_JUDGE_EVALUATOR_ID.to_owned(),
            session: Some(pack.session),
            vocab: Some(vocab),
            threshold_bps: pack.manifest.threshold_bps.min(10_000),
        })
    }

    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            evaluator_id: ONNX_JUDGE_EVALUATOR_ID.to_owned(),
            session: None,
            vocab: None,
            threshold_bps: 5_000,
        }
    }

    fn evaluate_sync(&self, record: &VerifiedRecord) -> ModelAdvisorySignal {
        let (Some(sess), Some(vocab)) = (&self.session, &self.vocab) else {
            return ModelAdvisorySignal::CouldNotLook(UnavailableReason::ModelFault);
        };
        if !validate_evaluator_id(&self.evaluator_id) {
            return ModelAdvisorySignal::CouldNotLook(UnavailableReason::MalformedOutput);
        }
        let Ok((prob, best_win)) = sess.score_text_windows(vocab, &record.plain_text) else {
            return ModelAdvisorySignal::CouldNotLook(UnavailableReason::ModelFault);
        };
        let (Ok(prob_bps), Ok(scaled)) = (
            finite_prob_to_u16_scaled(prob, 10_000),
            finite_prob_to_u16_scaled(prob, 250),
        ) else {
            return ModelAdvisorySignal::CouldNotLook(UnavailableReason::MalformedOutput);
        };
        if prob_bps < self.threshold_bps || scaled == 0 {
            return ModelAdvisorySignal::Advisory(VerifiedAdvisory {
                action: AdvisoryAction::NoChange,
                risk_score: BoundedRiskScore::clamped(0),
                labels: BTreeSet::new(),
                findings: Vec::new(),
                evaluator_id: self.evaluator_id.clone(),
            });
        }

        let Some(w) = best_win else {
            return ModelAdvisorySignal::CouldNotLook(UnavailableReason::QuoteNotGrounded);
        };
        let span = w.start_byte..w.end_byte.max(w.start_byte);
        let Some(quote_slice) = record
            .plain_text
            .get(span.clone())
            .and_then(|_| longest_safe_mapped_run(&record.plain_text, &[span]))
        else {
            return ModelAdvisorySignal::CouldNotLook(UnavailableReason::QuoteNotGrounded);
        };
        let quote = quote_slice.to_owned();
        let action = if prob_bps >= 8_000 {
            AdvisoryAction::RaiseReviewPriority
        } else {
            AdvisoryAction::AddAdvisoryLabel
        };
        let sev = if prob_bps >= 8_500 {
            AdvisorySeverityCap::High
        } else {
            AdvisorySeverityCap::Medium
        };

        ModelAdvisorySignal::Advisory(VerifiedAdvisory {
            action,
            risk_score: BoundedRiskScore::clamped(scaled),
            labels: BTreeSet::from([AdvisoryLabel::PromptInjectionSuspected]),
            findings: vec![FindingCandidate {
                record_id: record.record_id.clone(),
                label: AdvisoryLabel::PromptInjectionSuspected,
                severity: sev,
                exact_quote: quote,
                confidence_bps: prob_bps.min(10_000),
            }],
            evaluator_id: self.evaluator_id.clone(),
        })
    }
}

impl DetectorAdapter for OnnxJudgeDetector {
    fn adapter_id(&self) -> &'static str {
        ONNX_JUDGE_EVALUATOR_ID
    }

    fn inspect_verified<'a>(&'a self, record: &'a VerifiedRecord) -> DetectFuture<'a> {
        let cloned = self.clone();
        let rec = record.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || cloned.evaluate_sync(&rec))
                .await
                .unwrap_or(ModelAdvisorySignal::CouldNotLook(
                    UnavailableReason::ModelFault,
                ))
        })
    }
}

impl OnnxDetectorPort {
    pub fn from_verified_pack(pack: VerifiedModelPack) -> Result<Self, InferError> {
        if pack.manifest.role != ModelPackRole::ContentInjection {
            return Err(InferError::InvalidInput(
                "pack role mismatch for DLP DetectorPort".into(),
            ));
        }
        let vocab = pack.vocab.ok_or_else(|| {
            InferError::InvalidInput("content injection port requires vocab".into())
        })?;
        Ok(Self {
            session: Some(pack.session),
            vocab: Some(vocab),
            threshold_bps: pack.manifest.threshold_bps.min(10_000),
        })
    }

    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            session: None,
            vocab: None,
            threshold_bps: 5_000,
        }
    }
}

impl DetectorPort for OnnxDetectorPort {
    fn detector_id(&self) -> &'static str {
        ONNX_DLP_PORT_ID
    }

    fn origin(&self) -> FactOrigin {
        FactOrigin::Model
    }

    fn inspect(&self, input: &DetectorInput<'_>) -> Result<DetectorOutput, CodedError> {
        if matches!(
            input.capture_scope,
            CaptureScope::Off | CaptureScope::HashOnly
        ) {
            return Ok(could_not_look_port_output(
                "could_not_look: capture scope restricts content",
                DetectorCoverageStatus::PartialTimeoutOrFault,
            ));
        }
        if input.bytes.len() > MAX_FRAMED_RECORD_BYTES {
            return Ok(could_not_look_port_output(
                "could_not_look: input exceeds maximum byte bound",
                DetectorCoverageStatus::SizeLimitExceeded,
            ));
        }
        let Ok(text) = std::str::from_utf8(input.bytes) else {
            return Ok(could_not_look_port_output(
                "could_not_look: non-UTF8 bytes unavailable to text model",
                DetectorCoverageStatus::PartialTimeoutOrFault,
            ));
        };
        let (Some(sess), Some(vocab)) = (&self.session, &self.vocab) else {
            return Ok(could_not_look_port_output(
                "could_not_look: ONNX model unavailable or unverified",
                DetectorCoverageStatus::PartialTimeoutOrFault,
            ));
        };
        let Ok((prob, best_win)) = sess.score_text_windows(vocab, text) else {
            return Ok(could_not_look_port_output(
                "could_not_look: ONNX model runtime fault",
                DetectorCoverageStatus::PartialTimeoutOrFault,
            ));
        };
        let (Ok(prob_bps), Ok(risk_score)) = (
            finite_prob_to_u16_scaled(prob, 10_000),
            finite_prob_to_u16_scaled(prob, MAX_MODEL_DETECTOR_RISK),
        ) else {
            return Ok(could_not_look_port_output(
                "could_not_look: ONNX model produced non-finite output",
                DetectorCoverageStatus::PartialTimeoutOrFault,
            ));
        };
        if prob_bps < self.threshold_bps || risk_score == 0 {
            return Ok(DetectorOutput {
                facts: Vec::new(),
                decoded_layers: 1,
                coverage: DetectorCoverageStatus::Complete,
            });
        }
        let Some(w) = best_win else {
            return Ok(could_not_look_port_output(
                "could_not_look: missing grounded window span",
                DetectorCoverageStatus::PartialTimeoutOrFault,
            ));
        };
        let (start, end) = (w.start_byte, w.end_byte.max(w.start_byte));
        let Some(bounded_slice) = input.bytes.get(start..end) else {
            return Ok(could_not_look_port_output(
                "could_not_look: window span out of input bounds",
                DetectorCoverageStatus::PartialTimeoutOrFault,
            ));
        };
        let span = DetectedSpan {
            start_byte: u32::try_from(start).unwrap_or(0),
            end_byte: u32::try_from(end).unwrap_or(0),
            digest_sha256_hex: sha256_hex(bounded_slice),
        };
        Ok(DetectorOutput {
            facts: vec![DetectorFact::Model {
                kind: ModelFactKind::ContentInjectionModel,
                class_value: "prompt_injection_suspected".into(),
                risk_score,
                span: Some(span),
                unavailable_reason: None,
            }],
            decoded_layers: 1,
            coverage: DetectorCoverageStatus::Complete,
        })
    }
}

impl OnnxAgentProcessClassifier {
    pub fn from_verified_pack(pack: VerifiedModelPack) -> Result<Self, InferError> {
        if pack.manifest.role != ModelPackRole::AgentProcess {
            return Err(InferError::InvalidInput(
                "pack role is not agent_process".into(),
            ));
        }
        Ok(Self {
            evaluator_id: ONNX_JUDGE_EVALUATOR_ID.to_owned(),
            session: pack.session,
            threshold_bps: pack.manifest.threshold_bps.min(10_000),
        })
    }

    pub fn classify_features(&self, features: &[f32]) -> Result<AgentProcessAdvisory, InferError> {
        if features.is_empty() || features.iter().any(|v| !v.is_finite()) {
            return Err(InferError::InvalidInput(
                "invalid agent feature vector".into(),
            ));
        }
        let tensor = TensorValue {
            shape: vec![1, features.len()],
            data: TensorData::Float(features.to_vec()),
        };
        let outs = self.session.run(&[("X", tensor)])?;
        let prob_val = outs
            .get(1)
            .or_else(|| outs.first())
            .and_then(|t| t.as_floats().ok())
            .and_then(|f| f.get(1).or_else(|| f.first()))
            .copied()
            .ok_or_else(|| {
                InferError::InvalidInput("missing classifier probability output".into())
            })?;
        if !prob_val.is_finite() {
            return Err(InferError::InvalidInput(
                "non-finite classifier probability output".into(),
            ));
        }
        let bps = finite_prob_to_u16_scaled(prob_val, 10_000)?;
        let score = finite_prob_to_u16_scaled(prob_val, 250)?;
        Ok(AgentProcessAdvisory {
            risk_score: BoundedRiskScore::clamped(score),
            suspected_agent: bps >= self.threshold_bps,
            evaluator_id: self.evaluator_id.clone(),
        })
    }
}

fn could_not_look_port_output(reason: &str, coverage: DetectorCoverageStatus) -> DetectorOutput {
    DetectorOutput {
        facts: vec![DetectorFact::Model {
            kind: ModelFactKind::ContentInjectionModel,
            class_value: "could_not_look".into(),
            risk_score: 0,
            span: None,
            unavailable_reason: Some(reason.to_owned()),
        }],
        decoded_layers: 0,
        coverage,
    }
}

fn canonical_sign_body(m: &ModelPackManifest) -> Result<Vec<u8>, InferError> {
    let body = ManifestSignBody {
        pack_id: &m.pack_id,
        version: &m.version,
        role: m.role,
        model_file: &m.model_file,
        vocab_file: m.vocab_file.as_deref(),
        onnx_sha256: &m.onnx_sha256,
        vocab_sha256: m.vocab_sha256.as_deref(),
        max_bytes: m.max_bytes,
        threshold_bps: m.threshold_bps,
        signer_key_id: &m.signer_key_id,
    };
    serde_json::to_vec(&body).map_err(|e| {
        InferError::InvalidInput(format!("failed serializing manifest sign body: {e}"))
    })
}
