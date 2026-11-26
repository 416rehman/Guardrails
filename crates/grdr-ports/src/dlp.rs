// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Data-loss prevention, taint/declassification, baseline snapshot, and external label ports.

#[path = "dlp_labels.rs"]
mod dlp_labels;

pub use dlp_labels::{GoogleDriveLabelReader, MsipLabelReader, OrgLabelTable, PurviewLabelReader};
use serde::{Deserialize, Serialize};

use grdr_model::{ActionClass, CodedError, DataClass};

use crate::tenant::SingleCtx;

pub const CODE_DLP_IO: &str = "GRDR-DLP-0001";
pub const CODE_DLP_DECLASSIFY_MISMATCH: &str = "GRDR-DLP-0002";
pub const CODE_DLP_BASELINE_FAILED: &str = "GRDR-DLP-0003";
pub const CODE_DLP_MASS_CHANGE: &str = "GRDR-DLP-0004";
pub const CODE_DLP_HONEYTOKEN: &str = "GRDR-DLP-0005";

pub const MAX_MODEL_DETECTOR_RISK: u16 = 250;
pub const MAX_LABEL_METADATA_BYTES: usize = 256 * 1024;
pub const MAX_CLASS_VALUE_BYTES: usize = 128;
pub const MAX_UNAVAILABLE_REASON_BYTES: usize = 256;
pub const DEFAULT_MASS_CHANGE_THRESHOLD: u32 = 200;
pub const DEFAULT_MASS_CHANGE_WINDOW_SECS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactOrigin {
    Deterministic,
    Heuristic,
    Model,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeterministicFactKind {
    SecretType,
    ContentSecret,
    PiiClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFactKind {
    ContentInjectionModel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawDetectedSpan")]
pub struct DetectedSpan {
    pub start_byte: u32,
    pub end_byte: u32,
    pub digest_sha256_hex: String,
}

#[derive(Deserialize)]
struct RawDetectedSpan {
    start_byte: u32,
    end_byte: u32,
    digest_sha256_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceMethod {
    StructuralChecksum,
    PrefixAndEntropy,
    ModelScoring,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "origin",
    rename_all = "snake_case",
    try_from = "RawDetectorFact"
)]
pub enum DetectorFact {
    Deterministic {
        kind: DeterministicFactKind,
        class_value: String,
        confidence_bps: u16,
        span: DetectedSpan,
        method: ConfidenceMethod,
    },
    Model {
        kind: ModelFactKind,
        class_value: String,
        risk_score: u16,
        span: Option<DetectedSpan>,
        unavailable_reason: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "origin", rename_all = "snake_case")]
enum RawDetectorFact {
    Deterministic {
        kind: DeterministicFactKind,
        class_value: String,
        confidence_bps: u16,
        span: DetectedSpan,
        method: ConfidenceMethod,
    },
    Model {
        kind: ModelFactKind,
        class_value: String,
        risk_score: u16,
        span: Option<DetectedSpan>,
        unavailable_reason: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureScope {
    Off,
    HashOnly,
    Redacted,
    FullWithSecretScrub,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorInput<'a> {
    pub session_id: &'a str,
    pub action_class: ActionClass,
    pub field_name: &'a str,
    pub bytes: &'a [u8],
    pub data_class: DataClass,
    pub capture_scope: CaptureScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorCoverageStatus {
    Complete,
    PartialTimeoutOrFault,
    SizeLimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorOutput {
    pub facts: Vec<DetectorFact>,
    pub decoded_layers: u8,
    pub coverage: DetectorCoverageStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivitySource {
    Msip,
    MicrosoftPurview,
    GoogleDrive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityTier {
    Public,
    Internal,
    Confidential,
    Secret,
    Regulated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMarking {
    Unencrypted,
    RmsOrEncrypted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSensitivityLabel {
    pub source: SensitivitySource,
    pub label_id: String,
    pub label_name: String,
    pub tier: SensitivityTier,
    pub parent_label_id: Option<String>,
    pub protection: ProtectionMarking,
    pub policy_tag: Option<String>,
    pub advisory_only: bool,
    pub site_id: Option<String>,
    pub foreign_site: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineLifecycle {
    Active,
    Restored,
    CircuitBreakerTripped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSnapshotRef {
    pub snapshot_id: String,
    pub session_id: String,
    pub root_path: String,
    pub created_at_ms: i64,
    pub file_count: u32,
    pub root_digest_sha256: String,
    pub lifecycle: BaselineLifecycle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreOutcome {
    pub snapshot_id: String,
    pub restored_files: u32,
    pub pre_restore_backup_id: String,
    pub verified_digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoneytokenRecord {
    pub token_id: String,
    pub kind: String,
    pub hmac_tag_hex: String,
    pub deployed_path: String,
    pub retired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationGrantSpec {
    pub grant_id: String,
    pub session_id: String,
    pub target_class: String,
    pub content_digest_sha256: String,
    pub destination_prefix: String,
    pub expires_at_ms: i64,
}

pub trait DetectorPort {
    fn detector_id(&self) -> &'static str;
    fn origin(&self) -> FactOrigin;
    fn inspect(&self, input: &DetectorInput<'_>) -> Result<DetectorOutput, CodedError>;
}

pub trait LabelReaderPort {
    fn source(&self) -> SensitivitySource;
    fn read_labels_with_table(
        &self,
        object_ref: &str,
        raw_metadata: &[u8],
        table: &OrgLabelTable,
    ) -> Result<Vec<ExternalSensitivityLabel>, CodedError>;

    fn read_labels(
        &self,
        object_ref: &str,
        raw_metadata: &[u8],
    ) -> Result<Vec<ExternalSensitivityLabel>, CodedError> {
        self.read_labels_with_table(object_ref, raw_metadata, &OrgLabelTable::default())
    }
}

pub trait WorkspaceBaselinePort {
    fn create_snapshot(
        &self,
        ctx: &SingleCtx,
        session_id: &str,
        root_path: &str,
        now_ms: i64,
    ) -> Result<WorkspaceSnapshotRef, CodedError>;

    fn restore_snapshot(
        &self,
        ctx: &SingleCtx,
        snapshot: &WorkspaceSnapshotRef,
        target_paths: &[String],
    ) -> Result<RestoreOutcome, CodedError>;
}

impl TryFrom<RawDetectedSpan> for DetectedSpan {
    type Error = String;
    fn try_from(raw: RawDetectedSpan) -> Result<Self, Self::Error> {
        if raw.start_byte > raw.end_byte {
            return Err(format!(
                "DetectedSpan start_byte ({}) > end_byte ({})",
                raw.start_byte, raw.end_byte
            ));
        }
        if !is_valid_sha256_hex(&raw.digest_sha256_hex) {
            return Err("DetectedSpan digest_sha256_hex must be 64 hex characters".into());
        }
        Ok(Self {
            start_byte: raw.start_byte,
            end_byte: raw.end_byte,
            digest_sha256_hex: raw.digest_sha256_hex,
        })
    }
}

impl TryFrom<RawDetectorFact> for DetectorFact {
    type Error = String;
    fn try_from(raw: RawDetectorFact) -> Result<Self, Self::Error> {
        match raw {
            RawDetectorFact::Deterministic {
                kind,
                class_value,
                confidence_bps,
                span,
                method,
            } => {
                if confidence_bps > 10_000 {
                    return Err(format!(
                        "deterministic confidence_bps {confidence_bps} exceeds 10000"
                    ));
                }
                if !is_valid_class_value(&class_value) {
                    return Err(
                        "detector class_value must be 1..=128 non-blank non-control bytes".into(),
                    );
                }
                Ok(Self::Deterministic {
                    kind,
                    class_value,
                    confidence_bps,
                    span,
                    method,
                })
            }
            RawDetectorFact::Model {
                kind,
                class_value,
                risk_score,
                span,
                unavailable_reason,
            } => {
                if risk_score > MAX_MODEL_DETECTOR_RISK {
                    return Err(format!(
                        "model risk_score {risk_score} exceeds cap {MAX_MODEL_DETECTOR_RISK}"
                    ));
                }
                if !is_valid_class_value(&class_value) {
                    return Err(
                        "model detector class_value must be 1..=128 non-blank non-control bytes"
                            .into(),
                    );
                }
                if unavailable_reason
                    .as_deref()
                    .is_some_and(|r| !is_valid_unavailable_reason(r))
                {
                    return Err(
                        "model detector unavailable_reason must be bounded non-blank non-control text"
                            .into(),
                    );
                }
                Ok(Self::Model {
                    kind,
                    class_value,
                    risk_score,
                    span,
                    unavailable_reason,
                })
            }
        }
    }
}

impl DetectorOutput {
    pub fn validate_for_origin(&self, expected_origin: FactOrigin) -> Result<(), CodedError> {
        for fact in &self.facts {
            if expected_origin != FactOrigin::Deterministic && fact.is_policy_enforcing() {
                return Err(dlp_err(
                    CODE_DLP_IO,
                    "non-deterministic DetectorPort cannot emit Deterministic facts",
                ));
            }
            match fact {
                DetectorFact::Deterministic {
                    confidence_bps,
                    span,
                    class_value,
                    ..
                } => {
                    if *confidence_bps > 10_000
                        || !is_valid_class_value(class_value)
                        || span.start_byte > span.end_byte
                        || !is_valid_sha256_hex(&span.digest_sha256_hex)
                    {
                        return Err(dlp_err(
                            CODE_DLP_IO,
                            "deterministic detector fact failed field or span validation",
                        ));
                    }
                }
                DetectorFact::Model {
                    class_value,
                    risk_score,
                    span,
                    unavailable_reason,
                    ..
                } => {
                    if *risk_score > MAX_MODEL_DETECTOR_RISK {
                        return Err(dlp_err(
                            CODE_DLP_IO,
                            "model detector fact risk exceeds MAX_MODEL_DETECTOR_RISK",
                        ));
                    }
                    if !is_valid_class_value(class_value)
                        || unavailable_reason
                            .as_deref()
                            .is_some_and(|r| !is_valid_unavailable_reason(r))
                    {
                        return Err(dlp_err(
                            CODE_DLP_IO,
                            "model detector fact failed class_value or unavailable_reason validation",
                        ));
                    }
                    if let Some(s) = span
                        && (s.start_byte > s.end_byte || !is_valid_sha256_hex(&s.digest_sha256_hex))
                    {
                        return Err(dlp_err(
                            CODE_DLP_IO,
                            "model detector span failed hex or offset validation",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn inspect_with_origin_guard(
    port: &dyn DetectorPort,
    input: &DetectorInput<'_>,
) -> Result<DetectorOutput, CodedError> {
    let output = port.inspect(input)?;
    output.validate_for_origin(port.origin())?;
    Ok(output)
}

impl DetectorFact {
    #[must_use]
    pub const fn origin(&self) -> FactOrigin {
        match self {
            Self::Deterministic { .. } => FactOrigin::Deterministic,
            Self::Model { .. } => FactOrigin::Model,
        }
    }

    #[must_use]
    pub const fn is_policy_enforcing(&self) -> bool {
        matches!(self, Self::Deterministic { .. })
    }

    #[must_use]
    pub fn restrict_only_model(
        class_value: impl Into<String>,
        risk_score: u16,
        span: Option<DetectedSpan>,
        unavailable_reason: Option<String>,
    ) -> Self {
        Self::Model {
            kind: ModelFactKind::ContentInjectionModel,
            class_value: class_value.into(),
            risk_score: risk_score.min(MAX_MODEL_DETECTOR_RISK),
            span,
            unavailable_reason,
        }
    }
}

pub(crate) fn is_valid_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_valid_class_value(val: &str) -> bool {
    !val.trim().is_empty()
        && val.len() <= MAX_CLASS_VALUE_BYTES
        && !val.chars().any(char::is_control)
}

fn is_valid_unavailable_reason(reason: &str) -> bool {
    !reason.trim().is_empty()
        && reason.len() <= MAX_UNAVAILABLE_REASON_BYTES
        && !reason.chars().any(char::is_control)
}

pub(crate) fn dlp_err(code: &'static str, msg: impl Into<String>) -> CodedError {
    CodedError::new(
        code,
        msg.into(),
        "Provide valid schema-compliant DLP metadata within configured limits.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RogueModelPort;
    impl DetectorPort for RogueModelPort {
        fn detector_id(&self) -> &'static str {
            "rogue"
        }
        fn origin(&self) -> FactOrigin {
            FactOrigin::Model
        }
        fn inspect(&self, _input: &DetectorInput<'_>) -> Result<DetectorOutput, CodedError> {
            Ok(DetectorOutput {
                facts: vec![DetectorFact::Deterministic {
                    kind: DeterministicFactKind::SecretType,
                    class_value: "fake".into(),
                    confidence_bps: 10000,
                    span: DetectedSpan {
                        start_byte: 0,
                        end_byte: 4,
                        digest_sha256_hex: "00".repeat(32),
                    },
                    method: ConfidenceMethod::StructuralChecksum,
                }],
                decoded_layers: 0,
                coverage: DetectorCoverageStatus::Complete,
            })
        }
    }

    #[test]
    fn msip_purview_drive_site_id_enabled_false_and_guid_table_work() {
        let mut table = OrgLabelTable::default();
        table
            .guid_tiers
            .insert("1111-abcd".into(), SensitivityTier::Secret);
        table.org_site_ids.insert("org-tenant-1".into());
        let msip_raw = b"MSIP_Label_1111-abcd_Name=Vertraulich\nMSIP_Label_1111-abcd_Enabled=true\nMSIP_Label_1111-abcd_SiteId=external-tenant\nMSIP_Label_2222_Name=Public\nMSIP_Label_2222_Enabled=false\n";
        let msip = MsipLabelReader
            .read_labels_with_table("doc.docx", msip_raw, &table)
            .expect("msip");
        assert_eq!(msip.len(), 1);
        let lbl = msip.first().expect("label");
        assert_eq!(lbl.tier, SensitivityTier::Secret);
        assert_eq!(lbl.protection, ProtectionMarking::Unencrypted);
        assert!(lbl.foreign_site);
        assert_eq!(lbl.policy_tag.as_deref(), Some("sensitive:external-label"));

        let unrestr = MsipLabelReader
            .read_labels(
                "doc2.docx",
                b"MSIP_Label_9_Name=Unrestricted\nMSIP_Label_9_Enabled=true\n",
            )
            .expect("unrestricted");
        assert_eq!(
            unrestr.first().map(|l| l.tier),
            Some(SensitivityTier::Public)
        );

        let unknown = MsipLabelReader
            .read_labels(
                "doc3.docx",
                b"MSIP_Label_9_Name=Custom Project X\nMSIP_Label_9_Enabled=true\n",
            )
            .expect("unknown");
        assert_eq!(
            unknown.first().map(|l| l.tier),
            Some(SensitivityTier::Internal)
        );

        let purview_raw = br#"{"sensitivityLabelId":"lbl-p","displayName":"Strictly Private","protectionEnabled":true,"restrictionAction":"block"}"#;
        let purview = PurviewLabelReader
            .read_labels("sheet.xlsx", purview_raw)
            .expect("purview");
        let p0 = purview.first().expect("purview item");
        assert_eq!(p0.tier, SensitivityTier::Secret);
        assert!(p0.advisory_only);
        assert_eq!(p0.policy_tag.as_deref(), Some("advisory:purview:block"));

        let drive = GoogleDriveLabelReader
            .read_labels(
                "file-id",
                br#"{"labelInfo":{"labels":[{"id":"gd-1","title":"PCI Regulated"}]}}"#,
            )
            .expect("drive");
        assert_eq!(
            drive.first().map(|l| l.tier),
            Some(SensitivityTier::Regulated)
        );
    }

    #[test]
    fn model_detector_deserialization_rejects_oversized_risk_bad_span_and_origin_spoof() {
        let bad_risk = r#"{"origin":"model","kind":"content_injection_model","class_value":"inj","risk_score":999,"span":null,"unavailable_reason":null}"#;
        assert!(serde_json::from_str::<DetectorFact>(bad_risk).is_err());
        let bad_span = r#"{"start_byte":10,"end_byte":2,"digest_sha256_hex":"aa"}"#;
        assert!(serde_json::from_str::<DetectedSpan>(bad_span).is_err());
        let model_fact = DetectorFact::restrict_only_model("prompt-injection", 900, None, None);
        assert_eq!(model_fact.origin(), FactOrigin::Model);
        assert!(!model_fact.is_policy_enforcing());
        let inp = DetectorInput {
            session_id: "s1",
            action_class: ActionClass::NetRequest,
            field_name: "body",
            bytes: b"hello",
            data_class: DataClass::Content,
            capture_scope: CaptureScope::Redacted,
        };
        assert!(inspect_with_origin_guard(&RogueModelPort, &inp).is_err());
    }

    struct RogueHeuristicPort;

    impl DetectorPort for RogueHeuristicPort {
        fn detector_id(&self) -> &'static str {
            "rogue-heuristic"
        }

        fn origin(&self) -> FactOrigin {
            FactOrigin::Heuristic
        }

        fn inspect(&self, _input: &DetectorInput<'_>) -> Result<DetectorOutput, CodedError> {
            Ok(DetectorOutput {
                facts: vec![DetectorFact::Deterministic {
                    kind: DeterministicFactKind::SecretType,
                    class_value: "aws_key".into(),
                    confidence_bps: 9000,
                    span: DetectedSpan {
                        start_byte: 0,
                        end_byte: 5,
                        digest_sha256_hex: "0".repeat(64),
                    },
                    method: ConfidenceMethod::StructuralChecksum,
                }],
                decoded_layers: 1,
                coverage: DetectorCoverageStatus::Complete,
            })
        }
    }

    #[test]
    fn round2_dlp_origin_bounds_and_label_classification_hardening() {
        let inp = DetectorInput {
            session_id: "s1",
            action_class: ActionClass::NetRequest,
            field_name: "body",
            bytes: b"hello",
            data_class: DataClass::Content,
            capture_scope: CaptureScope::Redacted,
        };
        assert!(inspect_with_origin_guard(&RogueHeuristicPort, &inp).is_err());

        // Non-64-hex digest and confidence_bps > 10_000 rejected in serde and validate_for_origin.
        let bad_hex_json = serde_json::json!({
            "origin": "deterministic",
            "kind": "secret_type",
            "class_value": "aws_key",
            "confidence_bps": 9000,
            "span": {
                "start_byte": 0,
                "end_byte": 5,
                "digest_sha256_hex": "zzzz"
            },
            "method": "structural_checksum"
        })
        .to_string();
        assert!(serde_json::from_str::<DetectorFact>(&bad_hex_json).is_err());

        let bad_conf = DetectorOutput {
            facts: vec![DetectorFact::Deterministic {
                kind: DeterministicFactKind::SecretType,
                class_value: "aws_key".into(),
                confidence_bps: 10_001,
                span: DetectedSpan {
                    start_byte: 0,
                    end_byte: 4,
                    digest_sha256_hex: "a".repeat(64),
                },
                method: ConfidenceMethod::PrefixAndEntropy,
            }],
            decoded_layers: 1,
            coverage: DetectorCoverageStatus::Complete,
        };
        assert!(
            bad_conf
                .validate_for_origin(FactOrigin::Deterministic)
                .is_err()
        );

        // OrgLabelTable case-insensitive GUID and site lookup.
        let mut table = OrgLabelTable::default();
        table
            .guid_tiers
            .insert("GUID-SECRET-UPPER".into(), SensitivityTier::Secret);
        table.org_site_ids.insert("SITE-CORP-1".into());
        assert_eq!(
            table.lookup_guid_tier("guid-secret-upper"),
            Some(SensitivityTier::Secret)
        );
        assert!(table.is_known_org_site("site-corp-1"));

        // Label precedence, General->Internal, negated Public, missing siteId -> foreign, restriction allowlist, P8 error hygiene.
        let purview_json = serde_json::json!({
            "labels": [
                { "sensitivityLabelId": "g1", "displayName": "Restricted PII" },
                { "sensitivityLabelId": "g2", "displayName": "Highly Confidential HIPAA" },
                { "sensitivityLabelId": "g3", "displayName": "General" },
                { "sensitivityLabelId": "g4", "displayName": "Non-Public" },
                { "sensitivityLabelId": "g5", "displayName": "Not Public" },
                { "sensitivityLabelId": "guid-secret-upper", "displayName": "Custom" }
            ]
        })
        .to_string();
        let labels = PurviewLabelReader
            .read_labels_with_table("sharepoint://tenant/doc", purview_json.as_bytes(), &table)
            .expect("purview labels");
        assert_eq!(labels.len(), 6);
        assert_eq!(labels[0].tier, SensitivityTier::Regulated);
        assert_eq!(labels[1].tier, SensitivityTier::Regulated);
        assert_eq!(labels[2].tier, SensitivityTier::Internal);
        assert_eq!(labels[3].tier, SensitivityTier::Internal);
        assert_eq!(labels[4].tier, SensitivityTier::Internal);
        assert_eq!(labels[5].tier, SensitivityTier::Secret);
        assert!(
            labels
                .iter()
                .all(|l| l.foreign_site
                    && l.policy_tag.as_deref() == Some("advisory:external-label"))
        );

        // Purview restrictionAction allowlist rejects unsupported "allow" while allowing "block".
        let purview_bad_action = serde_json::json!({
            "labels": [{
                "sensitivityLabelId": "lbl-1",
                "displayName": "Confidential",
                "restrictionAction": "allow"
            }]
        })
        .to_string();
        assert!(
            PurviewLabelReader
                .read_labels_with_table("doc-a", purview_bad_action.as_bytes(), &table)
                .is_err()
        );
        let purview_block = serde_json::json!({
            "labels": [{
                "sensitivityLabelId": "lbl-2",
                "displayName": "Secret",
                "restrictionAction": "block"
            }]
        })
        .to_string();
        let purview_block_labels = PurviewLabelReader
            .read_labels_with_table("doc-b", purview_block.as_bytes(), &table)
            .expect("purview block");
        assert_eq!(
            purview_block_labels[0].policy_tag.as_deref(),
            Some("advisory:purview:block")
        );

        // Semicolon-delimited MSIP_Labels parsed.
        let msip_raw = b"MSIP_Label_g1_Enabled=true; MSIP_Label_g1_Name=Restricted PII; MSIP_Label_g2_Enabled=true; MSIP_Label_g2_Name=Confidential";
        let msip_labels = MsipLabelReader
            .read_labels("C:\\docs\\a.docx", msip_raw)
            .expect("msip semicolon");
        assert_eq!(msip_labels.len(), 2);
        assert_eq!(msip_labels[0].tier, SensitivityTier::Regulated);
        assert_eq!(msip_labels[1].tier, SensitivityTier::Confidential);

        // Drive missing siteId -> foreign_site=true; matching customerId (case-insensitive) -> foreign_site=false.
        let drive_json = serde_json::json!({
            "labels": [{
                "id": "lbl-1",
                "name": "Confidential"
            }, {
                "id": "lbl-2",
                "name": "Secret",
                "customerId": "site-corp-1"
            }]
        })
        .to_string();
        let drive_labels = GoogleDriveLabelReader
            .read_labels_with_table("gdrive://file-1", drive_json.as_bytes(), &table)
            .expect("drive labels");
        assert!(drive_labels[0].foreign_site);
        assert_eq!(
            drive_labels[0].policy_tag.as_deref(),
            Some("sensitive:external-label")
        );
        assert!(!drive_labels[1].foreign_site);
        assert_eq!(
            drive_labels[1].policy_tag.as_deref(),
            Some("sensitive:secret")
        );

        // CodedError must never leak local paths / untrusted JSON details.
        let err = PurviewLabelReader
            .read_labels("C:\\Users\\alice\\top-secret-payroll.docx", b"{invalid")
            .unwrap_err();
        assert!(!err.message.contains("top-secret-payroll.docx"));
        assert!(!err.message.contains("alice"));
    }

    #[test]
    fn round4_model_fact_rejects_unbounded_or_control_class_value_and_unavailable_reason() {
        for bad_class in [
            String::new(),
            "   ".to_owned(),
            "x".repeat(MAX_CLASS_VALUE_BYTES + 1),
            "bad\x00class".to_owned(),
        ] {
            let wire = serde_json::json!({
                "origin": "model",
                "kind": "content_injection_model",
                "class_value": bad_class,
                "risk_score": 10,
                "span": null,
                "unavailable_reason": null
            })
            .to_string();
            assert!(serde_json::from_str::<DetectorFact>(&wire).is_err());

            let out = DetectorOutput {
                facts: vec![DetectorFact::restrict_only_model(bad_class, 10, None, None)],
                decoded_layers: 0,
                coverage: DetectorCoverageStatus::Complete,
            };
            assert!(out.validate_for_origin(FactOrigin::Model).is_err());
        }

        for bad_reason in [
            String::new(),
            "   ".to_owned(),
            "r".repeat(MAX_UNAVAILABLE_REASON_BYTES + 1),
            "bad\nreason".to_owned(),
        ] {
            let wire = serde_json::json!({
                "origin": "model",
                "kind": "content_injection_model",
                "class_value": "prompt_injection",
                "risk_score": 0,
                "span": null,
                "unavailable_reason": bad_reason
            })
            .to_string();
            assert!(serde_json::from_str::<DetectorFact>(&wire).is_err());

            let out = DetectorOutput {
                facts: vec![DetectorFact::restrict_only_model(
                    "prompt_injection",
                    0,
                    None,
                    Some(bad_reason),
                )],
                decoded_layers: 0,
                coverage: DetectorCoverageStatus::PartialTimeoutOrFault,
            };
            assert!(out.validate_for_origin(FactOrigin::Model).is_err());
        }

        let valid_wire = serde_json::json!({
            "origin": "model",
            "kind": "content_injection_model",
            "class_value": "prompt_injection",
            "risk_score": 0,
            "span": null,
            "unavailable_reason": "timeout"
        })
        .to_string();
        assert!(serde_json::from_str::<DetectorFact>(&valid_wire).is_ok());
    }
}
