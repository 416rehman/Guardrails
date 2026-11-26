// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Lossless bounded unknown-field preservation for reserved `900..=999` sealed twins.

use std::collections::BTreeSet;

use prost::Message;
use prost::bytes::Buf;
use prost::encoding::decode_key;

use crate::ProtoError;
use crate::canonical::{
    bootstrap,
    common_types::{
        ClockReading, DecimalInput, Digest, ExecutableRef, MessageArg, MessageRef, PathRef,
        ProtoDuration, ProtoTimestamp, Redaction, Sealed, TargetRef, TraceContext,
    },
    decide,
    decision::{DecisionRecord, Expectation, Grant, Receipt, Verdict},
    embed,
    entity::{
        AgentInstance, AgentType, Artifact, Device, McpServer, Organisation, Principal, Session,
        ToolCall,
    },
    event::{
        Action, ActionRollup, ActorChain, Attribution, ConfigEvent, CredAction, DeterministicFact,
        ElevateAction, Envelope, Event, ExecAction, FileAction, FiveWayCommitments, HealthEvent,
        Integrity, LlmAction, McpAction, MerkleRollupProof, NetAction, SecondaryActionRef,
        SessionLifecycleEvent, Source,
    },
    export::{ExportCursor, ExportRecord},
    feed::{FeedHeader, FeedSummaryRecord, GapRecord},
    finding::{EvidenceSpan, Finding, Incident, Observable, Suppression},
    fleet,
    governance::assurance::{AssuranceRecord, CapabilityProbeResult, ControlPointCapability},
    identity, ingest,
    inventory::{
        AgentBom, AgentDeclaration, BomComponent, BomEdge, DeclaredSourceRow, DeclaredToolSpec,
        DiscoveryEvidence, InventoryChange,
    },
    local, operator, provider,
};
use crate::common::{ErrorDetail, ErrorInfo, PageInfo, RevisionMeta};
use crate::descriptor_wire::skip_other_field;

pub use crate::unknown_fields_nested::{
    MAX_NESTED_NODES, NestedPreservingEnvelope, UnknownFieldTree,
};

pub const UNKNOWN_FIELD_MIN_TAG: u32 = 900;
pub const UNKNOWN_FIELD_MAX_TAG: u32 = 999;
pub const MAX_UNKNOWN_FIELD_COUNT: usize = 64;
pub const MAX_UNKNOWN_FIELD_BYTES: usize = 65_536;
pub const MAX_NESTED_PRESERVE_DEPTH: usize = 32;

pub trait KnownFieldTags {
    const KNOWN_TAGS: &'static [u32];
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnknownFields {
    raw_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreservingEnvelope<M> {
    pub message: M,
    pub unknown_fields: UnknownFields,
}

macro_rules! impl_known_field_tags {
    ($( $ty:ty => [ $( $tag:expr ),* $(,)? ] ),* $(,)?) => {
        $(
            impl KnownFieldTags for $ty {
                const KNOWN_TAGS: &'static [u32] = &[ $( $tag ),* ];
            }
        )*
    };
}

impl_known_field_tags!(
    RevisionMeta => [1, 2],
    ErrorInfo => [1, 2, 3],
    ErrorDetail => [1, 2, 3, 4, 5, 6, 7, 8, 9],
    PageInfo => [1, 2, 3, 4],
    ProtoTimestamp => [1, 2],
    ProtoDuration => [1, 2],
    Digest => [1, 2, 3],
    TraceContext => [1, 2, 3],
    PathRef => [1, 2, 3, 4],
    ExecutableRef => [1, 2, 3, 4],
    TargetRef => [1, 2, 3],
    ClockReading => [1, 2, 3],
    Redaction => [1, 2, 3, 4],
    Sealed => [1, 2, 3, 4],
    DecimalInput => [1, 2],
    MessageArg => [1, 2, 3, 4, 5, 6, 7, 8, 9],
    MessageRef => [1, 2, 3],
    Organisation => [1, 2, 3],
    Device => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    Principal => [1, 2, 3, 4, 5, 6],
    AgentType => [1, 2, 3, 4],
    AgentInstance => [1, 2, 3, 4, 5, 6, 7],
    Session => [1, 2, 3, 4, 5, 6, 7, 8],
    ToolCall => [1, 2, 3, 4],
    McpServer => [1, 2, 3, 4, 5],
    Artifact => [1, 2, 3, 4, 5, 6],
    Source => [1, 3, 4, 5, 6, 7, 8],
    ActorChain => [1, 2, 3, 4, 5],
    Attribution => [1, 2, 3, 4],
    FiveWayCommitments => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    MerkleRollupProof => [1, 2, 3, 4],
    Integrity => [1, 2, 3, 4, 5, 6, 7],
    Envelope => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    DeterministicFact => [1, 2, 3, 4, 5, 6],
    SecondaryActionRef => [1, 2],
    ExecAction => [1, 2, 3, 4, 5, 6, 7, 8],
    FileAction => [1, 2, 3, 4],
    NetAction => [1, 2, 3, 4, 5, 6],
    McpAction => [1, 2, 3, 4, 5],
    LlmAction => [1, 2, 3, 4, 5],
    CredAction => [1, 2, 3, 4, 5],
    ElevateAction => [1, 2, 3],
    Action => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    ActionRollup => [1, 2, 3, 4, 5, 6, 7],
    SessionLifecycleEvent => [1, 2, 3, 4],
    HealthEvent => [1, 2, 3, 4, 5, 6, 7],
    ConfigEvent => [1, 2, 3, 4],
    Event => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    Verdict => [1, 2, 3, 4, 5, 6],
    Grant => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    Receipt => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
    Expectation => [1, 2, 3, 4, 5, 6, 7, 8, 9],
    DecisionRecord => [1, 2, 3, 4, 5, 6],
    EvidenceSpan => [1, 2, 3, 4, 5, 6],
    Observable => [1, 2, 3, 4, 5, 6],
    Suppression => [1, 2, 3, 4, 5, 6],
    Finding => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    Incident => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    ControlPointCapability => [1, 2, 3, 4, 5, 6, 7],
    CapabilityProbeResult => [1, 2, 3, 4],
    AssuranceRecord => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    DiscoveryEvidence => [1, 2, 3, 4, 5, 6],
    InventoryChange => [1, 2, 3, 4, 5],
    BomComponent => [1, 2, 3, 4, 5, 6, 7, 8, 9],
    BomEdge => [1, 2, 3],
    AgentBom => [1, 2, 3, 4, 5, 6],
    AgentDeclaration => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    DeclaredSourceRow => [1, 2, 3, 4, 5],
    DeclaredToolSpec => [1, 2],
    FeedHeader => [1, 2, 3, 4, 5, 6, 7, 8, 9],
    FeedSummaryRecord => [1, 2, 3, 4],
    GapRecord => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    ExportCursor => [1, 2, 3],
    ExportRecord => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    decide::BlockNotice => [1, 2, 3, 4, 5, 6],
    decide::ControlPointCapability => [1, 2, 3, 4],
    decide::HelloRequest => [1, 2, 3],
    decide::HelloResponse => [1, 2, 3],
    decide::DecideRequest => [1, 2, 3, 4, 5, 6],
    decide::DecideAck => [1, 2, 3],
    decide::DecideResponse => [1, 2, 3, 4, 5, 6, 7],
    decide::ReportRequest => [1, 2, 3, 4],
    decide::ReportResponse => [1, 2],
    provider::GetCapabilitiesRequest => [],
    provider::GetCapabilitiesResponse => [1, 2, 3, 4],
    provider::EvaluateVerdictRequest => [1, 2, 3, 4],
    provider::EvaluateVerdictResponse => [1, 2, 3, 4, 5],
    local::HealthCondition => [1, 2, 3, 4],
    local::GetStatusRequest => [],
    local::GetStatusResponse => [1, 2, 3, 4, 5, 6],
    local::ExplainRequest => [1],
    local::ExplainResponse => [1, 2, 3, 4],
    local::ProposeRequest => [1, 2, 3, 4],
    local::ProposeResponse => [1, 2, 3],
    local::LocalQueryRequest => [1, 2],
    local::LocalQueryResponse => [1],
    local::SubscribeRequest => [1, 2],
    local::SubscribeResponse => [1, 2, 3],
    local::RequestLeaseRequest => [1, 2, 3],
    local::RequestLeaseResponse => [1, 2, 3],
    local::OpenRelayRequest => [1, 2],
    local::OpenRelayResponse => [1],
    local::SendFrameRequest => [1, 2, 3],
    local::SendFrameResponse => [1, 2],
    identity::ExternalId => [1, 2, 3],
    identity::AgentIdentity => [1, 2, 3, 4, 5, 6, 7, 8, 9],
    identity::LocalAttestation => [1, 2, 3, 4, 5, 6, 7, 8],
    identity::Ceiling => [1, 2, 3, 4],
    identity::Correlation => [1, 2, 3, 4],
    identity::Lease => [1, 2, 3, 4, 5, 6, 7],
    fleet::CompatRange => [1, 2, 3],
    fleet::Schedule => [1, 2, 3, 4, 5, 6],
    fleet::Handshake => [1, 2, 3],
    fleet::ResponseKeyCertificate => [1, 2, 3, 4, 5],
    fleet::CommandEnvelope => [1, 2, 3, 4, 5, 6],
    fleet::EnrolRequest => [1, 2, 3, 4],
    fleet::EnrolResponse => [1, 2, 3, 4, 5],
    fleet::CheckInRequest => [1, 2, 3, 4, 5],
    fleet::CheckInResponse => [1, 2, 3, 4, 5],
    fleet::WaitRequest => [1, 2],
    fleet::WaitResponse => [1, 2, 3],
    fleet::PendingCommandsRequest => [1],
    fleet::PendingCommandsResponse => [1],
    ingest::LaneAck => [1, 2, 3, 4, 5],
    ingest::FlowControl => [1, 2, 3, 4],
    ingest::PushBatchRequest => [1, 2, 3, 4, 5, 6, 7, 8, 9],
    ingest::PushBatchResponse => [1, 2, 3, 4, 5, 6],
    bootstrap::HelloRequest => [1, 2, 3],
    bootstrap::HelloResponse => [1, 2, 3, 4, 5],
    embed::Tick => [1],
    embed::Input => [1, 2],
    embed::Effect => [1, 2, 3],
    embed::Diagnostic => [1, 2, 3, 4],
    embed::Output => [1, 2, 3, 4, 5],
    embed::load_report::NotEvaluable => [1, 2],
    embed::LoadReport => [1, 2],
    embed::EngineState => [1, 2, 3],
    embed::HostProfile => [1, 2],
    embed::ActuatorRequest => [1, 2, 3],
    embed::ActuatorResult => [1, 2, 3],
    embed::LoadBundleRequest => [1, 2],
    embed::LoadBundleResponse => [1],
    embed::StepRequest => [1, 2],
    embed::StepResponse => [1],
    embed::GetEngineHealthRequest => [],
    embed::GetEngineHealthResponse => [1, 2],
    operator::RuntimeSettingEntry => [1, 2, 3, 4],
    operator::RuntimeConfigRevision => [1, 2, 3, 4, 5, 6],
    operator::OperatorTargetHealth => [1, 2, 3, 4],
    operator::OrganisationSummary => [1, 2, 3],
    operator::OperatorAuditEntry => [1, 2, 3, 4, 5, 6],
    operator::ListRuntimeRevisionsRequest => [1, 2],
    operator::ListRuntimeRevisionsResponse => [1, 2],
    operator::StageRuntimeRevisionRequest => [1, 2],
    operator::StageRuntimeRevisionResponse => [1],
    operator::ApplyRuntimeRevisionRequest => [1, 2],
    operator::ApplyRuntimeRevisionResponse => [1],
    operator::ListTargetHealthRequest => [],
    operator::ListTargetHealthResponse => [1],
    operator::ListOperatorAuditRequest => [1, 2],
    operator::ListOperatorAuditResponse => [1, 2],
);

impl UnknownFields {
    pub fn empty() -> Self {
        Self {
            raw_bytes: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.raw_bytes.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    pub fn parse_reserved(bytes: &[u8]) -> Result<Self, ProtoError> {
        validate_unknown_wire_slice(
            bytes,
            &BTreeSet::new(),
            MAX_UNKNOWN_FIELD_COUNT,
            MAX_UNKNOWN_FIELD_BYTES,
        )?;
        Ok(Self {
            raw_bytes: bytes.to_vec(),
        })
    }

    pub(crate) fn from_validated_raw(raw_bytes: Vec<u8>) -> Self {
        Self { raw_bytes }
    }
}

impl<M: Message + Default> PreservingEnvelope<M> {
    pub fn decode_bytes(bytes: &[u8]) -> Result<Self, ProtoError>
    where
        M: KnownFieldTags,
    {
        Self::decode_with_known_tags(bytes, M::KNOWN_TAGS)
    }

    pub fn decode_with_known_tags(bytes: &[u8], known_tags: &[u32]) -> Result<Self, ProtoError> {
        let (message, unknown_fields) = decode_preserving_unknowns_with_tags(bytes, known_tags)?;
        Ok(Self {
            message,
            unknown_fields,
        })
    }

    pub fn encode_bytes(&self) -> Result<Vec<u8>, ProtoError>
    where
        M: KnownFieldTags,
    {
        self.encode_with_known_tags(M::KNOWN_TAGS)
    }

    pub fn encode_with_known_tags(&self, known_tags: &[u32]) -> Result<Vec<u8>, ProtoError> {
        encode_preserving_unknowns_with_tags(&self.message, &self.unknown_fields, known_tags)
    }
}

pub fn decode_preserving_unknowns_with_tags<M: Message + Default>(
    bytes: &[u8],
    known_tags: &[u32],
) -> Result<(M, UnknownFields), ProtoError> {
    let msg = M::decode(bytes)
        .map_err(|e| ProtoError::InvalidPayload(format!("protobuf decode failed: {e}")))?;
    let tag_set: BTreeSet<u32> = known_tags.iter().copied().collect();
    let unknown_raw = extract_reserved_unknown_fields(bytes, &tag_set)?;
    Ok((msg, UnknownFields::from_validated_raw(unknown_raw)))
}

pub fn encode_preserving_unknowns_with_tags<M: Message>(
    msg: &M,
    unknowns: &UnknownFields,
    known_tags: &[u32],
) -> Result<Vec<u8>, ProtoError> {
    let tag_set: BTreeSet<u32> = known_tags.iter().copied().collect();
    validate_unknown_wire_slice(
        &unknowns.raw_bytes,
        &tag_set,
        MAX_UNKNOWN_FIELD_COUNT,
        MAX_UNKNOWN_FIELD_BYTES,
    )?;
    let mut out = Vec::with_capacity(msg.encoded_len().saturating_add(unknowns.raw_bytes.len()));
    msg.encode(&mut out)
        .map_err(|e| ProtoError::InvalidPayload(format!("protobuf encode failed: {e}")))?;
    out.extend_from_slice(&unknowns.raw_bytes);
    Ok(out)
}

fn validate_reserved_tag(tag: u32, known_tags: &BTreeSet<u32>) -> Result<(), ProtoError> {
    if known_tags.contains(&tag) {
        return Err(ProtoError::ConstraintViolation(format!(
            "unknown field tag {tag} collides with schema field tag"
        )));
    }
    if !(UNKNOWN_FIELD_MIN_TAG..=UNKNOWN_FIELD_MAX_TAG).contains(&tag) {
        return Err(ProtoError::ConstraintViolation(format!(
            "unknown field tag {tag} outside reserved seam 900..=999"
        )));
    }
    Ok(())
}

pub(crate) fn validate_unknown_wire_slice(
    bytes: &[u8],
    known_tags: &BTreeSet<u32>,
    max_count: usize,
    max_bytes: usize,
) -> Result<(), ProtoError> {
    if bytes.len() > max_bytes {
        return Err(ProtoError::ConstraintViolation(format!(
            "unknown fields exceed cap ({max_bytes} bytes)"
        )));
    }
    let mut cursor = bytes;
    let mut count = 0usize;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor)
            .map_err(|e| ProtoError::InvalidPayload(format!("unknown wire key error: {e}")))?;
        skip_other_field(wire, tag, &mut cursor)?;
        validate_reserved_tag(tag, known_tags)?;
        count = count.checked_add(1).ok_or_else(|| {
            ProtoError::ConstraintViolation("unknown field count overflowed usize".into())
        })?;
        if count > max_count {
            return Err(ProtoError::ConstraintViolation(format!(
                "unknown field count exceeds cap ({max_count})"
            )));
        }
    }
    Ok(())
}

fn extract_reserved_unknown_fields(
    bytes: &[u8],
    known_tags: &BTreeSet<u32>,
) -> Result<Vec<u8>, ProtoError> {
    let mut cursor = bytes;
    let mut out = Vec::new();
    let mut count = 0usize;
    while cursor.has_remaining() {
        let start = bytes.len().saturating_sub(cursor.len());
        let (tag, wire) = decode_key(&mut cursor)
            .map_err(|e| ProtoError::InvalidPayload(format!("wire key error: {e}")))?;
        skip_other_field(wire, tag, &mut cursor)?;
        let end = bytes.len().saturating_sub(cursor.len());
        if !known_tags.contains(&tag) {
            validate_reserved_tag(tag, known_tags)?;
            let slice = bytes.get(start..end).ok_or_else(|| {
                ProtoError::InvalidPayload("wire field slice out of bounds".into())
            })?;
            count = count.checked_add(1).ok_or_else(|| {
                ProtoError::ConstraintViolation("unknown field count overflow".into())
            })?;
            if count > MAX_UNKNOWN_FIELD_COUNT {
                return Err(ProtoError::ConstraintViolation(format!(
                    "unknown field count exceeds MAX_UNKNOWN_FIELD_COUNT ({MAX_UNKNOWN_FIELD_COUNT})"
                )));
            }
            if out.len().saturating_add(slice.len()) > MAX_UNKNOWN_FIELD_BYTES {
                return Err(ProtoError::ConstraintViolation(format!(
                    "unknown field bytes exceed MAX_UNKNOWN_FIELD_BYTES ({MAX_UNKNOWN_FIELD_BYTES})"
                )));
            }
            out.extend_from_slice(slice);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::entity::Principal;
    use crate::canonical::event::{Envelope, FiveWayCommitments, Integrity};

    #[test]
    fn preserving_envelope_roundtrips_900_to_999_fields() {
        let env = Envelope {
            event_id: "evt-1".into(),
            organisation_id: "org-1".into(),
            device_id: "dev-1".into(),
            epoch: 1,
            lane: 1,
            seq: 1,
            integrity: Some(Integrity {
                prev: "sha256:00".into(),
                digest: "sha256:11".into(),
                commitments: Some(FiveWayCommitments {
                    d_identifier: "id".into(),
                    d_structural: "st".into(),
                    d_derived: "dr".into(),
                    d_argument: "ar".into(),
                    d_body: "bd".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut wire = env.encode_to_vec();
        prost::encoding::bytes::encode(901, &b"sealed-ident".to_vec(), &mut wire);
        prost::encoding::bytes::encode(905, &b"sealed-body".to_vec(), &mut wire);

        let wrapped = PreservingEnvelope::<Envelope>::decode_bytes(&wire).unwrap();
        assert_eq!(wrapped.message, env);
        assert!(!wrapped.unknown_fields.is_empty());
        assert_eq!(wrapped.encode_bytes().unwrap(), wire);
    }

    #[test]
    fn preserving_envelope_rejects_tags_outside_900_to_999_and_groups() {
        let mut wire = Principal::default().encode_to_vec();
        prost::encoding::string::encode(899, &"bad-tag".to_owned(), &mut wire);
        assert!(PreservingEnvelope::<Principal>::decode_bytes(&wire).is_err());

        let mut above = Principal::default().encode_to_vec();
        prost::encoding::string::encode(1000, &"above-range".to_owned(), &mut above);
        assert!(PreservingEnvelope::<Principal>::decode_bytes(&above).is_err());

        let mut grp = Principal::default().encode_to_vec();
        // Field 901 start_group wire_type=3 ((901 << 3) | 3 = 7211), end_group=4 (7212).
        prost::encoding::encode_varint(7211, &mut grp);
        prost::encoding::encode_varint(7212, &mut grp);
        assert!(PreservingEnvelope::<Principal>::decode_bytes(&grp).is_err());

        // Count cap (> 64 unknown fields) and bytes cap (> 64 KiB).
        let mut too_many = Principal::default().encode_to_vec();
        for _ in 0..65 {
            prost::encoding::bytes::encode(901, &b"x".to_vec(), &mut too_many);
        }
        assert!(PreservingEnvelope::<Principal>::decode_bytes(&too_many).is_err());

        let mut too_big = Principal::default().encode_to_vec();
        prost::encoding::bytes::encode(901, &vec![0x41u8; 65_537], &mut too_big);
        assert!(PreservingEnvelope::<Principal>::decode_bytes(&too_big).is_err());
    }

    #[test]
    fn unknown_fields_parse_reserved_rejects_truncated_slice() {
        // Length-delimited field 901 claiming 10 bytes with only 2 present.
        let mut bad = Vec::new();
        prost::encoding::encode_key(901, prost::encoding::WireType::LengthDelimited, &mut bad);
        prost::encoding::encode_varint(10, &mut bad);
        bad.extend_from_slice(&[1, 2]);
        assert!(UnknownFields::parse_reserved(&bad).is_err());
    }
}
