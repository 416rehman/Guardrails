// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Machine-checked parity tests linking `descriptors/proto.binpb` to Rust codecs and method tables.

use std::collections::{BTreeMap, BTreeSet};

use grdr_proto::canonical::{
    bootstrap,
    common_types::{
        ClockReading, DecimalInput, Digest, ExecutableRef, MessageArg, MessageRef, PathRef,
        ProtoDuration, ProtoTimestamp, Redaction, Sealed, TargetRef, TraceContext,
    },
    decide, decision, embed, entity, event, export, feed, finding, fleet,
    governance::assurance,
    identity, ingest, inventory, local, operator, provider,
};
use grdr_proto::common::{
    ALL_METHODS, AuditClass, ConfirmClass, ErrorDetail, ErrorInfo, IdempotencyLevel, PageInfo,
    RateClass, RevisionMeta, SURFACES_AND_OPERATOR_METHODS,
};
use grdr_proto::descriptor::{
    DescriptorSet, MessageDescriptor, load_embedded_descriptor_set, read_string_option,
    read_varint_option,
};
use grdr_proto::unknown_fields::KnownFieldTags;

fn audit_wire_to_rust(raw: u64) -> Result<AuditClass, String> {
    match raw {
        1 => Ok(AuditClass::None),
        2 => Ok(AuditClass::Read),
        3 => Ok(AuditClass::SensitiveRead),
        4 => Ok(AuditClass::Mutation),
        5 => Ok(AuditClass::CriticalMutation),
        other => Err(format!("unexpected AuditClass wire value {other}")),
    }
}

fn rate_wire_to_rust(raw: u64) -> Result<RateClass, String> {
    match raw {
        1 => Ok(RateClass::Health),
        2 => Ok(RateClass::Standard),
        3 => Ok(RateClass::Interactive),
        4 => Ok(RateClass::Critical),
        5 => Ok(RateClass::Bulk),
        6 => Ok(RateClass::Ingest),
        other => Err(format!("unexpected RateClass wire value {other}")),
    }
}

fn confirm_wire_to_rust(raw: u64) -> Result<ConfirmClass, String> {
    match raw {
        1 => Ok(ConfirmClass::None),
        2 => Ok(ConfirmClass::Consequence),
        3 => Ok(ConfirmClass::Typed),
        4 => Ok(ConfirmClass::Propose),
        5 => Ok(ConfirmClass::Quorum),
        other => Err(format!("unexpected ConfirmClass wire value {other}")),
    }
}

fn idempotency_wire_to_rust(raw: u64) -> Result<IdempotencyLevel, String> {
    match raw {
        0 => Ok(IdempotencyLevel::Unknown),
        1 => Ok(IdempotencyLevel::NoSideEffects),
        other => Err(format!("unexpected IdempotencyLevel wire value {other}")),
    }
}

fn resolve_method_option_tags(
    set: &DescriptorSet,
) -> Result<(i32, i32, i32, i32, i32, i32), String> {
    let options_file = set
        .files
        .iter()
        .find(|f| f.package == "grdr.common.v1alpha1" && f.name.ends_with("options.proto"))
        .ok_or_else(|| "options.proto missing from proto.binpb".to_owned())?;
    let mut tags = BTreeMap::new();
    for ext in &options_file.extensions {
        if ext.extendee == ".google.protobuf.MethodOptions" {
            tags.insert(ext.name.as_str(), ext.number);
        }
    }
    let desc_file = set
        .files
        .iter()
        .find(|f| f.package == "google.protobuf" && f.name == "google/protobuf/descriptor.proto")
        .ok_or_else(|| "google/protobuf/descriptor.proto missing from proto.binpb".to_owned())?;
    let method_options_msg = desc_file
        .messages
        .iter()
        .find(|m| m.name == "MethodOptions")
        .ok_or_else(|| "MethodOptions missing from descriptor.proto".to_owned())?;
    let idem_tag = method_options_msg
        .fields
        .iter()
        .find(|f| f.name == "idempotency_level")
        .ok_or_else(|| "MethodOptions.idempotency_level missing".to_owned())?
        .number;
    let get = |k: &str| {
        tags.get(k)
            .copied()
            .ok_or_else(|| format!("MethodOptions.{k} missing"))
    };
    Ok((
        get("scope")?,
        get("audit")?,
        get("rate_class")?,
        get("confirm")?,
        get("mcp_exposed")?,
        idem_tag,
    ))
}

fn ensure(cond: bool, msg: String) -> Result<(), String> {
    if cond { Ok(()) } else { Err(msg) }
}

fn ensure_eq<T: PartialEq + core::fmt::Debug>(a: &T, b: &T, ctx: &str) -> Result<(), String> {
    if a == b {
        Ok(())
    } else {
        Err(format!("{ctx}: left={a:?}, right={b:?}"))
    }
}

#[test]
fn proto_binpb_api_rpc_options_match_method_tables_one_to_one() -> Result<(), String> {
    let set = load_embedded_descriptor_set().map_err(|e| e.to_string())?;
    let (scope_tag, audit_tag, rate_tag, confirm_tag, mcp_tag, idem_tag) =
        resolve_method_option_tags(&set)?;

    let mut rust_methods = BTreeMap::new();
    for entry in ALL_METHODS
        .iter()
        .chain(SURFACES_AND_OPERATOR_METHODS.iter())
    {
        let prev = rust_methods.insert((entry.service, entry.method), entry);
        ensure(
            prev.is_none(),
            format!("duplicate Rust method {}.{}", entry.service, entry.method),
        )?;
    }

    let mut proto_methods = BTreeSet::new();
    for file in &set.files {
        if !file.package.starts_with("grdr.api.") {
            continue;
        }
        for svc in &file.services {
            let svc_fqn = format!("{}.{}", file.package, svc.name);
            for method in &svc.methods {
                let key = (svc_fqn.as_str(), method.name.as_str());
                ensure(
                    proto_methods.insert((svc_fqn.clone(), method.name.clone())),
                    format!("duplicate proto method {}.{}", svc_fqn, method.name),
                )?;
                let rust = rust_methods.get(&key).ok_or_else(|| {
                    format!(
                        "proto RPC {}.{} missing from Rust tables",
                        svc_fqn, method.name
                    )
                })?;

                let scope = read_string_option(&method.raw_options, scope_tag)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("missing scope on {}.{}", svc_fqn, method.name))?;
                let audit = read_varint_option(&method.raw_options, audit_tag)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("missing audit on {}.{}", svc_fqn, method.name))?;
                let rate = read_varint_option(&method.raw_options, rate_tag)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("missing rate_class on {}.{}", svc_fqn, method.name))?;
                let confirm = read_varint_option(&method.raw_options, confirm_tag)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("missing confirm on {}.{}", svc_fqn, method.name))?;
                let mcp = read_varint_option(&method.raw_options, mcp_tag)
                    .map_err(|e| e.to_string())?
                    .unwrap_or(0)
                    != 0;
                let idem = read_varint_option(&method.raw_options, idem_tag)
                    .map_err(|e| e.to_string())?
                    .unwrap_or(0);

                ensure_eq(
                    &scope.as_str(),
                    &rust.scope,
                    &format!("scope drift on {}.{}", svc_fqn, method.name),
                )?;
                ensure_eq(
                    &audit_wire_to_rust(audit)?,
                    &rust.audit,
                    &format!("audit drift on {}.{}", svc_fqn, method.name),
                )?;
                ensure_eq(
                    &rate_wire_to_rust(rate)?,
                    &rust.rate_class,
                    &format!("rate drift on {}.{}", svc_fqn, method.name),
                )?;
                ensure_eq(
                    &confirm_wire_to_rust(confirm)?,
                    &rust.confirm,
                    &format!("confirm drift on {}.{}", svc_fqn, method.name),
                )?;
                ensure_eq(
                    &mcp,
                    &rust.mcp_exposed,
                    &format!("mcp_exposed drift on {}.{}", svc_fqn, method.name),
                )?;
                ensure_eq(
                    &idempotency_wire_to_rust(idem)?,
                    &rust.idempotency,
                    &format!("idempotency_level drift on {}.{}", svc_fqn, method.name),
                )?;
            }
        }
    }

    ensure_eq(
        &proto_methods.len(),
        &rust_methods.len(),
        "mismatch between proto grdr.api.* RPC count and Rust method tables",
    )?;
    Ok(())
}

fn collect_messages<'a>(
    pkg: &str,
    prefix: &str,
    msgs: &'a [MessageDescriptor],
    out: &mut BTreeMap<String, &'a MessageDescriptor>,
) {
    for msg in msgs {
        if msg.is_map_entry {
            continue;
        }
        let full = if prefix.is_empty() {
            format!("{pkg}.{}", msg.name)
        } else {
            format!("{prefix}.{}", msg.name)
        };
        collect_messages(pkg, &full, &msg.nested_messages, out);
        out.insert(full, msg);
    }
}

#[test]
fn proto_binpb_canonical_messages_match_known_field_tags() -> Result<(), String> {
    let set = load_embedded_descriptor_set().map_err(|e| e.to_string())?;
    let mut proto_msgs = BTreeMap::new();
    for file in &set.files {
        if file.package.starts_with("grdr.") {
            collect_messages(&file.package, "", &file.messages, &mut proto_msgs);
        }
    }

    let expected_canonical: &[(&str, &[u32])] = &[
        ("grdr.common.v1alpha1.ErrorInfo", ErrorInfo::KNOWN_TAGS),
        ("grdr.common.v1alpha1.ErrorDetail", ErrorDetail::KNOWN_TAGS),
        ("grdr.common.v1alpha1.PageInfo", PageInfo::KNOWN_TAGS),
        (
            "grdr.common.v1alpha1.RevisionMeta",
            RevisionMeta::KNOWN_TAGS,
        ),
        (
            "grdr.common.v1alpha1.ClockReading",
            ClockReading::KNOWN_TAGS,
        ),
        ("grdr.common.v1alpha1.Digest", Digest::KNOWN_TAGS),
        (
            "grdr.common.v1alpha1.TraceContext",
            TraceContext::KNOWN_TAGS,
        ),
        ("grdr.common.v1alpha1.PathRef", PathRef::KNOWN_TAGS),
        (
            "grdr.common.v1alpha1.ExecutableRef",
            ExecutableRef::KNOWN_TAGS,
        ),
        ("grdr.common.v1alpha1.TargetRef", TargetRef::KNOWN_TAGS),
        ("grdr.common.v1alpha1.Redaction", Redaction::KNOWN_TAGS),
        ("grdr.common.v1alpha1.Sealed", Sealed::KNOWN_TAGS),
        (
            "grdr.common.v1alpha1.DecimalInput",
            DecimalInput::KNOWN_TAGS,
        ),
        ("grdr.common.v1alpha1.MessageArg", MessageArg::KNOWN_TAGS),
        ("grdr.common.v1alpha1.MessageRef", MessageRef::KNOWN_TAGS),
        (
            "grdr.entity.v1alpha1.Organisation",
            entity::Organisation::KNOWN_TAGS,
        ),
        ("grdr.entity.v1alpha1.Device", entity::Device::KNOWN_TAGS),
        (
            "grdr.entity.v1alpha1.Principal",
            entity::Principal::KNOWN_TAGS,
        ),
        (
            "grdr.entity.v1alpha1.AgentType",
            entity::AgentType::KNOWN_TAGS,
        ),
        (
            "grdr.entity.v1alpha1.AgentInstance",
            entity::AgentInstance::KNOWN_TAGS,
        ),
        ("grdr.entity.v1alpha1.Session", entity::Session::KNOWN_TAGS),
        (
            "grdr.entity.v1alpha1.ToolCall",
            entity::ToolCall::KNOWN_TAGS,
        ),
        (
            "grdr.entity.v1alpha1.McpServer",
            entity::McpServer::KNOWN_TAGS,
        ),
        (
            "grdr.entity.v1alpha1.Artifact",
            entity::Artifact::KNOWN_TAGS,
        ),
        ("grdr.event.v1alpha1.Source", event::Source::KNOWN_TAGS),
        (
            "grdr.event.v1alpha1.ActorChain",
            event::ActorChain::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.Attribution",
            event::Attribution::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.FiveWayCommitments",
            event::FiveWayCommitments::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.MerkleRollupProof",
            event::MerkleRollupProof::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.Integrity",
            event::Integrity::KNOWN_TAGS,
        ),
        ("grdr.event.v1alpha1.Envelope", event::Envelope::KNOWN_TAGS),
        (
            "grdr.event.v1alpha1.DeterministicFact",
            event::DeterministicFact::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.SecondaryActionRef",
            event::SecondaryActionRef::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.ExecAction",
            event::ExecAction::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.FileAction",
            event::FileAction::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.NetAction",
            event::NetAction::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.McpAction",
            event::McpAction::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.LlmAction",
            event::LlmAction::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.CredAction",
            event::CredAction::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.ElevateAction",
            event::ElevateAction::KNOWN_TAGS,
        ),
        ("grdr.event.v1alpha1.Action", event::Action::KNOWN_TAGS),
        (
            "grdr.event.v1alpha1.ActionRollup",
            event::ActionRollup::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.SessionLifecycleEvent",
            event::SessionLifecycleEvent::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.HealthEvent",
            event::HealthEvent::KNOWN_TAGS,
        ),
        (
            "grdr.event.v1alpha1.ConfigEvent",
            event::ConfigEvent::KNOWN_TAGS,
        ),
        ("grdr.event.v1alpha1.Event", event::Event::KNOWN_TAGS),
        (
            "grdr.decision.v1alpha1.Verdict",
            decision::Verdict::KNOWN_TAGS,
        ),
        ("grdr.decision.v1alpha1.Grant", decision::Grant::KNOWN_TAGS),
        (
            "grdr.decision.v1alpha1.Receipt",
            decision::Receipt::KNOWN_TAGS,
        ),
        (
            "grdr.decision.v1alpha1.Expectation",
            decision::Expectation::KNOWN_TAGS,
        ),
        (
            "grdr.decision.v1alpha1.DecisionRecord",
            decision::DecisionRecord::KNOWN_TAGS,
        ),
        (
            "grdr.finding.v1alpha1.EvidenceSpan",
            finding::EvidenceSpan::KNOWN_TAGS,
        ),
        (
            "grdr.finding.v1alpha1.Observable",
            finding::Observable::KNOWN_TAGS,
        ),
        (
            "grdr.finding.v1alpha1.Suppression",
            finding::Suppression::KNOWN_TAGS,
        ),
        (
            "grdr.finding.v1alpha1.Finding",
            finding::Finding::KNOWN_TAGS,
        ),
        (
            "grdr.finding.v1alpha1.Incident",
            finding::Incident::KNOWN_TAGS,
        ),
        (
            "grdr.assurance.v1alpha1.ControlPointCapability",
            assurance::ControlPointCapability::KNOWN_TAGS,
        ),
        (
            "grdr.assurance.v1alpha1.CapabilityProbeResult",
            assurance::CapabilityProbeResult::KNOWN_TAGS,
        ),
        (
            "grdr.assurance.v1alpha1.AssuranceRecord",
            assurance::AssuranceRecord::KNOWN_TAGS,
        ),
        (
            "grdr.inventory.v1alpha1.DiscoveryEvidence",
            inventory::DiscoveryEvidence::KNOWN_TAGS,
        ),
        (
            "grdr.inventory.v1alpha1.DeclaredToolSpec",
            inventory::DeclaredToolSpec::KNOWN_TAGS,
        ),
        (
            "grdr.inventory.v1alpha1.AgentDeclaration",
            inventory::AgentDeclaration::KNOWN_TAGS,
        ),
        (
            "grdr.inventory.v1alpha1.DeclaredSourceRow",
            inventory::DeclaredSourceRow::KNOWN_TAGS,
        ),
        (
            "grdr.inventory.v1alpha1.InventoryChange",
            inventory::InventoryChange::KNOWN_TAGS,
        ),
        (
            "grdr.inventory.v1alpha1.BomComponent",
            inventory::BomComponent::KNOWN_TAGS,
        ),
        (
            "grdr.inventory.v1alpha1.BomEdge",
            inventory::BomEdge::KNOWN_TAGS,
        ),
        (
            "grdr.inventory.v1alpha1.AgentBom",
            inventory::AgentBom::KNOWN_TAGS,
        ),
        (
            "grdr.feed.v1alpha1.FeedHeader",
            feed::FeedHeader::KNOWN_TAGS,
        ),
        (
            "grdr.feed.v1alpha1.FeedSummaryRecord",
            feed::FeedSummaryRecord::KNOWN_TAGS,
        ),
        ("grdr.feed.v1alpha1.GapRecord", feed::GapRecord::KNOWN_TAGS),
        (
            "grdr.export.v1alpha1.ExportCursor",
            export::ExportCursor::KNOWN_TAGS,
        ),
        (
            "grdr.export.v1alpha1.ExportRecord",
            export::ExportRecord::KNOWN_TAGS,
        ),
        (
            "grdr.decide.v1alpha1.BlockNotice",
            decide::BlockNotice::KNOWN_TAGS,
        ),
        (
            "grdr.decide.v1alpha1.ControlPointCapability",
            decide::ControlPointCapability::KNOWN_TAGS,
        ),
        (
            "grdr.decide.v1alpha1.HelloRequest",
            decide::HelloRequest::KNOWN_TAGS,
        ),
        (
            "grdr.decide.v1alpha1.HelloResponse",
            decide::HelloResponse::KNOWN_TAGS,
        ),
        (
            "grdr.decide.v1alpha1.DecideRequest",
            decide::DecideRequest::KNOWN_TAGS,
        ),
        (
            "grdr.decide.v1alpha1.DecideAck",
            decide::DecideAck::KNOWN_TAGS,
        ),
        (
            "grdr.decide.v1alpha1.DecideResponse",
            decide::DecideResponse::KNOWN_TAGS,
        ),
        (
            "grdr.decide.v1alpha1.ReportRequest",
            decide::ReportRequest::KNOWN_TAGS,
        ),
        (
            "grdr.decide.v1alpha1.ReportResponse",
            decide::ReportResponse::KNOWN_TAGS,
        ),
        (
            "grdr.provider.v1alpha1.GetCapabilitiesRequest",
            provider::GetCapabilitiesRequest::KNOWN_TAGS,
        ),
        (
            "grdr.provider.v1alpha1.GetCapabilitiesResponse",
            provider::GetCapabilitiesResponse::KNOWN_TAGS,
        ),
        (
            "grdr.provider.v1alpha1.EvaluateVerdictRequest",
            provider::EvaluateVerdictRequest::KNOWN_TAGS,
        ),
        (
            "grdr.provider.v1alpha1.EvaluateVerdictResponse",
            provider::EvaluateVerdictResponse::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.HealthCondition",
            local::HealthCondition::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.GetStatusRequest",
            local::GetStatusRequest::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.GetStatusResponse",
            local::GetStatusResponse::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.ExplainRequest",
            local::ExplainRequest::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.ExplainResponse",
            local::ExplainResponse::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.ProposeRequest",
            local::ProposeRequest::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.ProposeResponse",
            local::ProposeResponse::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.LocalQueryRequest",
            local::LocalQueryRequest::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.LocalQueryResponse",
            local::LocalQueryResponse::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.SubscribeRequest",
            local::SubscribeRequest::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.SubscribeResponse",
            local::SubscribeResponse::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.RequestLeaseRequest",
            local::RequestLeaseRequest::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.RequestLeaseResponse",
            local::RequestLeaseResponse::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.OpenRelayRequest",
            local::OpenRelayRequest::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.OpenRelayResponse",
            local::OpenRelayResponse::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.SendFrameRequest",
            local::SendFrameRequest::KNOWN_TAGS,
        ),
        (
            "grdr.local.v1alpha1.SendFrameResponse",
            local::SendFrameResponse::KNOWN_TAGS,
        ),
        (
            "grdr.identity.v1alpha1.ExternalId",
            identity::ExternalId::KNOWN_TAGS,
        ),
        (
            "grdr.identity.v1alpha1.AgentIdentity",
            identity::AgentIdentity::KNOWN_TAGS,
        ),
        (
            "grdr.identity.v1alpha1.LocalAttestation",
            identity::LocalAttestation::KNOWN_TAGS,
        ),
        (
            "grdr.identity.v1alpha1.Ceiling",
            identity::Ceiling::KNOWN_TAGS,
        ),
        (
            "grdr.identity.v1alpha1.Correlation",
            identity::Correlation::KNOWN_TAGS,
        ),
        ("grdr.identity.v1alpha1.Lease", identity::Lease::KNOWN_TAGS),
        (
            "grdr.fleet.v1alpha1.CompatRange",
            fleet::CompatRange::KNOWN_TAGS,
        ),
        ("grdr.fleet.v1alpha1.Schedule", fleet::Schedule::KNOWN_TAGS),
        (
            "grdr.fleet.v1alpha1.Handshake",
            fleet::Handshake::KNOWN_TAGS,
        ),
        (
            "grdr.fleet.v1alpha1.ResponseKeyCertificate",
            fleet::ResponseKeyCertificate::KNOWN_TAGS,
        ),
        (
            "grdr.fleet.v1alpha1.CommandEnvelope",
            fleet::CommandEnvelope::KNOWN_TAGS,
        ),
        (
            "grdr.fleet.v1alpha1.EnrolRequest",
            fleet::EnrolRequest::KNOWN_TAGS,
        ),
        (
            "grdr.fleet.v1alpha1.EnrolResponse",
            fleet::EnrolResponse::KNOWN_TAGS,
        ),
        (
            "grdr.fleet.v1alpha1.CheckInRequest",
            fleet::CheckInRequest::KNOWN_TAGS,
        ),
        (
            "grdr.fleet.v1alpha1.CheckInResponse",
            fleet::CheckInResponse::KNOWN_TAGS,
        ),
        (
            "grdr.fleet.v1alpha1.WaitRequest",
            fleet::WaitRequest::KNOWN_TAGS,
        ),
        (
            "grdr.fleet.v1alpha1.WaitResponse",
            fleet::WaitResponse::KNOWN_TAGS,
        ),
        (
            "grdr.fleet.v1alpha1.PendingCommandsRequest",
            fleet::PendingCommandsRequest::KNOWN_TAGS,
        ),
        (
            "grdr.fleet.v1alpha1.PendingCommandsResponse",
            fleet::PendingCommandsResponse::KNOWN_TAGS,
        ),
        ("grdr.ingest.v1alpha1.LaneAck", ingest::LaneAck::KNOWN_TAGS),
        (
            "grdr.ingest.v1alpha1.FlowControl",
            ingest::FlowControl::KNOWN_TAGS,
        ),
        (
            "grdr.ingest.v1alpha1.PushBatchRequest",
            ingest::PushBatchRequest::KNOWN_TAGS,
        ),
        (
            "grdr.ingest.v1alpha1.PushBatchResponse",
            ingest::PushBatchResponse::KNOWN_TAGS,
        ),
        (
            "grdr.bootstrap.v1.HelloRequest",
            bootstrap::HelloRequest::KNOWN_TAGS,
        ),
        (
            "grdr.bootstrap.v1.HelloResponse",
            bootstrap::HelloResponse::KNOWN_TAGS,
        ),
        ("grdr.embed.v1alpha1.Tick", embed::Tick::KNOWN_TAGS),
        ("grdr.embed.v1alpha1.Input", embed::Input::KNOWN_TAGS),
        ("grdr.embed.v1alpha1.Effect", embed::Effect::KNOWN_TAGS),
        (
            "grdr.embed.v1alpha1.Diagnostic",
            embed::Diagnostic::KNOWN_TAGS,
        ),
        ("grdr.embed.v1alpha1.Output", embed::Output::KNOWN_TAGS),
        (
            "grdr.embed.v1alpha1.LoadReport.NotEvaluable",
            embed::load_report::NotEvaluable::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.LoadReport",
            embed::LoadReport::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.EngineState",
            embed::EngineState::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.HostProfile",
            embed::HostProfile::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.ActuatorRequest",
            embed::ActuatorRequest::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.ActuatorResult",
            embed::ActuatorResult::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.LoadBundleRequest",
            embed::LoadBundleRequest::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.LoadBundleResponse",
            embed::LoadBundleResponse::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.StepRequest",
            embed::StepRequest::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.StepResponse",
            embed::StepResponse::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.GetEngineHealthRequest",
            embed::GetEngineHealthRequest::KNOWN_TAGS,
        ),
        (
            "grdr.embed.v1alpha1.GetEngineHealthResponse",
            embed::GetEngineHealthResponse::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.RuntimeSettingEntry",
            operator::RuntimeSettingEntry::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.RuntimeConfigRevision",
            operator::RuntimeConfigRevision::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.OperatorTargetHealth",
            operator::OperatorTargetHealth::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.OrganisationSummary",
            operator::OrganisationSummary::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.OperatorAuditEntry",
            operator::OperatorAuditEntry::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.ListRuntimeRevisionsRequest",
            operator::ListRuntimeRevisionsRequest::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.ListRuntimeRevisionsResponse",
            operator::ListRuntimeRevisionsResponse::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.StageRuntimeRevisionRequest",
            operator::StageRuntimeRevisionRequest::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.StageRuntimeRevisionResponse",
            operator::StageRuntimeRevisionResponse::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.ApplyRuntimeRevisionRequest",
            operator::ApplyRuntimeRevisionRequest::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.ApplyRuntimeRevisionResponse",
            operator::ApplyRuntimeRevisionResponse::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.ListTargetHealthRequest",
            operator::ListTargetHealthRequest::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.ListTargetHealthResponse",
            operator::ListTargetHealthResponse::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.ListOperatorAuditRequest",
            operator::ListOperatorAuditRequest::KNOWN_TAGS,
        ),
        (
            "grdr.operator.v1alpha1.ListOperatorAuditResponse",
            operator::ListOperatorAuditResponse::KNOWN_TAGS,
        ),
    ];

    let mut checked = BTreeSet::new();
    for (name, rust_tags) in expected_canonical {
        ensure(checked.insert(*name), format!("duplicate entry {name}"))?;
        let msg = proto_msgs
            .get(*name)
            .ok_or_else(|| format!("canonical proto message missing from proto.binpb: {name}"))?;
        let mut proto_tag_set = BTreeSet::new();
        for f in &msg.fields {
            let tag = u32::try_from(f.number).map_err(|_| format!("negative tag on {name}"))?;
            proto_tag_set.insert(tag);
        }
        let rust_tag_set: BTreeSet<u32> = rust_tags.iter().copied().collect();
        ensure_eq(
            &proto_tag_set,
            &rust_tag_set,
            &format!("tag parity drift on {name}"),
        )?;
    }

    for full_name in proto_msgs.keys() {
        if full_name.starts_with("grdr.api.") {
            continue;
        }
        if full_name.starts_with("grdr.common.v1alpha1.") && !checked.contains(full_name.as_str()) {
            continue;
        }
        ensure(
            checked.contains(full_name.as_str()),
            format!(
                "canonical proto message {full_name} is missing KnownFieldTags parity coverage"
            ),
        )?;
    }

    ensure_eq(
        &ProtoTimestamp::KNOWN_TAGS,
        &&[1u32, 2u32][..],
        "ProtoTimestamp KNOWN_TAGS",
    )?;
    ensure_eq(
        &ProtoDuration::KNOWN_TAGS,
        &&[1u32, 2u32][..],
        "ProtoDuration KNOWN_TAGS",
    )?;
    Ok(())
}
