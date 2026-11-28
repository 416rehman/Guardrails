// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-Gap S-31 conformance scenarios covering offline boot, TUF/DSSE verification, live packs, and zero egress.

use std::collections::BTreeMap;
use std::path::PathBuf;

use grdr_comply::oscal::OSCAL_VERSION;
use grdr_comply::{
    EvidenceDataClass, EvidencePipelineInput, EvidenceQuery, EvidenceResult, FieldRead,
    default_registry, deployment_fingerprint, evaluate_evidence_item, export_component_definition,
    export_offline_bundle, verify_evidence_bundle,
};
use grdr_core::policy::{essentials_pack, evaluate};
use grdr_crypto::SigningKeypair;
use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, KillSwitchState, SignatureStatus,
    SigningKeypairExt as _, Verdict, verify_receipt,
};
use grdr_update::{
    AirgapArtifact, AirgapBundleEntry, AirgapBundleManifest, BundleApprovalState, RolloutHaltEntry,
    RootKeyRole, RootMetadata, SignedMetadata, TufRole, TufRootKind, UpdateError, UpdateTrust,
    canonical_sha256, sign_dsse_envelope, sign_metadata, verify_airgap_bundle,
};
use jiff::Timestamp;

use crate::pack_verify::validate_live_packs;
use crate::{ConformanceError, ScenarioCategory, ScenarioOutcome, ScenarioResult};

pub fn run_airgap_s31_checks() -> Result<Vec<ScenarioResult>, ConformanceError> {
    Ok(vec![
        s31_offline_tuf_dsse_bundle_verification()?,
        s31_live_packs_lint_and_signature()?,
        s31_offline_enforcement_and_signed_receipts()?,
        s31_offline_compliance_oscal_and_tamper_detection()?,
    ])
}

fn s31_offline_tuf_dsse_bundle_verification() -> Result<ScenarioResult, ConformanceError> {
    let release_signer = SigningKeypair::generate().map_err(|e| map_err("S31-01", e))?;
    let rebuilder = SigningKeypair::generate().map_err(|e| map_err("S31-01", e))?;
    let now = Timestamp::from_second(1_750_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let expires = Timestamp::from_second(1_781_536_000).unwrap_or(now);

    let root = build_test_project_root(&release_signer, &rebuilder, expires)?;
    let trust = UpdateTrust::new(root, now).map_err(|e| map_err("S31-01", e))?;

    let sample_bytes = b"id = \"grdr.essentials\"\nversion = \"1.0.0\"\n".to_vec();
    let sample_sha = canonical_sha256(&sample_bytes);
    let manifest = AirgapBundleManifest {
        bundle_id: "s31-conformance-bundle".into(),
        bundle_version: "1.0.0".into(),
        created_at: now,
        entries: vec![AirgapBundleEntry {
            path: "packs/essentials/pack.toml".into(),
            pack_id: "grdr.essentials".into(),
            version: "1.0.0".into(),
            sha256: sample_sha,
            length: u64::try_from(sample_bytes.len()).unwrap_or(u64::MAX),
        }],
        halted_releases: Vec::new(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|e| map_err("S31-01", e))?;
    let dsse_single = sign_dsse_envelope(
        "application/vnd.grdr.airgap-manifest+json",
        &manifest_bytes,
        &[&release_signer],
    )
    .map_err(|e| map_err("S31-01", e))?;
    let dsse = sign_dsse_envelope(
        "application/vnd.grdr.airgap-manifest+json",
        &manifest_bytes,
        &[&release_signer, &rebuilder],
    )
    .map_err(|e| map_err("S31-01", e))?;
    let artifacts = vec![AirgapArtifact {
        path: "packs/essentials/pack.toml".into(),
        bytes: sample_bytes,
    }];

    let accepted_early = BundleApprovalState::TermsAccepted {
        operator_id: "airgap-op-1".into(),
        accepted_at: now,
    };
    if verify_airgap_bundle(&trust, &dsse_single, &artifacts, &accepted_early, &[], now).is_ok() {
        return Err(map_err(
            "S31-01",
            "single-signer DSSE accepted against 2-of-2 content threshold",
        ));
    }

    let unaccepted = verify_airgap_bundle(
        &trust,
        &dsse,
        &artifacts,
        &BundleApprovalState::AwaitingTermsAcceptance,
        &[],
        now,
    );
    if !matches!(unaccepted, Err(UpdateError::TermsNotAccepted)) {
        return Err(map_err(
            "S31-01",
            "bundle accepted without operator terms acceptance",
        ));
    }

    let accepted = BundleApprovalState::TermsAccepted {
        operator_id: "airgap-op-1".into(),
        accepted_at: now,
    };
    let mut tampered = artifacts.clone();
    if let Some(first) = tampered.first_mut()
        && let Some(b) = first.bytes.first_mut()
    {
        *b ^= 0xff;
    }
    if !matches!(
        verify_airgap_bundle(&trust, &dsse, &tampered, &accepted, &[], now),
        Err(UpdateError::ArtifactIntegrity { .. })
    ) {
        return Err(map_err(
            "S31-01",
            "tampered airgap artifact passed verification",
        ));
    }

    let halt = vec![RolloutHaltEntry {
        pack_id: "grdr.essentials".into(),
        version: "1.0.0".into(),
        reason: "S-31 halt check".into(),
    }];
    if !matches!(
        verify_airgap_bundle(&trust, &dsse, &artifacts, &accepted, &halt, now),
        Err(UpdateError::HaltedRelease(_))
    ) {
        return Err(map_err("S31-01", "halted release was not rejected"));
    }

    let ok = verify_airgap_bundle(&trust, &dsse, &artifacts, &accepted, &[], now)
        .map_err(|e| map_err("S31-01", e))?;

    Ok(ScenarioResult {
        id: "S31-01".into(),
        category: ScenarioCategory::Airgap,
        title: "Offline air-gap bundle DSSE+TUF trust, terms, tamper, and halt verification".into(),
        outcome: ScenarioOutcome::Pass,
        detail: format!(
            "verified {} entry under 2-of-2 project root",
            ok.verified_entries
        ),
    })
}

fn s31_live_packs_lint_and_signature() -> Result<ScenarioResult, ConformanceError> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let summary = validate_live_packs(&repo_root)?;
    Ok(ScenarioResult {
        id: "S31-02".into(),
        category: ScenarioCategory::Airgap,
        title:
            "Live default signed packs pass P7, Cedar strict modes, Sigma detection fixtures, and compliance parity"
                .into(),
        outcome: ScenarioOutcome::Pass,
        detail: format!(
            "signed_packs={} detections={} actions={} capabilities={} frameworks={}",
            summary.signed_packs_verified,
            summary.detection_rules_count,
            summary.response_actions_count,
            summary.compliance_capabilities_count,
            summary.compliance_frameworks_count
        ),
    })
}

fn s31_offline_enforcement_and_signed_receipts() -> Result<ScenarioResult, ConformanceError> {
    let now = Timestamp::from_second(1_750_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let device_kp = SigningKeypair::generate().map_err(|e| map_err("S31-03", e))?;
    let packs = vec![essentials_pack()];

    let control_write = ActionAttempt {
        id: "att-s31-deny".into(),
        session_id: "sess-s31".into(),
        device_id: "dev-airgap-1".into(),
        device_name: "airgap-node".into(),
        agent_name: "claude-code".into(),
        action_class: ActionClass::FileWrite,
        control_point: ControlPoint::Hook,
        target: ".claude/settings.json".into(),
        summary: "write agent config".into(),
        timestamp: now,
        ..Default::default()
    };
    let mut deny_receipt = evaluate(&control_write, &packs, &[], &KillSwitchState::Inactive, now);
    if deny_receipt.verdict != Verdict::Deny {
        return Err(map_err(
            "S31-03",
            "control-file write was not denied offline",
        ));
    }
    device_kp
        .sign_receipt(&mut deny_receipt)
        .map_err(|e| map_err("S31-03", e))?;
    if verify_receipt(&deny_receipt, &[device_kp.public_info()]) != SignatureStatus::Verified {
        return Err(map_err("S31-03", "offline receipt verification failed"));
    }

    let cred_read = ActionAttempt {
        id: "att-s31-ask".into(),
        action_class: ActionClass::FileRead,
        target: "/home/dev/.ssh/id_ed25519".into(),
        ..control_write
    };
    let ask_receipt = evaluate(&cred_read, &packs, &[], &KillSwitchState::Inactive, now);
    if ask_receipt.verdict != Verdict::StepUp {
        return Err(map_err(
            "S31-03",
            "credential-store read did not yield StepUp offline",
        ));
    }

    Ok(ScenarioResult {
        id: "S31-03".into(),
        category: ScenarioCategory::Airgap,
        title: "Isolated offline Essentials enforcement and Ed25519 receipt verification".into(),
        outcome: ScenarioOutcome::Pass,
        detail:
            "verified Deny + StepUp verdicts and receipt signature offline with zero server calls"
                .into(),
    })
}

fn s31_offline_compliance_oscal_and_tamper_detection() -> Result<ScenarioResult, ConformanceError> {
    let now = Timestamp::from_second(1_750_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let start = Timestamp::from_second(1_749_913_600).unwrap_or(Timestamp::UNIX_EPOCH);
    let kp = SigningKeypair::generate().map_err(|e| map_err("S31-04", e))?;
    let registry = default_registry().map_err(|e| map_err("S31-04", e))?;

    let comp = export_component_definition(&registry, "Guardrails ADR", "0.1.0", now);
    if comp.component_definition.metadata.oscal_version != OSCAL_VERSION {
        return Err(map_err("S31-04", "OSCAL component version mismatch"));
    }

    let query = EvidenceQuery {
        id: "q.preexec.enforce".into(),
        version: "1.0.0".into(),
        capability: "cap.preexec.enforce".into(),
        reads: vec![FieldRead {
            field_path: "receipt.verdict".into(),
            data_class: EvidenceDataClass::Derived,
        }],
        max_class: EvidenceDataClass::Derived,
        group_by: vec!["capability".into()],
    };
    let lagged_input = EvidencePipelineInput {
        organisation: "airgap-org".into(),
        period_start: start,
        period_end: now,
        pipeline_lag_seconds: 900,
        max_lag_seconds: 300,
        total_observations: 10,
        covered_observations: 10,
        sample_ids: vec!["rcp_s31_1".into()],
        query_digest: canonical_sha256(b"q.preexec"),
        pack_digest: canonical_sha256(b"grdr.compliance@1.0.0"),
        schema_rev: "v1alpha1".into(),
    };
    let lag_item = evaluate_evidence_item(&query, &lagged_input, &registry, &kp)
        .map_err(|e| map_err("S31-04", e))?;
    if lag_item.result != EvidenceResult::NotEvaluable {
        return Err(map_err(
            "S31-04",
            "lagged pipeline did not yield P9 NotEvaluable",
        ));
    }

    let fresh_input = EvidencePipelineInput {
        pipeline_lag_seconds: 0,
        ..lagged_input
    };
    let ok_item = evaluate_evidence_item(&query, &fresh_input, &registry, &kp)
        .map_err(|e| map_err("S31-04", e))?;
    let items = vec![ok_item];
    let mut bundle =
        export_offline_bundle(&kp, "airgap-org", &items, now).map_err(|e| map_err("S31-04", e))?;
    let fp = deployment_fingerprint(&kp.public_info());
    let report = verify_evidence_bundle(&bundle, &fp).map_err(|e| map_err("S31-04", e))?;
    if report.oscal_version != OSCAL_VERSION || report.verified_items != 1 {
        return Err(map_err(
            "S31-04",
            "unexpected offline bundle verification report",
        ));
    }

    if let Some(first) = bundle.items.first_mut() {
        first.organisation = "tampered-org".into();
    }
    if verify_evidence_bundle(&bundle, &fp).is_ok() {
        return Err(map_err(
            "S31-04",
            "tampered evidence bundle was not rejected",
        ));
    }

    Ok(ScenarioResult {
        id: "S31-04".into(),
        category: ScenarioCategory::Airgap,
        title:
            "Offline OSCAL 1.2.3 compliance bundle export, lag->NotEvaluable, and tamper rejection"
                .into(),
        outcome: ScenarioOutcome::Pass,
        detail: "OSCAL 1.2.3 verified offline and rejected mutated evidence item".into(),
    })
}

fn build_test_project_root(
    release_signer: &SigningKeypair,
    rebuilder: &SigningKeypair,
    expires: Timestamp,
) -> Result<SignedMetadata<RootMetadata>, ConformanceError> {
    let mut keys = BTreeMap::new();
    keys.insert(
        release_signer.key_id().to_owned(),
        release_signer.public_info(),
    );
    keys.insert(rebuilder.key_id().to_owned(), rebuilder.public_info());
    let mut roles = BTreeMap::new();
    for role in [TufRole::Root, TufRole::Binaries, TufRole::Content] {
        roles.insert(
            role,
            RootKeyRole {
                key_ids: vec![
                    release_signer.key_id().to_owned(),
                    rebuilder.key_id().to_owned(),
                ],
                threshold: 2,
            },
        );
    }
    for role in [TufRole::Timestamp, TufRole::Snapshot, TufRole::Targets] {
        roles.insert(
            role,
            RootKeyRole {
                key_ids: vec![release_signer.key_id().to_owned()],
                threshold: 1,
            },
        );
    }
    sign_metadata(
        RootMetadata {
            root_kind: TufRootKind::Project,
            version: 1,
            expires,
            keys,
            roles,
        },
        &[release_signer, rebuilder],
    )
    .map_err(|e| map_err("S31-01", e))
}

fn map_err(id: &str, err: impl ToString) -> ConformanceError {
    ConformanceError::ScenarioFailed {
        scenario_id: id.to_owned(),
        detail: err.to_string(),
    }
}
