// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::fmt::Debug;

use jiff::Timestamp;

use grdr_compat::{SemVer, VersionRange};
use grdr_crypto::SigningKeypair;
use grdr_model::CodedError;
use grdr_ports::{OrgId, SingleCtx};
use grdr_saas::{
    BUCKET_COUNT, BucketRange, CODE_SAAS_LATE_USAGE_WINDOW, CODE_SAAS_OPS_BOUND_EXCEEDED,
    CODE_SAAS_RECONCILIATION_BLOCKED, CODE_SAAS_REGION_VIOLATION, CODE_SAAS_SIGNATURE_INVALID,
    CODE_SAAS_TENANT_MISMATCH, CellCapacityVector, CellEndpoint, CellId, CellRouter, CellState,
    ChangeFreezeWindow, DeterministicSanctionsScreen, DeviceRedirectSpec, ExportOrgBundleRequest,
    GateRequirementStatus, HostedGateChecklist, ImportBaseline, InMemoryUsageLedger,
    InvoiceAdapter, InvoiceUnitPrices, KillBillAdapter, MaintenanceStep, MeterPeriod,
    MigrationTargetKind, OperationsRunner, OpsBounds, OrgPlacementInput, PaidOfferGateChecklist,
    RegionId, RunbookActor, SaasOperationalBounds, SanctionsDecision, SanctionsScreen,
    StatementFileAdapter, StripeMeterAdapter, TenantLifecycleRecord, UnitEconomicsInput,
    UsageRecorder, UsageSample, UsageSampleKind, WatermarkedState, compute_unit_economics,
    device_bucket, evaluate_hosted_gate, evaluate_paid_offer_gate, export_org_bundle,
    generate_signed_statement, import_org_bundle, reconcile_usage_vs_invoice,
    sample_idempotency_key, sign_device_redirect, sign_route_ticket, verify_device_redirect,
    verify_route_ticket, verify_statement,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn test_keypair() -> SigningKeypair {
    SigningKeypair::from_seed([0x2Au8; 32])
}

fn default_protocol_range() -> VersionRange {
    VersionRange {
        min_inclusive: SemVer::new(0, 1, 0),
        max_exclusive: Some(SemVer::new(2, 0, 0)),
    }
}

fn ensure(cond: bool, msg: &str) -> Result<(), CodedError> {
    if cond {
        Ok(())
    } else {
        Err(CodedError::new("GRDR-TEST-0001", msg, ""))
    }
}

fn ensure_eq<T: PartialEq + Debug>(left: T, right: T, msg: &str) -> Result<(), CodedError> {
    if left == right {
        Ok(())
    } else {
        Err(CodedError::new(
            "GRDR-TEST-0001",
            format!("{msg}: left={left:?}, right={right:?}"),
            "",
        ))
    }
}

fn sample_cell(id: &str, region: &str, url: &str, cpu_pct: u8) -> Result<CellEndpoint, CodedError> {
    Ok(CellEndpoint {
        cell_id: CellId::new(id)?,
        region: RegionId::new(region)?,
        api_endpoint: url.to_owned(),
        state: CellState::Active,
        buckets: BucketRange::full(),
        capacity: CellCapacityVector {
            cpu_pct,
            active_sessions: 100,
            storage_pct: 20,
            write_iops_pct: 20,
            max_sessions: 10_000,
        },
        protocol_range: default_protocol_range(),
    })
}

fn expect_err<T>(res: Result<T, CodedError>, context: &str) -> Result<CodedError, CodedError> {
    match res {
        Ok(_) => Err(CodedError::new("GRDR-TEST-0001", context, "")),
        Err(err) => Ok(err),
    }
}

#[test]
fn cell_router_region_split_and_signed_route_ticket() -> TestResult {
    let mut router = CellRouter::new()?;
    let sanctions = DeterministicSanctionsScreen::new(&["KP", "IR"], &["defense"])?;
    let us_east = RegionId::new("us-east-1")?;
    let eu_central = RegionId::new("eu-central-1")?;

    let cell_us_1 = sample_cell(
        "cell-us-01",
        "us-east-1",
        "https://cell-us-01.example.test",
        35,
    )?;
    let cell_eu_1 = sample_cell(
        "cell-eu-01",
        "eu-central-1",
        "https://cell-eu-01.example.test",
        25,
    )?;
    router.register_cell(cell_us_1)?;
    router.register_cell(cell_eu_1)?;

    let acme = OrgId::new("org-acme")?;
    let eu_cell_id = CellId::new("cell-eu-01")?;
    let region_err = expect_err(
        router.place_org(
            OrgPlacementInput {
                org_id: acme.clone(),
                required_region: us_east.clone(),
                preferred_cell: Some(eu_cell_id),
                iso_country: "US".to_owned(),
                entity_name: "Acme Example Inc".to_owned(),
            },
            &sanctions,
        ),
        "cross-region placement should fail",
    )?;
    ensure_eq(
        region_err.code.as_str(),
        CODE_SAAS_REGION_VIOLATION,
        "region error code",
    )?;

    let placed = router.place_org(
        OrgPlacementInput {
            org_id: acme.clone(),
            required_region: us_east,
            preferred_cell: None,
            iso_country: "US".to_owned(),
            entity_name: "Acme Example Inc".to_owned(),
        },
        &sanctions,
    )?;
    ensure_eq(placed.primary_cell.as_str(), "cell-us-01", "placed cell")?;

    let split = router.split_cell(
        &CellId::new("cell-us-01")?,
        CellId::new("cell-us-02")?,
        "https://cell-us-02.example.test".to_owned(),
    )?;
    ensure_eq(
        split.source_buckets,
        BucketRange::new(0, 2048)?,
        "left half range",
    )?;
    ensure_eq(
        split.new_buckets,
        BucketRange::new(2048, BUCKET_COUNT)?,
        "right half range",
    )?;

    let (routed_cell, bucket) =
        router.route_device(&acme, "dev-laptop-42", SemVer::new(0, 4, 0))?;
    ensure(bucket < BUCKET_COUNT, "bucket below 4096")?;
    ensure_eq(
        bucket,
        device_bucket("dev-laptop-42"),
        "deterministic device bucket",
    )?;

    let kp = test_keypair();
    let mut ticket = sign_route_ticket(
        &kp,
        &acme,
        "dev-laptop-42",
        bucket,
        &routed_cell,
        1_700_000_000,
        300,
    )?;
    verify_route_ticket(
        &kp.public_key_b64(),
        &ticket,
        &acme,
        "dev-laptop-42",
        1_700_000_100,
    )?;

    let expired = expect_err(
        verify_route_ticket(
            &kp.public_key_b64(),
            &ticket,
            &acme,
            "dev-laptop-42",
            1_700_000_400,
        ),
        "expired route ticket should fail",
    )?;
    ensure_eq(
        expired.code.as_str(),
        CODE_SAAS_SIGNATURE_INVALID,
        "expired code",
    )?;

    ticket.api_endpoint = "https://attacker.example.invalid".to_owned();
    let tampered = expect_err(
        verify_route_ticket(
            &kp.public_key_b64(),
            &ticket,
            &acme,
            "dev-laptop-42",
            1_700_000_100,
        ),
        "tampered route ticket should fail",
    )?;
    ensure_eq(
        tampered.code.as_str(),
        CODE_SAAS_SIGNATURE_INVALID,
        "tamper code",
    )?;

    let wrong_eu = OrgId::new("org-euro")?;
    let eu_placed = router.place_org(
        OrgPlacementInput {
            org_id: wrong_eu,
            required_region: eu_central,
            preferred_cell: None,
            iso_country: "DE".to_owned(),
            entity_name: "Euro GmbH".to_owned(),
        },
        &sanctions,
    )?;
    ensure_eq(eu_placed.primary_cell.as_str(), "cell-eu-01", "eu cell")?;
    Ok(())
}

#[test]
fn org_migration_bundle_roundtrip_rejects_tamper_and_cross_tenant() -> TestResult {
    let acme = OrgId::new("org-acme")?;
    let other = OrgId::new("org-other")?;
    let ctx_acme = SingleCtx::new(acme.clone());
    let ctx_other = SingleCtx::new(other);
    let kp = test_keypair();
    let ts = Timestamp::from_second(1_795_000_000)?;

    let mut files = BTreeMap::new();
    files.insert(
        "lake/2026-11/events.parquet".to_owned(),
        b"parquet-bytes".to_vec(),
    );
    files.insert(
        "audit/receipts.jsonl".to_owned(),
        b"{\"receipt\":1}\n".to_vec(),
    );

    let watermarks = WatermarkedState {
        lake_watermark: 912,
        audit_watermark: 405,
        revoked_grant_ids: vec!["grant-revoked-01".to_owned()],
        kill_switch_epoch: 3,
    };

    let bundle = export_org_bundle(
        &ctx_acme,
        ExportOrgBundleRequest {
            source_cell: "cell-us-01".to_owned(),
            target_kind: MigrationTargetKind::SelfHostedCluster,
            exported_at: ts,
            min_agent_version: SemVer::new(0, 3, 0),
            watermarks,
            raw_files: files,
        },
        &kp,
    )?;

    let baseline = ImportBaseline::default();
    let imported = import_org_bundle(&ctx_acme, &bundle, &kp.public_key_b64(), &baseline)?;
    ensure_eq(imported.restored_files, 2, "restored files count")?;
    ensure_eq(
        imported.watermarks.kill_switch_epoch,
        3,
        "kill switch epoch",
    )?;
    ensure_eq(
        imported.watermarks.revoked_grant_ids,
        vec!["grant-revoked-01".to_owned()],
        "revoked grants",
    )?;

    let cross_tenant = expect_err(
        import_org_bundle(&ctx_other, &bundle, &kp.public_key_b64(), &baseline),
        "cross-tenant import should fail",
    )?;
    ensure_eq(
        cross_tenant.code.as_str(),
        CODE_SAAS_TENANT_MISMATCH,
        "tenant mismatch code",
    )?;

    let mut tampered = bundle.clone();
    tampered
        .payload_blobs
        .insert("audit/receipts.jsonl".to_owned(), b"tampered".to_vec());
    let tamper_err = expect_err(
        import_org_bundle(&ctx_acme, &tampered, &kp.public_key_b64(), &baseline),
        "tampered bundle blob should fail",
    )?;
    ensure_eq(
        tamper_err.code.as_str(),
        CODE_SAAS_SIGNATURE_INVALID,
        "tamper signature code",
    )?;

    let redirect = sign_device_redirect(
        &kp,
        DeviceRedirectSpec {
            org_id: acme.clone(),
            device_id: "dev-99".to_owned(),
            old_cell: "cell-us-01".to_owned(),
            new_cell: "self-hosted-01".to_owned(),
            new_endpoint: "https://grdr.internal.example.test".to_owned(),
            min_client_version: SemVer::new(0, 3, 0),
            issued_at_s: 1_795_000_000,
            ttl_seconds: 600,
        },
    )?;
    verify_device_redirect(
        &kp.public_key_b64(),
        &redirect,
        &acme,
        "dev-99",
        SemVer::new(0, 3, 2),
        1_795_000_120,
    )?;
    ensure(
        verify_device_redirect(
            &kp.public_key_b64(),
            &redirect,
            &acme,
            "dev-99",
            SemVer::new(0, 2, 9),
            1_795_000_120,
        )
        .is_err(),
        "stale client version should fail redirect verification",
    )?;
    Ok(())
}

#[test]
fn usage_ledger_dedup_late_window_and_billing_reconciliation() -> TestResult {
    let bounds = SaasOperationalBounds::load_embedded()?;
    let org = OrgId::new("org-usage")?;
    let kp = test_keypair();
    let mut ledger = InMemoryUsageLedger::try_new(bounds)?;
    let obs_day1 = Timestamp::from_second(1_793_577_600)?;
    let rec_ok = Timestamp::from_second(1_793_577_660)?;

    let key1 = sample_idempotency_key(
        &org,
        "dev-1",
        UsageSampleKind::DailyActiveEndpoint,
        obs_day1,
    );
    let sample1 = UsageSample {
        idempotency_key: key1,
        org_id: org.clone(),
        actor_or_device_id: "dev-1".to_owned(),
        kind: UsageSampleKind::DailyActiveEndpoint,
        quantity_units: 1,
        observed_at: obs_day1,
        recorded_at: rec_ok,
    };
    ensure(
        ledger.record_sample(sample1.clone())?,
        "first record accepted",
    )?;
    ensure(
        !ledger.record_sample(sample1)?,
        "duplicate sample deduplicated",
    )?;

    let eph_key = sample_idempotency_key(
        &org,
        "runner-ci-1",
        UsageSampleKind::EphemeralSensorHour,
        obs_day1,
    );
    ensure(
        ledger.record_sample(UsageSample {
            idempotency_key: eph_key,
            org_id: org.clone(),
            actor_or_device_id: "runner-ci-1".to_owned(),
            kind: UsageSampleKind::EphemeralSensorHour,
            quantity_units: 4,
            observed_at: obs_day1,
            recorded_at: rec_ok,
        })?,
        "ephemeral sample accepted",
    )?;

    let too_late = Timestamp::from_second(1_793_577_600_i64.saturating_add(36 * 86_400))?;
    let late_err = expect_err(
        ledger.record_sample(UsageSample {
            idempotency_key: sample_idempotency_key(
                &org,
                "dev-2",
                UsageSampleKind::DailyActiveEndpoint,
                obs_day1,
            ),
            org_id: org.clone(),
            actor_or_device_id: "dev-2".to_owned(),
            kind: UsageSampleKind::DailyActiveEndpoint,
            quantity_units: 1,
            observed_at: obs_day1,
            recorded_at: too_late,
        }),
        "samples older than 35 days should fail",
    )?;
    ensure_eq(
        late_err.code.as_str(),
        CODE_SAAS_LATE_USAGE_WINDOW,
        "late window code",
    )?;

    let period = MeterPeriod::try_from_timestamp(obs_day1)?;
    let statement = generate_signed_statement(&ledger, &org, period, &kp)?;
    verify_statement(&kp.public_key_b64(), &statement)?;
    ensure_eq(statement.summary.peak_active_endpoints, 1, "peak endpoints")?;
    ensure_eq(
        statement.summary.ephemeral_sensor_hours,
        4,
        "ephemeral sensor hours",
    )?;

    let prices = InvoiceUnitPrices {
        endpoint_unit_cents: 1500,
        ephemeral_hour_cents: 10,
        endpoint_day_cents: 50,
        over_retention_gb_day_cents: 5,
    };
    let stripe = StripeMeterAdapter;
    let file_adapter = StatementFileAdapter;
    let kill_bill = KillBillAdapter;

    let stripe_lines = stripe.emit_invoice_lines(&statement, prices)?;
    let file_lines = file_adapter.emit_invoice_lines(&statement, prices)?;
    let kb_lines = kill_bill.emit_invoice_lines(&statement, prices)?;

    ensure_eq(stripe_lines.len(), 4, "stripe line count")?;
    ensure_eq(
        file_lines.first().map(|l| l.subtotal_cents),
        Some(1500),
        "statement subtotal",
    )?;
    ensure_eq(
        kb_lines.get(1).map(|l| l.subtotal_cents),
        Some(40),
        "kill bill ephemeral subtotal",
    )?;

    let report = reconcile_usage_vs_invoice(&statement, &prices, &stripe_lines, true, &bounds)?;
    ensure_eq(report.drift_bps, 0, "exact reconciliation")?;

    let mut skewed = stripe_lines;
    if let Some(first) = skewed.first_mut() {
        first.billable_units = 99;
        first.subtotal_cents = 99 * prices.endpoint_unit_cents;
    }
    let blocked = expect_err(
        reconcile_usage_vs_invoice(&statement, &prices, &skewed, true, &bounds),
        "skewed invoice should block reconciliation",
    )?;
    ensure_eq(
        blocked.code.as_str(),
        CODE_SAAS_RECONCILIATION_BLOCKED,
        "blocked reconciliation code",
    )?;
    Ok(())
}

#[test]
fn ops_runner_dunning_economics_gates_and_sanctions() -> TestResult {
    let bounds = SaasOperationalBounds::load_embedded()?;
    let mut runner = OperationsRunner::try_new(
        OpsBounds::from_saas_bounds(&bounds),
        vec![ChangeFreezeWindow {
            label: "peak-incident-freeze".to_owned(),
            start_s: 2_000,
            end_s: 3_000,
        }],
    )?;
    let actor = RunbookActor {
        operator_id: "sre-alice".to_owned(),
        ticket_id: "INC-2026-01".to_owned(),
        reason: "cell-dr-drill".to_owned(),
    };

    let freeze_err = expect_err(
        runner.execute_step(
            &actor,
            &MaintenanceStep {
                runbook_id: "RB-04".to_owned(),
                region: "us-east-1".to_owned(),
                blast_radius_pct: 10,
                scheduled_at_s: 2_500,
            },
        ),
        "freeze window should reject maintenance",
    )?;
    ensure_eq(
        freeze_err.code.as_str(),
        CODE_SAAS_OPS_BOUND_EXCEEDED,
        "freeze bound code",
    )?;

    runner.execute_step(
        &actor,
        &MaintenanceStep {
            runbook_id: "RB-04".to_owned(),
            region: "us-east-1".to_owned(),
            blast_radius_pct: 20,
            scheduled_at_s: 4_000,
        },
    )?;
    let overlap_err = expect_err(
        runner.execute_step(
            &actor,
            &MaintenanceStep {
                runbook_id: "RB-04".to_owned(),
                region: "eu-central-1".to_owned(),
                blast_radius_pct: 10,
                scheduled_at_s: 4_100,
            },
        ),
        "overlapping region maintenance should fail",
    )?;
    ensure_eq(
        overlap_err.code.as_str(),
        CODE_SAAS_OPS_BOUND_EXCEEDED,
        "overlap bound code",
    )?;
    runner.complete_region("us-east-1", 4_200)?;
    ensure_eq(runner.audit_log().len(), 1, "audit log length")?;

    let org = OrgId::new("org-dunning")?;
    let now = Timestamp::from_second(1_795_000_000)?;
    let mut lifecycle = TenantLifecycleRecord::active(org.clone(), now);
    lifecycle.advance_dunning(45, now, &bounds)?;
    ensure(
        lifecycle.local_enforcement_active(),
        "enforcement must stay active during suspension",
    )?;

    lifecycle.set_legal_hold(true, now)?;
    ensure(
        lifecycle.schedule_erasure(now, &bounds).is_err(),
        "legal hold must prevent erasure",
    )?;

    let econ = compute_unit_economics(
        &UnitEconomicsInput {
            paid_endpoints: 100,
            price_per_endpoint_cents: 1500,
            compute_cents: 8000,
            storage_cents: 2000,
            egress_cents: 1000,
            model_eval_cents: 500,
            support_ops_cents: 3000,
            payment_fee_bps: 290,
        },
        bounds.min_gross_margin_bps,
    )?;
    ensure(econ.sustainable_above_target, "margin clears 70% floor")?;

    let hosted = evaluate_hosted_gate(&HostedGateChecklist {
        cell_restore_under_4h_rto: GateRequirementStatus::Passed,
        backup_restore_verified: GateRequirementStatus::Passed,
        slo_burn_alerts_active: GateRequirementStatus::Passed,
        org_export_roundtrip_passed: GateRequirementStatus::Passed,
        runbooks_complete: GateRequirementStatus::Passed,
    });
    ensure(hosted.ready, "hosted gate ready")?;

    let paid = evaluate_paid_offer_gate(&PaidOfferGateChecklist {
        hosted_gate_passed: GateRequirementStatus::Passed,
        reconciliation_zero_variance: GateRequirementStatus::Passed,
        dunning_keeps_enforcement: GateRequirementStatus::Passed,
        sanctions_screen_wired: GateRequirementStatus::Passed,
        model_terms_reviewed: GateRequirementStatus::Pending {
            reason: "pre-hosted-capacity".to_owned(),
        },
    });
    ensure(!paid.ready, "paid gate blocks when pending item exists")?;

    let sanctions = DeterministicSanctionsScreen::new(&["KP"], &["weapons"])?;
    ensure(
        matches!(
            sanctions.screen_org(&org, "US", "Example Robotics Inc"),
            SanctionsDecision::Clear
        ),
        "US org clear",
    )?;
    ensure(
        matches!(
            sanctions.screen_org(&org, "KP", "Blocked Corp"),
            SanctionsDecision::Blocked { .. }
        ),
        "embargoed country blocked",
    )?;
    Ok(())
}
