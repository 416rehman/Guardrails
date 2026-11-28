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
    BucketRange, CODE_SAAS_CELL_UNAVAILABLE, CODE_SAAS_INVALID_INPUT, CODE_SAAS_OPS_BOUND_EXCEEDED,
    CODE_SAAS_RECONCILIATION_BLOCKED, CODE_SAAS_REGION_VIOLATION, CODE_SAAS_SIGNATURE_INVALID,
    CODE_SAAS_TENANT_MISMATCH, CellCapacityVector, CellEndpoint, CellId, CellRouter, CellState,
    ChangeFreezeWindow, DeterministicSanctionsScreen, DeviceRedirectSpec, ExportOrgBundleRequest,
    ImportBaseline, InMemoryUsageLedger, InvoiceAdapter, InvoiceUnitPrices, MaintenanceStep,
    MeterPeriod, MigrationStage, MigrationTargetKind, OperationsRunner, OpsBounds,
    OrgPlacementInput, RegionId, RunbookActor, SaasOperationalBounds, SanctionsDecision,
    SanctionsScreen, StripeMeterAdapter, TenantLifecycleRecord, UnitEconomicsInput, UsageRecorder,
    UsageSample, UsageSampleKind, WatermarkedState, compute_unit_economics, export_org_bundle,
    generate_signed_statement, import_org_bundle, reconcile_usage_vs_invoice,
    sample_idempotency_key, sign_device_redirect, sign_route_ticket, verify_device_redirect,
    verify_route_ticket, verify_statement,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn test_keypair() -> SigningKeypair {
    SigningKeypair::from_seed([0x4Bu8; 32])
}

fn default_range() -> VersionRange {
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

fn expect_err<T>(res: Result<T, CodedError>, context: &str) -> Result<CodedError, CodedError> {
    match res {
        Ok(_) => Err(CodedError::new("GRDR-TEST-0001", context, "")),
        Err(err) => Ok(err),
    }
}

#[test]
fn statement_rejects_outer_org_forgery_and_reconciliation_blocks_overflow_and_swaps() -> TestResult
{
    let bounds = SaasOperationalBounds::load_embedded()?;
    let kp = test_keypair();
    let org_a = OrgId::new("org-a")?;
    let org_b = OrgId::new("org-b")?;
    let obs = Timestamp::from_second(1_793_577_600)?;

    let mut ledger = InMemoryUsageLedger::try_new(bounds)?;
    let key = sample_idempotency_key(&org_a, "dev-1", UsageSampleKind::DailyActiveEndpoint, obs);
    ensure(
        ledger.record_sample(UsageSample {
            idempotency_key: key,
            org_id: org_a.clone(),
            actor_or_device_id: "dev-1".to_owned(),
            kind: UsageSampleKind::DailyActiveEndpoint,
            quantity_units: 1,
            observed_at: obs,
            recorded_at: obs,
        })?,
        "record dae sample",
    )?;
    let key_eph = sample_idempotency_key(
        &org_a,
        "runner-1",
        UsageSampleKind::EphemeralSensorHour,
        Timestamp::from_second(1_793_581_200)?,
    );
    ensure(
        key_eph
            != sample_idempotency_key(
                &org_a,
                "runner-1",
                UsageSampleKind::EphemeralSensorHour,
                obs,
            ),
        "ephemeral usage keys must differentiate hourly windows",
    )?;
    ensure(
        ledger.record_sample(UsageSample {
            idempotency_key: key_eph,
            org_id: org_a.clone(),
            actor_or_device_id: "runner-1".to_owned(),
            kind: UsageSampleKind::EphemeralSensorHour,
            quantity_units: 10,
            observed_at: obs,
            recorded_at: obs,
        })?,
        "record ephemeral sample",
    )?;

    let period = MeterPeriod::try_from_timestamp(obs)?;
    let mut forged = generate_signed_statement(&ledger, &org_a, period, &kp)?;
    forged.org_id = org_b;
    let err = expect_err(
        verify_statement(&kp.public_key_b64(), &forged),
        "outer org mismatch must fail verification",
    )?;
    ensure_eq(
        err.code.as_str(),
        CODE_SAAS_TENANT_MISMATCH,
        "outer org mismatch",
    )?;

    let valid = generate_signed_statement(&ledger, &org_a, period, &kp)?;
    let prices = InvoiceUnitPrices {
        endpoint_unit_cents: 2000,
        ephemeral_hour_cents: 10,
        endpoint_day_cents: 50,
        over_retention_gb_day_cents: 5,
    };
    let mut lines = StripeMeterAdapter.emit_invoice_lines(&valid, prices)?;

    // Reject duplicate idempotency_key even if amounts happen to look clean.
    let mut dup = lines.clone();
    if let Some(first) = lines.first().cloned() {
        dup.push(first);
    }
    let dup_err = expect_err(
        reconcile_usage_vs_invoice(&valid, &prices, &dup, false, &bounds),
        "duplicate idempotency key must fail",
    )?;
    ensure_eq(
        dup_err.code.as_str(),
        CODE_SAAS_RECONCILIATION_BLOCKED,
        "dup key blocked",
    )?;

    // Reject metric swap (1 active endpoint moved into ephemeral hours keeps aggregate sum intact).
    if let Some(l0) = lines.get_mut(0) {
        l0.billable_units = 0;
        l0.subtotal_cents = 0;
    }
    if let Some(l1) = lines.get_mut(1) {
        l1.billable_units = 11;
        l1.subtotal_cents = 11 * prices.ephemeral_hour_cents;
    }
    let swap_err = expect_err(
        reconcile_usage_vs_invoice(&valid, &prices, &lines, false, &bounds),
        "metric swap must fail per-metric reconciliation",
    )?;
    ensure_eq(
        swap_err.code.as_str(),
        CODE_SAAS_RECONCILIATION_BLOCKED,
        "metric swap blocked",
    )?;

    // Reject huge billable_units (> 1.84e15) that previously wrapped u64::saturating_mul in drift check.
    let mut overflow_lines = StripeMeterAdapter.emit_invoice_lines(&valid, prices)?;
    if let Some(l0) = overflow_lines.get_mut(0) {
        l0.billable_units = 2_000_000_000_000_000_000;
        l0.unit_price_cents = 0;
        l0.subtotal_cents = 0;
    }
    let overflow_err = expect_err(
        reconcile_usage_vs_invoice(&valid, &prices, &overflow_lines, false, &bounds),
        "overflow billable_units must fail reconciliation",
    )?;
    ensure_eq(
        overflow_err.code.as_str(),
        CODE_SAAS_RECONCILIATION_BLOCKED,
        "overflow blocked",
    )?;
    Ok(())
}

#[test]
fn usage_ledger_isolates_tenants_and_enforces_capacity() -> TestResult {
    let mut bounds = SaasOperationalBounds::load_embedded()?;
    bounds.max_ledger_samples = 2;
    let mut ledger = InMemoryUsageLedger::try_new(bounds)?;

    let org_a = OrgId::new("org-alpha")?;
    let org_b = OrgId::new("org-beta")?;
    let obs = Timestamp::from_second(1_793_577_600)?;
    let shared_uuid = uuid::Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);

    ensure(
        ledger.record_sample(UsageSample {
            idempotency_key: shared_uuid,
            org_id: org_a.clone(),
            actor_or_device_id: "dev-a".to_owned(),
            kind: UsageSampleKind::DailyActiveEndpoint,
            quantity_units: 1,
            observed_at: obs,
            recorded_at: obs,
        })?,
        "org_a inserts uuid",
    )?;
    ensure(
        ledger.record_sample(UsageSample {
            idempotency_key: shared_uuid,
            org_id: org_b,
            actor_or_device_id: "dev-b".to_owned(),
            kind: UsageSampleKind::DailyActiveEndpoint,
            quantity_units: 1,
            observed_at: obs,
            recorded_at: obs,
        })?,
        "org_b inserts same uuid independently",
    )?;

    let cap_err = expect_err(
        ledger.record_sample(UsageSample {
            idempotency_key: uuid::Uuid::from_u128(12345),
            org_id: org_a,
            actor_or_device_id: "dev-c".to_owned(),
            kind: UsageSampleKind::DailyActiveEndpoint,
            quantity_units: 1,
            observed_at: obs,
            recorded_at: obs,
        }),
        "capacity exhaustion must fail cleanly",
    )?;
    ensure_eq(
        cap_err.code.as_str(),
        CODE_SAAS_OPS_BOUND_EXCEEDED,
        "capacity bound code",
    )?;
    Ok(())
}

#[test]
fn portability_rejects_smuggling_delegation_stage_and_downgrade_replay() -> TestResult {
    let acme = OrgId::new("org-acme")?;
    let ctx = SingleCtx::new(acme.clone());
    let delegated = SingleCtx::with_delegation(acme.clone(), "del-01", 1)?;
    let kp = test_keypair();
    let ts = Timestamp::from_second(1_795_000_000)?;

    let mut files = BTreeMap::new();
    files.insert("lake/ev.parquet".to_owned(), b"pq".to_vec());
    let req = ExportOrgBundleRequest {
        source_cell: "cell-us-01".to_owned(),
        target_kind: MigrationTargetKind::HostedCell,
        exported_at: ts,
        min_agent_version: SemVer::new(0, 3, 0),
        watermarks: WatermarkedState {
            lake_watermark: 100,
            audit_watermark: 50,
            revoked_grant_ids: vec!["grant-1".to_owned()],
            kill_switch_epoch: 5,
        },
        raw_files: files,
    };

    ensure_eq(
        expect_err(
            export_org_bundle(&delegated, req.clone(), &kp),
            "delegated export",
        )?
        .code
        .as_str(),
        CODE_SAAS_TENANT_MISMATCH,
        "delegated export rejected",
    )?;

    let bundle = export_org_bundle(&ctx, req, &kp)?;
    ensure_eq(
        expect_err(
            import_org_bundle(
                &delegated,
                &bundle,
                &kp.public_key_b64(),
                &ImportBaseline::default(),
            ),
            "delegated import",
        )?
        .code
        .as_str(),
        CODE_SAAS_TENANT_MISMATCH,
        "delegated import rejected",
    )?;

    let mut smuggled = bundle.clone();
    smuggled
        .payload_blobs
        .insert("audit/extra.jsonl".to_owned(), b"smuggled".to_vec());
    ensure_eq(
        expect_err(
            import_org_bundle(
                &ctx,
                &smuggled,
                &kp.public_key_b64(),
                &ImportBaseline::default(),
            ),
            "smuggled unmanifested blob",
        )?
        .code
        .as_str(),
        CODE_SAAS_INVALID_INPUT,
        "smuggling rejected",
    )?;

    let mut non_frozen = bundle.clone();
    non_frozen.stage = MigrationStage::DualWrite;
    ensure_eq(
        expect_err(
            import_org_bundle(
                &ctx,
                &non_frozen,
                &kp.public_key_b64(),
                &ImportBaseline::default(),
            ),
            "non-frozen stage",
        )?
        .code
        .as_str(),
        CODE_SAAS_INVALID_INPUT,
        "non-frozen stage rejected",
    )?;

    let strict_baseline = ImportBaseline {
        min_exported_at: Some(ts),
        min_kill_switch_epoch: 6,
        min_lake_watermark: 100,
        min_audit_watermark: 50,
        required_revoked_grant_ids: vec!["grant-1".to_owned()],
    };
    ensure_eq(
        expect_err(
            import_org_bundle(&ctx, &bundle, &kp.public_key_b64(), &strict_baseline),
            "downgrade replay",
        )?
        .code
        .as_str(),
        CODE_SAAS_SIGNATURE_INVALID,
        "downgrade replay rejected",
    )?;
    Ok(())
}

#[test]
fn tickets_redirects_and_ops_enforce_injection_cooldown_and_erasure_locks() -> TestResult {
    let bounds = SaasOperationalBounds::load_embedded()?;
    let kp = test_keypair();
    let acme = OrgId::new("org-acme")?;
    let bad_cell = CellEndpoint {
        cell_id: CellId::new("cell-1")?,
        region: RegionId::new("us-east-1")?,
        api_endpoint: "https://".to_owned(),
        state: CellState::Active,
        buckets: BucketRange::full(),
        capacity: CellCapacityVector {
            cpu_pct: 10,
            active_sessions: 1,
            storage_pct: 10,
            write_iops_pct: 10,
            max_sessions: 100,
        },
        protocol_range: default_range(),
    };
    ensure_eq(
        expect_err(
            sign_route_ticket(&kp, &acme, "dev-1", 0, &bad_cell, 100, 60),
            "bare https url rejected",
        )?
        .code
        .as_str(),
        CODE_SAAS_INVALID_INPUT,
        "bare https rejected",
    )?;

    let good_cell = CellEndpoint {
        api_endpoint: "https://cell-1.example.test".to_owned(),
        ..bad_cell
    };
    let ticket = sign_route_ticket(&kp, &acme, "dev-1", 0, &good_cell, 100, 60)?;
    ensure_eq(
        expect_err(
            verify_route_ticket(&kp.public_key_b64(), &ticket, &acme, "other-dev", 120),
            "wrong device ticket rejected",
        )?
        .code
        .as_str(),
        CODE_SAAS_TENANT_MISMATCH,
        "wrong device rejected",
    )?;

    ensure(
        sign_device_redirect(
            &kp,
            DeviceRedirectSpec {
                org_id: acme.clone(),
                device_id: "dev\n1".to_owned(),
                old_cell: "c1".to_owned(),
                new_cell: "c2".to_owned(),
                new_endpoint: "https://cell-2.example.test".to_owned(),
                min_client_version: SemVer::new(0, 1, 0),
                issued_at_s: 100,
                ttl_seconds: 60,
            },
        )
        .is_err(),
        "newline in device_id rejected",
    )?;
    let redirect = sign_device_redirect(
        &kp,
        DeviceRedirectSpec {
            org_id: acme.clone(),
            device_id: "dev-1".to_owned(),
            old_cell: "c1".to_owned(),
            new_cell: "c2".to_owned(),
            new_endpoint: "https://cell-2.example.test".to_owned(),
            min_client_version: SemVer::new(0, 1, 0),
            issued_at_s: 100,
            ttl_seconds: 60,
        },
    )?;
    ensure_eq(
        expect_err(
            verify_device_redirect(
                &kp.public_key_b64(),
                &redirect,
                &OrgId::new("org-evil")?,
                "dev-1",
                SemVer::new(0, 2, 0),
                110,
            ),
            "cross-tenant redirect rejected",
        )?
        .code
        .as_str(),
        CODE_SAAS_TENANT_MISMATCH,
        "cross-tenant redirect code",
    )?;

    ensure(
        OperationsRunner::try_new(
            OpsBounds::from_saas_bounds(&bounds),
            vec![ChangeFreezeWindow {
                label: "bad".to_owned(),
                start_s: 200,
                end_s: 100,
            }],
        )
        .is_err(),
        "inverted freeze window rejected",
    )?;
    let mut runner = OperationsRunner::try_new(OpsBounds::from_saas_bounds(&bounds), vec![])?;
    let actor = RunbookActor {
        operator_id: "op-1".to_owned(),
        ticket_id: "INC-1".to_owned(),
        reason: "patch".to_owned(),
    };
    runner.execute_step(
        &actor,
        &MaintenanceStep {
            runbook_id: "RB-01".to_owned(),
            region: "us-east-1".to_owned(),
            blast_radius_pct: 5,
            scheduled_at_s: 1_000,
        },
    )?;
    runner.complete_region("us-east-1", 1_100)?;
    ensure_eq(
        expect_err(
            runner.execute_step(
                &actor,
                &MaintenanceStep {
                    runbook_id: "RB-01".to_owned(),
                    region: "us-east-1".to_owned(),
                    blast_radius_pct: 5,
                    scheduled_at_s: 1_200,
                },
            ),
            "cooldown window enforced",
        )?
        .code
        .as_str(),
        CODE_SAAS_OPS_BOUND_EXCEEDED,
        "cooldown bound code",
    )?;

    let now = Timestamp::from_second(1_795_000_000)?;
    let mut lifecycle = TenantLifecycleRecord::active(acme.clone(), now);
    lifecycle.schedule_erasure(now, &bounds)?;
    ensure_eq(
        expect_err(
            lifecycle.advance_dunning(0, now, &bounds),
            "dunning after erasure",
        )?
        .code
        .as_str(),
        CODE_SAAS_OPS_BOUND_EXCEEDED,
        "dunning blocked after pending erasure",
    )?;
    ensure_eq(
        expect_err(
            lifecycle.schedule_erasure(now, &bounds),
            "double schedule erasure",
        )?
        .code
        .as_str(),
        CODE_SAAS_OPS_BOUND_EXCEEDED,
        "double erasure blocked",
    )?;
    let mut max_lifecycle = TenantLifecycleRecord::active(acme, Timestamp::MAX);
    ensure_eq(
        expect_err(
            max_lifecycle.schedule_erasure(Timestamp::MAX, &bounds),
            "overflow erasure",
        )?
        .code
        .as_str(),
        CODE_SAAS_OPS_BOUND_EXCEEDED,
        "timestamp overflow erasure rejected",
    )?;
    Ok(())
}

#[test]
fn serde_invariants_sanctions_router_overlap_and_economics_bounds() -> TestResult {
    ensure(
        serde_json::from_str::<RegionId>(r#""US_EAST_INVALID""#).is_err(),
        "invalid RegionId serde rejected",
    )?;
    ensure(
        serde_json::from_str::<BucketRange>(r#"{"start_inclusive":10,"end_exclusive":5}"#).is_err(),
        "inverted BucketRange serde rejected",
    )?;
    ensure(
        serde_json::from_str::<MeterPeriod>(r#"{"year":2026,"month":13}"#).is_err(),
        "month 13 MeterPeriod serde rejected",
    )?;

    let sanctions = DeterministicSanctionsScreen::new(&["KP"], &["defense"])?;
    let org = OrgId::new("org-test")?;
    ensure(
        matches!(
            sanctions.screen_org(&org, "US", "   "),
            SanctionsDecision::Blocked { .. }
        ),
        "blank entity name fails closed",
    )?;

    let mut router = CellRouter::new()?;
    let c1 = CellEndpoint {
        cell_id: CellId::new("cell-1")?,
        region: RegionId::new("us-east-1")?,
        api_endpoint: "https://c1.example.test".to_owned(),
        state: CellState::Active,
        buckets: BucketRange::new(0, 2048)?,
        capacity: CellCapacityVector {
            cpu_pct: 10,
            active_sessions: 1,
            storage_pct: 10,
            write_iops_pct: 10,
            max_sessions: 100,
        },
        protocol_range: default_range(),
    };
    let c2_overlap = CellEndpoint {
        cell_id: CellId::new("cell-2")?,
        api_endpoint: "https://c2.example.test".to_owned(),
        buckets: BucketRange::new(1024, 4096)?,
        ..c1.clone()
    };
    router.register_cell(c1)?;
    ensure_eq(
        expect_err(router.register_cell(c2_overlap), "overlapping buckets")?
            .code
            .as_str(),
        CODE_SAAS_INVALID_INPUT,
        "overlapping cell bucket rejected",
    )?;

    router.place_org(
        OrgPlacementInput {
            org_id: org.clone(),
            required_region: RegionId::new("us-east-1")?,
            preferred_cell: None,
            iso_country: "US".to_owned(),
            entity_name: "Clean Org LLC".to_owned(),
        },
        &sanctions,
    )?;
    ensure_eq(
        expect_err(
            router.place_org(
                OrgPlacementInput {
                    org_id: org,
                    required_region: RegionId::new("eu-central-1")?,
                    preferred_cell: None,
                    iso_country: "DE".to_owned(),
                    entity_name: "Clean Org LLC".to_owned(),
                },
                &sanctions,
            ),
            "silent region move",
        )?
        .code
        .as_str(),
        CODE_SAAS_REGION_VIOLATION,
        "region pin immutability",
    )?;

    ensure_eq(
        expect_err(
            compute_unit_economics(
                &UnitEconomicsInput {
                    paid_endpoints: 10,
                    price_per_endpoint_cents: 1000,
                    compute_cents: 100,
                    storage_cents: 100,
                    egress_cents: 100,
                    model_eval_cents: 100,
                    support_ops_cents: 100,
                    payment_fee_bps: 10_001,
                },
                7000,
            ),
            "fee bps > 10000",
        )?
        .code
        .as_str(),
        CODE_SAAS_INVALID_INPUT,
        "fee bps upper bound rejected",
    )?;
    Ok(())
}

#[test]
fn hardening_sanctions_serde_https_ports_decommissioned_and_drain_split() -> TestResult {
    let org = OrgId::new("org-hardening")?;
    let deserialized: DeterministicSanctionsScreen = serde_json::from_str(
        r#"{"blocked_countries":[" kp "," ir "],"review_keywords":["Defense"]}"#,
    )?;
    ensure(
        matches!(
            deserialized.screen_org(&org, "KP", "Normalized Country Corp"),
            SanctionsDecision::Blocked { .. }
        ),
        "deserialized lowercase blocked country must normalize and block",
    )?;
    ensure(
        matches!(
            deserialized.screen_org(&org, "US", "Acme Defense Systems"),
            SanctionsDecision::ManualReview { .. }
        ),
        "deserialized review keyword must normalize case",
    )?;
    ensure(
        serde_json::from_str::<DeterministicSanctionsScreen>(r#"{"blocked_countries":[]}"#)
            .is_err(),
        "empty deserialized blocked_countries must fail closed",
    )?;
    ensure(
        serde_json::from_str::<DeterministicSanctionsScreen>(r#"{"blocked_countries":["k1"]}"#)
            .is_err(),
        "invalid deserialized ISO country code must fail closed",
    )?;

    let kp = test_keypair();
    let bad_urls = [
        "https://..",
        "https://-bad.example",
        "https://bad-.example",
        "https://example..com",
        "https://cell-1.example.test:0",
        "https://cell-1.example.test:99999",
        "https://cell-1.example.test:notaport",
        "https://cell-1.example.test:443:8443",
    ];
    for url in bad_urls {
        let cell = CellEndpoint {
            cell_id: CellId::new("cell-url")?,
            region: RegionId::new("us-east-1")?,
            api_endpoint: url.to_owned(),
            state: CellState::Active,
            buckets: BucketRange::full(),
            capacity: CellCapacityVector {
                cpu_pct: 10,
                active_sessions: 1,
                storage_pct: 10,
                write_iops_pct: 10,
                max_sessions: 100,
            },
            protocol_range: default_range(),
        };
        ensure(
            sign_route_ticket(&kp, &org, "dev-1", 0, &cell, 100, 60).is_err(),
            "malformed https port/host must fail",
        )?;
    }

    let valid_port_cell = CellEndpoint {
        cell_id: CellId::new("cell-1")?,
        region: RegionId::new("us-east-1")?,
        api_endpoint: "https://cell-1.example.test:8443".to_owned(),
        state: CellState::Active,
        buckets: BucketRange::new(0, 2048)?,
        capacity: CellCapacityVector {
            cpu_pct: 10,
            active_sessions: 1,
            storage_pct: 10,
            write_iops_pct: 10,
            max_sessions: 100,
        },
        protocol_range: default_range(),
    };
    ensure(
        sign_route_ticket(&kp, &org, "dev-1", 0, &valid_port_cell, 100, 60).is_ok(),
        "valid https hostname with port 8443 must pass",
    )?;

    let mut router = CellRouter::new()?;
    let cell_a = CellEndpoint {
        cell_id: CellId::new("cell-a")?,
        region: RegionId::new("us-east-1")?,
        api_endpoint: "https://cell-a.example.test".to_owned(),
        state: CellState::Active,
        buckets: BucketRange::new(0, 2048)?,
        capacity: valid_port_cell.capacity,
        protocol_range: default_range(),
    };
    let cell_b = CellEndpoint {
        cell_id: CellId::new("cell-b")?,
        api_endpoint: "https://cell-b.example.test".to_owned(),
        buckets: BucketRange::new(2048, 4096)?,
        ..cell_a.clone()
    };
    let cell_c = CellEndpoint {
        cell_id: CellId::new("cell-c")?,
        api_endpoint: "https://cell-c.example.test".to_owned(),
        buckets: BucketRange::new(0, 2048)?,
        ..cell_a.clone()
    };
    router.register_cell(cell_a)?;
    router.register_cell(cell_b)?;
    router.place_org(
        OrgPlacementInput {
            org_id: org.clone(),
            required_region: RegionId::new("us-east-1")?,
            preferred_cell: Some(CellId::new("cell-a")?),
            iso_country: "US".to_owned(),
            entity_name: "Clean Org Inc".to_owned(),
        },
        &deserialized,
    )?;

    // Splitting cell-b while org is actively draining into cell-b must fail closed.
    router.start_drain(&org, CellId::new("cell-b")?)?;
    ensure_eq(
        expect_err(
            router.split_cell(
                &CellId::new("cell-b")?,
                CellId::new("cell-b2")?,
                "https://cell-b2.example.test".to_owned(),
            ),
            "splitting target cell during active drain must fail",
        )?
        .code
        .as_str(),
        CODE_SAAS_CELL_UNAVAILABLE,
        "split during active drain blocked",
    )?;

    // Decommissioned cells cannot transition back to Active.
    router.update_cell_state(&CellId::new("cell-a")?, CellState::Decommissioned)?;
    router.register_cell(cell_c)?;
    ensure_eq(
        expect_err(
            router.update_cell_state(&CellId::new("cell-a")?, CellState::Active),
            "reactivating decommissioned cell must fail",
        )?
        .code
        .as_str(),
        CODE_SAAS_CELL_UNAVAILABLE,
        "decommissioned reactivation blocked",
    )?;
    Ok(())
}
