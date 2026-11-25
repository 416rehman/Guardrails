// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use grdr_crypto::{SigningKeypair, sha256_hex};
use grdr_wire::generate_nonce;

use grdr_uplink::allowlist::AllowEntry;
use grdr_uplink::auth::{
    EphemeralTransportSigner, FleetTrustAnchor, RequestKind, ResponseKeyCertificate,
    ResponseVerifier, SignedResponse, TransportKeyCertificate, sign_fleet_response,
};
use grdr_uplink::backoff::{CircuitState, OriginFailureController, full_jitter_backoff_ms};
use grdr_uplink::control::{
    COMMAND_DEDUP_CAP, CommandAction, ControlChannel, ControlChannelState, OpaqueArtifactStager,
    PendingCommand, SUBSCRIBE_MAX_HEARTBEAT_MS, SUBSCRIBE_MIN_HEARTBEAT_MS,
};
use grdr_uplink::dialer::{
    DialPurpose, DialTarget, Dialer, NetworkCondition, NetworkFingerprint, NetworkMode,
    PinVerification, ProxyCredentialKind, ProxySelection, TransportRung,
};
use grdr_uplink::error::{OfflineReason, UplinkError, UplinkHealthCondition};
use grdr_uplink::lanes::{
    BULK_MAX_DEFER_MS, ConnectionMetered, Lane, LaneBatcher, MAX_QUEUED_RECORDS, PowerSource,
    PreemptionOutcome, QueuedRecord, WatermarkAdvance, WatermarkTracker,
};
use grdr_uplink::schedule::{ClampOutcome, FleetSchedule, ScheduleManager, deterministic_phase_ms};

type TestResult = Result<(), Box<dyn Error>>;

const _: () = assert!(SUBSCRIBE_MIN_HEARTBEAT_MS < SUBSCRIBE_MAX_HEARTBEAT_MS);

fn unique_test_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::now_v7()))
}

fn check(cond: bool, msg: &str) -> TestResult {
    if !cond {
        return Err(msg.into());
    }
    Ok(())
}

#[test]
fn isolated_mode_enforces_allowlist_and_blocks_ssrf() {
    let res = run_isolated_mode_enforces_allowlist_and_blocks_ssrf();
    assert!(res.is_ok(), "{res:?}");
}

fn run_isolated_mode_enforces_allowlist_and_blocks_ssrf() -> TestResult {
    let allow = vec![
        AllowEntry::parse("*.fleet.corp.internal")?,
        AllowEntry::parse("10.42.0.0/16")?,
        AllowEntry::parse("fd00:42::/32")?,
    ];
    let dialer = Dialer::new(
        NetworkMode::Isolated { allow_list: allow },
        ProxySelection::Direct,
    );

    let allowed_target = DialTarget {
        uri: "https://cell-01.fleet.corp.internal/v1/fleet/push".to_string(),
        purpose: DialPurpose::FleetPush,
        resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 42, 7, 19))],
    };
    let plan = dialer.authorize_dial(&allowed_target, None, 1_000)?;
    check(
        dialer.build_http_client_for_plan(Some(&plan)).is_ok(),
        "pinned dialer HTTP client must build",
    )?;

    check(
        matches!(
            dialer.authorize_dial(
                &DialTarget {
                    uri: "https://fleet.corp.internal/v1/fleet/push".to_string(),
                    purpose: DialPurpose::FleetPush,
                    resolved_ips: vec![],
                },
                None,
                1_000,
            ),
            Err(UplinkError::EgressUnlisted { .. })
        ),
        "wildcard *.domain must NOT match bare apex domain",
    )?;

    let denied_host = dialer.authorize_dial(
        &DialTarget {
            uri: "https://telemetry.public-saas.example/ingest".to_string(),
            purpose: DialPurpose::FleetPush,
            resolved_ips: vec![],
        },
        None,
        1_000,
    );
    check(
        matches!(denied_host, Err(ref err) if err.code() == "GRDR-CFG-0020"),
        "unlisted host must return GRDR-CFG-0020",
    )?;

    let ssrf_rebind = dialer.authorize_dial(
        &DialTarget {
            uri: "https://cell-01.fleet.corp.internal/v1/fleet/push".to_string(),
            purpose: DialPurpose::FleetPush,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
        },
        None,
        1_000,
    );
    check(
        matches!(ssrf_rebind, Err(UplinkError::EgressUnlisted { .. })),
        "DNS rebind to link-local IP must be rejected",
    )?;

    let v6_allowed = dialer.authorize_dial(
        &DialTarget {
            uri: "https://[fd00:42::9]:8443/v1/fleet".to_string(),
            purpose: DialPurpose::FleetControl,
            resolved_ips: vec![IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0042, 0, 0, 0, 0, 0, 9))],
        },
        None,
        1_000,
    );
    check(v6_allowed.is_ok(), "allowlisted v6 endpoint must succeed")?;

    for confused_uri in [
        "http://cell-01.fleet.corp.internal/v1/fleet/push",
        "https://cell-01.fleet.corp.internal?@evil.example/ingest",
        "https://cell-01.fleet.corp.internal\\@evil.example/ingest",
        "https://127.1/latest/meta-data",
        "https://2130706433/latest/meta-data",
        "https://0x7f.0.0.1/latest/meta-data",
    ] {
        check(
            matches!(
                dialer.authorize_dial(
                    &DialTarget {
                        uri: confused_uri.to_string(),
                        purpose: DialPurpose::FleetPush,
                        resolved_ips: vec![],
                    },
                    None,
                    1_000,
                ),
                Err(UplinkError::InvalidEndpoint { .. })
            ),
            "malformed/non-canonical URI must be rejected",
        )?;
    }

    let std_dialer = Dialer::new(NetworkMode::Standard, ProxySelection::Direct);
    for bad_ip in [
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe)),
        IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001)),
        IpAddr::V6(Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0000, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
    ] {
        check(
            matches!(
                std_dialer.authorize_dial(
                    &DialTarget {
                        uri: "https://fleet.example/v1/push".to_string(),
                        purpose: DialPurpose::FleetPush,
                        resolved_ips: vec![bad_ip],
                    },
                    None,
                    1_000,
                ),
                Err(UplinkError::EgressUnlisted { .. })
            ),
            "special-use/transition IP must be blocked in Standard mode",
        )?;
    }

    for blocked_proxy in [
        ProxySelection::System {
            credential: ProxyCredentialKind::ProtectedMachine,
        },
        ProxySelection::Pac {
            pac_url: "https://cell-01.fleet.corp.internal/proxy.pac".to_string(),
            credential: ProxyCredentialKind::ProtectedMachine,
        },
        ProxySelection::Explicit {
            host: "rogue-proxy.public.example".to_string(),
            port: 3128,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            credential: ProxyCredentialKind::None,
        },
    ] {
        let isolated = Dialer::new(
            NetworkMode::Isolated {
                allow_list: vec![AllowEntry::parse("*.fleet.corp.internal")?],
            },
            blocked_proxy,
        );
        check(
            matches!(
                isolated.authorize_dial(
                    &DialTarget {
                        uri: "https://cell-01.fleet.corp.internal/v1/checkin".to_string(),
                        purpose: DialPurpose::FleetControl,
                        resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 42, 7, 19))],
                    },
                    None,
                    1_000,
                ),
                Err(UplinkError::EgressUnlisted { .. })
            ),
            "System/PAC/unlisted proxy must be refused in isolated mode",
        )?;
    }

    for unpinned_target in [
        Dialer::new(NetworkMode::Standard, ProxySelection::Direct).authorize_dial(
            &DialTarget {
                uri: "https://fleet.example/v1/push".to_string(),
                purpose: DialPurpose::FleetPush,
                resolved_ips: vec![],
            },
            None,
            1_000,
        ),
        dialer.authorize_dial(
            &DialTarget {
                uri: "https://cell-01.fleet.corp.internal/v1/fleet/push".to_string(),
                purpose: DialPurpose::FleetPush,
                resolved_ips: vec![],
            },
            None,
            1_000,
        ),
    ] {
        check(
            matches!(unpinned_target, Err(UplinkError::EgressUnlisted { .. })),
            "DNS hostname target with empty resolved_ips must fail closed",
        )?;
    }

    for ssrf_proxy_host in ["127.0.0.1", "169.254.169.254", "[::1]"] {
        let bad_proxy_dialer = Dialer::new(
            NetworkMode::Standard,
            ProxySelection::Explicit {
                host: ssrf_proxy_host.to_string(),
                port: 3128,
                resolved_ips: vec![],
                credential: ProxyCredentialKind::None,
            },
        );
        check(
            matches!(
                bad_proxy_dialer.build_http_client_for_plan(None),
                Err(UplinkError::EgressUnlisted { .. })
            ),
            "private/IMDS explicit proxy literal must fail in build_http_client_for_plan",
        )?;
    }

    for bad_host in ["127.1", "2130706433"] {
        let non_canonical_proxy = Dialer::new(
            NetworkMode::Standard,
            ProxySelection::Explicit {
                host: bad_host.to_string(),
                port: 3128,
                resolved_ips: vec![],
                credential: ProxyCredentialKind::None,
            },
        );
        check(
            matches!(
                non_canonical_proxy.build_http_client_for_plan(None),
                Err(UplinkError::InvalidEndpoint { .. })
            ),
            "non-canonical explicit proxy host must be rejected",
        )?;
    }

    let zero_port_proxy = Dialer::new(
        NetworkMode::Standard,
        ProxySelection::Explicit {
            host: "proxy.corp.example".to_string(),
            port: 0,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            credential: ProxyCredentialKind::None,
        },
    );
    check(
        matches!(
            zero_port_proxy.build_http_client_for_plan(None),
            Err(UplinkError::InvalidEndpoint { .. })
        ),
        "zero-port explicit proxy must be rejected in build_http_client_for_plan(None)",
    )?;

    let empty_dns_proxy = Dialer::new(
        NetworkMode::Standard,
        ProxySelection::Explicit {
            host: "proxy.corp.example".to_string(),
            port: 3128,
            resolved_ips: vec![],
            credential: ProxyCredentialKind::None,
        },
    );
    check(
        matches!(
            empty_dns_proxy.authorize_dial(
                &DialTarget {
                    uri: "https://fleet.example/v1/push".to_string(),
                    purpose: DialPurpose::FleetPush,
                    resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))],
                },
                None,
                1_000,
            ),
            Err(UplinkError::EgressUnlisted { .. })
        ),
        "explicit DNS proxy without resolved_ips must fail closed",
    )?;
    Ok(())
}

#[test]
fn dialer_rejects_user_interactive_proxy_auth_and_tracks_24h_ladder() {
    let user_proxy_dialer = Dialer::new(
        NetworkMode::Standard,
        ProxySelection::System {
            credential: ProxyCredentialKind::UserInteractive,
        },
    );
    let res = user_proxy_dialer.authorize_dial(
        &DialTarget {
            uri: "https://fleet.example/v1/checkin".to_string(),
            purpose: DialPurpose::FleetControl,
            resolved_ips: vec![],
        },
        None,
        5_000,
    );
    assert!(matches!(
        res,
        Err(ref err)
            if err.health_condition()
                == Some(UplinkHealthCondition::UplinkOffline(
                    OfflineReason::ProxyAuthUserOnly
                ))
    ));

    let mut dialer = Dialer::new(
        NetworkMode::Standard,
        ProxySelection::Explicit {
            host: "proxy.corp.example".to_string(),
            port: 3128,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            credential: ProxyCredentialKind::ProtectedMachine,
        },
    );

    let fp = NetworkFingerprint {
        gateway_mac_hash: "ab12cd34".to_string(),
        dns_suffix: "corp.example".to_string(),
    };
    let cond = dialer.record_ladder_probe(
        fp.clone(),
        TransportRung::ExplicitProxyHttp11,
        NetworkCondition::TlsInspected {
            issuer: "Corp-Proxy-CA".to_string(),
        },
        PinVerification::SystemRootFallback,
        "x25519",
        10_000,
    );
    assert_eq!(cond, UplinkHealthCondition::UplinkDowngraded);
    assert!(dialer.cached_ladder(&fp, 10_000).is_some());
    assert!(dialer.cached_ladder(&fp, 86_420_000).is_none());
}

#[test]
fn schedule_clamping_phase_expiry_and_retry_after_floor() {
    let res = run_schedule_clamping_phase_expiry_and_retry_after_floor();
    assert!(res.is_ok(), "{res:?}");
}

fn run_schedule_clamping_phase_expiry_and_retry_after_floor() -> TestResult {
    let mut mgr = ScheduleManager::with_unix_ms(b"dev-node-9001".to_vec(), 1_760_000_000_000);
    let p1 = deterministic_phase_ms(b"dev-node-9001", "salt-a", 300_000);
    let p2 = deterministic_phase_ms(b"dev-node-9001", "salt-b", 300_000);
    check(
        p1 != p2 && p1 < 300_000,
        "phase must depend on salt and stay bounded",
    )?;

    let incoming = FleetSchedule {
        fleet_profile_id: "hostile-test".to_string(),
        heartbeat_interval_ms: 100,
        evidence_interval_ms: 999_999_999,
        bulk_interval_ms: 1,
        jitter_fraction: 0.95,
        phase_salt: "salt-c".to_string(),
        max_request_bytes: 1024,
        max_events_per_batch: 1,
        evidence_credit_bytes: u64::MAX,
        backfill_credit_bytes: 0,
        control_backoff_cap_ms: 100,
        data_backoff_cap_ms: 99_999_999,
        reconnect_spread_ms: 10,
        issued_at_unix_ms: 1_760_000_000_000,
        valid_until_unix_ms: 9_999_999_999_999,
    };
    let (clamped, health) = mgr.apply_server_schedule(incoming)?;
    check(
        clamped.outcome == ClampOutcome::Clamped,
        "schedule should be clamped",
    )?;
    check(
        health == Some(UplinkHealthCondition::ScheduleClamped),
        "clamping must report ScheduleClamped health",
    )?;
    check(
        clamped.effective.evidence_credit_bytes == 16_777_216
            && clamped.effective.backfill_credit_bytes == 65_536
            && clamped.effective.valid_until_unix_ms == 1_760_000_000_000 + 86_400_000,
        "credits and TTL must clamp cleanly",
    )?;

    check(
        mgr.refresh_expiry(1_760_000_000_000 + 90_000_000),
        "expired schedule should revert",
    )?;
    check(
        mgr.current_schedule().heartbeat_interval_ms == 300_000,
        "reverted defaults mismatch",
    )?;

    let d_low = full_jitter_backoff_ms(0, 1_000, 120_000, Some(10_000), 0.0);
    let d_high = full_jitter_backoff_ms(0, 1_000, 120_000, Some(10_000), 0.99);
    check(d_low == 10_000, "retry_after floor lower bound mismatch")?;
    check(
        d_high > 19_000 && d_high <= 20_000,
        "retry_after floor upper bound mismatch",
    )
}

#[test]
fn circuit_breaker_and_retry_budget_protect_origin() {
    let res = run_circuit_breaker_and_retry_budget_protect_origin();
    assert!(res.is_ok(), "{res:?}");
}

fn run_circuit_breaker_and_retry_budget_protect_origin() -> TestResult {
    let mut ctrl = OriginFailureController::new(0);
    for i in 0..5u64 {
        ctrl.allow_attempt("cell-01", false, i.saturating_mul(100))?;
        ctrl.record_failure(i.saturating_mul(100));
    }
    check(
        matches!(ctrl.state(), CircuitState::Open { .. }),
        "circuit must open after 5 failures",
    )?;
    let blocked = ctrl.allow_attempt("cell-01", false, 1_000);
    check(
        matches!(blocked, Err(UplinkError::CircuitOpen { .. })),
        "open circuit must fail fast",
    )?;

    ctrl.allow_attempt("cell-01", false, 31_000)?;
    ctrl.record_success();
    check(
        matches!(
            ctrl.state(),
            CircuitState::Closed {
                consecutive_failures: 0
            }
        ),
        "successful half-open probe must close circuit",
    )?;

    for _ in 0..6 {
        ctrl.allow_attempt("cell-01", true, 32_000)?;
    }
    let budget_err = ctrl.allow_attempt("cell-01", true, 32_000);
    check(
        matches!(budget_err, Err(UplinkError::RetryBudgetExhausted { .. })),
        "retry budget must enforce ceiling",
    )
}

#[test]
fn lanes_preempt_bulk_deferral_and_dual_watermarks() {
    let res = run_lanes_preempt_bulk_deferral_and_dual_watermarks();
    assert!(res.is_ok(), "{res:?}");
}

fn run_lanes_preempt_bulk_deferral_and_dual_watermarks() -> TestResult {
    let mut batcher = LaneBatcher::new(256, 16, 128, 64, 0);
    batcher.enqueue(QueuedRecord {
        seq: 1,
        lane: Lane::Bulk,
        enqueued_mono_ms: 0,
        payload: vec![b'b'; 80],
    })?;
    batcher.enqueue(QueuedRecord {
        seq: 2,
        lane: Lane::Decision,
        enqueued_mono_ms: 0,
        payload: vec![b'd'; 40],
    })?;
    check(
        batcher.has_urgent_work(300),
        "decision should trigger urgent flush",
    )?;

    let packed = batcher
        .pack_next_batch(
            "b1",
            PowerSource::BatterySaver,
            ConnectionMetered::Metered,
            300,
        )
        .ok_or("decision must flush immediately even on battery saver")?;
    check(packed.lane_counts.decision == 1, "decision count mismatch")?;
    check(
        packed.lane_counts.bulk == 0,
        "bulk should stay deferred on battery saver",
    )?;
    check(
        packed.preemption == PreemptionOutcome::DecisionPreemptedLowerLanes,
        "preemption marker mismatch",
    )?;

    let still_deferred = batcher.pack_next_batch(
        "b2",
        PowerSource::BatterySaver,
        ConnectionMetered::Metered,
        10_000,
    );
    check(
        still_deferred.is_none(),
        "bulk should remain deferred before 6h",
    )?;

    let deadline_flushed = batcher
        .pack_next_batch(
            "b3",
            PowerSource::BatterySaver,
            ConnectionMetered::Metered,
            BULK_MAX_DEFER_MS.saturating_add(1),
        )
        .ok_or("bulk flushes once 6h deadline passes")?;
    check(
        deadline_flushed.lane_counts.bulk == 1,
        "bulk deadline flush failed",
    )?;

    let mut tracker = WatermarkTracker::new();
    check(
        tracker.reject_unverified_ack() == WatermarkAdvance::RejectedUnverified,
        "unverified ack rejection mismatch",
    )?;
    check(
        tracker.durable_through() == 0,
        "durable watermark must stay 0",
    )?;
    check(
        batcher.retained_unacked_count() == 2,
        "unacked spool must retain items",
    )?;

    check(
        tracker.apply_verified_ack(2, 1, "epoch-1")
            == WatermarkAdvance::Advanced {
                acked_through: 2,
                durable_through: 1,
            },
        "verified ack advance mismatch",
    )?;
    check(
        batcher.prune_durable(tracker.durable_through()) == 1,
        "prune durable count mismatch",
    )?;

    check(
        tracker.apply_verified_ack(2, 1, "epoch-2")
            == WatermarkAdvance::ServerEpochChanged {
                backfill_from_seq: 2,
            },
        "epoch change must trigger backfill",
    )?;
    check(
        batcher.requeue_backfill(tracker.durable_through()) == 1,
        "backfill requeue count mismatch",
    )?;

    let mut bounded = LaneBatcher::new(64, 16, 64, 64, 0);
    for seq in 0..MAX_QUEUED_RECORDS {
        bounded.enqueue(QueuedRecord {
            seq: u64::try_from(seq).unwrap_or(0),
            lane: Lane::Bulk,
            enqueued_mono_ms: 0,
            payload: vec![1u8],
        })?;
    }
    check(
        matches!(
            bounded.enqueue(QueuedRecord {
                seq: 99_999,
                lane: Lane::Bulk,
                enqueued_mono_ms: 0,
                payload: vec![1u8],
            }),
            Err(UplinkError::BatchOverflow { .. })
        ),
        "queue ceiling must prevent OOM",
    )
}

#[test]
fn rfc9421_and_response_key_cert_verification_rejects_forgery_and_cross_deploy() {
    let res = run_rfc9421_and_response_key_cert_tests();
    assert!(res.is_ok(), "{res:?}");
}

fn run_rfc9421_and_response_key_cert_tests() -> TestResult {
    let device_key = SigningKeypair::generate()?;
    let transport_key = SigningKeypair::generate()?;
    let wrong_pub_key = SigningKeypair::generate()?;
    let fleet_key = SigningKeypair::generate()?;
    let response_key = SigningKeypair::generate()?;
    let now_s: i64 = 1_760_000_000;

    let mut mismatched_cert = TransportKeyCertificate::issue(
        &device_key,
        "dev-1",
        "dep-alpha",
        &wrong_pub_key,
        now_s.saturating_sub(60),
        3_600,
    )?;
    mismatched_cert.transport_key_id = transport_key.key_id().to_string();
    check(
        matches!(
            EphemeralTransportSigner::new(
                SigningKeypair::from_seed_b64(&transport_key.seed_b64())?,
                mismatched_cert
            ),
            Err(UplinkError::CertificateInvalid { .. })
        ),
        "mismatched transport public key must fail",
    )?;

    let t_cert = TransportKeyCertificate::issue(
        &device_key,
        "dev-1",
        "dep-alpha",
        &transport_key,
        now_s.saturating_sub(60),
        3_600,
    )?;
    let signer = EphemeralTransportSigner::new(transport_key, t_cert)?;

    check(
        matches!(
            signer.sign_request(
                "POST",
                "https://cell.fleet.example/v1/checkin\r\nEvil: true",
                b"{}",
                RequestKind::CheckIn,
                now_s,
                Some("abc"),
            ),
            Err(UplinkError::SignatureCreationFailed { .. })
        ),
        "header/newline injection in URI must be rejected",
    )?;

    let nonce = generate_nonce()?;
    let req_headers = signer.sign_request(
        "POST",
        "https://cell.fleet.example/v1/checkin",
        b"{\"hello\":true}",
        RequestKind::CheckIn,
        now_s,
        Some(&nonce),
    )?;

    let mut fleet_keys = BTreeMap::new();
    fleet_keys.insert(fleet_key.key_id().to_string(), fleet_key.public_key_b64());
    let mut verifier = ResponseVerifier::new(
        FleetTrustAnchor {
            deployment_id: "dep-alpha".to_string(),
            fleet_public_keys: fleet_keys,
        },
        now_s,
        0,
    );

    let r_cert = ResponseKeyCertificate::issue(
        &fleet_key,
        "dep-alpha",
        "cell-01",
        &response_key,
        now_s.saturating_sub(60),
        now_s.saturating_add(3_600),
    )?;

    let body = br#"{"ackedThrough":10,"durableThrough":10}"#;
    let (cd, sig_in, sig) = sign_fleet_response(
        &response_key,
        Some(&r_cert),
        &req_headers.request_sig_digest_b64,
        body,
        now_s,
    )?;

    let meta = verifier.verify_response(
        &req_headers,
        &SignedResponse {
            content_digest: &cd,
            signature_input: &sig_in,
            signature: &sig,
            response_cert: Some(&r_cert),
            server_time_unix_s: now_s,
            body,
        },
        now_s,
        1_000,
    )?;
    check(!meta.clock_skew_detected, "no skew expected")?;

    let bad_covered_sig_in = sig_in.replacen("(\"content-digest\")", "()", 1);
    check(
        matches!(
            verifier.verify_response(
                &req_headers,
                &SignedResponse {
                    content_digest: &cd,
                    signature_input: &bad_covered_sig_in,
                    signature: &sig,
                    response_cert: None,
                    server_time_unix_s: now_s,
                    body,
                },
                now_s,
                1_500,
            ),
            Err(UplinkError::AckUnverified { .. })
        ),
        "tampered covered components must be rejected",
    )?;

    let bad_alg_sig_in = sig_in.replacen("alg=\"ed25519\"", "alg=\"none\"", 1);
    check(
        matches!(
            verifier.verify_response(
                &req_headers,
                &SignedResponse {
                    content_digest: &cd,
                    signature_input: &bad_alg_sig_in,
                    signature: &sig,
                    response_cert: None,
                    server_time_unix_s: now_s,
                    body,
                },
                now_s,
                1_600,
            ),
            Err(UplinkError::AckUnverified { .. })
        ),
        "non-ed25519 algorithm must be rejected",
    )?;

    let wrong_deploy_cert = ResponseKeyCertificate::issue(
        &fleet_key,
        "dep-beta",
        "cell-01",
        &response_key,
        now_s.saturating_sub(60),
        now_s.saturating_add(3_600),
    )?;
    check(
        matches!(
            verifier.verify_response(
                &req_headers,
                &SignedResponse {
                    content_digest: &cd,
                    signature_input: &sig_in,
                    signature: &sig,
                    response_cert: Some(&wrong_deploy_cert),
                    server_time_unix_s: now_s,
                    body,
                },
                now_s,
                2_000,
            ),
            Err(UplinkError::AckUnverified { .. })
        ),
        "cross-deployment cert must be rejected",
    )?;

    let skewed_bad_ts = now_s.saturating_add(100_000);
    let (_cd_skew, sig_in_skew, sig_skew) = sign_fleet_response(
        &wrong_pub_key,
        Some(&r_cert),
        &req_headers.request_sig_digest_b64,
        body,
        skewed_bad_ts,
    )?;
    check(
        matches!(
            verifier.verify_response(
                &req_headers,
                &SignedResponse {
                    content_digest: &cd,
                    signature_input: &sig_in_skew,
                    signature: &sig_skew,
                    response_cert: None,
                    server_time_unix_s: skewed_bad_ts,
                    body,
                },
                now_s,
                2_100,
            ),
            Err(UplinkError::AckUnverified { .. })
        ),
        "bad-signature response with skewed server_time_unix_s must fail",
    )?;
    let _ = verifier.verify_response(
        &req_headers,
        &SignedResponse {
            content_digest: &cd,
            signature_input: &sig_in,
            signature: &sig,
            response_cert: None,
            server_time_unix_s: now_s,
            body,
        },
        now_s,
        2_200,
    )?;

    let older_ts = now_s.saturating_sub(30);
    let (_cd2, sig_in2, sig2) = sign_fleet_response(
        &response_key,
        None,
        &req_headers.request_sig_digest_b64,
        body,
        older_ts,
    )?;
    let _ = verifier.verify_response(
        &req_headers,
        &SignedResponse {
            content_digest: &cd,
            signature_input: &sig_in2,
            signature: &sig2,
            response_cert: None,
            server_time_unix_s: older_ts,
            body,
        },
        now_s,
        2_500,
    )?;
    check(
        verifier.estimated_server_time_s(2_500) >= now_s,
        "server time anchor must remain monotonic",
    )
}

#[test]
fn control_channel_fallback_and_opaque_artifact_staging() {
    let res = run_control_channel_fallback_and_staging();
    assert!(res.is_ok(), "{res:?}");
}

fn run_control_channel_fallback_and_staging() -> TestResult {
    let mut ctrl = ControlChannel::new();
    ctrl.enter_subscribe("cell-01", 0);
    ctrl.record_subscribe_beat(25_000);
    check(
        matches!(
            ctrl.state(),
            ControlChannelState::StreamingSubscribe {
                learned_heartbeat_ms: 30_000,
                ..
            }
        ),
        "subscribe beat should step up learned interval",
    )?;
    for t in [55_000u64, 85_000u64] {
        ctrl.check_subscribe_health(t);
    }
    check(
        matches!(ctrl.state(), ControlChannelState::LongPollWait { .. }),
        "2 missed beats must fall back to Wait",
    )?;

    let first_kill = ctrl.accept_commands(
        vec![PendingCommand {
            command_id: "cmd-kill-100".to_string(),
            generation: 100,
            ttl_expires_unix_s: 500,
            action: CommandAction::KillSwitch,
            payload_json: "{}".to_string(),
        }],
        200,
    );
    check(first_kill.len() == 1, "initial kill switch accepted")?;

    let mut filler = Vec::with_capacity(COMMAND_DEDUP_CAP.saturating_add(16));
    for i in 0..COMMAND_DEDUP_CAP.saturating_add(16) {
        filler.push(PendingCommand {
            command_id: format!("flush-{i}"),
            generation: u64::try_from(i).unwrap_or(0),
            ttl_expires_unix_s: 500,
            action: CommandAction::FlushSpool,
            payload_json: "{}".to_string(),
        });
    }
    let _ = ctrl.accept_commands(filler, 200);

    let replayed_kill = ctrl.accept_commands(
        vec![PendingCommand {
            command_id: "cmd-kill-100".to_string(),
            generation: 100,
            ttl_expires_unix_s: 500,
            action: CommandAction::KillSwitch,
            payload_json: "{}".to_string(),
        }],
        200,
    );
    check(
        replayed_kill.is_empty(),
        "monotonic generation floor must block KillSwitch replay even after FIFO eviction",
    )?;

    let root = unique_test_dir("grdr-uplink-staging");
    let stager = OpaqueArtifactStager::new(root.clone());
    let payload = vec![b'x'; 200_000];
    let expected_sha = sha256_hex(&payload);

    let (first, second) = payload.split_at(70_000);
    check(
        stager.write_chunk(&expected_sha, 0, first, 250_000)? == 70_000,
        "chunk 1 len mismatch",
    )?;
    check(
        stager.resume_offset(&expected_sha)? == 70_000,
        "resume offset mismatch",
    )?;
    check(
        stager.write_chunk(&expected_sha, 70_000, second, 250_000)? == 200_000,
        "chunk 2 len mismatch",
    )?;
    let staged = stager.finalize(&expected_sha, 250_000)?;
    check(
        staged.expected_sha256 == expected_sha && staged.byte_len == 200_000,
        "final sha256 or streaming length mismatch",
    )?;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
