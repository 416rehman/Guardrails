// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::{
    ActionClass, ApprovalGrade, Device, DiscoveredAgent, Finding, FindingClass, FindingLifecycle,
    FindingSeverity, InstallProfile, Mode, PolicyPack, PolicyRule, RuleMatch, SessionSummary,
};
use grdr_ports::{
    BusAppendMessage, BusPort, CODE_BUS_BEYOND_LOG, CODE_BUS_STALE_FENCE, FencingToken, OrgId,
    RelationalStorePort, SingleCtx, TenantCtx, TenantUserRecord,
};

use crate::sample_timestamp;

pub fn assert_relational_store_contract(store: &impl RelationalStorePort) -> Result<(), String> {
    let org_a = OrgId::new("org-contract-a").map_err(|e| e.to_string())?;
    let org_b = OrgId::new("org-contract-b").map_err(|e| e.to_string())?;
    let single_a = SingleCtx::new(org_a.clone());
    let single_b = SingleCtx::new(org_b.clone());
    let read_a = TenantCtx::Single(single_a.clone());
    let read_b = TenantCtx::Single(single_b.clone());
    let read_set = TenantCtx::set("snap-1", vec![org_a, org_b]).map_err(|e| e.to_string())?;
    let now = sample_timestamp();

    let dev_a = Device {
        id: "dev-shared-id".into(),
        hostname: "laptop-alpha".into(),
        os: "linux".into(),
        arch: "x86_64".into(),
        install_profile: InstallProfile::Protected,
        daemon_version: "0.1.0".into(),
        online: true,
        hook_effective: true,
        agents: vec![DiscoveredAgent {
            id: "agt-claude".into(),
            name: "claude-code".into(),
            kind: "coding-agent".into(),
            config_path: ".claude/settings.json".into(),
            hook_installed: true,
            mcp_count: 1,
            assurance: grdr_model::AssuranceRecord {
                visibility: grdr_model::Visibility::Observed,
                control: grdr_model::ControlStrength::Request,
                on_failure: grdr_model::OnFailure::Open,
                tamper: grdr_model::TamperGrade::Admin,
            },
            assurance_level: grdr_model::AssuranceLevel::Al2Guided,
            sponsor: None,
            detected_at: now,
        }],
        mcp_servers: Vec::new(),
        artifacts: Vec::new(),
        user_id: Some("usr-1".into()),
        user_display: Some("Maya Chen".into()),
        last_seen: now,
        public_key: None,
    };
    let mut dev_b = dev_a.clone();
    dev_b.hostname = "laptop-beta".into();

    store
        .upsert_device(&single_a, &dev_a)
        .map_err(|e| e.to_string())?;
    store
        .upsert_device(&single_b, &dev_b)
        .map_err(|e| e.to_string())?;

    let got_a = store
        .get_device(&read_a, "dev-shared-id")
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "missing dev_a".to_string())?;
    if got_a.hostname != "laptop-alpha" {
        return Err("tenant isolation failed on device lookup".into());
    }
    let got_b = store
        .get_device(&read_b, "dev-shared-id")
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "missing dev_b".to_string())?;
    if got_b.hostname != "laptop-beta" {
        return Err("tenant B device overwritten by tenant A".into());
    }
    if store
        .list_devices(&read_set)
        .map_err(|e| e.to_string())?
        .len()
        != 2
    {
        return Err("SetCtx should see both org devices".into());
    }

    let summary = SessionSummary {
        id: "sess-1".into(),
        device_id: "dev-shared-id".into(),
        device_name: "laptop-alpha".into(),
        agent_name: "claude-code".into(),
        user_id: Some("usr-1".into()),
        user_display: Some("Maya Chen".into()),
        turn_count: 2,
        parent_session_id: None,
        started_at: now,
        last_activity: now,
        total_actions: 4,
        blocked_count: 1,
        step_up_count: 0,
        watch_hits: 1,
        assurance_level: grdr_model::AssuranceLevel::Al2Guided,
        labels: Vec::new(),
    };
    store
        .upsert_session_summary(&single_a, &summary)
        .map_err(|e| e.to_string())?;
    if store
        .get_session_summary(&read_b, "sess-1")
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("org B must not read org A session summary".into());
    }

    let finding = Finding {
        id: "fnd-1".into(),
        session_id: "sess-1".into(),
        device_id: "dev-shared-id".into(),
        device_name: "laptop-alpha".into(),
        agent_name: "claude-code".into(),
        class: FindingClass::PolicyViolation,
        severity: FindingSeverity::High,
        lifecycle: FindingLifecycle::Open,
        rule_id: Some("rule-1".into()),
        title: "Blocked SSH key read".into(),
        summary: "Read denied".into(),
        target: "~/.ssh/id_rsa".into(),
        detected_at: now,
    };
    store
        .upsert_finding(&single_a, &finding)
        .map_err(|e| e.to_string())?;
    if store
        .list_findings(&read_a)
        .map_err(|e| e.to_string())?
        .len()
        != 1
        || !store
            .list_findings(&read_b)
            .map_err(|e| e.to_string())?
            .is_empty()
    {
        return Err("finding tenant isolation failed".into());
    }

    let pack = PolicyPack {
        id: "pack-1".into(),
        name: "Essentials".into(),
        description: "Baseline".into(),
        version: "1.0.0".into(),
        channel: "stable".into(),
        rules: vec![PolicyRule {
            id: "rule-1".into(),
            title: "Protect SSH keys".into(),
            description: "Block key reads".into(),
            mode: Mode::Block,
            min_grade: ApprovalGrade::G1,
            enabled: true,
            locked: true,
            matcher: RuleMatch {
                action_classes: vec![ActionClass::FileRead],
                target_prefixes: vec![],
                target_contains: vec![".ssh".into()],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Blocked".into(),
        }],
        key_id: None,
        signature: None,
    };
    store
        .upsert_pack(&single_a, &pack)
        .map_err(|e| e.to_string())?;
    if store
        .get_pack(&read_a, "pack-1")
        .map_err(|e| e.to_string())?
        .is_none()
    {
        return Err("expected pack-1 in org A".into());
    }

    let user = TenantUserRecord {
        id: "usr-1".into(),
        display_name: "Maya Chen".into(),
        email: "maya@example.test".into(),
        department: "Engineering".into(),
        idp_source: "okta".into(),
        pseudonym_id: "prn_maya".into(),
    };
    store
        .upsert_user(&single_a, &user)
        .map_err(|e| e.to_string())?;
    if store
        .get_user(&read_b, "usr-1")
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("org B must not read org A user".into());
    }

    store
        .put_kv(&single_a, "config", "privacy", "{\"mode\":\"named\"}")
        .map_err(|e| e.to_string())?;
    if store
        .get_kv(&read_a, "config", "privacy")
        .map_err(|e| e.to_string())?
        .is_none()
    {
        return Err("kv put/get failed".into());
    }
    store
        .delete_kv(&single_a, "config", "privacy")
        .map_err(|e| e.to_string())?;
    if store
        .get_kv(&read_a, "config", "privacy")
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("kv delete failed".into());
    }

    let search_hits = store
        .search_entities(&read_a, "laptop", 10)
        .map_err(|e| e.to_string())?;
    if search_hits.is_empty() {
        return Err("expected entity search hit for laptop".into());
    }
    if store
        .search_entities(&read_b, "Maya", 10)
        .map_err(|e| e.to_string())?
        .iter()
        .any(|h| h.entity_id == "usr-1")
    {
        return Err("entity search leaked org A user into org B".into());
    }
    if store
        .applied_migrations()
        .map_err(|e| e.to_string())?
        .is_empty()
    {
        return Err("expected applied_migrations to be non-empty".into());
    }
    Ok(())
}

pub fn assert_bus_port_contract(bus: &impl BusPort) -> Result<(), String> {
    let org_a = OrgId::new("org-bus-a").map_err(|e| e.to_string())?;
    let org_b = OrgId::new("org-bus-b").map_err(|e| e.to_string())?;
    let ctx_a = SingleCtx::new(org_a);
    let ctx_b = SingleCtx::new(org_b);
    let read_a = TenantCtx::Single(ctx_a.clone());
    let read_b = TenantCtx::Single(ctx_b.clone());

    let msgs = vec![
        BusAppendMessage {
            key: "dev-1".into(),
            headers: BTreeMap::new(),
            payload: b"batch-1".to_vec(),
        },
        BusAppendMessage {
            key: "dev-1".into(),
            headers: BTreeMap::new(),
            payload: b"batch-2".to_vec(),
        },
    ];
    let range = bus
        .append(&ctx_a, "events", 0, &msgs, 1_000)
        .map_err(|e| e.to_string())?;
    if range.first_offset != 0 || range.last_offset != 1 {
        return Err("unexpected initial offset range".into());
    }

    let b_range = bus
        .append(
            &ctx_b,
            "events",
            0,
            &[BusAppendMessage {
                key: "dev-2".into(),
                headers: BTreeMap::new(),
                payload: b"batch-b".to_vec(),
            }],
            1_001,
        )
        .map_err(|e| e.to_string())?;
    if b_range.first_offset != 2 {
        return Err("partition offset did not advance monotonically".into());
    }

    let fetched_a = bus
        .fetch(&read_a, "events", 0, None, 10)
        .map_err(|e| e.to_string())?;
    if fetched_a.len() != 2 {
        return Err("tenant A should only fetch its 2 messages".into());
    }
    let fetched_b = bus
        .fetch(&read_b, "events", 0, None, 10)
        .map_err(|e| e.to_string())?;
    match fetched_b.as_slice() {
        [only] if only.payload == b"batch-b" => {}
        _ => return Err("tenant B should only fetch its 1 message".into()),
    }

    let f2 = FencingToken::new(2);
    let f1 = FencingToken::new(1);
    let sub = bus
        .subscribe("store", "events", 0, "worker-2", f2, 10_000)
        .map_err(|e| e.to_string())?;
    if sub.fence != f2 {
        return Err("subscribe did not stamp fence".into());
    }
    let Err(stale_sub) = bus.subscribe("store", "events", 0, "worker-1", f1, 10_000) else {
        return Err("expected StaleFence on lower subscribe fence".into());
    };
    if stale_sub.code != CODE_BUS_STALE_FENCE {
        return Err(format!("expected StaleFence, got {}", stale_sub.code));
    }

    let Err(beyond) = bus.commit("store", "events", 0, 99, None, f2) else {
        return Err("expected BeyondLog on commit beyond head".into());
    };
    if beyond.code != CODE_BUS_BEYOND_LOG {
        return Err(format!("expected BeyondLog, got {}", beyond.code));
    }

    let Err(stale_commit) = bus.commit("store", "events", 0, 1, Some("snap-1"), f1) else {
        return Err("expected StaleFence on commit with stale fence".into());
    };
    if stale_commit.code != CODE_BUS_STALE_FENCE {
        return Err(format!(
            "expected StaleFence on commit, got {}",
            stale_commit.code
        ));
    }

    bus.commit("store", "events", 0, 1, Some("snap-1"), f2)
        .map_err(|e| e.to_string())?;
    let lag = bus
        .lag(&read_a, "store", "events", 0)
        .map_err(|e| e.to_string())?;
    if lag.committed_offset != Some(1) || lag.pending_messages != 1 {
        return Err(format!("unexpected lag: {lag:?}"));
    }
    Ok(())
}
