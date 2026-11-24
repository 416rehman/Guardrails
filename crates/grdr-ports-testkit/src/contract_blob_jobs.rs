// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_ports::{
    BlobPort, BlobVersionCondition, ByteRange, CODE_BLOB_ALREADY_EXISTS,
    CODE_BLOB_VERSION_CONFLICT, CODE_JOBS_STALE_FENCE, CODE_TENANT_SCOPE_MISMATCH, FencingToken,
    JobEnqueueOutcome, JobEnqueueRequest, JobPort, JobState, LeaseAcquireOutcome, LeaseState,
    OrgId, SingleCtx, TenantCtx, TenantPath, TenantRelPath,
};

pub fn assert_blob_port_contract(blobs: &impl BlobPort) -> Result<(), String> {
    let org_a = OrgId::new("org-blob-a").map_err(|e| e.to_string())?;
    let org_b = OrgId::new("org-blob-b").map_err(|e| e.to_string())?;
    let ctx_a = SingleCtx::new(org_a);
    let ctx_b = SingleCtx::new(org_b);
    let read_a = TenantCtx::Single(ctx_a.clone());
    let read_b = TenantCtx::Single(ctx_b.clone());

    let p1 = TenantPath::parse(&ctx_a, "class=decision/day=2026-11-24/seg-1.bin")
        .map_err(|e| e.to_string())?;
    let meta1 = blobs
        .put(&ctx_a, &p1, b"hello-guardrails-blob")
        .map_err(|e| e.to_string())?;
    if meta1.size_bytes != 21 {
        return Err("unexpected blob size".into());
    }

    let got = blobs
        .get(&read_a, &p1)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "expected blob object".to_string())?;
    if got.bytes != b"hello-guardrails-blob" {
        return Err("blob bytes mismatch".into());
    }

    let range = blobs
        .get_range(
            &read_a,
            &p1,
            ByteRange {
                offset: 6,
                length: 10,
            },
        )
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "expected range bytes".to_string())?;
    if range != b"guardrails" {
        return Err("blob range mismatch".into());
    }

    let Err(cross_err) = blobs.get(&read_b, &p1) else {
        return Err("expected cross-tenant read error".into());
    };
    if cross_err.code != CODE_TENANT_SCOPE_MISMATCH {
        return Err(format!(
            "expected scope mismatch on cross-tenant read, got {}",
            cross_err.code
        ));
    }

    let ver_path =
        TenantPath::parse(&ctx_a, "state-log/epoch-1.json").map_err(|e| e.to_string())?;
    let v1 = blobs
        .put_versioned(&ctx_a, &ver_path, b"v1", &BlobVersionCondition::CreateOnly)
        .map_err(|e| e.to_string())?;
    let Err(dup) = blobs.put_versioned(&ctx_a, &ver_path, b"v2", &BlobVersionCondition::CreateOnly)
    else {
        return Err("expected CreateOnly to fail on existing blob".into());
    };
    if dup.code != CODE_BLOB_ALREADY_EXISTS {
        return Err(format!("expected already exists, got {}", dup.code));
    }
    let Err(bad_match) = blobs.put_versioned(
        &ctx_a,
        &ver_path,
        b"v2",
        &BlobVersionCondition::IfMatch("wrong-etag".into()),
    ) else {
        return Err("expected IfMatch mismatch to fail".into());
    };
    if bad_match.code != CODE_BLOB_VERSION_CONFLICT {
        return Err(format!("expected version conflict, got {}", bad_match.code));
    }
    blobs
        .put_versioned(
            &ctx_a,
            &ver_path,
            b"v2",
            &BlobVersionCondition::IfMatch(v1.etag),
        )
        .map_err(|e| e.to_string())?;

    let prefix = TenantRelPath::parse_prefix("state-log").map_err(|e| e.to_string())?;
    let listed = blobs.list(&read_a, &prefix).map_err(|e| e.to_string())?;
    if listed.len() != 1 {
        return Err("expected 1 listed blob under state-log".into());
    }
    if !blobs
        .list(&read_b, &prefix)
        .map_err(|e| e.to_string())?
        .is_empty()
    {
        return Err("org B list should be empty".into());
    }
    if !blobs.delete(&ctx_a, &p1).map_err(|e| e.to_string())? {
        return Err("expected delete to return true".into());
    }
    if blobs
        .get(&read_a, &p1)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("deleted blob still readable".into());
    }
    Ok(())
}

pub fn assert_job_port_contract(jobs: &impl JobPort) -> Result<(), String> {
    let org_a = OrgId::new("org-jobs-a").map_err(|e| e.to_string())?;
    let org_b = OrgId::new("org-jobs-b").map_err(|e| e.to_string())?;
    let ctx_a = SingleCtx::new(org_a);
    let ctx_b = SingleCtx::new(org_b);
    let read_a = TenantCtx::Single(ctx_a.clone());
    let read_b = TenantCtx::Single(ctx_b.clone());

    let req = JobEnqueueRequest {
        kind: "retention".into(),
        idempotency_key: "daily-2026-11-24".into(),
        payload_json: "{}".into(),
        not_before_ms: 1_000,
    };
    let job_a = match jobs.enqueue(&ctx_a, &req).map_err(|e| e.to_string())? {
        JobEnqueueOutcome::Enqueued(j) => j,
        JobEnqueueOutcome::AlreadyExists(_) => {
            return Err("expected fresh enqueue for org A".into());
        }
    };
    match jobs.enqueue(&ctx_a, &req).map_err(|e| e.to_string())? {
        JobEnqueueOutcome::AlreadyExists(existing) if existing.id == job_a.id => {}
        _ => return Err("expected idempotent AlreadyExists for org A".into()),
    }
    let job_b = match jobs.enqueue(&ctx_b, &req).map_err(|e| e.to_string())? {
        JobEnqueueOutcome::Enqueued(j) => j,
        JobEnqueueOutcome::AlreadyExists(_) => {
            return Err("org B with same idempotency_key must create its own job".into());
        }
    };
    if job_a.id == job_b.id {
        return Err("org A and org B jobs must be distinct".into());
    }
    if jobs
        .get_job(&read_b, &job_a.id)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("org B must not see org A job".into());
    }

    let claimed = jobs
        .claim(&ctx_a, &["retention"], "worker-a", 1_500, 5_000)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "expected claimable job".to_string())?;
    let fence = match &claimed.state {
        JobState::Running { fence, .. } => *fence,
        other => return Err(format!("expected Running state, got {other:?}")),
    };

    let Err(stale) = jobs.record_step(
        &ctx_a,
        &claimed.id,
        0,
        "scan",
        FencingToken::new(fence.value().saturating_add(99)),
        "{}",
        1_600,
    ) else {
        return Err("expected StaleFence on mismatched job fence".into());
    };
    if stale.code != CODE_JOBS_STALE_FENCE {
        return Err(format!("expected stale fence, got {}", stale.code));
    }

    let s1 = jobs
        .record_step(
            &ctx_a,
            &claimed.id,
            0,
            "scan",
            fence,
            "{\"deleted\":2}",
            1_600,
        )
        .map_err(|e| e.to_string())?;
    let s1_idem = jobs
        .record_step(
            &ctx_a,
            &claimed.id,
            0,
            "scan",
            fence,
            "{\"deleted\":999}",
            1_700,
        )
        .map_err(|e| e.to_string())?;
    if s1 != s1_idem {
        return Err("step journal did not preserve idempotent output".into());
    }

    let done = jobs
        .complete(&ctx_a, &claimed.id, fence, 1_800)
        .map_err(|e| e.to_string())?;
    if !matches!(done.state, JobState::Completed { .. }) {
        return Err("expected Completed job state".into());
    }
    if jobs
        .get_job(&read_a, &claimed.id)
        .map_err(|e| e.to_string())?
        .is_none()
    {
        return Err("expected job readable via get_job".into());
    }

    assert_lease_fencing_contract(jobs)
}

fn assert_lease_fencing_contract(jobs: &impl JobPort) -> Result<(), String> {
    let l1 = match jobs
        .acquire_lease("compaction-singleton", "node-1", 2_000, 5_000)
        .map_err(|e| e.to_string())?
    {
        LeaseAcquireOutcome::Acquired(rec) => rec,
        LeaseAcquireOutcome::Contended { .. } => return Err("expected initial lease".into()),
    };
    let f_l1 = match l1.state {
        LeaseState::Held { fence, .. } => fence,
        _ => return Err("expected Held lease".into()),
    };
    if !matches!(
        jobs.acquire_lease("compaction-singleton", "node-2", 3_000, 5_000)
            .map_err(|e| e.to_string())?,
        LeaseAcquireOutcome::Contended { .. }
    ) {
        return Err("expected contention while lease held".into());
    }
    let l1_renew = match jobs
        .acquire_lease("compaction-singleton", "node-1", 4_000, 5_000)
        .map_err(|e| e.to_string())?
    {
        LeaseAcquireOutcome::Acquired(rec) => rec,
        LeaseAcquireOutcome::Contended { .. } => {
            return Err("expected renewal by same holder".into());
        }
    };
    let f_renew = match l1_renew.state {
        LeaseState::Held { fence, .. } => fence,
        _ => return Err("expected Held on renewal".into()),
    };
    if f_renew <= f_l1 {
        return Err("renewal must issue a strictly greater fencing token".into());
    }
    let expired = jobs
        .inspect_lease("compaction-singleton", 10_000)
        .map_err(|e| e.to_string())?;
    if !matches!(expired.state, LeaseState::Expired { .. }) {
        return Err("expected Expired lease after ttl".into());
    }
    let l2 = match jobs
        .acquire_lease("compaction-singleton", "node-2", 10_001, 5_000)
        .map_err(|e| e.to_string())?
    {
        LeaseAcquireOutcome::Acquired(rec) => rec,
        LeaseAcquireOutcome::Contended { .. } => {
            return Err("expected takeover after expiry".into());
        }
    };
    let f_l2 = match l2.state {
        LeaseState::Held { fence, .. } => fence,
        _ => return Err("expected Held after takeover".into()),
    };
    if f_l2 <= f_renew {
        return Err("takeover must issue strictly greater fencing token".into());
    }
    Ok(())
}
