// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use grdr_model::error::CODE_STORE_IO;
use grdr_model::{CodedError, Device, Finding, PolicyPack, SessionSummary};
use grdr_ports::{
    DeviceRepo, EntityKind, EntitySearchHit, FindingRepo, KvSnapshotRepo, MigrationRecord, OrgId,
    PolicyRepo, ProfileKind, RelationalStorePort, SessionSummaryRepo, SingleCtx, TenantCtx,
    TenantUserRecord, UserRepo,
};

#[derive(Debug, Default)]
struct MemRelInner {
    devices: BTreeMap<(String, String), Device>,
    sessions: BTreeMap<(String, String), SessionSummary>,
    findings: BTreeMap<(String, String), Finding>,
    packs: BTreeMap<(String, String), PolicyPack>,
    users: BTreeMap<(String, String), TenantUserRecord>,
    kv: BTreeMap<(String, String, String), String>,
}

#[derive(Debug, Default)]
pub struct MemoryRelationalStore {
    inner: Mutex<MemRelInner>,
}

impl DeviceRepo for MemoryRelationalStore {
    fn upsert_device(&self, ctx: &SingleCtx, device: &Device) -> Result<(), CodedError> {
        let mut g = lock_rel(&self.inner)?;
        g.devices.insert(
            (ctx.organisation_id().as_str().into(), device.id.clone()),
            device.clone(),
        );
        Ok(())
    }

    fn get_device(&self, ctx: &TenantCtx, device_id: &str) -> Result<Option<Device>, CodedError> {
        let g = lock_rel(&self.inner)?;
        for org in ctx.organisation_ids() {
            if let Some(d) = g.devices.get(&(org.as_str().into(), device_id.into())) {
                return Ok(Some(d.clone()));
            }
        }
        Ok(None)
    }

    fn list_devices(&self, ctx: &TenantCtx) -> Result<Vec<Device>, CodedError> {
        let g = lock_rel(&self.inner)?;
        let orgs = org_set(ctx);
        Ok(g.devices
            .iter()
            .filter(|((org, _), _)| orgs.contains(&org.as_str()))
            .map(|(_, d)| d.clone())
            .collect())
    }
}

impl SessionSummaryRepo for MemoryRelationalStore {
    fn upsert_session_summary(
        &self,
        ctx: &SingleCtx,
        summary: &SessionSummary,
    ) -> Result<(), CodedError> {
        let mut g = lock_rel(&self.inner)?;
        g.sessions.insert(
            (ctx.organisation_id().as_str().into(), summary.id.clone()),
            summary.clone(),
        );
        Ok(())
    }

    fn get_session_summary(
        &self,
        ctx: &TenantCtx,
        session_id: &str,
    ) -> Result<Option<SessionSummary>, CodedError> {
        let g = lock_rel(&self.inner)?;
        for org in ctx.organisation_ids() {
            if let Some(s) = g.sessions.get(&(org.as_str().into(), session_id.into())) {
                return Ok(Some(s.clone()));
            }
        }
        Ok(None)
    }

    fn list_session_summaries(&self, ctx: &TenantCtx) -> Result<Vec<SessionSummary>, CodedError> {
        let g = lock_rel(&self.inner)?;
        let orgs = org_set(ctx);
        Ok(g.sessions
            .iter()
            .filter(|((org, _), _)| orgs.contains(&org.as_str()))
            .map(|(_, s)| s.clone())
            .collect())
    }
}

impl FindingRepo for MemoryRelationalStore {
    fn upsert_finding(&self, ctx: &SingleCtx, finding: &Finding) -> Result<(), CodedError> {
        let mut g = lock_rel(&self.inner)?;
        g.findings.insert(
            (ctx.organisation_id().as_str().into(), finding.id.clone()),
            finding.clone(),
        );
        Ok(())
    }

    fn get_finding(
        &self,
        ctx: &TenantCtx,
        finding_id: &str,
    ) -> Result<Option<Finding>, CodedError> {
        let g = lock_rel(&self.inner)?;
        for org in ctx.organisation_ids() {
            if let Some(f) = g.findings.get(&(org.as_str().into(), finding_id.into())) {
                return Ok(Some(f.clone()));
            }
        }
        Ok(None)
    }

    fn list_findings(&self, ctx: &TenantCtx) -> Result<Vec<Finding>, CodedError> {
        let g = lock_rel(&self.inner)?;
        let orgs = org_set(ctx);
        Ok(g.findings
            .iter()
            .filter(|((org, _), _)| orgs.contains(&org.as_str()))
            .map(|(_, f)| f.clone())
            .collect())
    }
}

impl PolicyRepo for MemoryRelationalStore {
    fn upsert_pack(&self, ctx: &SingleCtx, pack: &PolicyPack) -> Result<(), CodedError> {
        let mut g = lock_rel(&self.inner)?;
        g.packs.insert(
            (ctx.organisation_id().as_str().into(), pack.id.clone()),
            pack.clone(),
        );
        Ok(())
    }

    fn get_pack(&self, ctx: &TenantCtx, pack_id: &str) -> Result<Option<PolicyPack>, CodedError> {
        let g = lock_rel(&self.inner)?;
        for org in ctx.organisation_ids() {
            if let Some(p) = g.packs.get(&(org.as_str().into(), pack_id.into())) {
                return Ok(Some(p.clone()));
            }
        }
        Ok(None)
    }

    fn list_packs(&self, ctx: &TenantCtx) -> Result<Vec<PolicyPack>, CodedError> {
        let g = lock_rel(&self.inner)?;
        let orgs = org_set(ctx);
        Ok(g.packs
            .iter()
            .filter(|((org, _), _)| orgs.contains(&org.as_str()))
            .map(|(_, p)| p.clone())
            .collect())
    }
}

impl UserRepo for MemoryRelationalStore {
    fn upsert_user(&self, ctx: &SingleCtx, user: &TenantUserRecord) -> Result<(), CodedError> {
        let mut g = lock_rel(&self.inner)?;
        g.users.insert(
            (ctx.organisation_id().as_str().into(), user.id.clone()),
            user.clone(),
        );
        Ok(())
    }

    fn get_user(
        &self,
        ctx: &TenantCtx,
        user_id: &str,
    ) -> Result<Option<TenantUserRecord>, CodedError> {
        let g = lock_rel(&self.inner)?;
        for org in ctx.organisation_ids() {
            if let Some(u) = g.users.get(&(org.as_str().into(), user_id.into())) {
                return Ok(Some(u.clone()));
            }
        }
        Ok(None)
    }

    fn list_users(&self, ctx: &TenantCtx) -> Result<Vec<TenantUserRecord>, CodedError> {
        let g = lock_rel(&self.inner)?;
        let orgs = org_set(ctx);
        Ok(g.users
            .iter()
            .filter(|((org, _), _)| orgs.contains(&org.as_str()))
            .map(|(_, u)| u.clone())
            .collect())
    }
}

impl KvSnapshotRepo for MemoryRelationalStore {
    fn put_kv(
        &self,
        ctx: &SingleCtx,
        namespace: &str,
        key: &str,
        value_json: &str,
    ) -> Result<(), CodedError> {
        let mut g = lock_rel(&self.inner)?;
        g.kv.insert(
            (
                ctx.organisation_id().as_str().into(),
                namespace.into(),
                key.into(),
            ),
            value_json.into(),
        );
        Ok(())
    }

    fn get_kv(
        &self,
        ctx: &TenantCtx,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, CodedError> {
        let g = lock_rel(&self.inner)?;
        for org in ctx.organisation_ids() {
            if let Some(v) =
                g.kv.get(&(org.as_str().into(), namespace.into(), key.into()))
            {
                return Ok(Some(v.clone()));
            }
        }
        Ok(None)
    }

    fn list_kv(
        &self,
        ctx: &TenantCtx,
        namespace: &str,
    ) -> Result<Vec<(String, String)>, CodedError> {
        let g = lock_rel(&self.inner)?;
        let orgs = org_set(ctx);
        Ok(g.kv
            .iter()
            .filter(|((org, ns, _), _)| orgs.contains(&org.as_str()) && ns == namespace)
            .map(|((_, _, k), v)| (k.clone(), v.clone()))
            .collect())
    }

    fn delete_kv(&self, ctx: &SingleCtx, namespace: &str, key: &str) -> Result<(), CodedError> {
        let mut g = lock_rel(&self.inner)?;
        g.kv.remove(&(
            ctx.organisation_id().as_str().into(),
            namespace.into(),
            key.into(),
        ));
        Ok(())
    }
}

impl RelationalStorePort for MemoryRelationalStore {
    fn profile(&self) -> ProfileKind {
        ProfileKind::Embedded
    }

    fn search_entities(
        &self,
        ctx: &TenantCtx,
        query: &str,
        limit: usize,
    ) -> Result<Vec<EntitySearchHit>, CodedError> {
        let needle = query.trim().to_ascii_lowercase();
        if needle.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let g = lock_rel(&self.inner)?;
        let orgs = org_set(ctx);
        let mut hits = Vec::new();
        collect_device_hits(&g.devices, &orgs, &needle, &mut hits);
        collect_pack_hits(&g.packs, &orgs, &needle, &mut hits);
        collect_user_hits(&g.users, &orgs, &needle, &mut hits);
        hits.truncate(limit);
        Ok(hits)
    }

    fn applied_migrations(&self) -> Result<Vec<MigrationRecord>, CodedError> {
        Ok(vec![MigrationRecord {
            version: 1,
            name: "memory_reference_v1".into(),
            applied_at: "1970-01-01T00:00:00Z".into(),
        }])
    }
}

fn lock_rel<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, CodedError> {
    mutex.lock().map_err(|_| {
        CodedError::new(
            CODE_STORE_IO,
            "In-memory relational testkit mutex poisoned.",
            "Recreate MemoryRelationalStore.",
        )
    })
}

fn org_set(ctx: &TenantCtx) -> Vec<&str> {
    ctx.organisation_ids()
        .into_iter()
        .map(OrgId::as_str)
        .collect()
}

fn collect_device_hits(
    devices: &BTreeMap<(String, String), Device>,
    orgs: &[&str],
    needle: &str,
    hits: &mut Vec<EntitySearchHit>,
) {
    for ((org, _), dev) in devices {
        if !orgs.contains(&org.as_str()) {
            continue;
        }
        if dev.hostname.to_ascii_lowercase().contains(needle) {
            hits.push(EntitySearchHit {
                entity_kind: EntityKind::Device,
                entity_id: dev.id.clone(),
                title: dev.hostname.clone(),
                subtitle: format!("{} {}", dev.os, dev.arch),
                rank_score: 0,
            });
        }
        for agent in &dev.agents {
            if agent.name.to_ascii_lowercase().contains(needle) {
                hits.push(EntitySearchHit {
                    entity_kind: EntityKind::Agent,
                    entity_id: agent.id.clone(),
                    title: agent.name.clone(),
                    subtitle: agent.kind.clone(),
                    rank_score: 0,
                });
            }
        }
        for mcp in &dev.mcp_servers {
            if mcp.name.to_ascii_lowercase().contains(needle) {
                hits.push(EntitySearchHit {
                    entity_kind: EntityKind::McpServer,
                    entity_id: mcp.name.clone(),
                    title: mcp.name.clone(),
                    subtitle: mcp.transport.clone(),
                    rank_score: 0,
                });
            }
        }
    }
}

fn collect_pack_hits(
    packs: &BTreeMap<(String, String), PolicyPack>,
    orgs: &[&str],
    needle: &str,
    hits: &mut Vec<EntitySearchHit>,
) {
    for ((org, _), pack) in packs {
        if !orgs.contains(&org.as_str()) {
            continue;
        }
        for rule in &pack.rules {
            if rule.title.to_ascii_lowercase().contains(needle)
                || rule.id.to_ascii_lowercase().contains(needle)
            {
                hits.push(EntitySearchHit {
                    entity_kind: EntityKind::Rule,
                    entity_id: rule.id.clone(),
                    title: rule.title.clone(),
                    subtitle: pack.name.clone(),
                    rank_score: 0,
                });
            }
        }
    }
}

fn collect_user_hits(
    users: &BTreeMap<(String, String), TenantUserRecord>,
    orgs: &[&str],
    needle: &str,
    hits: &mut Vec<EntitySearchHit>,
) {
    for ((org, _), user) in users {
        if !orgs.contains(&org.as_str()) {
            continue;
        }
        if user.display_name.to_ascii_lowercase().contains(needle)
            || user.email.to_ascii_lowercase().contains(needle)
        {
            hits.push(EntitySearchHit {
                entity_kind: EntityKind::User,
                entity_id: user.id.clone(),
                title: user.display_name.clone(),
                subtitle: user.department.clone(),
                rank_score: 0,
            });
        }
    }
}
