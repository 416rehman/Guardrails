// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::wire::RingEventVerdict;

pub const DEFAULT_LINEAGE_CAPACITY: usize = 64;
pub const MAX_LINEAGE_DEPTH: u16 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LineageState {
    Unmanaged = 0,
    TrackedAgent = 1,
    TrackedChild = 2,
    ContainedSandbox = 3,
    EscapedSuspect = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IsolationScope {
    Host = 0,
    Container = 1,
    UserNamespace = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageError {
    TableFull,
    UnknownParent,
    GenerationOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TaskNsIds {
    pub mnt_ns_inum: u32,
    pub pid_ns_inum: u32,
    pub net_ns_inum: u32,
    pub user_ns_inum: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ProcLineageEntry {
    pub tgid: u32,
    pub ppid: u32,
    pub root_agent_tgid: u32,
    pub session_hash: u64,
    pub cgroup_id: u64,
    pub ns: TaskNsIds,
    pub state: LineageState,
    pub isolation: IsolationScope,
    pub generation: u16,
    pub verdict_cap: RingEventVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRootSpec {
    pub tgid: u32,
    pub ppid: u32,
    pub session_hash: u64,
    pub cgroup_id: u64,
    pub ns: TaskNsIds,
    pub isolation: IsolationScope,
    pub verdict_cap: RingEventVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageTable<const N: usize = DEFAULT_LINEAGE_CAPACITY> {
    slots: [Option<ProcLineageEntry>; N],
    len: usize,
    degraded_overflow: bool,
}

impl TaskNsIds {
    pub const fn new(
        mnt_ns_inum: u32,
        pid_ns_inum: u32,
        net_ns_inum: u32,
        user_ns_inum: u32,
    ) -> Self {
        Self {
            mnt_ns_inum,
            pid_ns_inum,
            net_ns_inum,
            user_ns_inum,
        }
    }
}

impl ProcLineageEntry {
    pub const fn is_managed(&self) -> bool {
        !matches!(self.state, LineageState::Unmanaged)
    }
}

impl<const N: usize> Default for LineageTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> LineageTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            len: 0,
            degraded_overflow: false,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn is_degraded_overflow(&self) -> bool {
        self.degraded_overflow
    }

    pub fn get(&self, tgid: u32) -> Option<&ProcLineageEntry> {
        self.slots.iter().flatten().find(|entry| entry.tgid == tgid)
    }

    pub fn register_agent_root(
        &mut self,
        spec: AgentRootSpec,
    ) -> Result<ProcLineageEntry, LineageError> {
        let entry = ProcLineageEntry {
            tgid: spec.tgid,
            ppid: spec.ppid,
            root_agent_tgid: spec.tgid,
            session_hash: spec.session_hash,
            cgroup_id: spec.cgroup_id,
            ns: spec.ns,
            state: LineageState::TrackedAgent,
            isolation: spec.isolation,
            generation: 0,
            verdict_cap: spec.verdict_cap,
        };
        if let Err(err) = self.upsert(entry) {
            self.degraded_overflow = true;
            return Err(err);
        }
        Ok(entry)
    }

    pub fn on_fork(
        &mut self,
        parent_tgid: u32,
        child_tgid: u32,
        child_cgroup_id: u64,
        child_ns: TaskNsIds,
    ) -> Result<Option<ProcLineageEntry>, LineageError> {
        let Some(parent) = self.get(parent_tgid).copied() else {
            return Ok(None);
        };
        if !parent.is_managed() {
            return Ok(None);
        }
        let Some(next_gen) = parent
            .generation
            .checked_add(1)
            .filter(|g| *g <= MAX_LINEAGE_DEPTH)
        else {
            self.degraded_overflow = true;
            return Err(LineageError::GenerationOverflow);
        };
        let escaped = detect_namespace_escape(&parent, child_cgroup_id, child_ns);
        let child = ProcLineageEntry {
            tgid: child_tgid,
            ppid: parent_tgid,
            root_agent_tgid: parent.root_agent_tgid,
            session_hash: parent.session_hash,
            cgroup_id: child_cgroup_id,
            ns: child_ns,
            state: if escaped {
                LineageState::EscapedSuspect
            } else {
                match parent.state {
                    LineageState::ContainedSandbox => LineageState::ContainedSandbox,
                    LineageState::EscapedSuspect => LineageState::EscapedSuspect,
                    LineageState::TrackedAgent | LineageState::TrackedChild => {
                        LineageState::TrackedChild
                    }
                    LineageState::Unmanaged => LineageState::Unmanaged,
                }
            },
            isolation: parent.isolation,
            generation: next_gen,
            verdict_cap: parent.verdict_cap,
        };
        if let Err(err) = self.upsert(child) {
            self.degraded_overflow = true;
            return Err(err);
        }
        Ok(Some(child))
    }

    pub fn on_exec(
        &mut self,
        tgid: u32,
        cgroup_id: u64,
        ns: TaskNsIds,
        contained: bool,
    ) -> Option<ProcLineageEntry> {
        let mut updated = None;
        for slot in &mut self.slots {
            if let Some(entry) = slot
                && entry.tgid == tgid
            {
                let already_escaped = matches!(entry.state, LineageState::EscapedSuspect);
                let escaped = already_escaped || detect_namespace_escape(entry, cgroup_id, ns);
                entry.cgroup_id = cgroup_id;
                entry.ns = ns;
                entry.state = if escaped {
                    LineageState::EscapedSuspect
                } else if contained {
                    LineageState::ContainedSandbox
                } else if entry.generation == 0 {
                    LineageState::TrackedAgent
                } else {
                    LineageState::TrackedChild
                };
                updated = Some(*entry);
                break;
            }
        }
        updated
    }

    pub fn on_exit(&mut self, tgid: u32) -> Option<ProcLineageEntry> {
        for slot in &mut self.slots {
            if let Some(entry) = slot
                && entry.tgid == tgid
            {
                let removed = *entry;
                *slot = None;
                self.len = self.len.saturating_sub(1);
                return Some(removed);
            }
        }
        None
    }

    pub fn is_agent_descendant(&self, tgid: u32, root_agent_tgid: u32) -> bool {
        self.get(tgid)
            .is_some_and(|entry| entry.is_managed() && entry.root_agent_tgid == root_agent_tgid)
    }

    fn upsert(&mut self, entry: ProcLineageEntry) -> Result<(), LineageError> {
        for slot in &mut self.slots {
            if let Some(existing) = slot
                && existing.tgid == entry.tgid
            {
                *existing = entry;
                return Ok(());
            }
        }
        for slot in &mut self.slots {
            if slot.is_none() {
                *slot = Some(entry);
                self.len = self.len.saturating_add(1);
                return Ok(());
            }
        }
        Err(LineageError::TableFull)
    }
}

pub const fn detect_namespace_escape(
    parent: &ProcLineageEntry,
    child_cgroup_id: u64,
    child_ns: TaskNsIds,
) -> bool {
    if !matches!(parent.state, LineageState::ContainedSandbox) {
        return false;
    }
    child_cgroup_id != parent.cgroup_id
        || child_ns.mnt_ns_inum != parent.ns.mnt_ns_inum
        || child_ns.pid_ns_inum != parent.ns.pid_ns_inum
        || child_ns.user_ns_inum != parent.ns.user_ns_inum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagates_lineage_across_fork_exec_and_flags_sandbox_escape() {
        let mut table: LineageTable<4> = LineageTable::new();
        let ns = TaskNsIds::new(100, 101, 102, 103);
        let root = table.register_agent_root(AgentRootSpec {
            tgid: 500,
            ppid: 1,
            session_hash: 0xABCD,
            cgroup_id: 700,
            ns,
            isolation: IsolationScope::Host,
            verdict_cap: RingEventVerdict::Denied,
        });
        assert!(matches!(root, Ok(e) if e.state == LineageState::TrackedAgent));

        let child = table.on_fork(500, 501, 700, ns);
        assert!(matches!(
            child,
            Ok(Some(e)) if e.root_agent_tgid == 500 && e.generation == 1 && e.state == LineageState::TrackedChild
        ));
        assert!(table.is_agent_descendant(501, 500));

        let execed = table.on_exec(501, 700, ns, true);
        assert!(matches!(
            execed,
            Some(e) if e.state == LineageState::ContainedSandbox
        ));

        let escaped = table.on_fork(501, 502, 701, ns);
        assert!(matches!(
            escaped,
            Ok(Some(e)) if e.state == LineageState::EscapedSuspect
        ));

        assert!(table.on_exit(502).is_some());
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn enforces_bounded_capacity_without_panicking() {
        let mut table: LineageTable<2> = LineageTable::new();
        let ns = TaskNsIds::new(1, 2, 3, 4);
        assert!(
            table
                .register_agent_root(AgentRootSpec {
                    tgid: 10,
                    ppid: 1,
                    session_hash: 1,
                    cgroup_id: 1,
                    ns,
                    isolation: IsolationScope::Container,
                    verdict_cap: RingEventVerdict::Allowed,
                })
                .is_ok()
        );
        assert!(
            table
                .register_agent_root(AgentRootSpec {
                    tgid: 11,
                    ppid: 1,
                    session_hash: 2,
                    cgroup_id: 1,
                    ns,
                    isolation: IsolationScope::Container,
                    verdict_cap: RingEventVerdict::Allowed,
                })
                .is_ok()
        );
        assert_eq!(
            table.register_agent_root(AgentRootSpec {
                tgid: 12,
                ppid: 1,
                session_hash: 3,
                cgroup_id: 1,
                ns,
                isolation: IsolationScope::Container,
                verdict_cap: RingEventVerdict::Allowed,
            }),
            Err(LineageError::TableFull)
        );
        assert!(table.is_degraded_overflow());
    }

    #[test]
    fn preserves_escaped_suspect_monotonically_across_subsequent_exec() {
        let mut table: LineageTable<4> = LineageTable::new();
        let ns = TaskNsIds::new(10, 11, 12, 13);
        let root = table.register_agent_root(AgentRootSpec {
            tgid: 20,
            ppid: 1,
            session_hash: 99,
            cgroup_id: 500,
            ns,
            isolation: IsolationScope::Container,
            verdict_cap: RingEventVerdict::Denied,
        });
        assert!(root.is_ok());
        assert!(table.on_exec(20, 500, ns, true).is_some());
        let escaped = table.on_exec(20, 501, ns, true);
        assert!(matches!(escaped, Some(e) if e.state == LineageState::EscapedSuspect));
        let after_second_exec = table.on_exec(20, 501, ns, true);
        assert!(matches!(
            after_second_exec,
            Some(e) if e.state == LineageState::EscapedSuspect
        ));
    }
}
