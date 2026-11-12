# ADR-0013: One writer per work item; the repository holds code and decisions, and issues hold the work

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-47
- Requires: nothing
- RFC: not required: restates D-47 as repository mechanism
- Work items: [WI-0011], [WI-0005]

## Context
Parallel writers on one item overwrite each other, and peers that coordinate through locks ran at the throughput of one to three agents (brief 31). An agent with private memory makes decisions the repository cannot show.

## Decision
Each work item has exactly one writer at a time, chosen by the dispatcher's lease. Planners write no code. The repository holds code, gate configuration, decisions and evidence. GitHub issues hold every work item, its status and its discussion. No agent keeps memory outside those two places.

## Enforced by
The dispatcher grants one lease per item and posts it as a `lease.v1` comment ([WI-0011]). Auto memory is off in the managed settings; the key name `autoMemoryEnabled` is unconfirmed, and `kit check` validates it against the pinned Claude Code settings schema in [WI-0005]. Hooks hold each session to its item's write set.

## Consequences
A session that ends loses nothing that matters, because the issue and the branch hold the state. Work that spans squads names one lead squad.

## Alternatives rejected
- Self-claiming peer agents: lock contention and risk-averse behaviour.
- Agent memory files: state the gates and the next session cannot read.

## Revisit when
S-20 shows that single-writer items leave writer slots idle while ready items wait.
