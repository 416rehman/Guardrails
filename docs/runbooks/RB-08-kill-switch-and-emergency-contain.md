---
id: RB-08
actor: incident-commander
rto: 15m
rpo: 0m
---

# RB-08: Emergency Kill Switch and Scoped Containment

## Diagnosis

1. Confirm active misuse or high-severity containment signal in Console Respond (`grdr.api.response.v1alpha1.ResponseService`) or the Operator plane (`grdr.api.operator.v1alpha1.OperatorService`).
2. Identify exact scope (single agent session, single device, or tenant org) before escalating containment scope.

## Actions

1. Issue bounded kill-switch activation via Response RPC (`KillSwitchState`), verifying epoch increment (`kill_switch_epoch`) in endpoint receipts.
2. Confirm hook and MCP proxy fail closed (`Block`) across targeted sessions.
3. Preserve forensic audit chains and collect a support bundle (`grdr support-bundle`) prior to clearing containment state.

## Verification

- Verify `grdr status` reflects active isolation epoch and no targeted tool execution bypasses local enforcement.

## Rollback

Complete authenticated step-up approval in the Console or Desktop approval prompt and record a documented clearance reason before lifting kill switch.

## Escalation

Engage Trust & Safety and Customer Security Contact when cross-host lateral abuse is observed.
