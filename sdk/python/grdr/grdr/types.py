# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Typed data structures and failure modes for the Guardrails Agent SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Any


class Verdict(str, Enum):
    ALLOW = "allow"
    MODIFY = "modify"
    ASK = "ask"
    BLOCK = "block"

    @classmethod
    def parse(cls, value: str) -> Verdict:
        normalized = value.strip().lower()
        for prefix in ("verdict_",):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"unsupported verdict value: {value}")


class FailurePolicy(str, Enum):
    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"
    LOCAL_FLOOR = "local_floor"

    @classmethod
    def parse(cls, value: str | None) -> FailurePolicy:
        if not value:
            return cls.FAIL_CLOSED
        normalized = value.strip().lower().replace("-", "_")
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"invalid GRDR_ON_UNREACHABLE mode: {value}")


class GuardrailsError(Exception):
    """Base error raised by the Guardrails Agent SDK."""


class ApprovalRequired(GuardrailsError):
    """Raised when an action returns verdict 'ask' and caller gating is active."""

    def __init__(self, receipt: DecisionReceipt) -> None:
        self.receipt = receipt
        super().__init__(f"Approval required ({receipt.rule_id or 'policy'}): {receipt.reason}")


class ActionBlocked(GuardrailsError):
    """Raised when an action returns verdict 'block'."""

    def __init__(self, receipt: DecisionReceipt) -> None:
        self.receipt = receipt
        super().__init__(f"Action blocked ({receipt.rule_id or 'policy'}): {receipt.reason}")


@dataclass(frozen=True)
class ToolDeclaration:
    name: str
    action_class: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "action_class": self.action_class,
            "description": self.description,
        }


@dataclass(frozen=True)
class McpServerDeclaration:
    name: str
    transport: str = "streamable-http"
    endpoint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "transport": self.transport,
            "endpoint": self.endpoint,
        }


@dataclass
class AgentDeclaration:
    agent_name: str
    framework: str
    framework_version: str = ""
    control_point: str = "gateway"
    tools: list[ToolDeclaration] = field(default_factory=list)
    mcp_servers: list[McpServerDeclaration] = field(default_factory=list)
    egress_hosts: list[str] = field(default_factory=list)
    control_paths: list[str] = field(default_factory=list)
    covered_by: list[str] = field(default_factory=lambda: ["grdr-sdk"])
    uncovered_hosted_tools: list[str] = field(default_factory=list)
    schema: str = "grdr.agent-declaration.v1alpha1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "agent_name": self.agent_name,
            "framework": self.framework,
            "framework_version": self.framework_version,
            "control_point": self.control_point,
            "tools": [tool.to_dict() for tool in self.tools],
            "mcp_servers": [server.to_dict() for server in self.mcp_servers],
            "egress_hosts": list(self.egress_hosts),
            "control_paths": list(self.control_paths),
            "covered_by": list(self.covered_by),
            "uncovered_hosted_tools": list(self.uncovered_hosted_tools),
        }

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class DecideInput:
    agent_name: str
    action_class: str
    target: str
    control_point: str = "gateway"
    session_id: str | None = None
    device_id: str | None = None
    summary: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_wire_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "agent_name": self.agent_name,
            "action_class": self.action_class,
            "control_point": self.control_point,
            "target": self.target,
        }
        if self.session_id is not None:
            payload["session_id"] = self.session_id
        if self.device_id is not None:
            payload["device_id"] = self.device_id
        if self.summary is not None:
            payload["summary"] = self.summary
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


@dataclass(frozen=True)
class DecisionReceipt:
    id: str
    verdict: Verdict
    rule_id: str
    reason: str
    session_id: str = ""
    mode: str = ""
    degraded: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_wire_dict(cls, data: dict[str, Any]) -> DecisionReceipt:
        verdict = Verdict.parse(str(data.get("verdict", "block")))
        return cls(
            id=str(data.get("id", "")),
            verdict=verdict,
            rule_id=str(data.get("ruleId") or data.get("rule_id") or ""),
            reason=str(data.get("reason", "")),
            session_id=str(data.get("sessionId") or data.get("session_id") or ""),
            mode=str(data.get("mode", "")),
            degraded=bool(data.get("degraded", False)),
            raw=dict(data),
        )
