# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Framework middleware hooks (LangGraph, OpenAI Agents, Claude Agent SDK, CrewAI, AutoGen, ADK, ms-agent-hooks)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .client import GuardrailsClient
from .types import (
    AgentDeclaration,
    DecideInput,
    DecisionReceipt,
    McpServerDeclaration,
    ToolDeclaration,
    Verdict,
)


def declare_framework_agent(
    client: GuardrailsClient,
    *,
    agent_name: str,
    framework: str,
    tools: list[ToolDeclaration] | None = None,
    mcp_servers: list[McpServerDeclaration] | None = None,
    egress_hosts: list[str] | None = None,
    uncovered_hosted_tools: list[str] | None = None,
) -> AgentDeclaration:
    decl = AgentDeclaration(
        agent_name=agent_name,
        framework=framework,
        control_point="gateway",
        tools=list(tools or []),
        mcp_servers=list(mcp_servers or []),
        egress_hosts=list(egress_hosts or []),
        control_paths=[f"sdk:python:{framework}", "gateway:/v1/guard"],
        covered_by=["grdr-sdk"],
        uncovered_hosted_tools=list(uncovered_hosted_tools or []),
    )
    client.declare(decl)
    return decl


def langgraph_tool_node_middleware(
    client: GuardrailsClient,
    *,
    agent_name: str,
    action_class_map: dict[str, str] | None = None,
    session_id: str | None = None,
) -> Callable[[dict[str, Any], Callable[[dict[str, Any]], Any]], Any]:
    """Wrap LangGraph / LangChain tool invocations via DecideInput enforcement."""
    mapping = action_class_map or {}

    def middleware(request: dict[str, Any], next_fn: Callable[[dict[str, Any]], Any]) -> Any:
        tool_name = str(request.get("name", "tool"))
        args = request.get("args") or {}
        target = str(args.get("target") or args.get("path") or args.get("command") or tool_name)
        action_class = mapping.get(tool_name, "mcp.call")
        client.decide(
            DecideInput(
                agent_name=agent_name,
                action_class=action_class,
                target=target,
                control_point="gateway",
                session_id=session_id,
                summary=tool_name,
            ),
            raise_on_deny=True,
        )
        return next_fn(request)

    return middleware


def openai_agents_guardrail(
    client: GuardrailsClient,
    *,
    agent_name: str,
    hosted_tools: list[str] | None = None,
    session_id: str | None = None,
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """OpenAI Agents SDK tool guardrail hook with uncovered hosted-tool accounting."""
    if hosted_tools:
        declare_framework_agent(
            client,
            agent_name=agent_name,
            framework="openai-agents-sdk",
            uncovered_hosted_tools=hosted_tools,
        )

    def hook(tool_call: dict[str, Any]) -> dict[str, Any]:
        tool_name = str(tool_call.get("tool_name", "tool"))
        target = str(tool_call.get("target") or tool_call.get("arguments") or tool_name)
        action_class = str(tool_call.get("action_class", "mcp.call"))
        receipt = client.decide(
            DecideInput(
                agent_name=agent_name,
                action_class=action_class,
                target=target,
                control_point="gateway",
                session_id=session_id,
                summary=tool_name,
            ),
            raise_on_deny=False,
        )
        return {
            "tripwire_triggered": receipt.verdict is not Verdict.ALLOW,
            "verdict": receipt.verdict.value,
            "rule_id": receipt.rule_id,
            "reason": receipt.reason,
        }

    return hook


def claude_agent_sdk_hook(
    client: GuardrailsClient,
    *,
    agent_name: str = "claude-agent-sdk",
    session_id: str | None = None,
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Claude Agent SDK PreToolUse compatible hook adapter."""

    def pre_tool_use(event: dict[str, Any]) -> dict[str, Any]:
        tool_name = str(event.get("tool_name", ""))
        tool_input = event.get("tool_input") or {}
        action_class = str(event.get("action_class") or _infer_action_class(tool_name))
        target = str(
            tool_input.get("file_path")
            or tool_input.get("command")
            or tool_input.get("url")
            or tool_name
        )
        receipt = client.decide(
            DecideInput(
                agent_name=agent_name,
                action_class=action_class,
                target=target,
                control_point="hook",
                session_id=session_id or str(event.get("session_id") or "") or None,
                summary=tool_name,
            ),
            raise_on_deny=False,
        )
        if receipt.verdict is Verdict.ALLOW:
            return {"permissionDecision": "allow", "ruleId": receipt.rule_id}
        if receipt.verdict is Verdict.ASK:
            return {
                "permissionDecision": "ask",
                "permissionDecisionReason": receipt.reason,
                "ruleId": receipt.rule_id,
            }
        return {
            "permissionDecision": "deny",
            "permissionDecisionReason": receipt.reason,
            "ruleId": receipt.rule_id,
        }

    return pre_tool_use


def ms_agent_hooks_adapter(
    client: GuardrailsClient,
    *,
    agent_name: str,
    session_id: str | None = None,
) -> Callable[[dict[str, Any]], DecisionReceipt]:
    """Microsoft agent-hooks v0.1.0-beta.3 event adapter."""

    def before_tool(hook_ctx: dict[str, Any]) -> DecisionReceipt:
        tool_name = str(hook_ctx.get("tool_name") or hook_ctx.get("name") or "")
        params = hook_ctx.get("arguments") or {}
        target = str(params.get("target") or params.get("path") or params.get("command") or tool_name)
        return client.decide(
            DecideInput(
                agent_name=agent_name,
                action_class=str(hook_ctx.get("action_class") or _infer_action_class(tool_name)),
                target=target,
                control_point="hook",
                session_id=session_id,
                summary=tool_name,
            ),
            raise_on_deny=True,
        )

    return before_tool


def crewai_tool_guard(
    client: GuardrailsClient, *, agent_name: str, action_class: str = "exec"
) -> Callable[[str, dict[str, Any]], DecisionReceipt]:
    """CrewAI / AutoGen / Google ADK uniform before-tool callback."""

    def guard_call(tool_name: str, arguments: dict[str, Any]) -> DecisionReceipt:
        target = str(
            arguments.get("target")
            or arguments.get("command")
            or arguments.get("path")
            or tool_name
        )
        return client.decide(
            DecideInput(
                agent_name=agent_name,
                action_class=action_class,
                target=target,
                control_point="gateway",
                summary=tool_name,
            ),
            raise_on_deny=True,
        )

    return guard_call


def _infer_action_class(tool_name: str) -> str:
    lowered = tool_name.lower()
    if lowered in ("bash", "shell", "exec", "powershell"):
        return "exec"
    if lowered in ("read", "view_file", "read_file"):
        return "file.read"
    if lowered in ("write", "edit", "write_to_file", "write_file"):
        return "file.write"
    if lowered in ("delete", "remove", "rm"):
        return "file.delete"
    if lowered in ("webfetch", "http_request", "fetch"):
        return "net.request"
    return "mcp.call"
