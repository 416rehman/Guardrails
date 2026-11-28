# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Runtime decision client, session scope, declaration emitter, and floor fallback."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
import os
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request
import uuid

from .types import (
    ActionBlocked,
    AgentDeclaration,
    ApprovalRequired,
    DecideInput,
    DecisionReceipt,
    FailurePolicy,
    GuardrailsError,
    Verdict,
)

LocalFloorEvaluator = Callable[[DecideInput], DecisionReceipt]


class _NoRedirectHandler(urllib_request.HTTPRedirectHandler):
    """Refuse automatic HTTP redirects so Authorization headers never cross origins."""

    def redirect_request(  # type: ignore[override]
        self,
        req: urllib_request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib_request.Request | None:
        return None


_NO_REDIRECT_OPENER = urllib_request.build_opener(_NoRedirectHandler())


@dataclass(frozen=True)
class ClientConfig:
    endpoint: str = ""
    token: str = ""
    timeout_seconds: float = 5.0
    on_unreachable: FailurePolicy = FailurePolicy.FAIL_CLOSED
    declaration_dir: str = ""
    client_header: str = "grdr-sdk-python/0.1.0"

    @classmethod
    def from_env(cls) -> ClientConfig:
        return cls(
            endpoint=os.environ.get("GRDR_ENDPOINT", "http://127.0.0.1:8787"),
            token=os.environ.get("GRDR_TOKEN", ""),
            timeout_seconds=float(os.environ.get("GRDR_TIMEOUT_SECONDS", "5.0")),
            on_unreachable=FailurePolicy.parse(os.environ.get("GRDR_ON_UNREACHABLE")),
            declaration_dir=os.environ.get("GRDR_DECLARATION_DIR", ""),
        )


class GuardrailsClient:
    """Thread-safe Guardrails ADR runtime enforcement client."""

    def __init__(
        self,
        config: ClientConfig | None = None,
        local_floor: LocalFloorEvaluator | None = None,
    ) -> None:
        self.config = config or ClientConfig.from_env()
        self._local_floor = local_floor
        self._declarations: list[AgentDeclaration] = []

    def declare(self, declaration: AgentDeclaration) -> str:
        """Register an agent capability declaration and emit canonical JSON if configured."""
        self._declarations.append(declaration)
        canonical = declaration.to_canonical_json()
        if self.config.declaration_dir:
            os.makedirs(self.config.declaration_dir, exist_ok=True)
            safe_name = "".join(
                ch if ch.isalnum() or ch in ("-", "_") else "_"
                for ch in declaration.agent_name
            )
            path = os.path.join(self.config.declaration_dir, f"{safe_name}.declaration.json")
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(canonical + "\n")
        return canonical

    def session(self, agent_name: str, session_id: str | None = None) -> SessionHandle:
        """Create an isolated session handle tracking sequential step context."""
        sid = session_id or f"sess_{uuid.uuid4().hex[:16]}"
        return SessionHandle(client=self, agent_name=agent_name, session_id=sid)

    def decide(self, attempt: DecideInput, *, raise_on_deny: bool = False) -> DecisionReceipt:
        """Evaluate an ActionAttempt against /v1/guard or apply GRDR_ON_UNREACHABLE."""
        receipt = self._post_guard(attempt)
        if raise_on_deny:
            if receipt.verdict is Verdict.ASK:
                raise ApprovalRequired(receipt)
            if receipt.verdict is Verdict.BLOCK:
                raise ActionBlocked(receipt)
        return receipt

    def report(
        self,
        agent_name: str,
        action_class: str,
        target: str,
        verdict: Verdict,
        *,
        session_id: str | None = None,
        summary: str | None = None,
    ) -> dict[str, Any]:
        """Report post-execution outcome telemetry back to /v1/ingest."""
        body = {
            "device_id": os.environ.get("GRDR_DEVICE_ID", "sdk-local"),
            "attempts": [
                {
                    "id": f"att_{uuid.uuid4().hex[:16]}",
                    "session_id": session_id or "",
                    "agent_name": agent_name,
                    "action_class": action_class,
                    "target": target,
                    "summary": summary or "",
                }
            ],
            "receipts": [
                {
                    "id": f"rcpt_{uuid.uuid4().hex[:16]}",
                    "verdict": verdict.value,
                    "rule_id": "sdk.post-report",
                    "reason": summary or "post-action telemetry",
                }
            ],
        }
        return self._http_post("/v1/ingest", body)

    def guard(
        self,
        *,
        agent_name: str,
        action_class: str,
        target: Callable[..., str] | str,
        control_point: str = "gateway",
        session_id: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator enforcing decide() before invoking the wrapped function."""

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                resolved_target = target(*args, **kwargs) if callable(target) else target
                attempt = DecideInput(
                    agent_name=agent_name,
                    action_class=action_class,
                    target=resolved_target,
                    control_point=control_point,
                    session_id=session_id,
                    summary=fn.__name__,
                )
                self.decide(attempt, raise_on_deny=True)
                return fn(*args, **kwargs)

            wrapper.__name__ = fn.__name__
            wrapper.__doc__ = fn.__doc__
            return wrapper

        return decorator

    def _post_guard(self, attempt: DecideInput) -> DecisionReceipt:
        try:
            response = self._http_post("/v1/guard", attempt.to_wire_dict())
            raw_receipt = response.get("receipt", response)
            if not isinstance(raw_receipt, dict):
                raise GuardrailsError("invalid receipt payload from /v1/guard")
            return DecisionReceipt.from_wire_dict(raw_receipt)
        except (urllib_error.URLError, TimeoutError, OSError) as exc:
            return self._handle_unreachable(attempt, exc)

    def _http_post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        base = self.config.endpoint.rstrip("/")
        url = f"{base}{path}"
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self.config.client_header,
        }
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        req = urllib_request.Request(url, data=data, headers=headers, method="POST")
        try:
            with _NO_REDIRECT_OPENER.open(req, timeout=self.config.timeout_seconds) as resp:
                raw = resp.read().decode("utf-8")
                parsed = json.loads(raw) if raw else {}
                if not isinstance(parsed, dict):
                    raise GuardrailsError("expected JSON object response")
                return parsed
        except urllib_error.HTTPError as exc:
            if 300 <= exc.code < 500:
                detail = exc.read().decode("utf-8", errors="replace")
                raise GuardrailsError(f"gateway rejected request ({exc.code}): {detail}") from exc
            raise

    def _handle_unreachable(self, attempt: DecideInput, exc: Exception) -> DecisionReceipt:
        policy = self.config.on_unreachable
        if policy is FailurePolicy.FAIL_OPEN:
            return DecisionReceipt(
                id=f"degraded_{uuid.uuid4().hex[:12]}",
                verdict=Verdict.ALLOW,
                rule_id="sdk.fail_open",
                reason=f"endpoint unreachable ({exc}); allowed under GRDR_ON_UNREACHABLE=fail_open",
                session_id=attempt.session_id or "",
                degraded=True,
            )
        if policy is FailurePolicy.LOCAL_FLOOR:
            if self._local_floor is not None:
                return self._local_floor(attempt)
            return DecisionReceipt(
                id=f"floor_{uuid.uuid4().hex[:12]}",
                verdict=Verdict.BLOCK,
                rule_id="sdk.local_floor.no_table",
                reason="endpoint unreachable and no local floor table loaded; failing closed",
                session_id=attempt.session_id or "",
                degraded=True,
            )
        return DecisionReceipt(
            id=f"closed_{uuid.uuid4().hex[:12]}",
            verdict=Verdict.BLOCK,
            rule_id="sdk.fail_closed",
            reason=f"endpoint unreachable ({exc}); blocked under fail_closed",
            session_id=attempt.session_id or "",
            degraded=True,
        )


@dataclass
class SessionHandle:
    client: GuardrailsClient
    agent_name: str
    session_id: str

    def decide(
        self,
        action_class: str,
        target: str,
        *,
        control_point: str = "gateway",
        summary: str | None = None,
        raise_on_deny: bool = False,
    ) -> DecisionReceipt:
        return self.client.decide(
            DecideInput(
                agent_name=self.agent_name,
                action_class=action_class,
                target=target,
                control_point=control_point,
                session_id=self.session_id,
                summary=summary,
            ),
            raise_on_deny=raise_on_deny,
        )


_DEFAULT_CLIENT = GuardrailsClient()


def declare(declaration: AgentDeclaration) -> str:
    return _DEFAULT_CLIENT.declare(declaration)


def session(agent_name: str, session_id: str | None = None) -> SessionHandle:
    return _DEFAULT_CLIENT.session(agent_name, session_id=session_id)


def decide(attempt: DecideInput, *, raise_on_deny: bool = False) -> DecisionReceipt:
    return _DEFAULT_CLIENT.decide(attempt, raise_on_deny=raise_on_deny)


def report(
    agent_name: str,
    action_class: str,
    target: str,
    verdict: Verdict,
    *,
    session_id: str | None = None,
    summary: str | None = None,
) -> dict[str, Any]:
    return _DEFAULT_CLIENT.report(
        agent_name,
        action_class,
        target,
        verdict,
        session_id=session_id,
        summary=summary,
    )


def guard(
    *,
    agent_name: str,
    action_class: str,
    target: Callable[..., str] | str,
    control_point: str = "gateway",
    session_id: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    return _DEFAULT_CLIENT.guard(
        agent_name=agent_name,
        action_class=action_class,
        target=target,
        control_point=control_point,
        session_id=session_id,
    )
