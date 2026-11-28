# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Guardrails ADR Control-Plane REST /v1 API SDK."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Iterator
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request
import uuid


class _NoRedirectHandler(urllib_request.HTTPRedirectHandler):
    """Refuse automatic HTTP redirects so Authorization tokens cannot leak across origins."""

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
class ApiError(Exception):
    status: int
    code: str
    reason: str
    message: str
    details: dict[str, Any]

    def __str__(self) -> str:
        return f"HTTP {self.status} [{self.code}/{self.reason}]: {self.message}"


class GrdrApiClient:
    """Versioned REST /v1 OpenAPI client supporting ETag, Idempotency-Key, and cursor pagination."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str = "",
        timeout_seconds: float = 10.0,
        user_agent: str = "grdr-api-python/0.1.0",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent
        self._etags: dict[str, str] = {}

    def openapi_spec(self) -> dict[str, Any]:
        status, body, _ = self.request("GET", "/v1/openapi.json")
        if status != 200:
            raise RuntimeError(f"unexpected OpenAPI status {status}")
        return body

    def health(self) -> dict[str, Any]:
        return self._get_json("/v1/health")

    def overview(self) -> dict[str, Any]:
        return self._get_json("/v1/overview")

    def guard(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._mutate("POST", "/v1/guard", payload)

    def iter_collection(
        self,
        path: str,
        items_field: str,
        *,
        page_size: int = 50,
        filter_expr: str = "",
        order_by: str = "",
    ) -> Iterator[dict[str, Any]]:
        page_token = ""
        while True:
            params: dict[str, str] = {"page_size": str(page_size)}
            if page_token:
                params["page_token"] = page_token
            if filter_expr:
                params["filter"] = filter_expr
            if order_by:
                params["order_by"] = order_by
            query = urllib_parse.urlencode(params)
            data = self._get_json(f"{path}?{query}")
            for item in data.get(items_field, []):
                yield item
            page_info = data.get("pageInfo") or data.get("page_info") or {}
            next_tok = page_info.get("nextPageToken") or page_info.get("next_page_token") or ""
            if not next_tok:
                break
            page_token = str(next_tok)

    def list_devices(self, *, page_size: int = 50, filter_expr: str = "") -> list[dict[str, Any]]:
        return list(self.iter_collection("/v1/devices", "devices", page_size=page_size, filter_expr=filter_expr))

    def list_rules(self) -> list[dict[str, Any]]:
        packs = self._get_json("/v1/packs").get("packs", [])
        rules: list[dict[str, Any]] = []
        for pack in packs:
            rules.extend(pack.get("rules", []))
        return rules

    def create_rule(self, payload: dict[str, Any], *, idempotency_key: str | None = None) -> dict[str, Any]:
        return self._mutate("POST", "/v1/rules", payload, idempotency_key=idempotency_key)

    def create_policy_change(
        self, payload: dict[str, Any], *, idempotency_key: str | None = None
    ) -> dict[str, Any]:
        return self._mutate("POST", "/v1/policy-changes", payload, idempotency_key=idempotency_key)

    def check_policy_change(self, change_id: str) -> dict[str, Any]:
        safe_id = urllib_parse.quote(change_id, safe="")
        return self._mutate("POST", f"/v1/policy-changes/{safe_id}:check", {})

    def simulate_policy_change(self, change_id: str) -> dict[str, Any]:
        safe_id = urllib_parse.quote(change_id, safe="")
        return self._mutate("POST", f"/v1/policy-changes/{safe_id}:simulate", {})

    def apply_policy_change(
        self, change_id: str, *, idempotency_key: str | None = None
    ) -> dict[str, Any]:
        safe_id = urllib_parse.quote(change_id, safe="")
        return self._mutate("POST", f"/v1/policy-changes/{safe_id}:apply", {}, idempotency_key=idempotency_key)

    def approve_policy_change(
        self, change_id: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        safe_id = urllib_parse.quote(change_id, safe="")
        return self._mutate("POST", f"/v1/policy-changes/{safe_id}:approve", payload or {})

    def get_gitops_binding(self) -> dict[str, Any]:
        return self._get_json("/v1/gitops-binding")

    def upsert_gitops_binding(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._mutate("PUT", "/v1/gitops-binding", payload)

    def create_webhook_endpoint(
        self, payload: dict[str, Any], *, idempotency_key: str | None = None
    ) -> dict[str, Any]:
        return self._mutate("POST", "/v1/webhook-endpoints", payload, idempotency_key=idempotency_key)

    def get_operation(self, operation_id: str) -> dict[str, Any]:
        safe_id = urllib_parse.quote(operation_id, safe="")
        return self._get_json(f"/v1/operations/{safe_id}")

    def get_conditional(self, path: str) -> tuple[bool, dict[str, Any] | None]:
        headers: dict[str, str] = {}
        if path in self._etags:
            headers["If-None-Match"] = self._etags[path]
        status, body, resp_headers = self.request("GET", path, headers=headers)
        if status == 304:
            return False, None
        etag = resp_headers.get("etag")
        if etag:
            self._etags[path] = etag
        return True, body

    def _get_json(self, path: str) -> dict[str, Any]:
        _, body, _ = self.request("GET", path)
        return body

    def _mutate(
        self,
        method: str,
        path: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        key = idempotency_key or str(uuid.uuid4())
        _, body, _ = self.request(
            method,
            path,
            body=payload,
            headers={"Idempotency-Key": key},
        )
        return body

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        url = f"{self.base_url}{path}"
        req_headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        if self.token:
            req_headers["Authorization"] = f"Bearer {self.token}"
        if headers:
            req_headers.update(headers)
        data: bytes | None = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib_request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with _NO_REDIRECT_OPENER.open(req, timeout=self.timeout_seconds) as resp:
                raw = resp.read().decode("utf-8")
                parsed = json.loads(raw) if raw else {}
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, parsed if isinstance(parsed, dict) else {"value": parsed}, resp_headers
        except urllib_error.HTTPError as exc:
            if exc.code == 304:
                return 304, {}, {k.lower(): v for k, v in exc.headers.items()}
            if 300 <= exc.code < 400:
                raise ApiError(
                    status=exc.code,
                    code="redirect_blocked",
                    reason="REDIRECT_BLOCKED",
                    message="HTTP redirect blocked to protect Authorization header",
                    details={"location": exc.headers.get("Location", "")},
                ) from exc
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                err_json = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                err_json = {"message": raw}
            raise ApiError(
                status=exc.code,
                code=str(err_json.get("code", "")),
                reason=str(err_json.get("reason", "")),
                message=str(err_json.get("message", raw)),
                details=err_json if isinstance(err_json, dict) else {},
            ) from exc
