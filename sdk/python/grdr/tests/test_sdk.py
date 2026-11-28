# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Tests for the Guardrails Python Agent SDK against real HTTP gateway and golden vectors."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

from grdr import (
    ActionBlocked,
    AgentDeclaration,
    ApprovalRequired,
    ClientConfig,
    DecideInput,
    FailurePolicy,
    GuardrailsClient,
    McpServerDeclaration,
    ToolDeclaration,
    Verdict,
    claude_agent_sdk_hook,
    crewai_tool_guard,
    langgraph_tool_node_middleware,
    ms_agent_hooks_adapter,
    openai_agents_guardrail,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
CONFORMANCE_DIR = REPO_ROOT / "sdk" / "conformance"


class _MockGatewayHandler(BaseHTTPRequestHandler):
    rules: list[dict[str, str]] = []
    ingested: list[dict[str, object]] = []

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if self.path == "/v1/ingest":
            type(self).ingested.append(payload)
            body = json.dumps({"accepted": len(payload.get("attempts", []))}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path != "/v1/guard":
            self.send_response(404)
            self.end_headers()
            return

        if self.headers.get("Authorization") == "Bearer reject-401":
            body = json.dumps({"code": "unauthenticated", "message": "bad token"}).encode("utf-8")
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.headers.get("Authorization") == "Bearer redirect-302":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/steal-token")
            self.end_headers()
            return

        target = str(payload.get("target", ""))
        action_class = str(payload.get("action_class", ""))
        verdict = "allow"
        rule_id = ""
        reason = "allowed"
        if "--dangerously-skip-permissions" in target:
            verdict = "block"
            rule_id = "essentials.bypass-flags"
            reason = "bypass permissions flag is forbidden"
        elif ".claude/settings.json" in target and action_class == "file.write":
            verdict = "block"
            rule_id = "essentials.control-files.write"
            reason = "agent control file is protected"
        elif "~/.ssh/id_rsa" in target and action_class == "file.read":
            verdict = "ask"
            rule_id = "essentials.cred-store.read"
            reason = "reading credential store requires approval"

        resp = {
            "receipt": {
                "id": "rcpt_test_1",
                "verdict": verdict,
                "ruleId": rule_id,
                "reason": reason,
                "sessionId": payload.get("session_id", ""),
            }
        }
        body = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PythonAgentSdkTests(unittest.TestCase):
    server: ThreadingHTTPServer
    thread: threading.Thread
    endpoint: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _MockGatewayHandler)
        port = cls.server.server_address[1]
        cls.endpoint = f"http://127.0.0.1:{port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_declaration_matches_conformance_fixture(self) -> None:
        fixture = json.loads((CONFORMANCE_DIR / "agent-declaration-v1.json").read_text(encoding="utf-8"))
        decl = AgentDeclaration(
            agent_name=fixture["agent_name"],
            framework=fixture["framework"],
            framework_version=fixture["framework_version"],
            control_point=fixture["control_point"],
            tools=[ToolDeclaration(**t) for t in fixture["tools"]],
            mcp_servers=[McpServerDeclaration(**m) for m in fixture["mcp_servers"]],
            egress_hosts=fixture["egress_hosts"],
            control_paths=fixture["control_paths"],
            covered_by=fixture["covered_by"],
            uncovered_hosted_tools=fixture["uncovered_hosted_tools"],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            client = GuardrailsClient(
                ClientConfig(endpoint=self.endpoint, declaration_dir=tmpdir)
            )
            canonical = client.declare(decl)
            written = Path(tmpdir) / "research-orchestrator.declaration.json"
            self.assertTrue(written.exists())
            parsed = json.loads(canonical)
            self.assertEqual(parsed, fixture)

    def test_guard_vectors_and_exceptions(self) -> None:
        vectors = json.loads((CONFORMANCE_DIR / "guard-vectors.json").read_text(encoding="utf-8"))["vectors"]
        client = GuardrailsClient(ClientConfig(endpoint=self.endpoint))
        for vec in vectors[:4]:
            rcpt = client.decide(
                DecideInput(
                    agent_name=vec["agent_name"],
                    action_class=vec["action_class"],
                    target=vec["target"],
                    control_point=vec["control_point"],
                    summary=vec["summary"],
                )
            )
            self.assertIn(rcpt.verdict.value, vec["expected_verdicts"])
            if vec["expected_rule_prefix"]:
                self.assertTrue(rcpt.rule_id.startswith(vec["expected_rule_prefix"]))

        with self.assertRaises(ApprovalRequired):
            client.decide(
                DecideInput(
                    agent_name="claude-code",
                    action_class="file.read",
                    target="~/.ssh/id_rsa",
                ),
                raise_on_deny=True,
            )

        with self.assertRaises(ActionBlocked):
            client.decide(
                DecideInput(
                    agent_name="claude-code",
                    action_class="exec",
                    target="claude --dangerously-skip-permissions",
                ),
                raise_on_deny=True,
            )

    def test_unreachable_policies_and_local_floor(self) -> None:
        closed_client = GuardrailsClient(
            ClientConfig(
                endpoint="http://127.0.0.1:1",
                timeout_seconds=0.2,
                on_unreachable=FailurePolicy.FAIL_CLOSED,
            )
        )
        rcpt_closed = closed_client.decide(
            DecideInput(agent_name="a", action_class="exec", target="echo hi")
        )
        self.assertEqual(rcpt_closed.verdict, Verdict.BLOCK)
        self.assertTrue(rcpt_closed.degraded)

        open_client = GuardrailsClient(
            ClientConfig(
                endpoint="http://127.0.0.1:1",
                timeout_seconds=0.2,
                on_unreachable=FailurePolicy.FAIL_OPEN,
            )
        )
        rcpt_open = open_client.decide(
            DecideInput(agent_name="a", action_class="exec", target="echo hi")
        )
        self.assertEqual(rcpt_open.verdict, Verdict.ALLOW)
        self.assertTrue(rcpt_open.degraded)

        floor_client = GuardrailsClient(
            ClientConfig(
                endpoint="http://127.0.0.1:1",
                timeout_seconds=0.2,
                on_unreachable=FailurePolicy.LOCAL_FLOOR,
            ),
            local_floor=lambda inp: closed_client._handle_unreachable(inp, RuntimeError("ok"))
            if "id_rsa" in inp.target
            else open_client._handle_unreachable(inp, RuntimeError("ok")),
        )
        self.assertEqual(
            floor_client.decide(
                DecideInput(agent_name="a", action_class="file.read", target="~/.ssh/id_rsa")
            ).verdict,
            Verdict.BLOCK,
        )
        self.assertEqual(
            floor_client.decide(
                DecideInput(agent_name="a", action_class="file.read", target="src/main.rs")
            ).verdict,
            Verdict.ALLOW,
        )

    def test_framework_middlewares_and_guard_decorator(self) -> None:
        _MockGatewayHandler.ingested.clear()
        client = GuardrailsClient(ClientConfig(endpoint=self.endpoint))

        @client.guard(
            agent_name="research-orchestrator",
            action_class="file.write",
            target=lambda path: path,
        )
        def write_doc(path: str) -> str:
            return f"wrote:{path}"

        self.assertEqual(write_doc("docs/note.md"), "wrote:docs/note.md")
        with self.assertRaises(ActionBlocked):
            write_doc(".claude/settings.json")

        lg = langgraph_tool_node_middleware(
            client, agent_name="lg-agent", action_class_map={"read_file": "file.read"}
        )
        self.assertEqual(lg({"name": "read_file", "args": {"path": "README.md"}}, lambda r: "ok"), "ok")

        oa_hook = openai_agents_guardrail(
            client, agent_name="oa-agent", hosted_tools=["openai:web_search_preview"]
        )
        self.assertTrue(
            oa_hook(
                {
                    "tool_name": "shell",
                    "action_class": "exec",
                    "target": "claude --dangerously-skip-permissions",
                }
            )["tripwire_triggered"]
        )

        claude_hook = claude_agent_sdk_hook(client)
        self.assertEqual(
            claude_hook({"tool_name": "Read", "tool_input": {"file_path": "~/.ssh/id_rsa"}})[
                "permissionDecision"
            ],
            "ask",
        )

        ms_hook = ms_agent_hooks_adapter(client, agent_name="ms-agent")
        self.assertEqual(
            ms_hook({"tool_name": "Read", "arguments": {"path": "src/lib.rs"}}).verdict,
            Verdict.ALLOW,
        )

        crew_guard = crewai_tool_guard(client, agent_name="crew-agent", action_class="file.read")
        self.assertEqual(crew_guard("read_file", {"path": "Cargo.toml"}).verdict, Verdict.ALLOW)

        res = client.report("lg-agent", "file.read", "README.md", Verdict.ALLOW)
        self.assertEqual(res["accepted"], 1)
        self.assertEqual(len(_MockGatewayHandler.ingested), 1)
        self.assertIn("openai:web_search_preview", client._declarations[-1].uncovered_hosted_tools)
        os.environ.pop("GRDR_ON_UNREACHABLE", None)

    def test_http_4xx_and_redirects_fail_instead_of_fail_open_and_support_modify(self) -> None:
        from grdr import GuardrailsError

        self.assertEqual(Verdict.parse("modify"), Verdict.MODIFY)

        for tok in ("reject-401", "redirect-302"):
            fail_open_with_bad_auth = GuardrailsClient(
                ClientConfig(
                    endpoint=self.endpoint,
                    token=tok,
                    on_unreachable=FailurePolicy.FAIL_OPEN,
                )
            )
            with self.assertRaises(GuardrailsError):
                fail_open_with_bad_auth.decide(
                    DecideInput(agent_name="a", action_class="file.read", target="README.md")
                )


if __name__ == "__main__":
    unittest.main()
