# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Tests for grdr-api Standard Webhooks verification and HTTP/pagination client."""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import unittest

from grdr_api import (
    ApiError,
    GrdrApiClient,
    WebhookVerificationError,
    sign_v1_hmac,
    verify_webhook,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
CONFORMANCE_DIR = REPO_ROOT / "sdk" / "conformance"

# RFC 8032 test vector #1 (matches sdk/conformance/webhooks-vectors.json)
RFC8032_VEC1_SIG_HEX = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


class _MockApiHandler(BaseHTTPRequestHandler):
    seen_keys: dict[str, dict[str, object]] = {}

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/v1/devices"):
            if "page_token=p2" in self.path:
                payload = {"devices": [{"id": "dev-2"}], "pageInfo": {"nextPageToken": ""}}
            else:
                payload = {"devices": [{"id": "dev-1"}], "pageInfo": {"nextPageToken": "p2"}}
            self._send(200, payload)
            return
        if self.path == "/v1/health":
            etag = '"rev-health-1"'
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.end_headers()
                return
            self._send(200, {"status": "healthy"}, headers={"ETag": etag})
            return
        if self.path == "/v1/redirect-me":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/evil")
            self.end_headers()
            return
        if self.path.startswith("/v1/operations/"):
            self._send(200, {"observedPath": self.path})
            return
        self._send(404, {"code": "not_found", "message": "unknown path"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.startswith("/v1/policy-changes/"):
            self._send(200, {"observedPath": self.path})
            return
        idem = self.headers.get("Idempotency-Key", "")
        if not idem:
            self._send(400, {"code": "invalid_argument", "reason": "IDEMPOTENCY_KEY_MISSING", "message": "missing key"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        if idem in type(self).seen_keys:
            if type(self).seen_keys[idem] != body:
                self._send(422, {"code": "failed_precondition", "reason": "IDEMPOTENCY_KEY_REUSED", "message": "payload mismatch"})
                return
            self._send(200, {"rule": {"id": "r-1"}, "replayed": True})
            return
        type(self).seen_keys[idem] = body
        self._send(200, {"rule": {"id": "r-1"}, "replayed": False})

    def _send(self, code: int, data: dict[str, object], headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)


class PythonApiSdkTests(unittest.TestCase):
    server: ThreadingHTTPServer
    thread: threading.Thread
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _MockApiHandler)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_pagination_etag_and_idempotency(self) -> None:
        client = GrdrApiClient(self.base_url, token="tok")
        devices = client.list_devices()
        self.assertEqual([d["id"] for d in devices], ["dev-1", "dev-2"])

        changed1, body1 = client.get_conditional("/v1/health")
        self.assertTrue(changed1)
        self.assertEqual(body1, {"status": "healthy"})
        changed2, body2 = client.get_conditional("/v1/health")
        self.assertFalse(changed2)
        self.assertIsNone(body2)

        first = client.create_rule({"title": "rule-a"}, idempotency_key="idem-1")
        self.assertFalse(first["replayed"])
        replay = client.create_rule({"title": "rule-a"}, idempotency_key="idem-1")
        self.assertTrue(replay["replayed"])
        with self.assertRaises(ApiError) as ctx:
            client.create_rule({"title": "rule-b"}, idempotency_key="idem-1")
        self.assertEqual(ctx.exception.status, 422)
        self.assertEqual(ctx.exception.reason, "IDEMPOTENCY_KEY_REUSED")

    def test_standard_webhooks_v1_hmac_and_v1a_ed25519(self) -> None:
        vec = json.loads((CONFORMANCE_DIR / "webhooks-vectors.json").read_text(encoding="utf-8"))["standard_webhooks"]
        payload = vec["payload"].encode("utf-8")
        ts = int(vec["webhook_timestamp"])
        msg_id = str(vec["webhook_id"])
        hmac_sig = sign_v1_hmac(msg_id, ts, payload, vec["hmac_secret_b64"])

        verified = verify_webhook(
            headers={
                "webhook-id": msg_id,
                "webhook-timestamp": str(ts),
                "webhook-signature": hmac_sig,
            },
            payload=payload,
            hmac_secrets=[vec["hmac_secret_b64"]],
            now_seconds=ts + 10,
        )
        self.assertEqual(verified.algorithm, "v1")

        with self.assertRaises(WebhookVerificationError):
            verify_webhook(
                headers={
                    "webhook-id": msg_id,
                    "webhook-timestamp": str(ts),
                    "webhook-signature": hmac_sig,
                },
                payload=payload,
                hmac_secrets=[vec["hmac_secret_b64"]],
                now_seconds=ts + 600,
            )

        # Pure-stdlib RFC 8032 verification using the vector's public key on empty payload suffix
        pub_bytes = bytes.fromhex(vec["ed25519_public_hex"])
        sig_b64 = base64.b64encode(bytes.fromhex(RFC8032_VEC1_SIG_HEX)).decode("ascii")
        # For RFC 8032 test vector #1, message is empty b"".
        from grdr_api.webhooks import _ed25519_verify_pure

        self.assertTrue(_ed25519_verify_pure(pub_bytes, b"", base64.b64decode(sig_b64)))
        self.assertFalse(_ed25519_verify_pure(pub_bytes, b"tampered", base64.b64decode(sig_b64)))

        # Invalid base64 in an earlier rotated signature must not crash verification of a valid token.
        rotated = verify_webhook(
            headers={
                "webhook-id": msg_id,
                "webhook-timestamp": str(ts),
                "webhook-signature": f"v1,bad!base64 {hmac_sig}",
            },
            payload=payload,
            hmac_secrets=[vec["hmac_secret_b64"]],
            now_seconds=ts + 10,
        )
        self.assertEqual(rotated.algorithm, "v1")

        # Negative tolerance rejected cleanly.
        with self.assertRaises(WebhookVerificationError):
            verify_webhook(
                headers={
                    "webhook-id": msg_id,
                    "webhook-timestamp": str(ts),
                    "webhook-signature": hmac_sig,
                },
                payload=payload,
                hmac_secrets=[vec["hmac_secret_b64"]],
                tolerance_seconds=-1,
                now_seconds=ts,
            )

        # Path interpolation encoding & redirect protection.
        client = GrdrApiClient(self.base_url, token="tok")
        checked = client.check_policy_change("chg/1?x=2")
        self.assertEqual(checked["observedPath"], "/v1/policy-changes/chg%2F1%3Fx%3D2:check")
        op = client.get_operation("op/1#frag")
        self.assertEqual(op["observedPath"], "/v1/operations/op%2F1%23frag")
        with self.assertRaises(ApiError) as redir:
            client.request("GET", "/v1/redirect-me")
        self.assertEqual(redir.exception.reason, "REDIRECT_BLOCKED")


if __name__ == "__main__":
    unittest.main()
