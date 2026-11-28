// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  ApiError,
  GrdrApiClient,
  WebhookVerificationError,
  signV1Hmac,
  verifyWebhook,
} from "../src/index.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_DIR = path.resolve(__dirname, "../../../conformance");

interface WebhooksFixture {
  standard_webhooks: {
    webhook_id: string;
    webhook_timestamp: number;
    hmac_secret_b64: string;
    ed25519_public_hex: string;
    payload: string;
  };
}

describe("@grdr/api TypeScript Control-Plane SDK", () => {
  let server: http.Server;
  let baseUrl = "";
  const idempotencySeen = new Map<string, string>();

  before(async () => {
    server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const rawBody = Buffer.concat(chunks).toString("utf8");
        if (req.url?.startsWith("/v1/devices")) {
          const payload = req.url.includes("page_token=p2")
            ? { devices: [{ id: "dev-2" }], pageInfo: { nextPageToken: "" } }
            : { devices: [{ id: "dev-1" }], pageInfo: { nextPageToken: "p2" } };
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(payload));
          return;
        }
        if (req.url === "/v1/redirect-me") {
          res.writeHead(302, { Location: "http://127.0.0.1:9/evil" });
          res.end();
          return;
        }
        if (req.url?.startsWith("/v1/policy-changes/")) {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ observedUrl: req.url }));
          return;
        }
        if (req.url === "/v1/health") {
          const etag = '"rev-1"';
          if (req.headers["if-none-match"] === etag) {
            res.writeHead(304);
            res.end();
            return;
          }
          res.writeHead(200, { "Content-Type": "application/json", ETag: etag });
          res.end(JSON.stringify({ status: "healthy" }));
          return;
        }
        if (req.url === "/v1/rules" && req.method === "POST") {
          const key = String(req.headers["idempotency-key"] ?? "");
          const prev = idempotencySeen.get(key);
          if (prev !== undefined && prev !== rawBody) {
            res.writeHead(422, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                code: "failed_precondition",
                reason: "IDEMPOTENCY_KEY_REUSED",
                message: "payload conflict",
              }),
            );
            return;
          }
          const replayed = prev !== undefined;
          idempotencySeen.set(key, rawBody);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ rule: { id: "r1" }, replayed }));
          return;
        }
        res.writeHead(404);
        res.end();
      });
    });
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (addr && typeof addr === "object") {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  after(() => {
    server.close();
  });

  it("handles cursor pagination, ETag 304, and Idempotency-Key conflicts", async () => {
    const client = new GrdrApiClient({ baseUrl, token: "tok" });
    const devices = await client.listDevices();
    assert.deepEqual(
      devices.map((d) => d.id),
      ["dev-1", "dev-2"],
    );

    const first = await client.getConditional("/v1/health");
    assert.equal(first.modified, true);
    const second = await client.getConditional("/v1/health");
    assert.equal(second.modified, false);
    assert.equal(second.body, null);

    const r1 = await client.createRule({ title: "one" }, "idem-ts-1");
    assert.equal(r1.replayed, false);
    const r2 = await client.createRule({ title: "one" }, "idem-ts-1");
    assert.equal(r2.replayed, true);
    await assert.rejects(
      () => client.createRule({ title: "two" }, "idem-ts-1"),
      (err: unknown) => err instanceof ApiError && err.reason === "IDEMPOTENCY_KEY_REUSED",
    );
  });

  it("verifies Standard Webhooks v1 HMAC and v1a Ed25519 signatures", () => {
    const fixture = JSON.parse(
      fs.readFileSync(path.join(CONFORMANCE_DIR, "webhooks-vectors.json"), "utf8"),
    ) as WebhooksFixture;
    const sw = fixture.standard_webhooks;
    const hmacSig = signV1Hmac(sw.webhook_id, sw.webhook_timestamp, sw.payload, sw.hmac_secret_b64);
    const v1 = verifyWebhook({
      headers: {
        "webhook-id": sw.webhook_id,
        "webhook-timestamp": String(sw.webhook_timestamp),
        "webhook-signature": hmacSig,
      },
      payload: sw.payload,
      hmacSecrets: [sw.hmac_secret_b64],
      nowSeconds: sw.webhook_timestamp + 5,
    });
    assert.equal(v1.algorithm, "v1");

    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const spki = publicKey.export({ format: "der", type: "spki" });
    const rawPub = new Uint8Array(spki.subarray(spki.length - 32));
    const signedInput = `${sw.webhook_id}.${sw.webhook_timestamp}.${sw.payload}`;
    const edSig = crypto.sign(null, Buffer.from(signedInput, "utf8"), privateKey).toString("base64");
    const v1a = verifyWebhook({
      headers: {
        "webhook-id": sw.webhook_id,
        "webhook-timestamp": String(sw.webhook_timestamp),
        "webhook-signature": `v1a,${edSig}`,
      },
      payload: sw.payload,
      ed25519PublicKeys: [rawPub],
      nowSeconds: sw.webhook_timestamp + 5,
    });
    assert.equal(v1a.algorithm, "v1a");

    assert.throws(
      () =>
        verifyWebhook({
          headers: {
            "webhook-id": sw.webhook_id,
            "webhook-timestamp": String(sw.webhook_timestamp),
            "webhook-signature": `v1a,${edSig}`,
          },
          payload: sw.payload,
          ed25519PublicKeys: [rawPub],
          nowSeconds: sw.webhook_timestamp + 900,
        }),
      WebhookVerificationError,
    );

    // NaN / negative toleranceSeconds must reject cleanly instead of comparing NaN > false.
    for (const badTol of [Number.NaN, -1]) {
      assert.throws(
        () =>
          verifyWebhook({
            headers: {
              "webhook-id": sw.webhook_id,
              "webhook-timestamp": String(sw.webhook_timestamp),
              "webhook-signature": hmacSig,
            },
            payload: sw.payload,
            hmacSecrets: [sw.hmac_secret_b64],
            toleranceSeconds: badTol,
            nowSeconds: sw.webhook_timestamp,
          }),
        WebhookVerificationError,
      );
    }

    // Malformed base64 alone must fail; malformed token before valid rotated token succeeds.
    assert.throws(
      () =>
        verifyWebhook({
          headers: {
            "webhook-id": sw.webhook_id,
            "webhook-timestamp": String(sw.webhook_timestamp),
            "webhook-signature": "v1,bad!chars",
          },
          payload: sw.payload,
          hmacSecrets: [sw.hmac_secret_b64],
          nowSeconds: sw.webhook_timestamp,
        }),
      WebhookVerificationError,
    );
    const rotated = verifyWebhook({
      headers: {
        "webhook-id": sw.webhook_id,
        "webhook-timestamp": String(sw.webhook_timestamp),
        "webhook-signature": `v1,bad!chars ${hmacSig}`,
      },
      payload: sw.payload,
      hmacSecrets: [sw.hmac_secret_b64],
      nowSeconds: sw.webhook_timestamp,
    });
    assert.equal(rotated.algorithm, "v1");
  });

  it("encodes path parameters and refuses Authorization-bearing HTTP redirects", async () => {
    const client = new GrdrApiClient({ baseUrl, token: "tok" });
    const checked = await client.checkPolicyChange("chg/1?evil=2");
    assert.equal(checked.observedUrl, "/v1/policy-changes/chg%2F1%3Fevil%3D2:check");
    await assert.rejects(
      () => client.request("GET", "/v1/redirect-me"),
      (err: unknown) => err instanceof ApiError && err.reason === "REDIRECT_BLOCKED",
    );
  });
});
