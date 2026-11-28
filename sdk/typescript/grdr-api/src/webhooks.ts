// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import * as crypto from "node:crypto";

export class WebhookVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebhookVerificationError";
  }
}

export interface VerifiedWebhook {
  webhookId: string;
  timestamp: number;
  algorithm: "v1" | "v1a";
  payload: Uint8Array;
}

function decodeStrictBase64(encoded: string): Buffer | null {
  const trimmed = encoded.trim();
  if (!trimmed || trimmed.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
    return null;
  }
  const decoded = Buffer.from(trimmed, "base64");
  if (decoded.length === 0 || decoded.toString("base64") !== trimmed) {
    return null;
  }
  return decoded;
}

export function decodeWhsec(secret: string): Buffer {
  const raw = secret.startsWith("whsec_") ? secret.slice(6) : secret;
  const decoded = decodeStrictBase64(raw);
  if (!decoded) {
    throw new WebhookVerificationError("invalid webhook secret encoding");
  }
  return decoded;
}

export function signV1Hmac(
  webhookId: string,
  timestamp: number,
  payload: Uint8Array | string,
  secret: string,
): string {
  const key = decodeWhsec(secret);
  const body = typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload);
  const signed = Buffer.concat([Buffer.from(`${webhookId}.${timestamp}.`, "utf8"), body]);
  const mac = crypto.createHmac("sha256", key).update(signed).digest("base64");
  return `v1,${mac}`;
}

export function rawEd25519PubToSpkiDer(raw32: Uint8Array): Buffer {
  if (raw32.length !== 32) {
    throw new WebhookVerificationError("Ed25519 public key must be 32 bytes");
  }
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  return Buffer.concat([spkiPrefix, Buffer.from(raw32)]);
}

export function verifyWebhook(opts: {
  headers: Record<string, string | undefined>;
  payload: Uint8Array | string;
  hmacSecrets?: readonly string[];
  ed25519PublicKeys?: readonly Uint8Array[];
  toleranceSeconds?: number;
  nowSeconds?: number;
}): VerifiedWebhook {
  const lowered: Record<string, string> = {};
  for (const [k, v] of Object.entries(opts.headers)) {
    if (typeof v === "string") {
      lowered[k.toLowerCase()] = v;
    }
  }
  const msgId = (lowered["webhook-id"] ?? "").trim();
  const tsRaw = (lowered["webhook-timestamp"] ?? "").trim();
  const sigHeader = (lowered["webhook-signature"] ?? "").trim();
  if (!msgId || !tsRaw || !sigHeader) {
    throw new WebhookVerificationError("missing Standard Webhooks headers");
  }
  const ts = Number.parseInt(tsRaw, 10);
  if (!Number.isFinite(ts) || String(ts) !== tsRaw) {
    throw new WebhookVerificationError("invalid webhook-timestamp");
  }
  const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
  const tolerance = opts.toleranceSeconds ?? 300;
  if (!Number.isFinite(tolerance) || tolerance < 0) {
    throw new WebhookVerificationError("toleranceSeconds must be a finite non-negative number");
  }
  if (Math.abs(now - ts) > tolerance) {
    throw new WebhookVerificationError("webhook timestamp outside tolerance window");
  }

  const body =
    typeof opts.payload === "string" ? Buffer.from(opts.payload, "utf8") : Buffer.from(opts.payload);
  const signed = Buffer.concat([Buffer.from(`${msgId}.${ts}.`, "utf8"), body]);

  for (const token of sigHeader.split(/\s+/)) {
    if (token.startsWith("v1a,")) {
      const sigBytes = decodeStrictBase64(token.slice(4));
      if (!sigBytes || sigBytes.length !== 64) {
        continue;
      }
      for (const rawKey of opts.ed25519PublicKeys ?? []) {
        try {
          const keyObj = crypto.createPublicKey({
            key: rawEd25519PubToSpkiDer(rawKey),
            format: "der",
            type: "spki",
          });
          if (crypto.verify(null, signed, keyObj, sigBytes)) {
            return { webhookId: msgId, timestamp: ts, algorithm: "v1a", payload: body };
          }
        } catch {
          continue;
        }
      }
    } else if (token.startsWith("v1,")) {
      const sigBytes = decodeStrictBase64(token.slice(3));
      if (!sigBytes) {
        continue;
      }
      for (const secret of opts.hmacSecrets ?? []) {
        const key = decodeWhsec(secret);
        const expected = crypto.createHmac("sha256", key).update(signed).digest();
        if (
          sigBytes.length === expected.length &&
          crypto.timingSafeEqual(sigBytes, expected)
        ) {
          return { webhookId: msgId, timestamp: ts, algorithm: "v1", payload: body };
        }
      }
    }
  }
  throw new WebhookVerificationError("no matching webhook signature");
}
