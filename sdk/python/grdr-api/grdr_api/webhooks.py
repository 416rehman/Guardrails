# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Standard Webhooks 1.0.0 verification for HMAC-SHA256 (v1) and Ed25519 (v1a)."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import time


class WebhookVerificationError(ValueError):
    """Raised when webhook signature, header format, or timestamp tolerance fails."""


@dataclass(frozen=True)
class VerifiedWebhook:
    webhook_id: str
    timestamp: int
    algorithm: str
    payload: bytes


_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_Q = 2**252 + 27742317777372353535851937790883648493


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify RFC 8032 Ed25519 signature using cryptography if available or pure stdlib fallback."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        from cryptography.exceptions import InvalidSignature  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore[import-not-found]
            Ed25519PublicKey,
        )

        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except InvalidSignature:
            return False
    except ImportError:
        return _ed25519_verify_pure(public_key, message, signature)


def _edwards_add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _edwards_double(p1: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    return _edwards_add(p1, p1)


def _edwards_cswap(
    bit: int,
    p0: tuple[int, int, int, int],
    p1: tuple[int, int, int, int],
) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int]]:
    mask = -bit
    a0, b0, c0, d0 = p0
    a1, b1, c1, d1 = p1
    da = mask & (a0 ^ a1)
    db = mask & (b0 ^ b1)
    dc = mask & (c0 ^ c1)
    dd = mask & (d0 ^ d1)
    return (a0 ^ da, b0 ^ db, c0 ^ dc, d0 ^ dd), (a1 ^ da, b1 ^ db, c1 ^ dc, d1 ^ dd)


def _edwards_scalar_mul(pt: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    r0 = (0, 1, 1, 0)
    r1 = pt
    for shift in range(255, -1, -1):
        bit = (scalar >> shift) & 1
        r0, r1 = _edwards_cswap(bit, r0, r1)
        r1 = _edwards_add(r0, r1)
        r0 = _edwards_double(r0)
        r0, r1 = _edwards_cswap(bit, r0, r1)
    return r0


def _point_decompress(buf: bytes) -> tuple[int, int, int, int] | None:
    y = int.from_bytes(buf, "little") & ((1 << 255) - 1)
    sign = (buf[31] >> 7) & 1
    if y >= _P:
        return None
    y2 = (y * y) % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    x = (u * pow(v, 3, _P) * pow((u * pow(v, 7, _P)) % _P, (_P - 5) // 8, _P)) % _P
    if (v * x * x) % _P != u:
        x = (x * pow(2, (_P - 1) // 4, _P)) % _P
    if (v * x * x) % _P != u:
        return None
    if (x & 1) != sign:
        if x == 0 and sign == 1:
            return None
        x = (_P - x) % _P
    return (x, y, 1, (x * y) % _P)


def _point_equal(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _cofactor_mul(pt: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    return _edwards_double(_edwards_double(_edwards_double(pt)))


def _ed25519_verify_pure(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_pt = _point_decompress(public_key)
    r_bytes = signature[:32]
    r_pt = _point_decompress(r_bytes)
    s = int.from_bytes(signature[32:], "little")
    if a_pt is None or r_pt is None or s < 0 or s >= _Q:
        return False
    gy = (4 * pow(5, _P - 2, _P)) % _P
    gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
    base_pt = (gx, gy, 1, (gx * gy) % _P)
    h = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _Q
    lhs = _cofactor_mul(_edwards_scalar_mul(base_pt, s))
    rhs = _cofactor_mul(_edwards_add(r_pt, _edwards_scalar_mul(a_pt, h)))
    return _point_equal(lhs, rhs)


def decode_whsec(secret: str) -> bytes:
    raw = secret[6:] if secret.startswith("whsec_") else secret
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise WebhookVerificationError(f"invalid webhook secret encoding: {exc}") from exc


def sign_v1_hmac(webhook_id: str, timestamp: int, payload: bytes, secret: str) -> str:
    key = decode_whsec(secret)
    signed = f"{webhook_id}.{timestamp}.".encode("utf-8") + payload
    digest = hmac.new(key, signed, hashlib.sha256).digest()
    return "v1," + base64.b64encode(digest).decode("ascii")


def verify_webhook(
    *,
    headers: dict[str, str],
    payload: bytes,
    hmac_secrets: list[str] | None = None,
    ed25519_public_keys: list[bytes] | None = None,
    tolerance_seconds: int = 300,
    now_seconds: int | None = None,
) -> VerifiedWebhook:
    lowered = {k.lower(): v for k, v in headers.items()}
    msg_id = lowered.get("webhook-id", "").strip()
    ts_raw = lowered.get("webhook-timestamp", "").strip()
    sig_header = lowered.get("webhook-signature", "").strip()
    if not msg_id or not ts_raw or not sig_header:
        raise WebhookVerificationError("missing Standard Webhooks headers")
    try:
        ts = int(ts_raw)
    except ValueError as exc:
        raise WebhookVerificationError("invalid webhook-timestamp") from exc

    if tolerance_seconds < 0:
        raise WebhookVerificationError("tolerance_seconds must be non-negative")
    now = int(time.time()) if now_seconds is None else now_seconds
    if abs(now - ts) > tolerance_seconds:
        raise WebhookVerificationError("webhook timestamp outside tolerance window")

    signed = f"{msg_id}.{ts}.".encode("utf-8") + payload
    for entry in sig_header.split():
        if entry.startswith("v1a,"):
            try:
                sig_bytes = base64.b64decode(entry[4:], validate=True)
            except (ValueError, binascii.Error):
                continue
            for pub in ed25519_public_keys or []:
                if _ed25519_verify(pub, signed, sig_bytes):
                    return VerifiedWebhook(msg_id, ts, "v1a", payload)
        elif entry.startswith("v1,"):
            try:
                sig_bytes = base64.b64decode(entry[3:], validate=True)
            except (ValueError, binascii.Error):
                continue
            for secret in hmac_secrets or []:
                key = decode_whsec(secret)
                expected = hmac.new(key, signed, hashlib.sha256).digest()
                if hmac.compare_digest(expected, sig_bytes):
                    return VerifiedWebhook(msg_id, ts, "v1", payload)

    raise WebhookVerificationError("no matching webhook signature")
