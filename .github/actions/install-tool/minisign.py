# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Check a minisign signature over a file, in the format minisign documents
(https://jedisct1.github.io/minisign/).

Only the prehashed `ED` algorithm is accepted: Ed25519 over the BLAKE2b-512 digest of the file,
and a global Ed25519 signature over the signature bytes followed by the trusted comment. BLAKE2b
is hashlib's. Ed25519 runs only in `openssl pkeyutl -verify -rawin` of OpenSSL 3 or later; there
is no Ed25519 code here (design/02 SD-07). Every failure raises SignatureRefused.
"""

import base64
import dataclasses
import hashlib
import os
import re
import subprocess
import tempfile

PREHASHED = b"ED"
KEY_ALGORITHM = b"Ed"
KEY_ID_BYTES = 8
ED25519_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
DIGEST_BYTES = 64
KEY_BYTES = len(KEY_ALGORITHM) + KEY_ID_BYTES + ED25519_KEY_BYTES
SIGNATURE_BYTES = len(PREHASHED) + KEY_ID_BYTES + ED25519_SIGNATURE_BYTES
SIGNATURE_FILE_LINES = 4
UNTRUSTED_PREFIX = b"untrusted comment: "
TRUSTED_PREFIX = b"trusted comment: "
FILENAME_FIELD = b"filename:"
TRUSTED_FIELD_SEPARATOR = b"\t"
# The SubjectPublicKeyInfo header of an Ed25519 key (RFC 8410), before the 32 key bytes.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
OPENSSL_VERSION = re.compile(rb"OpenSSL ([0-9]+)\.")
OPENSSL_MAJOR_FLOOR = 3


class SignatureRefused(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class PublicKey:
    key_id: bytes
    key: bytes


@dataclasses.dataclass(frozen=True)
class SignatureFile:
    key_id: bytes
    signature: bytes
    trusted_comment: bytes
    global_signature: bytes


def decode_strict(text, length, what):
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        raise SignatureRefused(f"the {what} is not base64") from None
    if base64.b64encode(raw) != text.encode("ascii"):
        raise SignatureRefused(f"the {what} is not canonical base64")
    if len(raw) != length:
        raise SignatureRefused(f"the {what} is {len(raw)} bytes, not {length}")
    return raw


def read_public_key(text):
    if not text.isascii():
        raise SignatureRefused("the public key is not base64")
    raw = decode_strict(text, KEY_BYTES, "public key")
    if not raw.startswith(KEY_ALGORITHM):
        raise SignatureRefused("the public key is not an Ed25519 minisign key")
    return PublicKey(key_id=raw[len(KEY_ALGORITHM):-ED25519_KEY_BYTES], key=raw[-ED25519_KEY_BYTES:])


def signature_lines(data):
    body = data[:-1] if data.endswith(b"\n") else data
    lines = body.split(b"\n")
    if len(lines) != SIGNATURE_FILE_LINES:
        raise SignatureRefused(f"the signature file has {len(lines)} lines, not {SIGNATURE_FILE_LINES}")
    untrusted, signature, trusted, global_signature = lines
    if not untrusted.startswith(UNTRUSTED_PREFIX) or not trusted.startswith(TRUSTED_PREFIX):
        raise SignatureRefused("the signature file's comment lines are not in minisign's form")
    if not signature.isascii() or not global_signature.isascii():
        raise SignatureRefused("a signature line is not base64")
    return signature.decode("ascii"), trusted[len(TRUSTED_PREFIX):], global_signature.decode("ascii")


def read_signature_file(data):
    signature_text, trusted_comment, global_text = signature_lines(data)
    raw = decode_strict(signature_text, SIGNATURE_BYTES, "signature")
    if not raw.startswith(PREHASHED):
        raise SignatureRefused("the signature is not of the prehashed ED algorithm")
    return SignatureFile(
        key_id=raw[len(PREHASHED):-ED25519_SIGNATURE_BYTES],
        signature=raw[-ED25519_SIGNATURE_BYTES:],
        trusted_comment=trusted_comment,
        global_signature=decode_strict(global_text, ED25519_SIGNATURE_BYTES, "global signature"),
    )


def require_openssl_3(openssl, timeout):
    try:
        result = subprocess.run([*openssl, "version"], capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        raise SignatureRefused(f"OpenSSL {OPENSSL_MAJOR_FLOOR} or later is required and none ran") from None
    found = OPENSSL_VERSION.match(result.stdout)
    if result.returncode != 0 or found is None or int(found[1]) < OPENSSL_MAJOR_FLOOR:
        raise SignatureRefused(f"OpenSSL {OPENSSL_MAJOR_FLOOR} or later is required")


def ed25519_verify(openssl, key, message, signature, timeout):
    pem = base64.encodebytes(ED25519_SPKI_PREFIX + key).decode("ascii")
    with tempfile.TemporaryDirectory() as folder:
        paths = {name: os.path.join(folder, name) for name in ("key.pem", "message", "signature")}
        contents = {
            "key.pem": f"-----BEGIN PUBLIC KEY-----\n{pem}-----END PUBLIC KEY-----\n".encode("ascii"),
            "message": message,
            "signature": signature,
        }
        for name, content in contents.items():
            with open(paths[name], "wb") as file:
                file.write(content)
        command = [*openssl, "pkeyutl", "-verify", "-pubin", "-inkey", paths["key.pem"], "-rawin",
                   "-in", paths["message"], "-sigfile", paths["signature"]]
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError):
            raise SignatureRefused("openssl pkeyutl did not run") from None
    return result.returncode == 0


def signed_filename(trusted_comment):
    fields = trusted_comment.split(TRUSTED_FIELD_SEPARATOR)
    return [field[len(FILENAME_FIELD):] for field in fields if field.startswith(FILENAME_FIELD)]


def verify(key_text, signed, signature_data, filename, openssl, timeout):
    key = read_public_key(key_text)
    signature = read_signature_file(signature_data)
    if signature.key_id != key.key_id:
        raise SignatureRefused("the signature is by another key")
    require_openssl_3(openssl, timeout)
    digest = hashlib.blake2b(signed, digest_size=DIGEST_BYTES).digest()
    if not ed25519_verify(openssl, key.key, digest, signature.signature, timeout):
        raise SignatureRefused("the signature does not verify")
    trusted = signature.signature + signature.trusted_comment
    if not ed25519_verify(openssl, key.key, trusted, signature.global_signature, timeout):
        raise SignatureRefused("the global signature over the trusted comment does not verify")
    if signed_filename(signature.trusted_comment) != [filename.encode("utf-8")]:
        raise SignatureRefused(f"the trusted comment does not name {filename}")
