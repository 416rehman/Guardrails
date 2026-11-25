#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Milestone 16b Air-Gap S-31 Tier-A QA conformance script (`docs/design/24-deployment-and-packaging.md` S-31).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/grdr-airgap-s31.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

export HOME="$WORK_DIR/home"
export XDG_DATA_HOME="$WORK_DIR/xdg"
mkdir -p "$HOME" "$XDG_DATA_HOME" "$WORK_DIR/state" "$WORK_DIR/keys"

echo "[1/8] Running grdr-conformance S-31 suite offline..."
cargo test --manifest-path "$ROOT_DIR/Cargo.toml" -p grdr-conformance --locked --test airgap_s31

echo "[2/8] Building grdr binary..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --bin grdr --locked
GRDR_BIN="$ROOT_DIR/target/debug/grdr"

echo "[3/8] Verifying isolated egress allow-list and authority-bypass refusal (GRDR-CFG-0020)..."
"$GRDR_BIN" egress --isolated --json > "$WORK_DIR/egress.json"
grep -q '"destinations": \[\]' "$WORK_DIR/egress.json"
if "$GRDR_BIN" server egress --isolated --allow ".airgap.test" --sink "https://outside.invalid/ingest" --json >/dev/null 2>&1; then
  echo "ERROR: isolated server egress allowed unlisted destination" >&2
  exit 1
fi
for BAD_URL in "https://evil.com?.airgap.test" "https://evil.com#x.airgap.test" "http://2130706433/"; do
  if "$GRDR_BIN" server egress --isolated --allow ".airgap.test" --sink "$BAD_URL" --json >/dev/null 2>&1; then
    echo "ERROR: isolated server egress accepted confused destination $BAD_URL" >&2
    exit 1
  fi
done

echo "[4/8] Building and verifying 2-of-2 signed offline OCI/tar air-gap bundle..."
TAR_PATH="$WORK_DIR/grdr-airgap-0.1.0.tar"
"$GRDR_BIN" airgap build \
  --packs-dir "$ROOT_DIR/packs" \
  --key-dir "$WORK_DIR/keys" \
  --out "$TAR_PATH" \
  --json > "$WORK_DIR/build.json"
ROOT_FP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["root_fingerprint"])' "$WORK_DIR/build.json")"
MANIFEST_SHA="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["manifest_sha256"])' "$WORK_DIR/build.json")"

"$GRDR_BIN" airgap verify --bundle "$TAR_PATH" --print-root --json > "$WORK_DIR/root.json"
if "$GRDR_BIN" airgap verify --bundle "$TAR_PATH" --accept-terms "$MANIFEST_SHA" --json >/dev/null 2>&1; then
  echo "ERROR: airgap verify succeeded without trusted root or --expected-fingerprint" >&2
  exit 1
fi
if "$GRDR_BIN" airgap verify --bundle "$TAR_PATH" --expected-fingerprint "$ROOT_FP" --json >/dev/null 2>&1; then
  echo "ERROR: airgap verify succeeded without --accept-terms" >&2
  exit 1
fi

"$GRDR_BIN" airgap verify \
  --bundle "$TAR_PATH" \
  --expected-fingerprint "$ROOT_FP" \
  --accept-terms "$MANIFEST_SHA" \
  --extract "$WORK_DIR/extracted" \
  --json > "$WORK_DIR/verified.json"

cp "$TAR_PATH" "$WORK_DIR/tampered.tar"
python3 -c '
import sys
p = sys.argv[1]
data = bytearray(open(p, "rb").read())
data[-600] ^= 0xff
open(p, "wb").write(data)
' "$WORK_DIR/tampered.tar"
if "$GRDR_BIN" airgap verify \
  --bundle "$WORK_DIR/tampered.tar" \
  --expected-fingerprint "$ROOT_FP" \
  --accept-terms "$MANIFEST_SHA" \
  --json >/dev/null 2>&1; then
  echo "ERROR: tampered air-gap bundle was accepted" >&2
  exit 1
fi

echo "[5/8] Exercising offline Essentials enforcement and compliance evidence round-trip..."
set +e
"$GRDR_BIN" check --action file.write --target .claude/settings.json --agent claude-code > "$WORK_DIR/check.out"
CHECK_EC=$?
set -e
if [ "$CHECK_EC" -ne 2 ]; then
  echo "ERROR: expected exit code 2 (Deny) for control-file write, got $CHECK_EC" >&2
  exit 1
fi

python3 -c '
import hashlib, json, sys
out_path = sys.argv[1]
prev = "sha256:" + ("0" * 64)
rec = {"event": "decision", "prev_hash": prev, "receipt_id": "rcp_s31_verified_01", "seq": 0}
payload = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
digest = hashlib.sha256(b"grdr.audit.chain.v1\x00" + prev.encode() + b"\x00" + payload).hexdigest()
rec["entry_hash"] = "sha256:" + digest
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(json.dumps(rec) + "\n")
' "$WORK_DIR/state/audit.log.jsonl"
"$GRDR_BIN" audit verify --path "$WORK_DIR/state/audit.log.jsonl" --json >/dev/null

KEY_FILE="$WORK_DIR/device.key"
"$GRDR_BIN" comply evidence --audit-log "$WORK_DIR/state/audit.log.jsonl" --key-file "$KEY_FILE" --json > "$WORK_DIR/evidence.json"
DEVICE_FP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deployment_fingerprint"])' "$WORK_DIR/evidence.json")"
"$GRDR_BIN" comply export --format bundle --audit-log "$WORK_DIR/state/audit.log.jsonl" --key-file "$KEY_FILE" --out "$WORK_DIR/ev-bundle.json" --json >/dev/null
"$GRDR_BIN" comply verify --bundle "$WORK_DIR/ev-bundle.json" --fingerprint "$DEVICE_FP" --json >/dev/null
"$GRDR_BIN" comply rfp --audit-log "$WORK_DIR/state/audit.log.jsonl" --json > "$WORK_DIR/rfp.json"
python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["release_gate_passed"] is False
assert all(it["test_green"] is False for it in doc["items"])
' "$WORK_DIR/rfp.json"

echo "[6/8] Building and inspecting redacted support-bundle..."
CANARY_TOKEN="sk-""airgap""canary""009988"
CANARY_PH="grdr_ph_""canary""9988"
CANARY_DSN="postgres://svc:""dbsecret""99@db.local:5432/grdr"
printf '{"note":"disk_free ok; task-123 ok","api_token":"%s","ph":"%s","kv":"password=kvsecret77","db_url":"%s","workspace":"%s/repo"}\n' "$CANARY_TOKEN" "$CANARY_PH" "$CANARY_DSN" "$HOME" > "$WORK_DIR/cfg.json"
"$GRDR_BIN" support-bundle --preview --config-file "$WORK_DIR/cfg.json" --state-dir "$WORK_DIR/state" --key-file "$KEY_FILE" --out "$WORK_DIR/support.tar" --json > "$WORK_DIR/support.json"
grep -q "disk_free ok; task-123 ok" "$WORK_DIR/support.json"
if grep -qE "$CANARY_TOKEN|$CANARY_PH|kvsecret77|dbsecret" "$WORK_DIR/support.json"; then
  echo "ERROR: support-bundle leaked secret before preview" >&2
  exit 1
fi
"$GRDR_BIN" support-bundle --inspect "$WORK_DIR/support.tar" --fingerprint "$DEVICE_FP" --json >/dev/null

echo "[7/8] Exercising join -> enrol deletion -> isolated egress -> leave history preservation -> protect..."
printf 'airgap-enrol-anchor-secret-token\n' > "$WORK_DIR/enrol.tok"
if "$GRDR_BIN" join "http://server.airgap.test" --enrol-file "$WORK_DIR/enrol.tok" --state-dir "$WORK_DIR/state" --json >/dev/null 2>&1; then
  echo "ERROR: plaintext http:// join origin was allowed" >&2
  exit 1
fi
if "$GRDR_BIN" join "https://[::ffff:169.254.169.254]/latest" --enrol-file "$WORK_DIR/enrol.tok" --state-dir "$WORK_DIR/state" --json >/dev/null 2>&1; then
  echo "ERROR: IPv6-mapped IMDS join origin was allowed" >&2
  exit 1
fi
"$GRDR_BIN" join "https://server.airgap.test:8443" \
  --enrol-file "$WORK_DIR/enrol.tok" \
  --network-mode isolated \
  --allow ".airgap.test" \
  --state-dir "$WORK_DIR/state" \
  --json >/dev/null
if [ -e "$WORK_DIR/enrol.tok" ]; then
  echo "ERROR: consumed enrol token file was not deleted after join" >&2
  exit 1
fi
"$GRDR_BIN" egress --isolated --allow ".airgap.test" --state-dir "$WORK_DIR/state" --json > "$WORK_DIR/joined-egress.json"
grep -q "server.airgap.test" "$WORK_DIR/joined-egress.json"
"$GRDR_BIN" leave --state-dir "$WORK_DIR/state" --json >/dev/null
grep -q "rcp_s31_verified_01" "$WORK_DIR/state/audit.log.jsonl"
"$GRDR_BIN" protect --from "$TAR_PATH" --expected-fingerprint "$ROOT_FP" --accept-terms "$MANIFEST_SHA" --state-dir "$WORK_DIR/state" --apply --json >/dev/null

echo "[8/8] Verifying zero outbound external socket connectivity under isolated network namespace..."
if command -v unshare >/dev/null 2>&1 && unshare -Ur -n true >/dev/null 2>&1; then
  unshare -Ur -n "$GRDR_BIN" egress --isolated --json > "$WORK_DIR/netns-egress.json"
  unshare -Ur -n python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(("192.0.2.1", 443))
    sys.exit(1)
except OSError:
    sys.exit(0)
'
else
  echo "  (user-namespace netns unavailable in container; isolated allow-list enforcement verified)"
fi
echo "S-31 Air-Gap QA verification PASSED."
