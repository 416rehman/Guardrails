#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
set -euo pipefail

SERVER_URL="${GRDR_SERVER_URL:-http://grdr-server:8787}"
OPERATOR_URL="${GRDR_OPERATOR_URL:-http://grdr-server:44444}"
SESSION_ID="sess-slice0-e2e"
SETTINGS_SEED="/opt/grdr/qa/claude-settings.json"
CLAUDE_DIR="$HOME/.claude"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/grdr"
BACKUP_FILE="$STATE_DIR/hook-backup-claude-code.json"
DATA_DIR="$HOME/.local/share/grdr/daemon"
DAEMON_STATE_DIR="${STATE_DIR}/daemon-state"
RUN_DIR="${XDG_RUNTIME_DIR:-${STATE_DIR}/run}"
FLOOR_BIN="${DAEMON_STATE_DIR}/floor.bin"
FLOOR_PUB="${DAEMON_STATE_DIR}/floor.pub"
DECIDE_SOCK="${GRDR_DECIDE_ENDPOINT:-${RUN_DIR}/decide.sock}"
LOCAL_SOCK="${GRDR_LOCAL_ENDPOINT:-${RUN_DIR}/local.sock}"
MISSING_SOCK="${RUN_DIR}/missing-decide.sock"
DAEMON_LOG="$HOME/grdr-daemon.log"
DAEMON_PID=""

cleanup() {
  if [ -n "${DAEMON_PID}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
    kill "${DAEMON_PID}" 2>/dev/null || true
    wait "${DAEMON_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [ "$(id -u)" -eq 0 ]; then
  echo "ERROR: endpoint-runner must run as a non-root user" >&2
  exit 1
fi

echo "[1/7] Checking server health, Web Console, and Operator UI at ${SERVER_URL} / ${OPERATOR_URL}"
python3 - "$SERVER_URL" "$OPERATOR_URL" <<'PY'
import json, sys, time, urllib.request

base, op_base = [s.rstrip("/") for s in sys.argv[1:3]]
for _ in range(30):
    try:
        with urllib.request.urlopen(
            f"{base}/grdr.api.overview.v1alpha1.OverviewService/GetHealth?encoding=json",
            timeout=2,
        ) as resp:
            assert resp.status == 200
            health = json.loads(resp.read().decode("utf-8"))
            assert health.get("status") in ("SERVER_HEALTH_HEALTHY", "SERVER_HEALTH_OK"), health
            break
    except Exception:
        time.sleep(1)
else:
    raise SystemExit("server health check timed out")

with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
    assert resp.status == 200
    html = resp.read().decode("utf-8", "replace")
    assert '<div id="root"></div>' in html, "console index.html missing #root"

with urllib.request.urlopen(f"{op_base}/", timeout=5) as resp:
    assert resp.status == 200
    op_html = resp.read().decode("utf-8", "replace")
    assert '<div id="root"></div>' in op_html, "operator index.html missing #root"
storage = health.get("storageMode") or {}
print(f"server health ok: version={health.get('version')} storage={storage.get('kind')}")
PY

echo "[2/7] Seeding Claude Code settings and verifying read-only discovery"
umask 077
mkdir -p -m 0700 "$CLAUDE_DIR" "$DATA_DIR" "$DAEMON_STATE_DIR" "$RUN_DIR"
chmod 0700 "$RUN_DIR" "$DAEMON_STATE_DIR"
cp "$SETTINGS_SEED" "$SETTINGS_FILE"
ORIG_SHA256="$(sha256sum "$SETTINGS_FILE" | awk '{print $1}')"

set +e
STATUS_BEFORE="$(grdr hook status --agent claude-code --json)"
STATUS_BEFORE_RC=$?
set -e
if [ "$STATUS_BEFORE_RC" -ne 1 ]; then
  echo "ERROR: expected hook status exit 1 before install, got $STATUS_BEFORE_RC" >&2
  exit 1
fi
python3 - "$STATUS_BEFORE" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
assert payload["apiVersion"] == "grdr.cli.v1alpha1", payload
assert payload["type"] == "hook.status", payload
assert payload["data"]["agent"] == "claude-code", payload
assert payload["data"]["state"] == "not-configured", payload
assert payload["data"]["installed"] is False, payload
print("hook status before install ok: state=not-configured installed=false")
PY

SCAN_BEFORE="$(grdr scan --json --profile user)"
python3 - "$SCAN_BEFORE" <<'PY'
import json, sys
report = json.loads(sys.argv[1])
agents = {a["kind"]: a for a in report["agents"]}
assert "claude-code" in agents, report
assert agents["claude-code"]["hook_installed"] is False, agents["claude-code"]
print("discovery before install ok: claude-code found, hook_installed=false")
PY

echo "[3/7] Running grdr hook install dry-run, apply, status, and idempotent re-run"
grdr hook install --agent claude-code --command /usr/local/bin/grdr-hook >/dev/null
DRY_SHA256="$(sha256sum "$SETTINGS_FILE" | awk '{print $1}')"
if [ "$DRY_SHA256" != "$ORIG_SHA256" ]; then
  echo "ERROR: dry-run mutated $SETTINGS_FILE" >&2
  exit 1
fi

grdr hook install --agent claude-code --command /usr/local/bin/grdr-hook --apply
AFTER_FIRST_SHA256="$(sha256sum "$SETTINGS_FILE" | awk '{print $1}')"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "ERROR: missing backup journal at $BACKUP_FILE" >&2
  exit 1
fi
if [ -e "$CLAUDE_DIR/.grdr-backup.json" ] || [ -e "$CLAUDE_DIR/settings.json.grdr-backup.json" ]; then
  echo "ERROR: backup journal leaked into $CLAUDE_DIR" >&2
  exit 1
fi

RERUN_OUT="$(grdr hook install --agent claude-code --command /usr/local/bin/grdr-hook --apply)"
echo "$RERUN_OUT"
AFTER_RERUN_SHA256="$(sha256sum "$SETTINGS_FILE" | awk '{print $1}')"
if [ "$AFTER_FIRST_SHA256" != "$AFTER_RERUN_SHA256" ]; then
  echo "ERROR: hook install re-run was not idempotent" >&2
  exit 1
fi

STATUS_AFTER="$(grdr hook status --agent claude-code --json)"
python3 - "$STATUS_AFTER" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
assert payload["apiVersion"] == "grdr.cli.v1alpha1", payload
assert payload["type"] == "hook.status", payload
assert payload["data"]["agent"] == "claude-code", payload
assert payload["data"]["state"] == "effective", payload
assert payload["data"]["installed"] is True, payload
print("hook status after install ok: state=effective installed=true")
PY

SCAN_AFTER="$(grdr scan --json --profile user)"
python3 - "$SCAN_AFTER" <<'PY'
import json, sys
report = json.loads(sys.argv[1])
agents = {a["kind"]: a for a in report["agents"]}
assert agents["claude-code"]["hook_installed"] is True, agents["claude-code"]
print("discovery after install ok: hook_installed=true")
PY

echo "[4/7] Starting grdr-daemon with OS peer IPC endpoints (${DECIDE_SOCK})"
DAEMON_ARGS=(
  --profile user
  --server "$SERVER_URL"
  --data-dir "$DATA_DIR"
  --state-dir "$DAEMON_STATE_DIR"
  --decide-endpoint "$DECIDE_SOCK"
  --local-endpoint "$LOCAL_SOCK"
)
if [ -x /usr/libexec/grdr/grdr-engine ]; then
  DAEMON_ARGS+=(--engine-bin /usr/libexec/grdr/grdr-engine)
fi
if [ -x /usr/local/bin/grdr-uplink ]; then
  DAEMON_ARGS+=(--uplink-bin /usr/local/bin/grdr-uplink)
fi
grdr-daemon "${DAEMON_ARGS[@]}" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID="$!"

for _ in $(seq 1 40); do
  if [ -S "$DECIDE_SOCK" ] && [ -S "$LOCAL_SOCK" ] && [ -f "$FLOOR_BIN" ] && [ -f "$FLOOR_PUB" ]; then
    break
  fi
  sleep 0.25
done
if [ ! -S "$DECIDE_SOCK" ] || [ ! -S "$LOCAL_SOCK" ] || [ ! -f "$FLOOR_BIN" ] || [ ! -f "$FLOOR_PUB" ]; then
  cat "$DAEMON_LOG" >&2 || true
  echo "ERROR: grdr-daemon IPC sockets or signed floor cache did not initialize" >&2
  exit 1
fi

echo "[5/7] Exercising grdr-hook over OS peer IPC (Allow, Block, Ask, and offline floor fail-safe)"
printf '{"session_id":"%s","tool_name":"Bash","tool_input":{"command":"git status"}}' "$SESSION_ID" \
  | grdr-hook --socket "$DECIDE_SOCK" --state-dir "$DAEMON_STATE_DIR" --agent claude-code

set +e
BLOCK_CONTROL_OUT="$(printf '{"session_id":"%s","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' "$SESSION_ID" \
  | grdr-hook --socket "$DECIDE_SOCK" --state-dir "$DAEMON_STATE_DIR" --agent claude-code 2>&1)"
BLOCK_CONTROL_RC=$?

BLOCK_BYPASS_OUT="$(printf '{"session_id":"%s","tool_name":"Bash","tool_input":{"command":"git commit --no-verify"}}' "$SESSION_ID" \
  | grdr-hook --socket "$DECIDE_SOCK" --state-dir "$DAEMON_STATE_DIR" --agent claude-code 2>&1)"
BLOCK_BYPASS_RC=$?

ASK_DELETE_OUT="$(printf '{"session_id":"%s","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/slice0-e2e-target"}}' "$SESSION_ID" \
  | grdr-hook --socket "$DECIDE_SOCK" --state-dir "$DAEMON_STATE_DIR" --agent claude-code 2>&1)"
ASK_DELETE_RC=$?

FAILSAFE_OUT="$(printf '{"session_id":"%s-offline","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' "$SESSION_ID" \
  | grdr-hook --socket "$MISSING_SOCK" --state-dir "$DAEMON_STATE_DIR" --agent claude-code 2>&1)"
FAILSAFE_RC=$?
set -e

if [ "$BLOCK_CONTROL_RC" -ne 2 ]; then
  echo "ERROR: expected exit 2 for control-file write, got $BLOCK_CONTROL_RC: $BLOCK_CONTROL_OUT" >&2
  exit 1
fi
if [ "$BLOCK_BYPASS_RC" -ne 2 ]; then
  echo "ERROR: expected exit 2 for --no-verify, got $BLOCK_BYPASS_RC: $BLOCK_BYPASS_OUT" >&2
  exit 1
fi
if [ "$ASK_DELETE_RC" -ne 2 ]; then
  echo "ERROR: expected exit 2 for rm -rf, got $ASK_DELETE_RC: $ASK_DELETE_OUT" >&2
  exit 1
fi
if [ "$FAILSAFE_RC" -ne 2 ]; then
  echo "ERROR: expected exit 2 for offline failsafe, got $FAILSAFE_RC: $FAILSAFE_OUT" >&2
  exit 1
fi
echo "hook verdicts ok: control-file=$BLOCK_CONTROL_RC bypass=$BLOCK_BYPASS_RC rm-rf=$ASK_DELETE_RC offline-failsafe=$FAILSAFE_RC"

echo "[6/7] Verifying signed audit checkpoint and hash-chained WAL via grdr audit verify"
if [ ! -f "${DAEMON_STATE_DIR}/audit.checkpoint" ]; then
  echo "ERROR: missing signed audit.checkpoint in ${DAEMON_STATE_DIR}" >&2
  exit 1
fi
AUDIT_VERIFY_OUT="$(grdr audit verify --json --path "$DATA_DIR/receipts.wal.jsonl")"
python3 - "$AUDIT_VERIFY_OUT" <<'PY'
import json, sys
res = json.loads(sys.argv[1])
assert res.get("verified") is True, res
assert res.get("entries", 0) >= 4, res
print(f"grdr audit verify ok: entries={res['entries']} format={res.get('format')}")
PY

echo "[7/7] Running grdr hook uninstall and asserting byte-for-byte settings restoration"
grdr hook uninstall --agent claude-code
RESTORED_SHA256="$(sha256sum "$SETTINGS_FILE" | awk '{print $1}')"
if [ "$RESTORED_SHA256" != "$ORIG_SHA256" ]; then
  echo "ERROR: settings.json was not restored byte-for-byte (orig=$ORIG_SHA256 restored=$RESTORED_SHA256)" >&2
  exit 1
fi
if [ -e "$BACKUP_FILE" ]; then
  echo "ERROR: backup journal still present at $BACKUP_FILE" >&2
  exit 1
fi

set +e
grdr hook status --agent claude-code --json >/dev/null
STATUS_AFTER_UNINST=$?
set -e
if [ "$STATUS_AFTER_UNINST" -ne 1 ]; then
  echo "ERROR: expected hook status exit 1 after uninstall, got $STATUS_AFTER_UNINST" >&2
  exit 1
fi

echo "SLICE 0 DOCKER E2E PASSED"
