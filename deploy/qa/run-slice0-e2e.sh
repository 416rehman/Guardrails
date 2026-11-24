#!/usr/bin/env bash
set -euo pipefail

SERVER_URL="${GRDR_SERVER_URL:-http://grdr-server:8787}"
DAEMON_BIND="${GRDR_DAEMON_BIND:-127.0.0.1:8788}"
DAEMON_URL="${GRDR_DAEMON_URL:-http://127.0.0.1:8788}"
DEVICE_NAME="${GRDR_DEVICE_NAME:-qa-docker-endpoint}"
SESSION_ID="sess-slice0-e2e"
SETTINGS_SEED="/opt/grdr/qa/claude-settings.json"
CLAUDE_DIR="$HOME/.claude"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
BACKUP_FILE="$CLAUDE_DIR/settings.json.grdr-backup.json"
DATA_DIR="$HOME/.local/share/grdr/daemon"
FLOOR_TABLE="$HOME/.local/share/grdr/floor.json"
FLOOR_KEY="$HOME/.local/share/grdr/floor.pub"
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

echo "[1/7] Checking server health and static Web Console at ${SERVER_URL}"
python3 - "$SERVER_URL" <<'PY'
import json, sys, time, urllib.request

base = sys.argv[1].rstrip("/")
for _ in range(30):
    try:
        with urllib.request.urlopen(f"{base}/api/v1/health", timeout=2) as resp:
            assert resp.status == 200
            health = json.loads(resp.read().decode("utf-8"))
            assert health["status"] == "ok", health
            break
    except Exception:
        time.sleep(1)
else:
    raise SystemExit("server health check timed out")

with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
    assert resp.status == 200
    html = resp.read().decode("utf-8", "replace")
    assert "<div id=\"root\"></div>" in html, "console index.html missing #root"
print(f"server health ok: version={health.get('version')} storage={health.get('storage_mode')}")
PY

echo "[2/7] Seeding Claude Code settings and verifying read-only discovery"
mkdir -p "$CLAUDE_DIR" "$DATA_DIR"
cp "$SETTINGS_SEED" "$SETTINGS_FILE"
ORIG_SHA256="$(sha256sum "$SETTINGS_FILE" | awk '{print $1}')"

SCAN_BEFORE="$(grdr scan --json --profile user)"
python3 - "$SCAN_BEFORE" <<'PY'
import json, sys
report = json.loads(sys.argv[1])
agents = {a["kind"]: a for a in report["agents"]}
assert "claude-code" in agents, report
assert agents["claude-code"]["hook_installed"] is False, agents["claude-code"]
print("discovery before install ok: claude-code found, hook_installed=false")
PY

echo "[3/7] Running grdr install-hook dry-run, apply, and idempotent re-run"
grdr install-hook --agent claude-code --command /usr/local/bin/grdr-hook >/dev/null
DRY_SHA256="$(sha256sum "$SETTINGS_FILE" | awk '{print $1}')"
if [ "$DRY_SHA256" != "$ORIG_SHA256" ]; then
  echo "ERROR: dry-run mutated $SETTINGS_FILE" >&2
  exit 1
fi

grdr install-hook --agent claude-code --command /usr/local/bin/grdr-hook --apply
AFTER_FIRST_SHA256="$(sha256sum "$SETTINGS_FILE" | awk '{print $1}')"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "ERROR: missing backup journal at $BACKUP_FILE" >&2
  exit 1
fi

RERUN_OUT="$(grdr install-hook --agent claude-code --command /usr/local/bin/grdr-hook --apply)"
echo "$RERUN_OUT"
AFTER_RERUN_SHA256="$(sha256sum "$SETTINGS_FILE" | awk '{print $1}')"
if [ "$AFTER_FIRST_SHA256" != "$AFTER_RERUN_SHA256" ]; then
  echo "ERROR: install-hook re-run was not idempotent" >&2
  exit 1
fi

SCAN_AFTER="$(grdr scan --json --profile user)"
python3 - "$SCAN_AFTER" <<'PY'
import json, sys
report = json.loads(sys.argv[1])
agents = {a["kind"]: a for a in report["agents"]}
assert agents["claude-code"]["hook_installed"] is True, agents["claude-code"]
print("discovery after install ok: hook_installed=true")
PY

echo "[4/7] Starting grdr-daemon with uplink to ${SERVER_URL}"
grdr-daemon \
  --bind "$DAEMON_BIND" \
  --server "$SERVER_URL" \
  --profile user \
  --device-name "$DEVICE_NAME" \
  --interval-secs 3 \
  --data-dir "$DATA_DIR" \
  --floor-table "$FLOOR_TABLE" \
  >"$DAEMON_LOG" 2>&1 &
DAEMON_PID="$!"

for _ in $(seq 1 30); do
  if grdr status --daemon "$DAEMON_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
grdr status --daemon "$DAEMON_URL"

echo "[5/7] Exercising grdr-hook (Allow, Block, Ask, and offline fail-safe)"
printf '{"session_id":"%s","tool_name":"Bash","tool_input":{"command":"git status"}}' "$SESSION_ID" \
  | grdr-hook --daemon "$DAEMON_URL" --agent claude-code

set +e
BLOCK_CONTROL_OUT="$(printf '{"session_id":"%s","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' "$SESSION_ID" \
  | grdr-hook --daemon "$DAEMON_URL" --agent claude-code 2>&1)"
BLOCK_CONTROL_RC=$?

BLOCK_BYPASS_OUT="$(printf '{"session_id":"%s","tool_name":"Bash","tool_input":{"command":"git commit --no-verify"}}' "$SESSION_ID" \
  | grdr-hook --daemon "$DAEMON_URL" --agent claude-code 2>&1)"
BLOCK_BYPASS_RC=$?

ASK_DELETE_OUT="$(printf '{"session_id":"%s","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/slice0-e2e-target"}}' "$SESSION_ID" \
  | grdr-hook --daemon "$DAEMON_URL" --agent claude-code 2>&1)"
ASK_DELETE_RC=$?

FAILSAFE_OUT="$(printf '{"session_id":"%s-offline","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' "$SESSION_ID" \
  | grdr-hook --daemon "http://127.0.0.1:19999" --floor-table "$FLOOR_TABLE" --floor-key "$FLOOR_KEY" --agent claude-code 2>&1)"
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

echo "[6/7] Waiting for daemon uplink and verifying embedded server state"
python3 - "$DAEMON_URL" "$SERVER_URL" "$DEVICE_NAME" "$SESSION_ID" <<'PY'
import json, sys, time, urllib.request

daemon_url, server_url, device_name, session_id = [s.rstrip("/") for s in sys.argv[1:5]]

for _ in range(30):
    with urllib.request.urlopen(f"{daemon_url}/local/v1/status", timeout=2) as resp:
        st = json.loads(resp.read().decode("utf-8"))
    uplink = st.get("uplink") or {}
    if uplink.get("state") == "connected" and st.get("pending_events", 1) == 0:
        break
    time.sleep(1)
else:
    raise SystemExit(f"daemon uplink did not flush in time: {st}")

def get_json(path):
    with urllib.request.urlopen(f"{server_url}{path}", timeout=5) as resp:
        assert resp.status == 200, f"{path} -> {resp.status}"
        return json.loads(resp.read().decode("utf-8"))

devices = get_json("/api/v1/devices")
matching = [d for d in devices if d.get("hostname") == device_name]
assert matching and matching[0]["hook_effective"] is True, devices

detail = get_json(f"/api/v1/sessions/{session_id}")
verdicts = {r["target"]: r["verdict"] for r in detail["receipts"]}
assert verdicts.get("git status") == "allow", verdicts
assert verdicts.get(".claude/settings.json") == "deny", verdicts
assert verdicts.get("git commit --no-verify") == "deny", verdicts
assert verdicts.get("rm -rf /tmp/slice0-e2e-target") == "step_up", verdicts

findings = get_json("/api/v1/findings")
assert any(f.get("session_id") == session_id for f in findings), findings

audit = get_json("/api/v1/audit")
assert len(audit) >= 1, audit

with urllib.request.urlopen(f"{server_url}/api/v1/exports/audit.jsonl", timeout=5) as resp:
    assert resp.status == 200
    lines = [ln for ln in resp.read().decode("utf-8").splitlines() if ln.strip()]
    assert len(lines) >= 1

print(f"server ingest ok: device={matching[0]['id']} receipts={len(detail['receipts'])} findings={len(findings)} audit={len(audit)}")
PY

echo "[7/7] Running grdr uninstall-hook and asserting byte-for-byte settings restoration"
grdr uninstall-hook --agent claude-code
RESTORED_SHA256="$(sha256sum "$SETTINGS_FILE" | awk '{print $1}')"
if [ "$RESTORED_SHA256" != "$ORIG_SHA256" ]; then
  echo "ERROR: settings.json was not restored byte-for-byte (orig=$ORIG_SHA256 restored=$RESTORED_SHA256)" >&2
  exit 1
fi
if [ -e "$BACKUP_FILE" ]; then
  echo "ERROR: backup journal still present at $BACKUP_FILE" >&2
  exit 1
fi

echo "SLICE 0 DOCKER E2E PASSED"
