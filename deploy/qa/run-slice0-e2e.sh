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
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/grdr"
BACKUP_FILE="$STATE_DIR/hook-backup-claude-code.json"
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
    assert "<div id=\"root\"></div>" in html, "console index.html missing #root"
storage = health.get("storageMode") or {}
print(f"server health ok: version={health.get('version')} storage={storage.get('kind')}")
PY

echo "[2/7] Seeding Claude Code settings and verifying read-only discovery"
mkdir -p "$CLAUDE_DIR" "$DATA_DIR"
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

echo "[6/7] Waiting for daemon uplink, verifying Connect RPC state, and running grdr audit verify"
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

def rpc_post(method_path, body):
    req = urllib.request.Request(
        f"{server_url}{method_path}",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200, f"{method_path} -> {resp.status}"
        return json.loads(resp.read().decode("utf-8"))

devices_resp = rpc_post("/grdr.api.inventory.v1alpha1.InventoryService/ListDevices", {})
devices = devices_resp.get("devices", [])
matching = [d for d in devices if d.get("hostname") == device_name]
assert matching and matching[0].get("hookEffective") is True, devices

detail = rpc_post("/grdr.api.activity.v1alpha1.SessionService/GetSession", {"id": session_id})
verdicts = {r["target"]: r["verdict"] for r in detail.get("receipts", [])}
assert verdicts.get("git status") == "VERDICT_ALLOW", verdicts
assert verdicts.get(".claude/settings.json") == "VERDICT_DENY", verdicts
assert verdicts.get("git commit --no-verify") == "VERDICT_DENY", verdicts
assert verdicts.get("rm -rf /tmp/slice0-e2e-target") == "VERDICT_STEP_UP", verdicts

findings_resp = rpc_post("/grdr.api.response.v1alpha1.ResponseService/ListFindings", {})
findings = findings_resp.get("findings", [])
assert any(f.get("sessionId") == session_id for f in findings), findings

audit_resp = rpc_post("/grdr.api.response.v1alpha1.ResponseService/ListAuditEvents", {})
audit = audit_resp.get("entries", [])
assert len(audit) >= 1, audit

export_resp = rpc_post("/grdr.api.overview.v1alpha1.OverviewService/ExportAuditJsonl", {})
lines = [ln for ln in export_resp.get("payload", "").splitlines() if ln.strip()]
assert len(lines) >= 1, export_resp

print(f"server ingest ok: device={matching[0]['id']} receipts={len(detail['receipts'])} findings={len(findings)} audit={len(audit)}")
PY

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
