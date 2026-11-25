#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

set -euo pipefail

BIN_DIR=""
WORK_DIR="/tmp/grdr-wsl-e2e"
REPORT_PATH=""
MODE="wsl"
SERVER_PORT=0
DAEMON_PORT=0
SERVER_PID=""
DAEMON_PID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --work-dir) WORK_DIR="$2"; shift 2 ;;
    --report) REPORT_PATH="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --server-port) SERVER_PORT="$2"; shift 2 ;;
    --daemon-port) DAEMON_PORT="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${BIN_DIR}" ]]; then
  echo "Missing required --bin-dir argument." >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required inside the Linux QA environment." >&2
  exit 2
fi

HOME_DIR="${WORK_DIR}-home"
if [[ -z "${REPORT_PATH}" ]]; then
  REPORT_PATH="${WORK_DIR}-report.json"
fi

ASSERTIONS_FILE="$(mktemp)"

cleanup() {
  local rc=$?
  if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
    kill "${DAEMON_PID}" 2>/dev/null || true
    wait "${DAEMON_PID}" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK_DIR}" "${HOME_DIR}" "${ASSERTIONS_FILE}"
  exit "${rc}"
}
trap cleanup EXIT

mkdir -p "${WORK_DIR}/server-data" "${WORK_DIR}/daemon-data" "${HOME_DIR}/.claude" "${HOME_DIR}/.local/state"
export HOME="${HOME_DIR}"
export USERPROFILE="${HOME_DIR}"
export XDG_STATE_HOME="${HOME_DIR}/.local/state"
export PATH="${BIN_DIR}:${PATH}"

for bin in grdr grdr-daemon grdr-hook grdr-server; do
  if [[ ! -x "${BIN_DIR}/${bin}" ]]; then
    echo "Missing executable binary: ${BIN_DIR}/${bin}" >&2
    exit 1
  fi
done

pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

if [[ "${SERVER_PORT}" -eq 0 ]]; then
  SERVER_PORT="$(pick_port)"
fi
if [[ "${DAEMON_PORT}" -eq 0 ]]; then
  DAEMON_PORT="$(pick_port)"
fi

SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
DAEMON_URL="http://127.0.0.1:${DAEMON_PORT}"
START_MS="$(python3 -c 'import time; print(int(time.time()*1000))')"

record_assertion() {
  local name="$1"
  local passed="$2"
  local detail="$3"
  python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[1],"passed":sys.argv[2]=="true","detail":sys.argv[3]}))' \
    "${name}" "${passed}" "${detail}" >> "${ASSERTIONS_FILE}"
}

fail_assertion() {
  local name="$1"
  local detail="$2"
  record_assertion "${name}" "false" "${detail}"
  echo "FAIL [${name}]: ${detail}" >&2
  write_report "failed"
  exit 1
}

write_report() {
  local status="$1"
  mkdir -p "$(dirname "${REPORT_PATH}")"
  python3 - "${ASSERTIONS_FILE}" "${REPORT_PATH}" "${status}" "${MODE}" "${START_MS}" <<'PYEOF'
import json, platform, sys, time
assertions_path, report_path, status, mode, start_ms = sys.argv[1:6]
assertions = []
with open(assertions_path, "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if line:
            assertions.append(json.loads(line))
os_release = {}
try:
    with open("/etc/os-release", "r", encoding="utf-8") as fh:
        for line in fh:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                os_release[k] = v.strip('"')
except OSError:
    pass
report = {
    "schema_version": 1,
    "mode": mode,
    "status": status,
    "os": platform.system().lower(),
    "arch": platform.machine(),
    "distro": os_release.get("PRETTY_NAME", platform.platform()),
    "duration_ms": int(time.time() * 1000) - int(start_ms),
    "passed_count": sum(1 for a in assertions if a["passed"]),
    "failed_count": sum(1 for a in assertions if not a["passed"]),
    "assertions": assertions,
}
with open(report_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")
PYEOF
}

"${BIN_DIR}/grdr-server" --bind "127.0.0.1:${SERVER_PORT}" --data-dir "${WORK_DIR}/server-data" \
  >"${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!

SERVER_READY=0
for _ in $(seq 1 40); do
  if python3 -c "import urllib.request, json, sys; d=json.loads(urllib.request.urlopen('${SERVER_URL}/grdr.api.overview.v1alpha1.OverviewService/GetHealth?encoding=json', timeout=1).read()); sys.exit(0 if d.get('status') in ('SERVER_HEALTH_HEALTHY', 'SERVER_HEALTH_OK') else 1)" 2>/dev/null; then
    SERVER_READY=1
    break
  fi
  sleep 0.25
done
if [[ "${SERVER_READY}" -ne 1 ]]; then
  cat "${WORK_DIR}/server.log" >&2 || true
  fail_assertion "server_health" "grdr-server did not become healthy at ${SERVER_URL}/grdr.api.overview.v1alpha1.OverviewService/GetHealth?encoding=json"
fi
record_assertion "server_health" "true" "grdr-server healthy at ${SERVER_URL}"

CLAUDE_CFG="${HOME_DIR}/.claude/settings.json"
BACKUP_CFG="${HOME_DIR}/.local/state/grdr/hook-backup-claude-code.json"
printf '{"permissions":{"allow":["Read"]},"theme":"dark"}\n' > "${CLAUDE_CFG}"
ORIG_SHA="$(sha256sum "${CLAUDE_CFG}" | awk '{print $1}')"

STATUS_BEFORE_RC=0
STATUS_BEFORE="$("${BIN_DIR}/grdr" hook status --agent claude-code --json)" || STATUS_BEFORE_RC=$?
if [[ "${STATUS_BEFORE_RC}" -eq 1 ]] && python3 -c "import json,sys; d=json.loads(sys.stdin.read()); sys.exit(0 if d.get('data',{}).get('installed') is False and d.get('data',{}).get('state')=='not-configured' else 1)" <<< "${STATUS_BEFORE}"; then
  record_assertion "hook_status_before" "true" "grdr hook status --json reported not-configured (exit 1) before install"
else
  fail_assertion "hook_status_before" "unexpected hook status before install: rc=${STATUS_BEFORE_RC} out=${STATUS_BEFORE}"
fi

SCAN_JSON="$("${BIN_DIR}/grdr" scan --json --profile user)"
if python3 -c "import json,sys; d=json.loads(sys.stdin.read()); sys.exit(0 if any(a.get('kind')=='claude-code' and not a.get('hook_installed') for a in d.get('agents',[])) else 1)" <<< "${SCAN_JSON}"; then
  record_assertion "scan_isolated_agent" "true" "discovered unhooked claude-code in isolated home"
else
  fail_assertion "scan_isolated_agent" "grdr scan did not discover unhooked claude-code: ${SCAN_JSON}"
fi

"${BIN_DIR}/grdr" hook install --agent claude-code --command "${BIN_DIR}/grdr-hook" --apply >/dev/null
INSTALLED_SHA="$(sha256sum "${CLAUDE_CFG}" | awk '{print $1}')"
if [[ -f "${BACKUP_CFG}" ]] && grep -q "grdr-hook" "${CLAUDE_CFG}" && [[ ! -e "${HOME_DIR}/.claude/.grdr-backup.json" ]] && [[ ! -e "${HOME_DIR}/.claude/settings.json.grdr-backup.json" ]]; then
  record_assertion "install_hook_apply" "true" "hook installed with state-dir backup journal and zero leak in ~/.claude"
else
  fail_assertion "install_hook_apply" "hook or state-dir backup journal missing or leaked into ~/.claude after hook install --apply"
fi

RERUN_OUT="$("${BIN_DIR}/grdr" hook install --agent claude-code --command "${BIN_DIR}/grdr-hook" --apply)"
RERUN_SHA="$(sha256sum "${CLAUDE_CFG}" | awk '{print $1}')"
if [[ "${INSTALLED_SHA}" == "${RERUN_SHA}" ]] && grep -qi "already installed" <<< "${RERUN_OUT}"; then
  record_assertion "install_hook_idempotent" "true" "second hook install --apply was a clean no-op"
else
  fail_assertion "install_hook_idempotent" "rerun mutated config or missed already installed message"
fi

STATUS_AFTER="$("${BIN_DIR}/grdr" hook status --agent claude-code --json)"
if python3 -c "import json,sys; d=json.loads(sys.stdin.read()); sys.exit(0 if d.get('apiVersion')=='grdr.cli.v1alpha1' and d.get('type')=='hook.status' and d.get('data',{}).get('installed') is True and d.get('data',{}).get('state')=='effective' else 1)" <<< "${STATUS_AFTER}"; then
  record_assertion "hook_status_after" "true" "grdr hook status --json reported effective (installed=true)"
else
  fail_assertion "hook_status_after" "unexpected hook status after install: ${STATUS_AFTER}"
fi

DEVICE_NAME="qa-${MODE}-linux"
"${BIN_DIR}/grdr-daemon" \
  --bind "127.0.0.1:${DAEMON_PORT}" \
  --server "${SERVER_URL}" \
  --profile user \
  --interval-secs 3 \
  --data-dir "${WORK_DIR}/daemon-data" \
  --floor-table "${WORK_DIR}/floor.json" \
  --device-name "${DEVICE_NAME}" \
  >"${WORK_DIR}/daemon.log" 2>&1 &
DAEMON_PID=$!

DAEMON_READY=0
for _ in $(seq 1 40); do
  if python3 -c "import urllib.request, json, sys; d=json.loads(urllib.request.urlopen('${DAEMON_URL}/local/v1/status', timeout=1).read()); sys.exit(0 if d.get('status')=='running' and (d.get('uplink') or {}).get('state')=='connected' else 1)" 2>/dev/null; then
    DAEMON_READY=1
    break
  fi
  sleep 0.25
done
if [[ "${DAEMON_READY}" -ne 1 ]]; then
  cat "${WORK_DIR}/daemon.log" >&2 || true
  fail_assertion "daemon_health_and_checkin" "grdr-daemon did not reach uplink.state=connected at ${DAEMON_URL}"
fi
"${BIN_DIR}/grdr" status --daemon "${DAEMON_URL}" >/dev/null
if [[ -f "${WORK_DIR}/floor.json" && -f "${WORK_DIR}/floor.pub" ]]; then
  record_assertion "daemon_health_and_checkin" "true" "daemon running, uplink connected to server, and signed floor bundle written"
else
  fail_assertion "daemon_health_and_checkin" "signed floor bundle missing at ${WORK_DIR}/floor.json"
fi

ALLOW_RC=0
"${BIN_DIR}/grdr-hook" --daemon "${DAEMON_URL}" --timeout-ms 2000 --floor-table "${WORK_DIR}/floor.json" --floor-key "${WORK_DIR}/floor.pub" \
  <<< '{"session_id":"sess-qa-e2e","tool_name":"Bash","tool_input":{"command":"git status"}}' \
  >/dev/null 2>&1 || ALLOW_RC=$?
if [[ "${ALLOW_RC}" -eq 0 ]]; then
  record_assertion "hook_benign_allow" "true" "git status returned Allow (exit 0)"
else
  fail_assertion "hook_benign_allow" "expected exit 0 for git status, got ${ALLOW_RC}"
fi

BLOCK_EXEC_ERR=""
BLOCK_EXEC_RC=0
BLOCK_EXEC_ERR="$("${BIN_DIR}/grdr-hook" --daemon "${DAEMON_URL}" --timeout-ms 2000 --floor-table "${WORK_DIR}/floor.json" --floor-key "${WORK_DIR}/floor.pub" \
  <<< '{"session_id":"sess-qa-e2e","tool_name":"Bash","tool_input":{"command":"git commit --no-verify -m test"}}' 2>&1)" || BLOCK_EXEC_RC=$?
if [[ "${BLOCK_EXEC_RC}" -eq 2 ]] && grep -q "BLOCKED" <<< "${BLOCK_EXEC_ERR}" && grep -q "essentials.hook-bypass" <<< "${BLOCK_EXEC_ERR}"; then
  record_assertion "hook_risky_exec_block" "true" "git commit --no-verify blocked deterministically (exit 2, essentials.hook-bypass)"
else
  fail_assertion "hook_risky_exec_block" "expected exit 2 BLOCKED for --no-verify, got rc=${BLOCK_EXEC_RC} err=${BLOCK_EXEC_ERR}"
fi

BLOCK_FILE_ERR=""
BLOCK_FILE_RC=0
BLOCK_FILE_ERR="$("${BIN_DIR}/grdr-hook" --daemon "${DAEMON_URL}" --timeout-ms 2000 --floor-table "${WORK_DIR}/floor.json" --floor-key "${WORK_DIR}/floor.pub" \
  <<< '{"session_id":"sess-qa-e2e","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' 2>&1)" || BLOCK_FILE_RC=$?
if [[ "${BLOCK_FILE_RC}" -eq 2 ]] && grep -q "BLOCKED" <<< "${BLOCK_FILE_ERR}" && grep -q "essentials.agent-control-files" <<< "${BLOCK_FILE_ERR}"; then
  record_assertion "hook_control_file_block" "true" ".claude/settings.json write blocked deterministically (exit 2, essentials.agent-control-files)"
else
  fail_assertion "hook_control_file_block" "expected exit 2 BLOCKED for control file, got rc=${BLOCK_FILE_RC} err=${BLOCK_FILE_ERR}"
fi

FAILSAFE_RC=0
FAILSAFE_ERR=""
FAILSAFE_ERR="$("${BIN_DIR}/grdr-hook" --daemon "http://127.0.0.1:1" --floor-table "${WORK_DIR}/floor.json" --floor-key "${WORK_DIR}/floor.pub" \
  <<< '{"session_id":"sess-qa-e2e","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' 2>&1)" || FAILSAFE_RC=$?
if [[ "${FAILSAFE_RC}" -eq 2 ]] && grep -q "BLOCKED" <<< "${FAILSAFE_ERR}"; then
  record_assertion "hook_offline_failsafe" "true" "offline floor table blocked control-file write without daemon (exit 2)"
else
  fail_assertion "hook_offline_failsafe" "expected exit 2 offline BLOCKED, got rc=${FAILSAFE_RC} err=${FAILSAFE_ERR}"
fi

DOCTOR_JSON="$("${BIN_DIR}/grdr" doctor --json --profile user)"
if python3 -c "import json,sys; d=json.loads(sys.stdin.read()); sys.exit(0 if d.get('discovered_agent_count',0)>=1 and 'worst_severity' in d else 1)" <<< "${DOCTOR_JSON}"; then
  record_assertion "doctor_json" "true" "grdr doctor --json reported discovered_agent_count >= 1"
else
  fail_assertion "doctor_json" "unexpected grdr doctor --json payload: ${DOCTOR_JSON}"
fi

FLUSHED=0
for _ in $(seq 1 60); do
  if python3 -c "import urllib.request, json, sys; d=json.loads(urllib.request.urlopen('${DAEMON_URL}/local/v1/status', timeout=1).read()); sys.exit(0 if d.get('pending_events', 1) == 0 else 1)" 2>/dev/null; then
    FLUSHED=1
    break
  fi
  sleep 0.5
done
if [[ "${FLUSHED}" -ne 1 ]]; then
  cat "${WORK_DIR}/daemon.log" >&2 || true
  cat "${WORK_DIR}/server.log" >&2 || true
  fail_assertion "server_uplink_flush" "daemon pending_events did not drain to 0 within timeout"
fi

if python3 - "${SERVER_URL}" "${DEVICE_NAME}" <<'PYEOF'
import json, sys, urllib.request
server_url, device_name = sys.argv[1:3]

def rpc_post(method_path, body):
    req = urllib.request.Request(
        f"{server_url}{method_path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Connect-Protocol-Version": "1"},
        method="POST",
    )
    return json.loads(urllib.request.urlopen(req, timeout=2).read())

devices = rpc_post("/grdr.api.inventory.v1alpha1.InventoryService/ListDevices", {}).get("devices", [])
matching = [d for d in devices if d.get("hostname") == device_name]
if not matching or not matching[0].get("hookEffective"):
    raise SystemExit(f"device not found or hookEffective is false: {devices}")

session = rpc_post("/grdr.api.activity.v1alpha1.SessionService/GetSession", {"id": "sess-qa-e2e"})
receipts = session.get("receipts", [])
verdicts = [r.get("verdict") for r in receipts]
if verdicts.count("VERDICT_ALLOW") < 1 or verdicts.count("VERDICT_DENY") < 2:
    raise SystemExit(f"unexpected session verdicts: {verdicts}")

audit_resp = rpc_post("/grdr.api.overview.v1alpha1.OverviewService/ExportAuditJsonl", {})
audit_raw = audit_resp.get("payload", "")
audit_lines = [json.loads(line) for line in audit_raw.splitlines() if line.strip()]
receipt_records = [r for r in audit_lines if r.get("record_type") == "decision_receipt"]
if len(receipt_records) < 3:
    raise SystemExit(f"expected >= 3 decision_receipt records in ExportAuditJsonl, got {len(receipt_records)}")
for rec in receipt_records:
    r = rec.get("receipt", {})
    if not r.get("receipt_digest") or not r.get("signature"):
        raise SystemExit("audit.jsonl receipt missing digest or signature")
PYEOF
then
  AUDIT_VERIFY_JSON="$("${BIN_DIR}/grdr" audit verify --json --path "${WORK_DIR}/daemon-data/receipts.wal.jsonl")"
  if python3 -c "import json,sys; d=json.loads(sys.stdin.read()); sys.exit(0 if d.get('verified') is True and d.get('entries',0)>=3 else 1)" <<< "${AUDIT_VERIFY_JSON}"; then
    record_assertion "server_uplink_and_audit_verify" "true" "Connect RPC device/session/ExportAuditJsonl and native grdr audit verify passed"
  else
    fail_assertion "server_uplink_and_audit_verify" "grdr audit verify failed: ${AUDIT_VERIFY_JSON}"
  fi
else
  fail_assertion "server_uplink_and_audit_verify" "Connect RPC state or ExportAuditJsonl verification failed"
fi

"${BIN_DIR}/grdr" hook uninstall --agent claude-code >/dev/null
RESTORED_SHA="$(sha256sum "${CLAUDE_CFG}" | awk '{print $1}')"
if [[ "${ORIG_SHA}" == "${RESTORED_SHA}" && ! -f "${BACKUP_CFG}" ]]; then
  record_assertion "uninstall_byte_restore" "true" "claude settings.json restored byte-for-byte (${ORIG_SHA}) and backup journal removed"
else
  fail_assertion "uninstall_byte_restore" "restore mismatch (orig=${ORIG_SHA}, restored=${RESTORED_SHA})"
fi

write_report "passed"
echo "Linux E2E passed (${MODE}): report written to ${REPORT_PATH}"
