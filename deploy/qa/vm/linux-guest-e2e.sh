#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

set -euo pipefail

BIN_DIR=""
WORK_DIR=""
REPORT_PATH=""
MODE="wsl"
SERVER_PORT=0
SERVER_PID=""
DAEMON_PID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --work-dir) WORK_DIR="$2"; shift 2 ;;
    --report) REPORT_PATH="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --server-port) SERVER_PORT="$2"; shift 2 ;;
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

is_shared_tmp_path() {
  local raw="$1"
  local resolved
  resolved="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${raw}")"
  case "${resolved}" in
    /tmp|/tmp/*|/var/tmp|/var/tmp/*|/private/tmp|/private/tmp/*|/dev/shm|/dev/shm/*) return 0 ;;
    *) return 1 ;;
  esac
}

ASSERTIONS_FILE=""
umask 077
if [[ -z "${WORK_DIR}" ]]; then
  SAFE_BASE=""
  if [[ -n "${XDG_RUNTIME_DIR:-}" && ! -L "${XDG_RUNTIME_DIR}" ]] && ! is_shared_tmp_path "${XDG_RUNTIME_DIR}"; then
    SAFE_BASE="${XDG_RUNTIME_DIR}"
  else
    SAFE_BASE="${HOME}/.local/state/grdr-qa"
    if [[ -L "${HOME}/.local" || -L "${HOME}/.local/state" || -L "${SAFE_BASE}" ]]; then
      echo "Refusing symlinked QA parent dir: ${SAFE_BASE}" >&2
      exit 1
    fi
    mkdir -p -m 0700 "${SAFE_BASE}"
    chmod 0700 "${SAFE_BASE}"
  fi
  WORK_DIR="$(mktemp -d "${SAFE_BASE}/grdr-linux-e2e.XXXXXX")"
fi
if [[ -L "${WORK_DIR}" ]] || is_shared_tmp_path "${WORK_DIR}"; then
  echo "Refusing symlinked or shared-tmp work dir: ${WORK_DIR}" >&2
  exit 1
fi
HOME_DIR="${WORK_DIR}/home"
if [[ -L "${HOME_DIR}" ]]; then
  echo "Refusing symlinked home dir: ${HOME_DIR}" >&2
  exit 1
fi
if [[ -z "${REPORT_PATH}" ]]; then
  REPORT_PATH="${WORK_DIR}-report.json"
fi

mkdir -p -m 0700 "${WORK_DIR}"
ASSERTIONS_FILE="$(mktemp "${WORK_DIR}/assertions.XXXXXX")"

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

mkdir -p -m 0700 "${WORK_DIR}/server-data" "${WORK_DIR}/daemon-data" "${HOME_DIR}/.claude" "${HOME_DIR}/.local/state" "${WORK_DIR}/run"
chmod 0700 "${WORK_DIR}" "${HOME_DIR}" "${WORK_DIR}/run"
export HOME="${HOME_DIR}"
export USERPROFILE="${HOME_DIR}"
export XDG_STATE_HOME="${HOME_DIR}/.local/state"
export XDG_RUNTIME_DIR="${WORK_DIR}/run"
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

SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
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
  if python3 -c 'import urllib.request, json, sys; d=json.loads(urllib.request.urlopen(sys.argv[1] + "/grdr.api.overview.v1alpha1.OverviewService/GetHealth?encoding=json", timeout=1).read()); sys.exit(0 if d.get("status") in ("SERVER_HEALTH_HEALTHY", "SERVER_HEALTH_OK") else 1)' "${SERVER_URL}" 2>/dev/null; then
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

DAEMON_STATE="${WORK_DIR}/daemon-state"
DECIDE_SOCK="${WORK_DIR}/run/decide.sock"
LOCAL_SOCK="${WORK_DIR}/run/local.sock"
MISSING_SOCK="${WORK_DIR}/run/missing-decide.sock"
FLOOR_BIN="${DAEMON_STATE}/floor.bin"
FLOOR_PUB="${DAEMON_STATE}/floor.pub"
mkdir -p "${DAEMON_STATE}"

DAEMON_ARGS=(
  --profile user
  --server "${SERVER_URL}"
  --data-dir "${WORK_DIR}/daemon-data"
  --state-dir "${DAEMON_STATE}"
  --decide-endpoint "${DECIDE_SOCK}"
  --local-endpoint "${LOCAL_SOCK}"
)
if [[ -x "${BIN_DIR}/grdr-engine" ]]; then
  DAEMON_ARGS+=(--engine-bin "${BIN_DIR}/grdr-engine")
fi
if [[ -x "${BIN_DIR}/grdr-uplink" ]]; then
  DAEMON_ARGS+=(--uplink-bin "${BIN_DIR}/grdr-uplink")
fi
"${BIN_DIR}/grdr-daemon" "${DAEMON_ARGS[@]}" >"${WORK_DIR}/daemon.log" 2>&1 &
DAEMON_PID=$!

DAEMON_READY=0
for _ in $(seq 1 40); do
  if [[ -S "${DECIDE_SOCK}" && -S "${LOCAL_SOCK}" && -f "${FLOOR_BIN}" && -f "${FLOOR_PUB}" ]]; then
    DAEMON_READY=1
    break
  fi
  sleep 0.25
done
if [[ "${DAEMON_READY}" -ne 1 ]]; then
  cat "${WORK_DIR}/daemon.log" >&2 || true
  fail_assertion "daemon_health_and_checkin" "grdr-daemon did not create OS peer IPC sockets or signed floor bundle"
fi
record_assertion "daemon_health_and_checkin" "true" "daemon running with OS peer IPC sockets and signed floor bundle (floor.bin/floor.pub)"

ALLOW_RC=0
"${BIN_DIR}/grdr-hook" --agent claude-code --socket "${DECIDE_SOCK}" --state-dir "${DAEMON_STATE}" \
  <<< '{"session_id":"sess-qa-e2e","tool_name":"Bash","tool_input":{"command":"git status"}}' \
  >/dev/null 2>&1 || ALLOW_RC=$?
if [[ "${ALLOW_RC}" -eq 0 ]]; then
  record_assertion "hook_benign_allow" "true" "git status returned Allow (exit 0)"
else
  fail_assertion "hook_benign_allow" "expected exit 0 for git status, got ${ALLOW_RC}"
fi

BLOCK_EXEC_ERR=""
BLOCK_EXEC_RC=0
BLOCK_EXEC_ERR="$("${BIN_DIR}/grdr-hook" --agent claude-code --socket "${DECIDE_SOCK}" --state-dir "${DAEMON_STATE}" \
  <<< '{"session_id":"sess-qa-e2e","tool_name":"Bash","tool_input":{"command":"git commit --no-verify -m test"}}' 2>&1)" || BLOCK_EXEC_RC=$?
if [[ "${BLOCK_EXEC_RC}" -eq 2 ]] && grep -q "BLOCKED" <<< "${BLOCK_EXEC_ERR}" && grep -q "essentials.hook-bypass" <<< "${BLOCK_EXEC_ERR}"; then
  record_assertion "hook_risky_exec_block" "true" "git commit --no-verify blocked deterministically (exit 2, essentials.hook-bypass)"
else
  fail_assertion "hook_risky_exec_block" "expected exit 2 BLOCKED for --no-verify, got rc=${BLOCK_EXEC_RC} err=${BLOCK_EXEC_ERR}"
fi

BLOCK_FILE_ERR=""
BLOCK_FILE_RC=0
BLOCK_FILE_ERR="$("${BIN_DIR}/grdr-hook" --agent claude-code --socket "${DECIDE_SOCK}" --state-dir "${DAEMON_STATE}" \
  <<< '{"session_id":"sess-qa-e2e","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' 2>&1)" || BLOCK_FILE_RC=$?
if [[ "${BLOCK_FILE_RC}" -eq 2 ]] && grep -q "BLOCKED" <<< "${BLOCK_FILE_ERR}" && grep -q "essentials.agent-control-files" <<< "${BLOCK_FILE_ERR}"; then
  record_assertion "hook_control_file_block" "true" ".claude/settings.json write blocked deterministically (exit 2, essentials.agent-control-files)"
else
  fail_assertion "hook_control_file_block" "expected exit 2 BLOCKED for control file, got rc=${BLOCK_FILE_RC} err=${BLOCK_FILE_ERR}"
fi

FAILSAFE_RC=0
FAILSAFE_ERR=""
FAILSAFE_ERR="$("${BIN_DIR}/grdr-hook" --agent claude-code --socket "${MISSING_SOCK}" --state-dir "${DAEMON_STATE}" \
  <<< '{"session_id":"sess-qa-e2e","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' 2>&1)" || FAILSAFE_RC=$?
if [[ "${FAILSAFE_RC}" -eq 2 ]] && grep -q "BLOCKED" <<< "${FAILSAFE_ERR}"; then
  record_assertion "hook_offline_failsafe" "true" "offline signed floor bundle blocked control-file write without daemon (exit 2)"
else
  fail_assertion "hook_offline_failsafe" "expected exit 2 offline BLOCKED, got rc=${FAILSAFE_RC} err=${FAILSAFE_ERR}"
fi

DOCTOR_JSON="$("${BIN_DIR}/grdr" doctor --json --profile user)"
if python3 -c "import json,sys; d=json.loads(sys.stdin.read()); sys.exit(0 if d.get('discovered_agent_count',0)>=1 and 'worst_severity' in d else 1)" <<< "${DOCTOR_JSON}"; then
  record_assertion "doctor_json" "true" "grdr doctor --json reported discovered_agent_count >= 1"
else
  fail_assertion "doctor_json" "unexpected grdr doctor --json payload: ${DOCTOR_JSON}"
fi

if [[ ! -f "${DAEMON_STATE}/audit.checkpoint" ]]; then
  fail_assertion "server_uplink_and_audit_verify" "missing signed audit.checkpoint in ${DAEMON_STATE}"
fi
AUDIT_VERIFY_JSON="$("${BIN_DIR}/grdr" audit verify --json --path "${WORK_DIR}/daemon-data/receipts.wal.jsonl")"
if python3 -c "import json,sys; d=json.loads(sys.stdin.read()); sys.exit(0 if d.get('verified') is True and d.get('entries',0)>=3 else 1)" <<< "${AUDIT_VERIFY_JSON}"; then
  record_assertion "server_uplink_and_audit_verify" "true" "signed audit.checkpoint and native grdr audit verify passed (${AUDIT_VERIFY_JSON})"
else
  fail_assertion "server_uplink_and_audit_verify" "grdr audit verify failed: ${AUDIT_VERIFY_JSON}"
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
