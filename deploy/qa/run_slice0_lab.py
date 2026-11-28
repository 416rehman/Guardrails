# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Cross-platform Slice 0 E2E runner for .github/workflows/lab.yml (linux, macos, windows)."""

import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def _repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


def _exe(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" else name


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(cmd: list[str], *, cwd: pathlib.Path, env: dict[str, str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, env=env, input=input_text, capture_output=True, text=True, check=False)


def _get_json(url: str) -> object:
    with urllib.request.urlopen(url, timeout=5) as resp:
        if resp.status != 200:
            raise RuntimeError(f"GET {url} returned HTTP {resp.status}")
        return json.loads(resp.read().decode("utf-8"))


def _rpc_post(server_url: str, method_path: str, body: dict[str, object]) -> dict[str, object]:
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
        if resp.status != 200:
            raise RuntimeError(f"POST {method_path} returned HTTP {resp.status}")
        parsed = json.loads(resp.read().decode("utf-8"))
        if not isinstance(parsed, dict):
            raise RuntimeError(f"unexpected Connect RPC response for {method_path}")
        return parsed


def _wait_ready(url: str, timeout_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"endpoint not ready in time: {url}")


def _try_build_web(root: pathlib.Path, env: dict[str, str]) -> pathlib.Path | None:
    candidate = root / "web" / "dist"
    if (candidate / "index.html").is_file():
        return candidate
    pnpm = shutil.which("pnpm")
    if not pnpm:
        return None
    pnpm_env = {**env, "CI": "true"}
    for step in (["--dir", "web", "install", "--frozen-lockfile", "--ignore-scripts"], ["--dir", "web", "run", "build"]):
        res = subprocess.run([pnpm, *step], cwd=root, env=pnpm_env, stdin=subprocess.DEVNULL, check=False)
        if res.returncode != 0:
            return None
    return candidate if (candidate / "index.html").is_file() else None


def _is_shared_tmp(path: pathlib.Path) -> bool:
    resolved = str(path.resolve())
    return any(
        resolved == prefix or resolved.startswith(prefix + "/")
        for prefix in ("/tmp", "/var/tmp", "/private/tmp", "/dev/shm")
    )


def _safe_lab_parent() -> str | None:
    if os.name == "nt":
        return None
    xdg = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    if xdg:
        xdg_path = pathlib.Path(xdg)
        if xdg_path.exists() and not xdg_path.is_symlink() and not _is_shared_tmp(xdg_path):
            return str(xdg_path.resolve())
    fallback = pathlib.Path.home() / ".local" / "state" / "grdr-qa"
    for cur in (fallback.parent.parent, fallback.parent, fallback):
        if cur.is_symlink():
            raise RuntimeError(f"refusing symlinked QA directory {cur}")
    fallback.mkdir(parents=True, exist_ok=True, mode=0o700)
    if _is_shared_tmp(fallback):
        raise RuntimeError(f"refusing world-writable temp root for QA endpoints: {fallback}")
    os.chmod(fallback, 0o700)
    return str(fallback)


def _ipc_endpoints(tmp_path: pathlib.Path) -> tuple[str, str, str]:
    pid = os.getpid()
    if os.name == "nt":
        return (
            rf"\\.\pipe\grdr-lab-{pid}-decide",
            rf"\\.\pipe\grdr-lab-{pid}-local",
            rf"\\.\pipe\grdr-lab-{pid}-missing",
        )
    sock_dir = tmp_path / "run"
    sock_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(sock_dir, 0o700)
    return (
        str(sock_dir / "decide.sock"),
        str(sock_dir / "local.sock"),
        str(sock_dir / "missing-decide.sock"),
    )


def _wait_ipc_ready(decide_ep: str, local_ep: str, state_dir: pathlib.Path, timeout_s: float = 20.0) -> None:
    floor_bin = state_dir / "floor.bin"
    floor_pub = state_dir / "floor.pub"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if floor_bin.is_file() and floor_pub.is_file():
            if os.name == "nt":
                pipe_leaf = decide_ep.rsplit("\\", 1)[-1]
                try:
                    if pipe_leaf in os.listdir(r"\\.\pipe"):
                        return
                except OSError:
                    pass
            else:
                if pathlib.Path(decide_ep).exists() and pathlib.Path(local_ep).exists():
                    return
        time.sleep(0.25)
    raise RuntimeError(f"daemon OS IPC endpoints or floor bundle not ready: {decide_ep}")


def _build_binaries(root: pathlib.Path, env: dict[str, str]) -> pathlib.Path | None:
    web_dist = _try_build_web(root, env)

    build_res = subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "--bin",
            "grdr",
            "--bin",
            "grdr-hook",
            "--bin",
            "grdr-daemon",
            "--bin",
            "grdr-engine",
            "--bin",
            "grdr-uplink",
            "--bin",
            "grdr-server",
        ],
        cwd=root,
        env=env,
        check=False,
    )
    if build_res.returncode != 0:
        raise RuntimeError(f"cargo build failed with {build_res.returncode}")
    return web_dist


def main() -> int:
    root = _repo_root()
    base_env = dict(os.environ)
    web_dist = _build_binaries(root, base_env)

    release_dir = root / "target" / "release"
    grdr_bin = str(release_dir / _exe("grdr"))
    hook_bin = str(release_dir / _exe("grdr-hook"))
    daemon_bin = str(release_dir / _exe("grdr-daemon"))
    engine_bin = str(release_dir / _exe("grdr-engine"))
    uplink_bin = str(release_dir / _exe("grdr-uplink"))
    server_bin = str(release_dir / _exe("grdr-server"))

    server_port = _free_port()
    operator_port = _free_port()
    server_url = f"http://127.0.0.1:{server_port}"
    session_id = "sess-lab-slice0"

    with tempfile.TemporaryDirectory(prefix="lab-", dir=_safe_lab_parent()) as tmp:
        tmp_path = pathlib.Path(tmp)
        if os.name != "nt":
            os.chmod(tmp_path, 0o700)
        home_dir = tmp_path / "home"
        claude_dir = home_dir / ".claude"
        claude_dir.mkdir(parents=True, exist_ok=True)
        settings_file = claude_dir / "settings.json"
        seed_bytes = (root / ".github" / "install-smoke" / "fixtures" / "claude-settings.json").read_bytes()
        settings_file.write_bytes(seed_bytes)
        orig_sha = hashlib.sha256(seed_bytes).hexdigest()

        env = dict(base_env)
        env["HOME"] = str(home_dir)
        env["USERPROFILE"] = str(home_dir)
        env["XDG_STATE_HOME"] = str(home_dir / ".local" / "state")
        env["LOCALAPPDATA"] = str(home_dir / "AppData" / "Local")
        env["APPDATA"] = str(home_dir / "AppData" / "Roaming")

        expected_state_dir = (
            (home_dir / "AppData" / "Local" / "grdr" / "state")
            if os.name == "nt"
            else (home_dir / ".local" / "state" / "grdr")
        )
        backup_journal = expected_state_dir / "hook-backup-claude-code.json"

        server_data = tmp_path / "server-data"
        daemon_data = tmp_path / "daemon-data"
        daemon_state = tmp_path / "daemon-state"
        decide_ep, local_ep, missing_ep = _ipc_endpoints(tmp_path)

        server_cmd = [
            server_bin,
            "--bind",
            f"127.0.0.1:{server_port}",
            "--operator-bind",
            f"127.0.0.1:{operator_port}",
            "--profile",
            "embedded",
            "--data-dir",
            str(server_data),
        ]
        if web_dist is not None:
            server_cmd.extend(["--web-dir", str(web_dist)])
        op_dist = root / "web" / "dist-operator"
        if (op_dist / "index.html").is_file():
            server_cmd.extend(["--operator-web-dir", str(op_dist)])

        server_proc = subprocess.Popen(server_cmd, cwd=root, env=env)
        daemon_proc: subprocess.Popen[bytes] | None = None
        try:
            _wait_ready(f"{server_url}/grdr.api.overview.v1alpha1.OverviewService/GetHealth?encoding=json")

            status_before = _run([grdr_bin, "hook", "status", "--agent", "claude-code", "--json"], cwd=root, env=env)
            if status_before.returncode != 1:
                raise RuntimeError(f"expected hook status exit 1 before install, got {status_before.returncode}")

            scan_before = _run([grdr_bin, "scan", "--json", "--profile", "user"], cwd=root, env=env)
            if scan_before.returncode != 0:
                raise RuntimeError(f"grdr scan failed: {scan_before.stderr}")

            inst_first = _run(
                [grdr_bin, "hook", "install", "--agent", "claude-code", "--command", hook_bin, "--apply"],
                cwd=root,
                env=env,
            )
            if inst_first.returncode != 0:
                raise RuntimeError(f"hook install failed: {inst_first.stderr}")
            if not backup_journal.is_file():
                raise RuntimeError(f"missing state-dir backup journal at {backup_journal}")
            if (claude_dir / ".grdr-backup.json").exists() or (claude_dir / "settings.json.grdr-backup.json").exists():
                raise RuntimeError("backup journal leaked into .claude directory")
            sha_first = hashlib.sha256(settings_file.read_bytes()).hexdigest()

            inst_rerun = _run(
                [grdr_bin, "hook", "install", "--agent", "claude-code", "--command", hook_bin, "--apply"],
                cwd=root,
                env=env,
            )
            if inst_rerun.returncode != 0 or hashlib.sha256(settings_file.read_bytes()).hexdigest() != sha_first:
                raise RuntimeError("hook install re-run was not idempotent")

            status_after = _run([grdr_bin, "hook", "status", "--agent", "claude-code", "--json"], cwd=root, env=env)
            if status_after.returncode != 0:
                raise RuntimeError(f"hook status failed after install: {status_after.stderr}")
            status_obj = json.loads(status_after.stdout)
            if status_obj.get("data", {}).get("installed") is not True or status_obj.get("data", {}).get("state") != "effective":
                raise RuntimeError(f"unexpected hook status JSON: {status_obj}")

            daemon_cmd = [
                daemon_bin,
                "--profile",
                "user",
                "--server",
                server_url,
                "--data-dir",
                str(daemon_data),
                "--state-dir",
                str(daemon_state),
                "--decide-endpoint",
                decide_ep,
                "--local-endpoint",
                local_ep,
                "--engine-bin",
                engine_bin,
                "--uplink-bin",
                uplink_bin,
            ]
            daemon_proc = subprocess.Popen(daemon_cmd, cwd=root, env=env)
            _wait_ipc_ready(decide_ep, local_ep, daemon_state)

            allow_res = _run(
                [hook_bin, "--socket", decide_ep, "--state-dir", str(daemon_state), "--agent", "claude-code"],
                cwd=root,
                env=env,
                input_text=json.dumps({"session_id": session_id, "tool_name": "Bash", "tool_input": {"command": "git status"}}),
            )
            if allow_res.returncode != 0:
                raise RuntimeError(f"expected allow exit 0, got {allow_res.returncode}: {allow_res.stderr}")

            block_res = _run(
                [hook_bin, "--socket", decide_ep, "--state-dir", str(daemon_state), "--agent", "claude-code"],
                cwd=root,
                env=env,
                input_text=json.dumps({"session_id": session_id, "tool_name": "Write", "tool_input": {"file_path": ".claude/settings.json"}}),
            )
            if block_res.returncode != 2:
                raise RuntimeError(f"expected block exit 2, got {block_res.returncode}: {block_res.stderr}")

            bypass_res = _run(
                [hook_bin, "--socket", decide_ep, "--state-dir", str(daemon_state), "--agent", "claude-code"],
                cwd=root,
                env=env,
                input_text=json.dumps({"session_id": session_id, "tool_name": "Bash", "tool_input": {"command": "git commit --no-verify"}}),
            )
            if bypass_res.returncode != 2:
                raise RuntimeError(f"expected bypass block exit 2, got {bypass_res.returncode}: {bypass_res.stderr}")

            ask_res = _run(
                [hook_bin, "--socket", decide_ep, "--state-dir", str(daemon_state), "--agent", "claude-code"],
                cwd=root,
                env=env,
                input_text=json.dumps({"session_id": session_id, "tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/slice0-lab"}}),
            )
            if ask_res.returncode != 2:
                raise RuntimeError(f"expected stepup exit 2, got {ask_res.returncode}: {ask_res.stderr}")

            failsafe_res = _run(
                [
                    hook_bin,
                    "--socket",
                    missing_ep,
                    "--state-dir",
                    str(daemon_state),
                    "--agent",
                    "claude-code",
                ],
                cwd=root,
                env=env,
                input_text=json.dumps({"session_id": f"{session_id}-offline", "tool_name": "Write", "tool_input": {"file_path": ".claude/settings.json"}}),
            )
            if failsafe_res.returncode != 2:
                raise RuntimeError(f"expected offline failsafe exit 2, got {failsafe_res.returncode}")

            if not (daemon_state / "audit.checkpoint").is_file():
                raise RuntimeError(f"missing signed audit.checkpoint in {daemon_state}")

            verdicts = {
                "git status": "VERDICT_ALLOW",
                ".claude/settings.json": "VERDICT_DENY",
                "git commit --no-verify": "VERDICT_DENY",
                "rm -rf /tmp/slice0-lab": "VERDICT_STEP_UP",
            }
            audit_res = _run(
                [grdr_bin, "audit", "verify", "--json", "--path", str(daemon_data / "receipts.wal.jsonl")],
                cwd=root,
                env=env,
            )
            if audit_res.returncode != 0:
                raise RuntimeError(f"grdr audit verify failed: {audit_res.stderr}")
            audit_obj = json.loads(audit_res.stdout)
            if audit_obj.get("verified") is not True or audit_obj.get("entries", 0) < 4:
                raise RuntimeError(f"unexpected grdr audit verify result: {audit_obj}")

            uninst = _run([grdr_bin, "hook", "uninstall", "--agent", "claude-code"], cwd=root, env=env)
            if uninst.returncode != 0:
                raise RuntimeError(f"hook uninstall failed: {uninst.stderr}")
            if hashlib.sha256(settings_file.read_bytes()).hexdigest() != orig_sha:
                raise RuntimeError("settings.json was not restored byte-for-byte")
            if backup_journal.exists():
                raise RuntimeError("backup journal still present after uninstall")

            evidence_dir = os.environ.get("GRDR_LAB_EVIDENCE_DIR")
            if evidence_dir:
                out_dir = pathlib.Path(evidence_dir)
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "slice0-summary.json").write_text(
                    json.dumps({"status": "passed", "verdicts": verdicts, "web_console": web_dist is not None}, indent=2) + "\n",
                    encoding="utf-8",
                )
            print(f"SLICE 0 LAB E2E PASSED ({sys.platform}): verdicts={verdicts}")
            return 0
        finally:
            if daemon_proc is not None:
                daemon_proc.terminate()
                daemon_proc.wait(timeout=5)
            server_proc.terminate()
            server_proc.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
