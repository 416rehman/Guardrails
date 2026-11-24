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
    for step in (["--dir", "web", "install", "--frozen-lockfile"], ["--dir", "web", "run", "build"]):
        res = subprocess.run([pnpm, *step], cwd=root, env=pnpm_env, stdin=subprocess.DEVNULL, check=False)
        if res.returncode != 0:
            return None
    return candidate if (candidate / "index.html").is_file() else None


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
    server_bin = str(release_dir / _exe("grdr-server"))

    server_port = _free_port()
    daemon_port = _free_port()
    server_url = f"http://127.0.0.1:{server_port}"
    daemon_url = f"http://127.0.0.1:{daemon_port}"
    session_id = "sess-lab-slice0"
    device_name = f"lab-{sys.platform}"

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
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
        env["LOCALAPPDATA"] = str(home_dir / "AppData" / "Local")
        env["APPDATA"] = str(home_dir / "AppData" / "Roaming")

        server_data = tmp_path / "server-data"
        daemon_data = tmp_path / "daemon-data"
        floor_table = tmp_path / "floor.json"
        floor_key = tmp_path / "floor.pub"

        server_cmd = [
            server_bin,
            "--bind",
            f"127.0.0.1:{server_port}",
            "--profile",
            "embedded",
            "--data-dir",
            str(server_data),
        ]
        if web_dist is not None:
            server_cmd.extend(["--web-dir", str(web_dist)])

        server_proc = subprocess.Popen(server_cmd, cwd=root, env=env)
        daemon_proc: subprocess.Popen[bytes] | None = None
        try:
            _wait_ready(f"{server_url}/api/v1/health")

            scan_before = _run([grdr_bin, "scan", "--json", "--profile", "user"], cwd=root, env=env)
            if scan_before.returncode != 0:
                raise RuntimeError(f"grdr scan failed: {scan_before.stderr}")

            inst_first = _run(
                [grdr_bin, "install-hook", "--agent", "claude-code", "--command", hook_bin, "--apply"],
                cwd=root,
                env=env,
            )
            if inst_first.returncode != 0:
                raise RuntimeError(f"install-hook failed: {inst_first.stderr}")
            sha_first = hashlib.sha256(settings_file.read_bytes()).hexdigest()

            inst_rerun = _run(
                [grdr_bin, "install-hook", "--agent", "claude-code", "--command", hook_bin, "--apply"],
                cwd=root,
                env=env,
            )
            if inst_rerun.returncode != 0 or hashlib.sha256(settings_file.read_bytes()).hexdigest() != sha_first:
                raise RuntimeError("install-hook re-run was not idempotent")

            daemon_proc = subprocess.Popen(
                [
                    daemon_bin,
                    "--bind",
                    f"127.0.0.1:{daemon_port}",
                    "--server",
                    server_url,
                    "--profile",
                    "user",
                    "--device-name",
                    device_name,
                    "--interval-secs",
                    "3",
                    "--data-dir",
                    str(daemon_data),
                    "--floor-table",
                    str(floor_table),
                ],
                cwd=root,
                env=env,
            )
            _wait_ready(f"{daemon_url}/local/v1/status")

            allow_res = _run(
                [hook_bin, "--daemon", daemon_url, "--agent", "claude-code"],
                cwd=root,
                env=env,
                input_text=json.dumps({"session_id": session_id, "tool_name": "Bash", "tool_input": {"command": "git status"}}),
            )
            if allow_res.returncode != 0:
                raise RuntimeError(f"expected allow exit 0, got {allow_res.returncode}: {allow_res.stderr}")

            block_res = _run(
                [hook_bin, "--daemon", daemon_url, "--agent", "claude-code"],
                cwd=root,
                env=env,
                input_text=json.dumps({"session_id": session_id, "tool_name": "Write", "tool_input": {"file_path": ".claude/settings.json"}}),
            )
            if block_res.returncode != 2:
                raise RuntimeError(f"expected block exit 2, got {block_res.returncode}: {block_res.stderr}")

            bypass_res = _run(
                [hook_bin, "--daemon", daemon_url, "--agent", "claude-code"],
                cwd=root,
                env=env,
                input_text=json.dumps({"session_id": session_id, "tool_name": "Bash", "tool_input": {"command": "git commit --no-verify"}}),
            )
            if bypass_res.returncode != 2:
                raise RuntimeError(f"expected bypass block exit 2, got {bypass_res.returncode}: {bypass_res.stderr}")

            ask_res = _run(
                [hook_bin, "--daemon", daemon_url, "--agent", "claude-code"],
                cwd=root,
                env=env,
                input_text=json.dumps({"session_id": session_id, "tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/slice0-lab"}}),
            )
            if ask_res.returncode != 2:
                raise RuntimeError(f"expected stepup exit 2, got {ask_res.returncode}: {ask_res.stderr}")

            failsafe_res = _run(
                [
                    hook_bin,
                    "--daemon",
                    "http://127.0.0.1:19999",
                    "--floor-table",
                    str(floor_table),
                    "--floor-key",
                    str(floor_key),
                    "--agent",
                    "claude-code",
                ],
                cwd=root,
                env=env,
                input_text=json.dumps({"session_id": f"{session_id}-offline", "tool_name": "Write", "tool_input": {"file_path": ".claude/settings.json"}}),
            )
            if failsafe_res.returncode != 2:
                raise RuntimeError(f"expected offline failsafe exit 2, got {failsafe_res.returncode}")

            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                st = _get_json(f"{daemon_url}/local/v1/status")
                uplink = st.get("uplink") if isinstance(st, dict) else None
                if (
                    isinstance(uplink, dict)
                    and uplink.get("state") == "connected"
                    and st.get("pending_events") == 0
                ):
                    break
                time.sleep(1)
            else:
                raise RuntimeError("daemon uplink did not flush pending events in time")

            detail = _get_json(f"{server_url}/api/v1/sessions/{session_id}")
            if not isinstance(detail, dict):
                raise RuntimeError("unexpected session detail response")
            verdicts = {r["target"]: r["verdict"] for r in detail["receipts"]}
            if (
                verdicts.get("git status") != "allow"
                or verdicts.get(".claude/settings.json") != "deny"
                or verdicts.get("git commit --no-verify") != "deny"
                or verdicts.get("rm -rf /tmp/slice0-lab") != "step_up"
            ):
                raise RuntimeError(f"unexpected session verdicts: {verdicts}")

            uninst = _run([grdr_bin, "uninstall-hook", "--agent", "claude-code"], cwd=root, env=env)
            if uninst.returncode != 0:
                raise RuntimeError(f"uninstall-hook failed: {uninst.stderr}")
            if hashlib.sha256(settings_file.read_bytes()).hexdigest() != orig_sha:
                raise RuntimeError("settings.json was not restored byte-for-byte")

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
