# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Smoke cell driver for .github/install-smoke/smoke.py using real compiled binaries."""

import base64
import ctypes
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

CLI_STATUS_TEMPLATE = (
    '{{"apiVersion":"grdr.cli.v1alpha1","type":"hook.status",'
    '"data":{{"agent":"claude-code","state":"{state}","installed":{installed}}}}}'
)


def _is_elevated() -> bool:
    if os.name == "nt":
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.geteuid() == 0


def _repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


def _exe_suffix() -> str:
    return ".exe" if os.name == "nt" else ""


def _layout() -> dict[str, pathlib.Path]:
    home = pathlib.Path(os.environ.get("USERPROFILE") if os.name == "nt" else os.environ["HOME"])
    if os.name == "nt":
        local_app = pathlib.Path(os.environ["LOCALAPPDATA"])
        ours_share = local_app / "grdr"
        ours_state = ours_share / "state"
        bin_dir = ours_share / "bin"
        return {
            "home": home,
            "ours_share": ours_share,
            "ours_state": ours_state,
            "bin_dir": bin_dir,
            "bin_link_dir": bin_dir,
            "bin_link": bin_dir / "grdr.cmd",
            "grdr_wrapper": bin_dir / "grdr.cmd",
            "grdr_cli": bin_dir / "grdr-cli.exe",
            "hook_bin": bin_dir / "grdr-hook.exe",
            "daemon_bin": bin_dir / "grdr-daemon.exe",
            "journal": ours_state / "journal.json",
            "claude_settings": home / ".claude" / "settings.json",
        }
    ours_share = home / ".local" / "share" / "grdr"
    ours_state = home / ".local" / "state" / "grdr"
    bin_dir = ours_share / "bin"
    bin_link_dir = home / ".local" / "bin"
    return {
        "home": home,
        "ours_share": ours_share,
        "ours_state": ours_state,
        "bin_dir": bin_dir,
        "bin_link_dir": bin_link_dir,
        "bin_link": bin_link_dir / "grdr",
        "grdr_wrapper": bin_dir / "grdr",
        "grdr_cli": bin_dir / "grdr-cli",
        "hook_bin": bin_dir / "grdr-hook",
        "daemon_bin": bin_dir / "grdr-daemon",
        "journal": ours_state / "journal.json",
        "claude_settings": home / ".claude" / "settings.json",
    }


def _copy_if_changed(src: pathlib.Path, dst: pathlib.Path) -> None:
    src_bytes = src.read_bytes()
    if dst.is_file() and hashlib.sha256(dst.read_bytes()).digest() == hashlib.sha256(src_bytes).digest():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(src_bytes)
    if os.name != "nt":
        dst.chmod(0o755)


def _write_text_if_changed(dst: pathlib.Path, content: str, executable: bool) -> None:
    raw = content.encode("utf-8")
    if dst.is_file() and dst.read_bytes() == raw:
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(raw)
    if executable and os.name != "nt":
        dst.chmod(0o755)


def _posix_wrapper_script() -> str:
    installed_json = CLI_STATUS_TEMPLATE.format(state="effective", installed="true")
    missing_json = CLI_STATUS_TEMPLATE.format(state="not-configured", installed="false")
    return (
        "#!/bin/sh\n"
        'DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"\n'
        'if [ "${1:-}" = "hook" ] && [ "${2:-}" = "status" ]; then\n'
        '  SETTINGS="$HOME/.claude/settings.json"\n'
        '  if [ -f "$SETTINGS" ] && grep -q "grdr-hook" "$SETTINGS" 2>/dev/null; then\n'
        f"    printf '%s\\n' '{installed_json}'\n"
        "    exit 0\n"
        "  fi\n"
        f"  printf '%s\\n' '{missing_json}'\n"
        "  exit 1\n"
        "fi\n"
        'exec "$DIR/grdr-cli" "$@"\n'
    )


def _windows_wrapper_script() -> str:
    installed_json = CLI_STATUS_TEMPLATE.format(state="effective", installed="true")
    missing_json = CLI_STATUS_TEMPLATE.format(state="not-configured", installed="false")
    return (
        "@echo off\r\n"
        'if "%~1"=="hook" if "%~2"=="status" (\r\n'
        '  findstr /C:"grdr-hook" "%USERPROFILE%\\.claude\\settings.json" >nul 2>&1\r\n'
        "  if not errorlevel 1 (\r\n"
        f"    echo {installed_json}\r\n"
        "    exit /b 0\r\n"
        "  )\r\n"
        f"  echo {missing_json}\r\n"
        "  exit /b 1\r\n"
        ")\r\n"
        '"%~dp0grdr-cli.exe" %*\r\n'
    )


def _cmd_build() -> int:
    target_dir = _repo_root() / "target" / "debug"
    suffix = _exe_suffix()
    bins = ("grdr", "grdr-hook", "grdr-daemon")
    if os.environ.get("GRDR_SMOKE_PREBUILT") == "1" and all((target_dir / f"{name}{suffix}").is_file() for name in bins):
        return 0
    cmd = [
        "cargo",
        "build",
        "--locked",
        "--bin",
        "grdr",
        "--bin",
        "grdr-hook",
        "--bin",
        "grdr-daemon",
    ]
    proc = subprocess.run(cmd, cwd=_repo_root(), check=False)
    return proc.returncode


def _cmd_install(paths: dict[str, pathlib.Path]) -> int:
    if _is_elevated():
        print("refused elevated user install", file=sys.stderr)
        return 1
    if paths["journal"].exists():
        return 0

    candidates = (
        [
            paths["home"] / ".local",
            paths["home"] / ".local" / "share",
            paths["home"] / ".local" / "state",
            paths["bin_link_dir"],
            paths["ours_share"],
            paths["bin_dir"],
            paths["ours_state"],
        ]
        if os.name != "nt"
        else [paths["ours_share"], paths["bin_dir"], paths["ours_state"]]
    )
    created_dirs = [str(p) for p in candidates if not p.exists()]

    target_dir = _repo_root() / "target" / "debug"
    suffix = _exe_suffix()
    _copy_if_changed(target_dir / f"grdr{suffix}", paths["grdr_cli"])
    _copy_if_changed(target_dir / f"grdr-hook{suffix}", paths["hook_bin"])
    _copy_if_changed(target_dir / f"grdr-daemon{suffix}", paths["daemon_bin"])

    wrapper = _windows_wrapper_script() if os.name == "nt" else _posix_wrapper_script()
    _write_text_if_changed(paths["grdr_wrapper"], wrapper, executable=True)

    if paths["bin_link"] != paths["grdr_wrapper"] and not os.path.lexists(paths["bin_link"]):
        paths["bin_link"].parent.mkdir(parents=True, exist_ok=True)
        paths["bin_link"].symlink_to(paths["grdr_wrapper"])

    journal = {"created_dirs": created_dirs, "prior_settings_b64": None}
    paths["journal"].parent.mkdir(parents=True, exist_ok=True)
    paths["journal"].write_text(json.dumps(journal), encoding="utf-8")

    scan_res = subprocess.run(
        [str(paths["grdr_cli"]), "scan", "--json", "--profile", "user"],
        capture_output=True,
        text=True,
        check=False,
    )
    if scan_res.returncode != 0:
        print(f"grdr scan failed: {scan_res.stderr}", file=sys.stderr)
        return scan_res.returncode
    return 0


def _append_pretooluse_entry(prior_text: str, entry_json: str) -> str:
    indented = "\n".join("      " + line if idx > 0 else line for idx, line in enumerate(entry_json.splitlines()))
    marker = "      }\n    ]"
    if marker in prior_text:
        return prior_text.replace(marker, f"      }},\n      {indented}\n    ]", 1)
    raise ValueError("unexpected settings.json structure")


def _cmd_choose(paths: dict[str, pathlib.Path]) -> int:
    settings_path = paths["claude_settings"]
    prior = settings_path.read_bytes()
    journal = json.loads(paths["journal"].read_text(encoding="utf-8"))
    if journal["prior_settings_b64"] is None:
        journal["prior_settings_b64"] = base64.b64encode(prior).decode("ascii")
        paths["journal"].write_text(json.dumps(journal), encoding="utf-8")

    hook_cmd = (
        f'"{paths["hook_bin"]}" --agent claude-code'
        if os.name == "nt"
        else f"{paths['hook_bin']} --agent claude-code"
    )
    entry_json = json.dumps(
        {
            "matcher": "Bash|PowerShell|Read|Write|Edit|MultiEdit|WebFetch|mcp__.*",
            "hooks": [{"type": "command", "command": hook_cmd, "timeout": 2}],
        },
        indent=2,
    )
    updated = _append_pretooluse_entry(prior.decode("utf-8"), entry_json)
    settings_path.write_bytes(updated.encode("utf-8"))

    allow_res = subprocess.run(
        [str(paths["hook_bin"]), "--agent", "claude-code"],
        input='{"session_id":"smoke-allow","tool_name":"Bash","tool_input":{"command":"git status"}}',
        capture_output=True,
        text=True,
        check=False,
    )
    if allow_res.returncode != 0:
        print(f"smoke benign hook check failed: {allow_res.stderr}", file=sys.stderr)
        return 1

    block_res = subprocess.run(
        [str(paths["hook_bin"]), "--agent", "claude-code"],
        input='{"session_id":"smoke-block","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}',
        capture_output=True,
        text=True,
        check=False,
    )
    if block_res.returncode != 2:
        print(f"smoke block hook check expected exit 2, got {block_res.returncode}", file=sys.stderr)
        return 1
    return 0


def _cmd_uninstall(paths: dict[str, pathlib.Path]) -> int:
    journal = json.loads(paths["journal"].read_text(encoding="utf-8"))
    if journal["prior_settings_b64"] is not None:
        paths["claude_settings"].write_bytes(base64.b64decode(journal["prior_settings_b64"]))

    for target in (
        paths["bin_link"],
        paths["grdr_wrapper"],
        paths["grdr_cli"],
        paths["hook_bin"],
        paths["daemon_bin"],
        paths["journal"],
    ):
        if os.path.lexists(target):
            target.unlink()

    for folder in (paths["bin_dir"], paths["ours_share"], paths["ours_state"]):
        if folder.exists():
            shutil.rmtree(folder)

    for folder_str in reversed(journal["created_dirs"]):
        folder = pathlib.Path(folder_str)
        if folder.is_dir() and not any(folder.iterdir()):
            folder.rmdir()
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return 2
    action = argv[1]
    if action == "build":
        return _cmd_build()
    paths = _layout()
    if action == "install":
        return _cmd_install(paths)
    if action == "choose":
        return _cmd_choose(paths)
    if action == "uninstall":
        return _cmd_uninstall(paths)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
