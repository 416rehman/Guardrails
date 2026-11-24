# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Smoke cell driver for .github/install-smoke/smoke.py using real compiled binaries."""

import ctypes
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys


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
            "bin_link": bin_dir / "grdr.exe",
            "grdr_bin": bin_dir / "grdr.exe",
            "hook_bin": bin_dir / "grdr-hook.exe",
            "daemon_bin": bin_dir / "grdr-daemon.exe",
            "journal": ours_state / "install-dirs.json",
            "hook_journal": ours_state / "hook-backup-claude-code.json",
            "claude_settings": home / ".claude" / "settings.json",
        }
    ours_share = home / ".local" / "share" / "grdr"
    xdg_state = os.environ.get("XDG_STATE_HOME")
    ours_state = (pathlib.Path(xdg_state) / "grdr") if xdg_state else (home / ".local" / "state" / "grdr")
    bin_dir = ours_share / "bin"
    bin_link_dir = home / ".local" / "bin"
    return {
        "home": home,
        "ours_share": ours_share,
        "ours_state": ours_state,
        "bin_dir": bin_dir,
        "bin_link_dir": bin_link_dir,
        "bin_link": bin_link_dir / "grdr",
        "grdr_bin": bin_dir / "grdr",
        "hook_bin": bin_dir / "grdr-hook",
        "daemon_bin": bin_dir / "grdr-daemon",
        "journal": ours_state / "install-dirs.json",
        "hook_journal": ours_state / "hook-backup-claude-code.json",
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
    _copy_if_changed(target_dir / f"grdr{suffix}", paths["grdr_bin"])
    _copy_if_changed(target_dir / f"grdr-hook{suffix}", paths["hook_bin"])
    _copy_if_changed(target_dir / f"grdr-daemon{suffix}", paths["daemon_bin"])

    if paths["bin_link"] != paths["grdr_bin"] and not os.path.lexists(paths["bin_link"]):
        paths["bin_link"].parent.mkdir(parents=True, exist_ok=True)
        paths["bin_link"].symlink_to(paths["grdr_bin"])

    journal = {"created_dirs": created_dirs}
    paths["journal"].parent.mkdir(parents=True, exist_ok=True)
    paths["journal"].write_text(json.dumps(journal), encoding="utf-8")

    scan_res = subprocess.run(
        [str(paths["grdr_bin"]), "scan", "--json", "--profile", "user"],
        capture_output=True,
        text=True,
        check=False,
    )
    if scan_res.returncode != 0:
        print(f"grdr scan failed: {scan_res.stderr}", file=sys.stderr)
        return scan_res.returncode
    return 0


def _cmd_choose(paths: dict[str, pathlib.Path]) -> int:
    hook_cmd = (
        f'"{paths["hook_bin"]}" --agent claude-code'
        if os.name == "nt"
        else f"{paths['hook_bin']} --agent claude-code"
    )
    install_res = subprocess.run(
        [
            str(paths["grdr_bin"]),
            "hook",
            "install",
            "--agent",
            "claude-code",
            "--command",
            hook_cmd,
            "--apply",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if install_res.returncode != 0:
        print(f"grdr hook install failed: {install_res.stderr}", file=sys.stderr)
        return install_res.returncode

    if not paths["hook_journal"].is_file():
        print(f"expected backup journal at {paths['hook_journal']}", file=sys.stderr)
        return 1

    claude_dir = paths["claude_settings"].parent
    for stray_name in (".grdr-backup.json", "settings.json.grdr-backup.json"):
        if (claude_dir / stray_name).exists():
            print(f"unexpected backup file in ~/.claude: {stray_name}", file=sys.stderr)
            return 1

    status_res = subprocess.run(
        [str(paths["grdr_bin"]), "hook", "status", "--agent", "claude-code", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if status_res.returncode != 0:
        print(f"grdr hook status failed: {status_res.stderr}", file=sys.stderr)
        return 1
    status_payload = json.loads(status_res.stdout)
    if status_payload.get("data", {}).get("installed") is not True:
        print(f"unexpected hook status payload: {status_payload}", file=sys.stderr)
        return 1

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
    if paths["grdr_bin"].is_file():
        uninst_res = subprocess.run(
            [str(paths["grdr_bin"]), "hook", "uninstall", "--agent", "claude-code"],
            capture_output=True,
            text=True,
            check=False,
        )
        if uninst_res.returncode != 0:
            print(f"grdr hook uninstall failed: {uninst_res.stderr}", file=sys.stderr)
            return uninst_res.returncode

    journal = json.loads(paths["journal"].read_text(encoding="utf-8"))
    for target in (
        paths["bin_link"],
        paths["grdr_bin"],
        paths["hook_bin"],
        paths["daemon_bin"],
        paths["journal"],
        paths["hook_journal"],
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
