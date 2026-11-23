# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Seeded fixture cell script for oracle-self-test (R5 of #1650).

Contains zero token-shaped strings. Supports clean, writes-outside-ours,
leaves-file-behind, and mutates-vendor-hook modes.
"""

import base64
import ctypes
import json
import os
import pathlib
import shutil
import sys

CLI_STATUS_JSON = (
    '{"apiVersion":"grdr.cli.v1alpha1","type":"hook.status",'
    '"data":{"agent":"claude-code","state":"configured","installed":true}}'
)


def _is_elevated() -> bool:
    if os.name == "nt":
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.geteuid() == 0


def _layout() -> dict[str, pathlib.Path]:
    home = pathlib.Path(os.environ["HOME"])
    if os.name == "nt":
        local_app = pathlib.Path(os.environ["LOCALAPPDATA"])
        ours_share = local_app / "grdr"
        ours_state = ours_share / "state"
        bin_dir = ours_share / "bin"
        return {
            "home": home,
            "ours_share": ours_share,
            "ours_state": ours_state,
            "bin_link_dir": bin_dir,
            "bin_link": bin_dir / "grdr.cmd",
            "grdr_bin": bin_dir / "grdr.cmd",
            "hook_bin": bin_dir / "grdr-hook.cmd",
            "journal": ours_state / "journal.json",
            "claude_settings": home / ".claude" / "settings.json",
            "stray": home / ".config" / "stray-file",
        }
    ours_share = home / ".local" / "share" / "grdr"
    ours_state = home / ".local" / "state" / "grdr"
    bin_link_dir = home / ".local" / "bin"
    return {
        "home": home,
        "ours_share": ours_share,
        "ours_state": ours_state,
        "bin_link_dir": bin_link_dir,
        "bin_link": bin_link_dir / "grdr",
        "grdr_bin": ours_share / "bin" / "grdr",
        "hook_bin": ours_share / "bin" / "grdr-hook",
        "journal": ours_state / "journal.json",
        "claude_settings": home / ".claude" / "settings.json",
        "stray": home / ".config" / "stray-file",
    }


def _write_if_changed(path: pathlib.Path, content: str, executable: bool) -> None:
    raw = content.encode("utf-8")
    if path.exists() and path.read_bytes() == raw:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    if executable and os.name != "nt":
        path.chmod(0o755)


def _cmd_install(mode: str, paths: dict[str, pathlib.Path]) -> int:
    if _is_elevated():
        print("refused elevated user install", file=sys.stderr)
        return 1
    if paths["journal"].exists():
        return 0

    created_dirs = []
    for candidate in (
        paths["home"] / ".local",
        paths["home"] / ".local" / "share",
        paths["home"] / ".local" / "state",
        paths["bin_link_dir"],
        paths["ours_share"],
        paths["ours_share"] / "bin",
        paths["ours_state"],
    ):
        if not candidate.exists():
            created_dirs.append(str(candidate))

    if os.name == "nt":
        grdr_src = f"@echo off\r\necho {CLI_STATUS_JSON}\r\nexit /b 1\r\n"
        hook_src = "@echo off\r\nexit /b 0\r\n"
    else:
        grdr_src = f"#!/bin/sh\nprintf '%s\\n' '{CLI_STATUS_JSON}'\nexit 1\n"
        hook_src = "#!/bin/sh\nexit 0\n"

    _write_if_changed(paths["grdr_bin"], grdr_src, executable=True)
    _write_if_changed(paths["hook_bin"], hook_src, executable=True)
    if paths["bin_link"] != paths["grdr_bin"] and not os.path.lexists(paths["bin_link"]):
        paths["bin_link"].parent.mkdir(parents=True, exist_ok=True)
        paths["bin_link"].symlink_to(paths["grdr_bin"])

    journal = {"created_dirs": created_dirs, "prior_settings_b64": None}
    paths["journal"].parent.mkdir(parents=True, exist_ok=True)
    paths["journal"].write_text(json.dumps(journal), encoding="utf-8")

    if mode == "writes-outside-ours":
        paths["stray"].parent.mkdir(parents=True, exist_ok=True)
        paths["stray"].write_text("stray\n", encoding="utf-8")
    return 0


def _cmd_choose(mode: str, paths: dict[str, pathlib.Path]) -> int:
    settings_path = paths["claude_settings"]
    prior = settings_path.read_bytes()
    journal = json.loads(paths["journal"].read_text(encoding="utf-8"))
    if journal["prior_settings_b64"] is None:
        journal["prior_settings_b64"] = base64.b64encode(prior).decode("ascii")
        paths["journal"].write_text(json.dumps(journal), encoding="utf-8")

    text = prior.decode("utf-8")
    hook_cmd = (
        f'"{paths["hook_bin"]}" --agent claude-code --event PreToolUse'
        if os.name == "nt"
        else f"{paths['hook_bin']} --agent claude-code --event PreToolUse"
    )
    entry_json = json.dumps(
        {"matcher": "*", "hooks": [{"type": "command", "command": hook_cmd, "timeout": 5}]},
        indent=2,
    )
    indented = "\n".join("      " + line if idx > 0 else line for idx, line in enumerate(entry_json.splitlines()))
    marker = "      }\n    ]"
    if marker not in text:
        return 1
    updated = text.replace(marker, f"      }},\n      {indented}\n    ]", 1)
    if mode == "mutates-vendor-hook":
        updated = updated.replace('"timeout": 10', '"timeout": 11', 1)
    settings_path.write_bytes(updated.encode("utf-8"))
    return 0


def _cmd_uninstall(mode: str, paths: dict[str, pathlib.Path]) -> int:
    journal = json.loads(paths["journal"].read_text(encoding="utf-8"))
    if journal["prior_settings_b64"] is not None:
        paths["claude_settings"].write_bytes(base64.b64decode(journal["prior_settings_b64"]))

    for target in (paths["bin_link"], paths["grdr_bin"], paths["hook_bin"], paths["journal"]):
        if os.path.lexists(target):
            target.unlink()

    if mode == "leaves-file-behind":
        (paths["ours_share"] / "leftover").write_text("left behind\n", encoding="utf-8")
        return 0

    for folder in (paths["ours_share"] / "bin", paths["ours_share"], paths["ours_state"]):
        if folder.exists():
            shutil.rmtree(folder)

    for folder_str in reversed(journal["created_dirs"]):
        folder = pathlib.Path(folder_str)
        if folder.is_dir() and not any(folder.iterdir()):
            folder.rmdir()
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 2
    mode, action = argv[1], argv[2]
    paths = _layout()
    if action == "build":
        print("fixture build ok")
        return 0
    if action == "install":
        return _cmd_install(mode, paths)
    if action == "choose":
        return _cmd_choose(mode, paths)
    if action == "uninstall":
        return _cmd_uninstall(mode, paths)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
