# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Smoke workflow planner, R4 cell runner, R5 self-test and R6 unit-lint.

Error codes GRDR-GATE-0010 through GRDR-GATE-0015 stay literals until registered under #278.
"""

import argparse
import dataclasses
import enum
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, Mapping

_HERE = str(pathlib.Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from claude_settings import verify_choose_changes
from runner_exec import CommandResult, run_argv, run_step_command
from snapshot import (
    ERR_CONFIG,
    ERR_SNAPSHOT,
    OracleError,
    OsName,
    Profile,
    SnapshotEntry,
    capture_snapshot,
    diff_snapshots,
    expand_path,
    format_diff,
    load_roots_config,
    ours_patterns,
    unexpected_diffs_outside_ours,
)

_DEFAULT_CAPTURE_SNAPSHOT = capture_snapshot

ERR_UNIT_LINT = "GRDR-GATE-0014"
ERR_SELF_TEST = "GRDR-GATE-0015"
REQUIRED_CELL_KEYS = ("id", "runner", "profile", "build", "install", "choose", "uninstall")
CELL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
DEFAULT_ROOTS_PATH = pathlib.Path(__file__).resolve().parent / "roots.toml"
DEFAULT_FIXTURE_CELLS = pathlib.Path(__file__).resolve().parent / "fixtures" / "cells.toml"
BUILD_FORBIDDEN_SUBSTRS = (";", "|", "&", ">", "<", "`", "$", "#", "(", ")")
INTERPRETER_ALLOWED_FLAGS: dict[str, set[str]] = {
    "python": {"-I", "-B", "-E", "-s", "-S", "-u"},
    "python3": {"-I", "-B", "-E", "-s", "-S", "-u"},
    "bash": {"-e", "-u", "-x", "-eu", "-ex", "-ux", "-eux"},
    "sh": {"-e", "-u", "-x", "-eu", "-ex", "-ux", "-eux"},
    "pwsh": {"-noprofile", "-noninteractive", "-file"},
    "powershell": {"-noprofile", "-noninteractive", "-file"},
}


class StepName(enum.Enum):
    SEED = "seed"
    INSTALL = "install"
    INSTALL_RERUN = "install-rerun"
    CHOOSE = "choose"
    INSTALL_ELEVATED = "install-elevated"
    UNINSTALL = "uninstall"


@dataclasses.dataclass(frozen=True)
class CellSpec:
    id: str
    runner: str
    profile: Profile
    build: str
    install: str
    choose: str
    uninstall: str
    expected_fail_step: StepName | None = None


@dataclasses.dataclass(frozen=True)
class CellPassed:
    step_log: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class CellFailed:
    failed_step: StepName
    reason: str
    step_log: tuple[str, ...]


CellOutcome = CellPassed | CellFailed


def _has_parent_traversal(token: str) -> bool:
    cleaned = token.strip("'\"").replace("\\", "/")
    return any(".." in pathlib.PurePosixPath(part).parts for part in cleaned.split("="))


def _matches_allowed_prefix(token: str, allowed_prefixes: tuple[str, ...]) -> bool:
    cleaned = token.strip("'\"").replace("\\", "/")
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return any(cleaned.startswith(prefix) and len(cleaned) > len(prefix) for prefix in allowed_prefixes)


def _validate_build_command(cmd: str, allowed_prefixes: tuple[str, ...]) -> bool:
    if not cmd.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in cmd):
        return False
    if any(bad in cmd for bad in BUILD_FORBIDDEN_SUBSTRS):
        return False
    try:
        tokens = shlex.split(cmd, posix=(os.name != "nt"))
    except ValueError:
        return False
    if not tokens or any(_has_parent_traversal(tok) for tok in tokens):
        return False

    first = tokens[0].strip("'\"").replace("\\", "/")
    if _matches_allowed_prefix(first, allowed_prefixes):
        return True
    if "/" in first:
        return False
    interp = first.lower().removesuffix(".exe")
    allowed_flags = INTERPRETER_ALLOWED_FLAGS.get(interp)
    if allowed_flags is None:
        return False

    idx = 1
    while idx < len(tokens):
        tok = tokens[idx].strip("'\"")
        flag_key = tok.lower() if interp in ("pwsh", "powershell") else tok
        if tok.startswith("-"):
            if flag_key not in allowed_flags:
                return False
            idx += 1
            continue
        return _matches_allowed_prefix(tok, allowed_prefixes)
    return False


def load_cells(
    smoke_path: pathlib.Path,
    roots_config: Mapping[str, Any],
    *,
    missing_ok: bool,
    allow_fixture_prefix: bool = False,
) -> list[CellSpec]:
    if smoke_path.is_symlink():
        raise OracleError(ERR_CONFIG, f"{smoke_path} must not be a symlink")
    if not os.path.lexists(smoke_path):
        if missing_ok:
            return []
        raise OracleError(ERR_CONFIG, f"{smoke_path} does not exist")
    if not smoke_path.is_file():
        raise OracleError(ERR_CONFIG, f"{smoke_path} is not a regular file")
    try:
        with smoke_path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError) as error:
        raise OracleError(ERR_CONFIG, f"cannot parse {smoke_path}: {type(error).__name__}") from None

    raw_cells = data.get("cell")
    if not isinstance(raw_cells, list):
        raise OracleError(ERR_CONFIG, f"{smoke_path} missing [[cell]] list")

    prefixes = (".github/install-smoke/fixtures/",) if allow_fixture_prefix else ("deploy/",)
    runners = roots_config.get("runners", {})
    seen_ids: set[str] = set()
    specs: list[CellSpec] = []

    for idx, raw in enumerate(raw_cells):
        if not isinstance(raw, dict):
            raise OracleError(ERR_CONFIG, f"{smoke_path}: cell[{idx}] is not a table")
        label = str(raw.get("id") or f"cell[{idx}]")
        for key in REQUIRED_CELL_KEYS:
            val = raw.get(key)
            if not isinstance(val, str) or not val.strip():
                raise OracleError(ERR_CONFIG, f"{smoke_path}: cell '{label}' missing key '{key}'")
        if not CELL_ID_RE.fullmatch(raw["id"]):
            raise OracleError(ERR_CONFIG, f"{smoke_path}: cell '{label}' invalid key 'id'")
        if raw["id"] in seen_ids:
            raise OracleError(ERR_CONFIG, f"{smoke_path}: duplicate cell id '{raw['id']}'")
        seen_ids.add(raw["id"])
        if raw["runner"] not in runners:
            raise OracleError(ERR_CONFIG, f"{smoke_path}: cell '{label}' unknown runner '{raw['runner']}'")
        try:
            profile = Profile(raw["profile"])
        except ValueError:
            raise OracleError(ERR_CONFIG, f"{smoke_path}: cell '{label}' invalid profile") from None
        if not _validate_build_command(raw["build"], prefixes):
            raise OracleError(ERR_CONFIG, f"{smoke_path}: cell '{label}' invalid key 'build'")

        expected = None
        if "expected_fail_step" in raw:
            try:
                expected = StepName(raw["expected_fail_step"])
            except ValueError:
                raise OracleError(ERR_CONFIG, f"{smoke_path}: cell '{label}' invalid expected_fail_step") from None

        specs.append(CellSpec(
            id=raw["id"], runner=raw["runner"], profile=profile,
            build=raw["build"], install=raw["install"], choose=raw["choose"],
            uninstall=raw["uninstall"], expected_fail_step=expected,
        ))
    return specs


def _find_grdr_binary(roots_cfg: Mapping[str, Any], os_name: OsName, env: Mapping[str, str]) -> str | None:
    found = shutil.which("grdr", path=env.get("PATH"))
    if found:
        return found
    for raw in roots_cfg["os"][os_name.value].get("grdr_search_paths", []):
        candidate = pathlib.Path(expand_path(raw, os_name, env))
        if candidate.is_file():
            return str(candidate)
        if candidate.parent.is_dir():
            via_which = shutil.which(candidate.stem, path=str(candidate.parent))
            if via_which:
                return via_which
    return None


def _verify_hook_status(
    roots_cfg: Mapping[str, Any],
    os_name: OsName,
    profile: Profile,
    env: Mapping[str, str],
    cwd: pathlib.Path,
) -> str | None:
    grdr_bin = _find_grdr_binary(roots_cfg, os_name, env)
    if grdr_bin is None:
        return "grdr binary not found after choose"
    timeout = int(roots_cfg["limits"]["status_timeout_seconds"])
    res = run_argv(
        [grdr_bin, "hook", "status", "--agent", "claude-code", "--json"],
        env,
        cwd,
        timeout,
        deelevate_windows=(os_name == OsName.WINDOWS and profile == Profile.USER),
    )
    if res.returncode not in (0, 1):
        return f"grdr hook status exited {res.returncode}: {res.stderr.strip()}"
    try:
        payload = json.loads(res.stdout)
    except ValueError as err:
        return f"grdr hook status emitted invalid JSON: {type(err).__name__}"
    if not isinstance(payload, dict) or payload.get("error") is not None:
        return "grdr hook status JSON reported error"

    data = payload.get("data", payload)
    if not isinstance(data, dict):
        return "grdr hook status JSON missing data object"
    if "agent" in data and data["agent"] != "claude-code":
        return f"unexpected agent in hook status: {data['agent']!r}"

    accepted = {s.lower() for s in roots_cfg["limits"]["accepted_hook_states"]}
    if "state" in data:
        state = str(data["state"]).lower().replace("_", "-")
        if state not in accepted:
            return f"hook status state '{state}' not in {sorted(accepted)}"
        if "installed" in data and data["installed"] is not True:
            return "hook status reported installed=false"
        return None
    if data.get("installed") is True:
        return None
    return "hook status JSON did not report installed entries"


def run_r4_cell(
    cell: CellSpec,
    roots_cfg: Mapping[str, Any],
    repo_root: pathlib.Path,
    env: Mapping[str, str] | None = None,
    override_roots: list[str] | None = None,
) -> CellOutcome:
    run_env = dict(os.environ if env is None else env)
    os_name = OsName(roots_cfg["runners"][cell.runner])
    timeout = int(roots_cfg["limits"]["step_timeout_seconds"])
    needs_elevated = cell.profile == Profile.PROTECTED
    patterns = ours_patterns(roots_cfg, os_name, cell.profile, run_env)
    logs: list[str] = []

    def fail(step: StepName, reason: str) -> CellOutcome:
        logs.append(f"step {step.value}: FAILED ({reason})")
        remaining = list(StepName)
        for later in remaining[remaining.index(step) + 1:]:
            if later == StepName.INSTALL_ELEVATED and cell.profile != Profile.USER:
                continue
            logs.append(f"step {later.value}: NOT RUN")
        return CellFailed(step, reason, tuple(logs))

    def run_cmd(cmd: str, *, elevated: bool = False) -> CommandResult:
        return run_step_command(cmd, os_name, cell.profile, run_env, repo_root, timeout, elevated=elevated)

    stat_cache: dict[str, tuple[tuple[Any, ...], SnapshotEntry]] = {}

    def snap() -> dict[str, SnapshotEntry]:
        if override_roots is not None:
            return capture_snapshot(roots_cfg, os_name, cell.profile, run_env, override_roots=override_roots)
        if capture_snapshot is _DEFAULT_CAPTURE_SNAPSHOT:
            return capture_snapshot(
                roots_cfg,
                os_name,
                cell.profile,
                run_env,
                stat_cache=stat_cache,
                system_stat_only=True,
            )
        return capture_snapshot(roots_cfg, os_name, cell.profile, run_env)

    seed_src = repo_root / roots_cfg["limits"]["claude_seed_fixture"]
    try:
        seeded_bytes = seed_src.read_bytes()
        user_settings = pathlib.Path(expand_path(roots_cfg["limits"]["claude_user_settings"], os_name, run_env))
        user_settings.parent.mkdir(parents=True, exist_ok=True)
        user_settings.write_bytes(seeded_bytes)
        logs.append(f"step {StepName.SEED.value}: OK")
    except OSError as err:
        return fail(StepName.SEED, f"cannot seed Claude settings: {type(err).__name__}")

    snap_s0 = snap()
    if run_cmd(cell.build).returncode != 0:
        return fail(StepName.INSTALL, "build exited non-zero")
    inst_res = run_cmd(cell.install, elevated=needs_elevated)
    if inst_res.returncode != 0:
        return fail(StepName.INSTALL, f"install exited {inst_res.returncode}")

    snap_s1 = snap()
    bad_s1 = unexpected_diffs_outside_ours(diff_snapshots(snap_s0, snap_s1), snap_s1, patterns, os_name)
    if bad_s1:
        return fail(StepName.INSTALL, "changes outside ours:\n" + "\n".join(format_diff(bad_s1)))
    logs.append(f"step {StepName.INSTALL.value}: OK")

    rerun_res = run_cmd(cell.install, elevated=needs_elevated)
    if rerun_res.returncode != 0:
        return fail(StepName.INSTALL_RERUN, f"install re-run exited {rerun_res.returncode}")
    rerun_diffs = diff_snapshots(snap_s1, snap())
    if rerun_diffs:
        return fail(StepName.INSTALL_RERUN, "re-run not idempotent:\n" + "\n".join(format_diff(rerun_diffs)))
    logs.append(f"step {StepName.INSTALL_RERUN.value}: OK")

    choose_res = run_cmd(cell.choose, elevated=needs_elevated)
    if choose_res.returncode != 0:
        return fail(StepName.CHOOSE, f"choose exited {choose_res.returncode}")
    snap_choose = snap()
    choose_errs = verify_choose_changes(snap_s1, snap_choose, roots_cfg, os_name, cell.profile, seeded_bytes, run_env)
    if choose_errs:
        return fail(StepName.CHOOSE, "; ".join(choose_errs))
    status_err = _verify_hook_status(roots_cfg, os_name, cell.profile, run_env, repo_root)
    if status_err:
        return fail(StepName.CHOOSE, status_err)
    logs.append(f"step {StepName.CHOOSE.value}: OK")

    if cell.profile == Profile.USER:
        elev_res = run_cmd(cell.install, elevated=True)
        if os_name != OsName.WINDOWS and elev_res.stderr.lstrip().lower().startswith("sudo:"):
            return fail(StepName.INSTALL_ELEVATED, "sudo -n failed before running user install")
        if elev_res.returncode == 0:
            return fail(StepName.INSTALL_ELEVATED, "elevated user install unexpectedly exited 0")
        elev_diffs = diff_snapshots(snap_choose, snap())
        if elev_diffs:
            return fail(StepName.INSTALL_ELEVATED, "elevated install changed snapshot:\n" + "\n".join(format_diff(elev_diffs)))
        logs.append(f"step {StepName.INSTALL_ELEVATED.value}: OK")

    uninst_res = run_cmd(cell.uninstall, elevated=needs_elevated)
    if uninst_res.returncode != 0:
        return fail(StepName.UNINSTALL, f"uninstall exited {uninst_res.returncode}")
    s2_diffs = diff_snapshots(snap_s0, snap())
    if s2_diffs:
        return fail(StepName.UNINSTALL, "post-uninstall snapshot differs from S0:\n" + "\n".join(format_diff(s2_diffs)))
    logs.append(f"step {StepName.UNINSTALL.value}: OK")
    return CellPassed(tuple(logs))


def isolated_env(home_dir: pathlib.Path, base_env: Mapping[str, str]) -> dict[str, str]:
    env = dict(base_env)
    orig_home_raw = (base_env.get("USERPROFILE") or base_env.get("HOME")) if os.name == "nt" else base_env.get("HOME")
    if orig_home_raw:
        orig_home = pathlib.Path(orig_home_raw)
        env["CARGO_HOME"] = base_env.get("CARGO_HOME") or str(orig_home / ".cargo")
        env["RUSTUP_HOME"] = base_env.get("RUSTUP_HOME") or str(orig_home / ".rustup")
    env["HOME"] = str(home_dir)
    env["XDG_CONFIG_HOME"] = str(home_dir / ".config")
    env["XDG_DATA_HOME"] = str(home_dir / ".local" / "share")
    env["XDG_STATE_HOME"] = str(home_dir / ".local" / "state")
    if os.name == "nt":
        local_app = home_dir / "AppData" / "Local"
        roaming_app = home_dir / "AppData" / "Roaming"
        local_app.mkdir(parents=True, exist_ok=True)
        roaming_app.mkdir(parents=True, exist_ok=True)
        env["USERPROFILE"] = str(home_dir)
        env["LOCALAPPDATA"] = str(local_app)
        env["APPDATA"] = str(roaming_app)
    return env


def _prepare_self_test_roots(
    tmp_root: pathlib.Path,
    os_name: OsName,
    profile: Profile,
    roots_cfg: Mapping[str, Any],
    env: Mapping[str, str],
) -> list[str]:
    user_roots = [
        expand_path(raw, os_name, env)
        for raw in roots_cfg["os"][os_name.value][profile.value]["scan_roots"]
        if raw.startswith(("~", "%LOCALAPPDATA%", "%APPDATA%"))
    ]
    synth_root = tmp_root / "synth_roots"
    private_etc = synth_root / "private_etc"
    private_etc.mkdir(parents=True, exist_ok=True)
    (private_etc / "sample.conf").write_text("seed=1\n", encoding="utf-8")

    etc_root = synth_root / "etc"
    try:
        etc_root.symlink_to(private_etc, target_is_directory=True)
    except OSError:
        etc_root.mkdir(parents=True, exist_ok=True)
        (etc_root / "sample.conf").write_text("seed=1\n", encoding="utf-8")

    usr_bin = synth_root / "usr" / "bin"
    usr_bin.mkdir(parents=True, exist_ok=True)
    (usr_bin / "tool").write_text("tool\n", encoding="utf-8")
    try:
        (usr_bin / "tool-link").symlink_to("tool")
    except OSError:
        pass

    var_lib = synth_root / "var_lib" / "state"
    var_lib.mkdir(parents=True, exist_ok=True)
    (var_lib / "marker").write_text("ok\n", encoding="utf-8")

    return [*user_roots, str(etc_root), str(synth_root / "usr"), str(synth_root / "var_lib")]


def run_self_test(roots_cfg: Mapping[str, Any], fixtures_path: pathlib.Path, repo_root: pathlib.Path) -> int:
    cells = load_cells(fixtures_path, roots_cfg, missing_ok=False, allow_fixture_prefix=True)
    expected_count = int(roots_cfg["limits"]["self_test_cell_count"])
    if len(cells) != expected_count:
        raise OracleError(ERR_SELF_TEST, f"expected {expected_count} fixture cells, found {len(cells)}")

    failures = 0
    for cell in cells:
        if cell.expected_fail_step is None:
            raise OracleError(ERR_SELF_TEST, f"fixture cell '{cell.id}' missing expected_fail_step")
        os_name = OsName(roots_cfg["runners"][cell.runner])
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            env = isolated_env(tmp_path / "home", os.environ)
            scan_roots = _prepare_self_test_roots(tmp_path, os_name, cell.profile, roots_cfg, env)
            outcome = run_r4_cell(cell, roots_cfg, repo_root, env, override_roots=scan_roots)
        print(f"=== fixture cell: {cell.id} (expected fail at {cell.expected_fail_step.value}) ===")
        for line in outcome.step_log:
            print(line)
        if not isinstance(outcome, CellFailed) or outcome.failed_step != cell.expected_fail_step:
            actual = "PASSED" if isinstance(outcome, CellPassed) else outcome.failed_step.value
            print(
                f"::error::{ERR_SELF_TEST} cell '{cell.id}' failed at '{actual}', expected '{cell.expected_fail_step.value}'",
                file=sys.stderr,
            )
            failures += 1
    return 1 if failures else 0


def _write_github_output(output_path: pathlib.Path | None, pairs: dict[str, str]) -> None:
    if output_path is None:
        return
    with output_path.open("a", encoding="utf-8") as handle:
        for key, value in pairs.items():
            handle.write(f"{key}={value}\n")


def cmd_plan(args: argparse.Namespace) -> int:
    roots_cfg = load_roots_config(args.roots)
    cells = load_cells(args.smoke_file, roots_cfg, missing_ok=True)
    matrix = [{"id": c.id, "runner": c.runner, "profile": c.profile.value} for c in cells]
    pairs = {
        "cells": json.dumps(matrix, separators=(",", ":")),
        "has_cells": "true" if matrix else "false",
        "count": str(len(matrix)),
    }
    _write_github_output(args.github_output, pairs)
    print(f"planned {len(matrix)} cell(s)")
    return 0


def cmd_run_cell(args: argparse.Namespace) -> int:
    roots_cfg = load_roots_config(args.roots)
    cells = load_cells(args.smoke_file, roots_cfg, missing_ok=False)
    cell = next((c for c in cells if c.id == args.cell_id), None)
    if cell is None:
        raise OracleError(ERR_CONFIG, f"unknown cell id '{args.cell_id}'")
    outcome = run_r4_cell(cell, roots_cfg, pathlib.Path.cwd())
    for line in outcome.step_log:
        print(line)
    if isinstance(outcome, CellFailed):
        print(f"::error::{ERR_SNAPSHOT} cell '{cell.id}' failed at step '{outcome.failed_step.value}'", file=sys.stderr)
        return 1
    return 0


def _glob_deploy(patterns: list[str]) -> list[pathlib.Path]:
    if not pathlib.Path("deploy").is_dir():
        return []
    found: set[pathlib.Path] = set()
    for pat in patterns:
        found.update(p for p in pathlib.Path(".").glob(pat) if p.is_file())
    return sorted(found)


def cmd_unit_lint(args: argparse.Namespace) -> int:
    roots_cfg = load_roots_config(args.roots)
    lint_cfg = roots_cfg["unit_lint"][args.os]
    for tool in lint_cfg["required_tools"]:
        if shutil.which(tool) is None:
            raise OracleError(ERR_UNIT_LINT, f"missing required tool: {tool}")

    total_files = 0
    if args.os == "linux":
        units = _glob_deploy(lint_cfg["unit_globs"])
        sysusers = _glob_deploy(lint_cfg["sysusers_globs"])
        total_files = len(units) + len(sysusers)
        if units:
            unit_dirs = os.pathsep.join(sorted({str(p.parent.resolve()) for p in units}))
            lint_env = dict(os.environ)
            lint_env["SYSTEMD_UNIT_PATH"] = f"{unit_dirs}{os.pathsep}"
            res = subprocess.run(
                ["systemd-analyze", "verify", *(str(p.resolve()) for p in units)],
                env=lint_env,
                check=False,
            )
            if res.returncode != 0:
                raise OracleError(ERR_UNIT_LINT, f"systemd-analyze verify exited {res.returncode}")
        for conf in sysusers:
            res = subprocess.run(["systemd-sysusers", "--dry-run", str(conf.resolve())], check=False)
            if res.returncode != 0:
                raise OracleError(ERR_UNIT_LINT, f"systemd-sysusers --dry-run failed on {conf}")
    elif args.os == "macos":
        plists = _glob_deploy(lint_cfg["plist_globs"])
        total_files = len(plists)
        for plist in plists:
            res = subprocess.run(["plutil", "-lint", str(plist.resolve())], check=False)
            if res.returncode != 0:
                raise OracleError(ERR_UNIT_LINT, f"plutil -lint failed on {plist}")

    _write_github_output(args.github_output, {"files": str(total_files)})
    print(f"unit-lint ({args.os}): {total_files} files")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="smoke.py")
    parser.add_argument("--roots", type=pathlib.Path, default=DEFAULT_ROOTS_PATH)
    sub = parser.add_subparsers(dest="cmd", required=True)

    plan_p = sub.add_parser("plan")
    plan_p.add_argument("--smoke-file", type=pathlib.Path, required=True)
    plan_p.add_argument("--github-output", type=pathlib.Path)

    cell_p = sub.add_parser("run-cell")
    cell_p.add_argument("--smoke-file", type=pathlib.Path, required=True)
    cell_p.add_argument("--cell-id", required=True)

    self_p = sub.add_parser("self-test")
    self_p.add_argument("--fixtures", type=pathlib.Path, default=DEFAULT_FIXTURE_CELLS)

    lint_p = sub.add_parser("unit-lint")
    lint_p.add_argument("--os", choices=["linux", "macos"], required=True)
    lint_p.add_argument("--github-output", type=pathlib.Path)

    args = parser.parse_args(argv[1:])
    if args.cmd == "plan":
        return cmd_plan(args)
    if args.cmd == "run-cell":
        return cmd_run_cell(args)
    if args.cmd == "self-test":
        return run_self_test(load_roots_config(args.roots), args.fixtures, pathlib.Path.cwd())
    return cmd_unit_lint(args)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except OracleError as err:
        print(f"::error::{err}", file=sys.stderr)
        sys.exit(1)
