# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Snapshot oracle for install-smoke across OS roots and state (D-48)."""

import argparse
import base64
import ctypes
from ctypes import wintypes
import dataclasses
import enum
import fnmatch
import hashlib
import json
import ntpath
import os
import pathlib
import posixpath
import stat
import subprocess
import sys
import tomllib
from typing import Any, Mapping

if os.name == "nt":
    import winreg
    _ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ADVAPI32.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]
    _ADVAPI32.GetFileSecurityW.restype = wintypes.BOOL
    _ADVAPI32.GetSecurityDescriptorOwner.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)
    ]
    _ADVAPI32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
    _ADVAPI32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _ADVAPI32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _KERNEL32.LocalFree.argtypes = [wintypes.HLOCAL]
    _KERNEL32.LocalFree.restype = wintypes.HLOCAL
else:
    winreg = None
    _ADVAPI32 = None
    _KERNEL32 = None

ERR_CONFIG = "GRDR-GATE-0010"
ERR_SNAPSHOT = "GRDR-GATE-0011"
ERR_SETTINGS = "GRDR-GATE-0012"
WINDOWS_REPARSE_ATTR = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
OWNER_SECURITY_INFO = 1
VIRTUAL_PREFIXES = ("reg://", "task://", "service://")


class Profile(enum.Enum):
    USER = "user"
    PROTECTED = "protected"


class OsName(enum.Enum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"


class EntryKind(enum.Enum):
    FILE = "file"
    DIR = "dir"
    SYMLINK = "symlink"
    OTHER = "other"
    DIR_UNREADABLE = "dir-unreadable"
    REG_KEY = "reg-key"
    REG_VALUE = "reg-value"
    TASK = "scheduled-task"
    SERVICE = "service"


class DiffKind(enum.Enum):
    ADDED = "+"
    REMOVED = "-"
    CHANGED = "~"


class OracleError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code} {message}")
        self.code = code


@dataclasses.dataclass(frozen=True)
class SnapshotEntry:
    path: str
    kind: EntryKind
    mode: str
    owner: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "type": self.kind.value,
            "mode": self.mode,
            "owner": self.owner,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, str]) -> "SnapshotEntry":
        return cls(
            path=raw["path"],
            kind=EntryKind(raw["type"]),
            mode=raw["mode"],
            owner=raw["owner"],
            sha256=raw["sha256"],
        )


@dataclasses.dataclass(frozen=True)
class DiffEntry:
    kind: DiffKind
    path: str
    before: SnapshotEntry | None
    after: SnapshotEntry | None


def detect_host_os() -> OsName:
    if sys.platform.startswith("linux"):
        return OsName.LINUX
    if sys.platform == "darwin":
        return OsName.MACOS
    if os.name == "nt":
        return OsName.WINDOWS
    raise OracleError(ERR_CONFIG, f"unsupported host platform: {sys.platform}")


def load_roots_config(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError) as error:
        raise OracleError(ERR_CONFIG, f"cannot read {path}: {type(error).__name__}") from None
    if not isinstance(data, dict) or data.get("schema") != "grdr.install-smoke.roots.v1":
        raise OracleError(ERR_CONFIG, f"{path} has unexpected schema")
    return data


def _home_dir(os_name: OsName, env: Mapping[str, str]) -> str:
    if os_name == OsName.WINDOWS:
        return env.get("USERPROFILE") or env.get("HOME") or os.path.expanduser("~")
    return env.get("HOME") or os.path.expanduser("~")


def expand_path(raw: str, os_name: OsName, env: Mapping[str, str] | None = None) -> str:
    source = os.environ if env is None else env
    text = raw
    if text == "~" or text.startswith(("~/", "~\\")):
        text = _home_dir(os_name, source) + text[1:]
    if os_name == OsName.WINDOWS:
        for key, value in source.items():
            text = _replace_case_insensitive_var(text, f"%{key}%", value)
        return ntpath.normpath(text)
    return posixpath.normpath(text.replace("\\", "/"))


def _replace_case_insensitive_var(text: str, needle: str, value: str) -> str:
    lower_text = text.lower()
    lower_needle = needle.lower()
    pos = lower_text.find(lower_needle)
    while pos >= 0:
        text = text[:pos] + value + text[pos + len(needle):]
        lower_text = text.lower()
        pos = lower_text.find(lower_needle, pos + len(value))
    return text


def normalize_for_match(path: str, os_name: OsName) -> str:
    if path.startswith(VIRTUAL_PREFIXES):
        return path.lower() if os_name == OsName.WINDOWS else path
    if os_name == OsName.WINDOWS:
        return ntpath.normcase(ntpath.normpath(path))
    return posixpath.normpath(path.replace("\\", "/"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str, chunk_bytes: int) -> str:
    try:
        with open(path, "rb") as handle:
            if hasattr(hashlib, "file_digest"):
                return hashlib.file_digest(handle, "sha256").hexdigest()
            digest = hashlib.sha256()
            while chunk := handle.read(chunk_bytes):
                digest.update(chunk)
            return digest.hexdigest()
    except OSError:
        return "<unreadable>"


def _windows_owner_sid(path: str) -> str:
    if _ADVAPI32 is None or _KERNEL32 is None:
        return ""
    needed = wintypes.DWORD(0)
    _ADVAPI32.GetFileSecurityW(path, OWNER_SECURITY_INFO, None, 0, ctypes.byref(needed))
    if needed.value == 0:
        return "<unreadable>"
    buf = ctypes.create_string_buffer(needed.value)
    if not _ADVAPI32.GetFileSecurityW(path, OWNER_SECURITY_INFO, buf, needed.value, ctypes.byref(needed)):
        return "<unreadable>"
    sid = ctypes.c_void_p()
    defaulted = wintypes.BOOL()
    if not _ADVAPI32.GetSecurityDescriptorOwner(buf, ctypes.byref(sid), ctypes.byref(defaulted)):
        return "<unreadable>"
    sid_str = wintypes.LPWSTR()
    if not _ADVAPI32.ConvertSidToStringSidW(sid, ctypes.byref(sid_str)):
        return "<unreadable>"
    try:
        return sid_str.value or ""
    finally:
        _KERNEL32.LocalFree(sid_str)


def _entry_metadata(path: str, st: os.stat_result, os_name: OsName, chunk_bytes: int) -> SnapshotEntry:
    is_reparse = os_name == OsName.WINDOWS and bool(getattr(st, "st_file_attributes", 0) & WINDOWS_REPARSE_ATTR)
    if stat.S_ISLNK(st.st_mode) or is_reparse:
        kind = EntryKind.SYMLINK
        try:
            digest = f"symlink:{sha256_bytes(os.readlink(path).encode('utf-8', 'surrogateescape'))}"
        except OSError:
            digest = "symlink:<unreadable>"
    elif stat.S_ISDIR(st.st_mode):
        kind = EntryKind.DIR
        digest = ""
    elif stat.S_ISREG(st.st_mode):
        kind = EntryKind.FILE
        digest = _sha256_file(path, chunk_bytes)
    else:
        kind = EntryKind.OTHER
        digest = ""

    if os_name == OsName.WINDOWS:
        attrs = getattr(st, "st_file_attributes", 0)
        mode = f"{stat.S_IMODE(st.st_mode):04o}:attr:{attrs:08x}"
        owner = _windows_owner_sid(path)
    else:
        mode = f"{stat.S_IMODE(st.st_mode):04o}"
        owner = f"{st.st_uid}:{st.st_gid}"
    return SnapshotEntry(path=path, kind=kind, mode=mode, owner=owner, sha256=digest)


def _is_ignored(norm_path: str, ignored: list[str], os_name: OsName) -> bool:
    sep = "\\" if os_name == OsName.WINDOWS else "/"
    for item in ignored:
        if norm_path == item or norm_path.startswith(item.rstrip(sep) + sep):
            return True
    return False


def _can_walk_root(
    root_path: str,
    root_entry: SnapshotEntry,
    ignored: list[str],
    os_name: OsName,
) -> bool:
    if root_entry.kind == EntryKind.DIR:
        return True
    if root_entry.kind != EntryKind.SYMLINK:
        return False
    try:
        target_stat = os.stat(root_path)
    except OSError:
        return False
    if not stat.S_ISDIR(target_stat.st_mode):
        return False
    resolved = normalize_for_match(os.path.realpath(root_path), os_name)
    return not _is_ignored(resolved, ignored, os_name)


def _scan_fs_root(
    root_path: str,
    ignored: list[str],
    os_name: OsName,
    chunk_bytes: int,
    records: dict[str, SnapshotEntry],
) -> None:
    try:
        root_stat = os.lstat(root_path)
    except FileNotFoundError:
        return
    except OSError:
        records[root_path] = SnapshotEntry(root_path, EntryKind.DIR_UNREADABLE, "", "", "<unreadable>")
        return

    norm = normalize_for_match(root_path, os_name)
    if _is_ignored(norm, ignored, os_name):
        return
    root_entry = _entry_metadata(root_path, root_stat, os_name, chunk_bytes)
    records[root_path] = root_entry
    if not _can_walk_root(root_path, root_entry, ignored, os_name):
        return

    stack = [root_path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                children = sorted(it, key=lambda item: item.name)
        except OSError:
            records[current] = SnapshotEntry(
                current, EntryKind.DIR_UNREADABLE, records[current].mode, records[current].owner, "<unreadable>"
            )
            continue
        for child in children:
            child_path = os.path.normpath(child.path)
            if _is_ignored(normalize_for_match(child_path, os_name), ignored, os_name):
                continue
            try:
                st = child.stat(follow_symlinks=False)
            except OSError:
                records[child_path] = SnapshotEntry(child_path, EntryKind.OTHER, "", "", "<unreadable>")
                continue
            entry = _entry_metadata(child_path, st, os_name, chunk_bytes)
            records[child_path] = entry
            if entry.kind == EntryKind.DIR:
                stack.append(child_path)


def _run_ps_json(script: str) -> Any:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise OracleError(ERR_SNAPSHOT, f"PowerShell query exited {result.returncode}")
    text = result.stdout.strip()
    if not text:
        return []
    parsed = json.loads(text)
    return parsed if isinstance(parsed, list) else [parsed]


def _scan_windows_registry(hives: list[str], records: dict[str, SnapshotEntry]) -> None:
    if winreg is None:
        return
    hive_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    for spec in hives:
        prefix, _, subkey = spec.partition("\\")
        hive = hive_map.get(prefix.upper())
        if hive is None:
            raise OracleError(ERR_CONFIG, f"unknown registry hive in {spec}")
        _walk_registry_key(hive, prefix.upper(), subkey, records)


def _walk_registry_key(hive: int, hive_label: str, subkey: str, records: dict[str, SnapshotEntry]) -> None:
    stack = [subkey]
    while stack:
        current = stack.pop()
        key_uri = f"reg://{hive_label}/{current.replace(chr(92), '/')}"
        try:
            with winreg.OpenKey(hive, current, 0, winreg.KEY_READ) as handle:
                nkeys, nvals, _ = winreg.QueryInfoKey(handle)
                records[key_uri] = SnapshotEntry(key_uri, EntryKind.REG_KEY, "", "", "")
                for idx in range(nvals):
                    name, value, vtype = winreg.EnumValue(handle, idx)
                    payload = json.dumps({"type": vtype, "value": repr(value)}, sort_keys=True).encode("utf-8")
                    val_uri = f"{key_uri}::{name or '(Default)'}"
                    records[val_uri] = SnapshotEntry(val_uri, EntryKind.REG_VALUE, str(vtype), "", sha256_bytes(payload))
                for idx in range(nkeys):
                    child = winreg.EnumKey(handle, idx)
                    stack.append(f"{current}\\{child}" if current else child)
        except OSError:
            records[key_uri] = SnapshotEntry(key_uri, EntryKind.REG_KEY, "", "", "<unreadable>")


def _scan_windows_tasks(records: dict[str, SnapshotEntry]) -> None:
    script = (
        "Get-ScheduledTask | Select-Object TaskPath,TaskName,"
        "@{n='UserId';e={$_.Principal.UserId}},"
        "@{n='RunLevel';e={$_.Principal.RunLevel.ToString()}},"
        "@{n='Actions';e={@($_.Actions | ForEach-Object { @($_.Execute,$_.Arguments,$_.WorkingDirectory) -join '|' })}}"
        " | ConvertTo-Json -Depth 4 -Compress"
    )
    for task in _run_ps_json(script):
        uri = f"task://{task.get('TaskPath', '')}{task.get('TaskName', '')}"
        digest = sha256_bytes(json.dumps(task, sort_keys=True).encode("utf-8"))
        records[uri] = SnapshotEntry(
            uri, EntryKind.TASK, str(task.get("RunLevel") or ""), str(task.get("UserId") or ""), digest
        )


def _scan_windows_services(records: dict[str, SnapshotEntry]) -> None:
    script = (
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,PathName,StartMode,StartName,ServiceType "
        "| ConvertTo-Json -Depth 3 -Compress"
    )
    for svc in _run_ps_json(script):
        uri = f"service://{svc.get('Name') or ''}"
        digest = sha256_bytes(json.dumps(svc, sort_keys=True).encode("utf-8"))
        records[uri] = SnapshotEntry(
            uri, EntryKind.SERVICE, str(svc.get("StartMode") or ""), str(svc.get("StartName") or ""), digest
        )


def capture_snapshot(
    config: dict[str, Any],
    os_name: OsName,
    profile: Profile,
    env: Mapping[str, str] | None = None,
    override_roots: list[str] | None = None,
) -> dict[str, SnapshotEntry]:
    source = os.environ if env is None else env
    chunk_bytes = int(config["limits"]["read_chunk_bytes"])
    os_cfg = config["os"][os_name.value]
    raw_roots = override_roots if override_roots is not None else os_cfg[profile.value]["scan_roots"]
    ignored = [normalize_for_match(expand_path(p, os_name, source), os_name) for p in os_cfg.get("ignore_paths", [])]
    records: dict[str, SnapshotEntry] = {}
    for raw_root in raw_roots:
        _scan_fs_root(expand_path(raw_root, os_name, source), ignored, os_name, chunk_bytes, records)

    if os_name == OsName.WINDOWS and os.name == "nt" and override_roots is None:
        _scan_windows_registry(os_cfg.get("windows_registry", []), records)
        if os_cfg.get("windows_tasks"):
            _scan_windows_tasks(records)
        if os_cfg.get("windows_services"):
            _scan_windows_services(records)
    return dict(sorted(records.items()))


def diff_snapshots(before: Mapping[str, SnapshotEntry], after: Mapping[str, SnapshotEntry]) -> list[DiffEntry]:
    diffs: list[DiffEntry] = []
    for path in sorted(set(before) | set(after)):
        old, new = before.get(path), after.get(path)
        if old is None and new is not None:
            diffs.append(DiffEntry(DiffKind.ADDED, path, None, new))
        elif new is None and old is not None:
            diffs.append(DiffEntry(DiffKind.REMOVED, path, old, None))
        elif old != new:
            diffs.append(DiffEntry(DiffKind.CHANGED, path, old, new))
    return diffs


def format_diff(diffs: list[DiffEntry]) -> list[str]:
    lines: list[str] = []
    for diff in diffs:
        if diff.kind == DiffKind.ADDED and diff.after is not None:
            e = diff.after
            lines.append(f"+ {diff.path} type={e.kind.value} mode={e.mode} owner={e.owner} sha256={e.sha256}")
        elif diff.kind == DiffKind.REMOVED and diff.before is not None:
            e = diff.before
            lines.append(f"- {diff.path} type={e.kind.value} mode={e.mode} owner={e.owner} sha256={e.sha256}")
        elif diff.before is not None and diff.after is not None:
            b, a = diff.before, diff.after
            lines.append(
                f"~ {diff.path} type={b.kind.value}->{a.kind.value} "
                f"mode={b.mode}->{a.mode} owner={b.owner}->{a.owner} sha256={b.sha256}->{a.sha256}"
            )
    return lines


def ours_patterns(
    config: Mapping[str, Any], os_name: OsName, profile: Profile, env: Mapping[str, str] | None = None
) -> list[str]:
    source = os.environ if env is None else env
    raw_list = config["os"][os_name.value][profile.value]["ours"]
    return [
        item if item.startswith(VIRTUAL_PREFIXES) else expand_path(item, os_name, source)
        for item in raw_list
    ]


def _segment_match(target: str, pattern: str, os_name: OsName) -> bool:
    if pattern.startswith(VIRTUAL_PREFIXES):
        norm_t = normalize_for_match(target, os_name)
        norm_p = normalize_for_match(pattern, os_name).rstrip("/")
        if pattern.startswith(("task://", "service://")):
            return fnmatch.fnmatchcase(norm_t, norm_p) and ".." not in norm_t
        return norm_t == norm_p or norm_t.startswith(norm_p + "/") or norm_t.startswith(norm_p + "::")

    path_cls = pathlib.PureWindowsPath if os_name == OsName.WINDOWS else pathlib.PurePosixPath
    path_t = path_cls(normalize_for_match(target, os_name))
    path_p = path_cls(normalize_for_match(pattern, os_name))
    parts_t, parts_p = path_t.parts, path_p.parts
    if "*" in pattern or "?" in pattern:
        if len(parts_t) < len(parts_p):
            return False
        if pattern.endswith((".plist", ".conf")) and len(parts_t) != len(parts_p):
            return False
        return all(fnmatch.fnmatchcase(parts_t[i], parts_p[i]) for i in range(len(parts_p)))
    return path_t == path_p or path_t.is_relative_to(path_p)


def is_under_ours(path: str, patterns: list[str], os_name: OsName) -> bool:
    is_virtual = path.startswith(VIRTUAL_PREFIXES)
    return any(
        _segment_match(path, pat, os_name)
        for pat in patterns
        if pat.startswith(VIRTUAL_PREFIXES) == is_virtual
    )


def is_ours_ancestor_dir(
    diff: DiffEntry,
    after: Mapping[str, SnapshotEntry],
    patterns: list[str],
    os_name: OsName,
) -> bool:
    if diff.kind != DiffKind.ADDED or diff.after is None or diff.after.kind != EntryKind.DIR:
        return False
    norm_dir = normalize_for_match(diff.path, os_name)
    sep = "\\" if os_name == OsName.WINDOWS else "/"
    prefix = norm_dir.rstrip(sep) + sep
    for path in after:
        if path == diff.path or path.startswith(VIRTUAL_PREFIXES):
            continue
        if normalize_for_match(path, os_name).startswith(prefix) and is_under_ours(path, patterns, os_name):
            return True
    return False


def unexpected_diffs_outside_ours(
    diffs: list[DiffEntry],
    after: Mapping[str, SnapshotEntry],
    patterns: list[str],
    os_name: OsName,
) -> list[DiffEntry]:
    return [
        diff
        for diff in diffs
        if not is_under_ours(diff.path, patterns, os_name)
        and not is_ours_ancestor_dir(diff, after, patterns, os_name)
    ]


def save_snapshot(entries: Mapping[str, SnapshotEntry], out_path: pathlib.Path) -> None:
    payload = [entry.to_dict() for entry in entries.values()]
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_snapshot(in_path: pathlib.Path) -> dict[str, SnapshotEntry]:
    raw = json.loads(in_path.read_text(encoding="utf-8"))
    return {item["path"]: SnapshotEntry.from_dict(item) for item in raw}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="snapshot.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    cap = sub.add_parser("capture")
    cap.add_argument("--roots", type=pathlib.Path, required=True)
    cap.add_argument("--profile", choices=[p.value for p in Profile], required=True)
    cap.add_argument("--out", type=pathlib.Path, required=True)

    cmp_p = sub.add_parser("diff")
    cmp_p.add_argument("before", type=pathlib.Path)
    cmp_p.add_argument("after", type=pathlib.Path)

    args = parser.parse_args(argv[1:])
    if args.cmd == "capture":
        config = load_roots_config(args.roots)
        entries = capture_snapshot(config, detect_host_os(), Profile(args.profile))
        save_snapshot(entries, args.out)
        print(f"captured {len(entries)} entries")
        return 0

    diffs = diff_snapshots(load_snapshot(args.before), load_snapshot(args.after))
    for line in format_diff(diffs):
        print(line)
    return 1 if diffs else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except OracleError as err:
        print(f"::error::{err}", file=sys.stderr)
        sys.exit(1)
