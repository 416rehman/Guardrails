# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Cross-platform step execution with Windows de-elevation and POSIX sudo support."""

import ctypes
from ctypes import wintypes
import dataclasses
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from typing import Mapping

_HERE = str(pathlib.Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from snapshot import OracleError, OsName, Profile

ERR_CONFIG = "GRDR-GATE-0010"
ERR_ELEVATION = "GRDR-GATE-0013"

DISABLE_MAX_PRIVILEGE = 0x1
LUA_TOKEN = 0x4
TOKEN_ELEVATION = 20
TOKEN_INTEGRITY_LEVEL = 25
TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ADJUST_DEFAULT = 0x0080
SE_GROUP_INTEGRITY = 0x00000020
STARTF_USESTDHANDLES = 0x00000100
CREATE_UNICODE_ENVIRONMENT = 0x00000400
HANDLE_FLAG_INHERIT = 0x00000001
INFINITE = 0xFFFFFFFF
MEDIUM_INTEGRITY_SID = "S-1-16-8192"
MEDIUM_INTEGRITY_RID = 0x2000
BUILTIN_ADMINS_SID = "S-1-5-32-544"
SECURITY_IDENTIFICATION = 1
PIPE_CHUNK_BYTES = 4096
PIPE_JOIN_SECONDS = 5
WAIT_TIMEOUT_EXIT_CODE = 124
MS_PER_SECOND = 1000


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


if os.name == "nt":
    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _StartupInfoW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
        ]

    class _ProcessInfo(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
        ]

    class _SidAndAttr(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class _TokenMandatoryLabel(ctypes.Structure):
        _fields_ = [("Label", _SidAndAttr)]

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _SHELL32 = ctypes.WinDLL("shell32", use_last_error=True)

    _SHELL32.IsUserAnAdmin.argtypes = []
    _SHELL32.IsUserAnAdmin.restype = wintypes.BOOL
    _KERNEL32.GetCurrentProcess.argtypes = []
    _KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.LocalFree.argtypes = [wintypes.HLOCAL]
    _KERNEL32.LocalFree.restype = wintypes.HLOCAL
    _KERNEL32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(_SecurityAttributes), wintypes.DWORD,
    ]
    _KERNEL32.CreatePipe.restype = wintypes.BOOL
    _KERNEL32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    _KERNEL32.SetHandleInformation.restype = wintypes.BOOL
    _KERNEL32.ReadFile.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    _KERNEL32.ReadFile.restype = wintypes.BOOL
    _KERNEL32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _KERNEL32.WaitForSingleObject.restype = wintypes.DWORD
    _KERNEL32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _KERNEL32.TerminateProcess.restype = wintypes.BOOL
    _KERNEL32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _KERNEL32.GetExitCodeProcess.restype = wintypes.BOOL
    _ADVAPI32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _ADVAPI32.OpenProcessToken.restype = wintypes.BOOL
    _ADVAPI32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]
    _ADVAPI32.GetTokenInformation.restype = wintypes.BOOL
    _ADVAPI32.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _ADVAPI32.SetTokenInformation.restype = wintypes.BOOL
    _ADVAPI32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    _ADVAPI32.ConvertStringSidToSidW.restype = wintypes.BOOL
    _ADVAPI32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _ADVAPI32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _ADVAPI32.DuplicateToken.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
    _ADVAPI32.DuplicateToken.restype = wintypes.BOOL
    _ADVAPI32.CheckTokenMembership.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL)]
    _ADVAPI32.CheckTokenMembership.restype = wintypes.BOOL
    _ADVAPI32.CreateRestrictedToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _ADVAPI32.CreateRestrictedToken.restype = wintypes.BOOL
    _ADVAPI32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfoW), ctypes.POINTER(_ProcessInfo),
    ]
    _ADVAPI32.CreateProcessAsUserW.restype = wintypes.BOOL


def is_windows_elevated() -> bool:
    if os.name != "nt":
        return False
    if _SHELL32.IsUserAnAdmin() != 0:
        return True
    token = wintypes.HANDLE()
    if not _ADVAPI32.OpenProcessToken(_KERNEL32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        return False
    try:
        elev = wintypes.DWORD(0)
        size = wintypes.DWORD(0)
        ok = _ADVAPI32.GetTokenInformation(
            token, TOKEN_ELEVATION, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(size)
        )
        return bool(ok and elev.value != 0)
    finally:
        _KERNEL32.CloseHandle(token)


def _set_medium_integrity(token: wintypes.HANDLE) -> None:
    sid = ctypes.c_void_p()
    if not _ADVAPI32.ConvertStringSidToSidW(MEDIUM_INTEGRITY_SID, ctypes.byref(sid)):
        raise OracleError(ERR_ELEVATION, f"ConvertStringSidToSidW failed ({ctypes.get_last_error()})")
    try:
        label = _TokenMandatoryLabel(_SidAndAttr(sid, SE_GROUP_INTEGRITY))
        if not _ADVAPI32.SetTokenInformation(
            token, TOKEN_INTEGRITY_LEVEL, ctypes.byref(label), ctypes.sizeof(label)
        ):
            raise OracleError(ERR_ELEVATION, f"SetTokenInformation failed ({ctypes.get_last_error()})")
    finally:
        _KERNEL32.LocalFree(sid)


def _query_token_integrity_rid(token: wintypes.HANDLE) -> int:
    needed = wintypes.DWORD(0)
    _ADVAPI32.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(needed))
    if needed.value < ctypes.sizeof(_TokenMandatoryLabel):
        raise OracleError(ERR_ELEVATION, f"GetTokenInformation(TokenIntegrityLevel) failed ({ctypes.get_last_error()})")
    buf = ctypes.create_string_buffer(needed.value)
    if not _ADVAPI32.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, buf, needed.value, ctypes.byref(needed)):
        raise OracleError(ERR_ELEVATION, f"GetTokenInformation(TokenIntegrityLevel) failed ({ctypes.get_last_error()})")
    tml = ctypes.cast(buf, ctypes.POINTER(_TokenMandatoryLabel)).contents
    sid_str = wintypes.LPWSTR()
    if not _ADVAPI32.ConvertSidToStringSidW(tml.Label.Sid, ctypes.byref(sid_str)):
        raise OracleError(ERR_ELEVATION, f"ConvertSidToStringSidW failed ({ctypes.get_last_error()})")
    try:
        text = sid_str.value or ""
    finally:
        _KERNEL32.LocalFree(sid_str)
    if not text.startswith("S-1-16-"):
        raise OracleError(ERR_ELEVATION, f"unexpected integrity SID: {text}")
    try:
        return int(text.rsplit("-", 1)[1])
    except ValueError:
        raise OracleError(ERR_ELEVATION, f"malformed integrity SID: {text}") from None


def _verify_unelevated_windows_token(token: wintypes.HANDLE) -> None:
    rid = _query_token_integrity_rid(token)
    if rid > MEDIUM_INTEGRITY_RID:
        raise OracleError(ERR_ELEVATION, f"de-elevated token integrity RID too high: {rid}")

    elev = wintypes.DWORD(1)
    size = wintypes.DWORD(0)
    if not _ADVAPI32.GetTokenInformation(
        token, TOKEN_ELEVATION, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(size)
    ):
        raise OracleError(ERR_ELEVATION, f"GetTokenInformation(TokenElevation) failed ({ctypes.get_last_error()})")
    if elev.value != 0:
        raise OracleError(ERR_ELEVATION, "de-elevated token remained elevated")

    imp_token = wintypes.HANDLE()
    if not _ADVAPI32.DuplicateToken(token, SECURITY_IDENTIFICATION, ctypes.byref(imp_token)):
        raise OracleError(ERR_ELEVATION, f"DuplicateToken failed ({ctypes.get_last_error()})")
    try:
        admin_sid = ctypes.c_void_p()
        if not _ADVAPI32.ConvertStringSidToSidW(BUILTIN_ADMINS_SID, ctypes.byref(admin_sid)):
            raise OracleError(ERR_ELEVATION, f"ConvertStringSidToSidW(admins) failed ({ctypes.get_last_error()})")
        try:
            is_admin = wintypes.BOOL(1)
            if not _ADVAPI32.CheckTokenMembership(imp_token, admin_sid, ctypes.byref(is_admin)):
                raise OracleError(ERR_ELEVATION, f"CheckTokenMembership failed ({ctypes.get_last_error()})")
            if is_admin.value != 0:
                raise OracleError(ERR_ELEVATION, "de-elevated token retained administrator membership")
        finally:
            _KERNEL32.LocalFree(admin_sid)
    finally:
        _KERNEL32.CloseHandle(imp_token)


def _create_unelevated_windows_token() -> wintypes.HANDLE:
    proc_token = wintypes.HANDLE()
    desired = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT
    if not _ADVAPI32.OpenProcessToken(_KERNEL32.GetCurrentProcess(), desired, ctypes.byref(proc_token)):
        raise OracleError(ERR_ELEVATION, f"OpenProcessToken failed ({ctypes.get_last_error()})")
    try:
        restricted = wintypes.HANDLE()
        if not _ADVAPI32.CreateRestrictedToken(
            proc_token,
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
            0,
            None,
            0,
            None,
            0,
            None,
            ctypes.byref(restricted),
        ):
            raise OracleError(ERR_ELEVATION, f"CreateRestrictedToken failed ({ctypes.get_last_error()})")
        try:
            _set_medium_integrity(restricted)
            _verify_unelevated_windows_token(restricted)
        except Exception:
            _KERNEL32.CloseHandle(restricted)
            raise
        return restricted
    finally:
        _KERNEL32.CloseHandle(proc_token)


def _run_with_windows_token(
    argv: list[str],
    env: Mapping[str, str],
    cwd: pathlib.Path,
    timeout_seconds: int,
) -> CommandResult:
    sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
    in_r, in_w = wintypes.HANDLE(), wintypes.HANDLE()
    out_r, out_w = wintypes.HANDLE(), wintypes.HANDLE()
    err_r, err_w = wintypes.HANDLE(), wintypes.HANDLE()
    if not _KERNEL32.CreatePipe(ctypes.byref(in_r), ctypes.byref(in_w), ctypes.byref(sa), 0):
        raise OracleError(ERR_ELEVATION, "CreatePipe stdin failed")
    if not _KERNEL32.CreatePipe(ctypes.byref(out_r), ctypes.byref(out_w), ctypes.byref(sa), 0):
        _KERNEL32.CloseHandle(in_r)
        _KERNEL32.CloseHandle(in_w)
        raise OracleError(ERR_ELEVATION, "CreatePipe stdout failed")
    if not _KERNEL32.CreatePipe(ctypes.byref(err_r), ctypes.byref(err_w), ctypes.byref(sa), 0):
        _KERNEL32.CloseHandle(in_r)
        _KERNEL32.CloseHandle(in_w)
        _KERNEL32.CloseHandle(out_r)
        _KERNEL32.CloseHandle(out_w)
        raise OracleError(ERR_ELEVATION, "CreatePipe stderr failed")
    _KERNEL32.SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0)
    _KERNEL32.SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0)
    _KERNEL32.SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0)

    try:
        token = _create_unelevated_windows_token()
    except Exception:
        for handle in (in_r, in_w, out_r, out_w, err_r, err_w):
            _KERNEL32.CloseHandle(handle)
        raise
    si = _StartupInfoW()
    si.cb = ctypes.sizeof(_StartupInfoW)
    si.dwFlags = STARTF_USESTDHANDLES
    si.hStdInput = in_r
    si.hStdOutput = out_w
    si.hStdError = err_w
    pi = _ProcessInfo()
    env_block = ctypes.create_unicode_buffer("\0".join(f"{k}={v}" for k, v in env.items()) + "\0\0")
    cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
    ok = _ADVAPI32.CreateProcessAsUserW(
        token, None, cmdline, None, None, True, CREATE_UNICODE_ENVIRONMENT, env_block,
        str(cwd), ctypes.byref(si), ctypes.byref(pi),
    )
    _KERNEL32.CloseHandle(token)
    _KERNEL32.CloseHandle(in_r)
    _KERNEL32.CloseHandle(in_w)
    _KERNEL32.CloseHandle(out_w)
    _KERNEL32.CloseHandle(err_w)
    if not ok:
        _KERNEL32.CloseHandle(out_r)
        _KERNEL32.CloseHandle(err_r)
        raise OracleError(ERR_ELEVATION, f"CreateProcessAsUserW failed ({ctypes.get_last_error()})")

    chunks_out: list[bytes] = []
    chunks_err: list[bytes] = []

    def _drain(handle: wintypes.HANDLE, sink: list[bytes]) -> None:
        buf = ctypes.create_string_buffer(PIPE_CHUNK_BYTES)
        read_n = wintypes.DWORD(0)
        while (
            _KERNEL32.ReadFile(handle, buf, PIPE_CHUNK_BYTES, ctypes.byref(read_n), None)
            and read_n.value > 0
        ):
            sink.append(buf.raw[: read_n.value])
        _KERNEL32.CloseHandle(handle)

    t1 = threading.Thread(target=_drain, args=(out_r, chunks_out), daemon=True)
    t2 = threading.Thread(target=_drain, args=(err_r, chunks_err), daemon=True)
    t1.start()
    t2.start()
    wait_ms = timeout_seconds * MS_PER_SECOND if timeout_seconds > 0 else INFINITE
    if _KERNEL32.WaitForSingleObject(pi.hProcess, wait_ms) != 0:
        _KERNEL32.TerminateProcess(pi.hProcess, WAIT_TIMEOUT_EXIT_CODE)
    exit_code = wintypes.DWORD(1)
    _KERNEL32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))
    _KERNEL32.CloseHandle(pi.hProcess)
    _KERNEL32.CloseHandle(pi.hThread)
    t1.join(timeout=PIPE_JOIN_SECONDS)
    t2.join(timeout=PIPE_JOIN_SECONDS)
    return CommandResult(
        returncode=int(exit_code.value),
        stdout=b"".join(chunks_out).decode("utf-8", "replace"),
        stderr=b"".join(chunks_err).decode("utf-8", "replace"),
    )


def _has_working_python3() -> bool:
    candidate = shutil.which("python3")
    if candidate is None:
        return False
    return not (os.name == "nt" and "windowsapps" in candidate.lower())


def _windows_git_bash() -> str | None:
    found = shutil.which("bash")
    if found and not found.lower().endswith("\\system32\\bash.exe"):
        return found
    for prefix in (os.environ.get("ProgramFiles", ""), os.environ.get("ProgramW6432", "")):
        if prefix:
            candidate = pathlib.Path(prefix) / "Git" / "bin" / "bash.exe"
            if candidate.is_file():
                return str(candidate)
    return found


def shell_argv_for_command(cmd: str) -> list[str]:
    if os.name == "nt" and cmd.startswith("python3 ") and not _has_working_python3():
        rest = shlex.split(cmd[len("python3 "):], posix=False)
        return [sys.executable, *[part.strip('"') for part in rest]]
    bash = _windows_git_bash() if os.name == "nt" else shutil.which("bash")
    if bash is not None:
        return [bash, "-eo", "pipefail", "-c", cmd]
    if os.name == "nt":
        return ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd]
    raise OracleError(ERR_CONFIG, "bash is missing on runner")


def run_argv(
    argv: list[str],
    env: Mapping[str, str],
    cwd: pathlib.Path,
    timeout_seconds: int,
    *,
    deelevate_windows: bool = False,
) -> CommandResult:
    if deelevate_windows and os.name == "nt" and is_windows_elevated():
        return _run_with_windows_token(argv, env, cwd, timeout_seconds)
    proc = subprocess.run(
        argv,
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def _run_posix_elevated(
    argv: list[str],
    env: Mapping[str, str],
    cwd: pathlib.Path,
    timeout_seconds: int,
) -> CommandResult:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        return run_argv(argv, env, cwd, timeout_seconds)
    if shutil.which("sudo") is None:
        raise OracleError(ERR_ELEVATION, "sudo is missing for elevated execution")
    sudo_env = [
        f"{k}={env[k]}"
        for k in ("HOME", "PATH", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME")
        if k in env
    ]
    with tempfile.TemporaryDirectory() as tmp:
        marker = pathlib.Path(tmp) / "uid"
        wrapped = [
            "sudo",
            "-n",
            "env",
            *sudo_env,
            "/bin/sh",
            "-c",
            'printf "%s" "$(id -u)" > "$1" && chmod 0644 "$1" && shift && exec "$@"',
            "grdr-sudo-check",
            str(marker),
            *argv,
        ]
        res = run_argv(wrapped, env, cwd, timeout_seconds)
        try:
            uid_text = marker.read_text(encoding="utf-8").strip()
        except OSError:
            uid_text = ""
    if uid_text != "0":
        raise OracleError(ERR_ELEVATION, f"sudo -n failed before running command as uid 0 (rc={res.returncode})")
    return res


def run_step_command(
    cmd: str,
    os_name: OsName,
    profile: Profile,
    env: Mapping[str, str],
    cwd: pathlib.Path,
    timeout_seconds: int,
    *,
    elevated: bool = False,
) -> CommandResult:
    argv = shell_argv_for_command(cmd)
    if elevated:
        if os_name == OsName.WINDOWS:
            if not is_windows_elevated():
                raise OracleError(ERR_ELEVATION, "Windows runner token is not elevated")
            return run_argv(argv, env, cwd, timeout_seconds, deelevate_windows=False)
        return _run_posix_elevated(argv, env, cwd, timeout_seconds)
    deelevate = os_name == OsName.WINDOWS and profile == Profile.USER
    return run_argv(argv, env, cwd, timeout_seconds, deelevate_windows=deelevate)
