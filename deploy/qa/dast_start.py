# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Build web console + grdr-server and launch the embedded server for OWASP ZAP DAST."""

import os
import pathlib
import shutil
import subprocess


def _repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


def _run(cmd: list[str], cwd: pathlib.Path, env: dict[str, str]) -> None:
    proc = subprocess.run(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def _find_pnpm(root: pathlib.Path, env: dict[str, str]) -> list[str]:
    pnpm = shutil.which("pnpm")
    if pnpm:
        return [pnpm]
    corepack = shutil.which("corepack")
    if corepack:
        _run([corepack, "enable"], root, env)
        _run([corepack, "prepare", "pnpm@10.6.1", "--activate"], root, env)
        return [corepack, "pnpm"]
    raise SystemExit("pnpm or corepack is required to build web/")


def main() -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["CI"] = "true"
    pnpm_cmd = _find_pnpm(root, env)
    _run([*pnpm_cmd, "--dir", "web", "install", "--frozen-lockfile"], root, env)
    _run([*pnpm_cmd, "--dir", "web", "run", "build"], root, env)
    _run(["cargo", "build", "--release", "--locked", "--bin", "grdr-server"], root, env)

    suffix = ".exe" if os.name == "nt" else ""
    server_bin = root / "target" / "release" / f"grdr-server{suffix}"
    args = [
        str(server_bin),
        "--bind",
        "127.0.0.1:8787",
        "--profile",
        "embedded",
        "--memory",
        "--demo-seed",
        "--web-dir",
        str(root / "web" / "dist"),
    ]
    os.execv(str(server_bin), args)


if __name__ == "__main__":
    main()
