"""Print the toolchain that a commit's rust-toolchain.toml pins as KEY=value lines for GITHUB_OUTPUT.

Usage: python3 -I pinned_toolchain.py <rev>

Reads rust-toolchain.toml from the git objects of <rev>, never from the working tree, with object
replacement turned off, and refuses while the repository holds a ref under refs/replace/. git comes
from an absolute PATH entry, never from the working directory, and runs with no GIT_ variable of
the caller. Prints RUSTUP_TOOLCHAIN (the channel), TOOLCHAIN_PROFILE, and TOOLCHAIN_COMPONENTS and
TOOLCHAIN_TARGETS separated by commas; a value the file leaves out is empty. Nothing is printed
unless the file parses, its [toolchain] table has a channel and no path key, and every value is one
toolchain word. A refusal exits 1 with a GRDR-GATE code on stderr.
"""

import os
import re
import subprocess
import sys
import tomllib

TOOLCHAIN_FILE = "rust-toolchain.toml"
WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
GIT_NAMES = ("git.exe",) if os.name == "nt" else ("git",)


class Refusal(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code} {message}")


def git_program():
    """git from an absolute PATH entry, never from the working directory."""
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        for name in GIT_NAMES if os.path.isabs(folder) else ():
            candidate = os.path.join(folder, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    raise Refusal("GRDR-GATE-0003", "git is not on PATH")


def git_environment():
    """The caller's environment with no GIT_ variable, and object replacement turned off."""
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def git(*args):
    try:
        result = subprocess.run(
            [git_program(), "--no-replace-objects", *args], env=git_environment(), capture_output=True, check=False,
        )
    except OSError as error:
        raise Refusal("GRDR-GATE-0003", f"cannot run git: {type(error).__name__}") from None
    if result.returncode != 0:
        raise Refusal("GRDR-GATE-0003", f"git {args[0]} exited {result.returncode}")
    return result.stdout


def committed_file(rev):
    if git("for-each-ref", "--format=%(refname)", "refs/replace/"):
        raise Refusal("GRDR-GATE-0007", "the repository holds a ref under refs/replace/")
    commit = git("rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}").decode("ascii").strip()
    return git("cat-file", "blob", f"{commit}:{TOOLCHAIN_FILE}")


def read_toolchain(rev):
    source = f"{rev}:{TOOLCHAIN_FILE}"
    try:
        table = tomllib.loads(committed_file(rev).decode("utf-8")).get("toolchain")
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise Refusal("GRDR-GATE-0003", f"cannot read {source}: {type(error).__name__}") from None
    if not isinstance(table, dict):
        raise Refusal("GRDR-GATE-0004", f"{source} has no [toolchain] table")
    if "path" in table:
        raise Refusal("GRDR-GATE-0004", f"{source} names a toolchain by path")
    return source, table


def word(source, key, value):
    if not isinstance(value, str) or not WORD.fullmatch(value):
        raise Refusal("GRDR-GATE-0004", f"{source} [toolchain] {key} is not a toolchain word")
    return value


def words(source, key, values):
    if not isinstance(values, list):
        raise Refusal("GRDR-GATE-0004", f"{source} [toolchain] {key} is not a list")
    return ",".join(word(source, key, value) for value in values)


def pin_lines(source, table):
    if "channel" not in table:
        raise Refusal("GRDR-GATE-0004", f"{source} [toolchain] has no channel")
    profile = table.get("profile")
    return [
        f"RUSTUP_TOOLCHAIN={word(source, 'channel', table['channel'])}",
        f"TOOLCHAIN_PROFILE={'' if profile is None else word(source, 'profile', profile)}",
        f"TOOLCHAIN_COMPONENTS={words(source, 'components', table.get('components', []))}",
        f"TOOLCHAIN_TARGETS={words(source, 'targets', table.get('targets', []))}",
    ]


def main(argv):
    if len(argv) != 2:
        raise Refusal("GRDR-GATE-0003", "usage: pinned_toolchain.py <rev>")
    print("\n".join(pin_lines(*read_toolchain(argv[1]))))


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Refusal as refusal:
        print(f"::error::{refusal}", file=sys.stderr)
        sys.exit(1)
