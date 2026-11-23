"""Refuse the path kinds a revision's tree may not hold.

Usage: python3 -I check_tree.py --rev <rev>

The tree comes from git objects (git ls-tree -r -t -z), never from a working tree, so every runner
gives the same answer. Object replacement is turned off, and the check refuses when the repository
holds a ref under refs/replace/. Each refused path is printed with the rule it breaks. Exit 0 when
no rule is broken, 1 when one is, and 2 when the revision cannot be read, a replacement ref exists,
or the check stops.
"""

import argparse
import os
import re
import subprocess
import sys

PRINTABLE = range(0x20, 0x7F)
TOOLCHAIN_FILE = b"rust-toolchain"
SHORT_NAME = re.compile(rb"~[0-9]")
SYMBOLIC_LINK = b"120000"
SUBMODULE = b"160000"
GIT_NAMES = ("git.exe",) if os.name == "nt" else ("git",)

RULE_BYTES = "a byte outside printable ASCII"
RULE_CASE = "a path equal to another under ASCII case folding"
RULE_TOOLCHAIN = "a rust-toolchain file"
RULE_SHORT_NAME = "a path segment holding ~ and a digit"
RULE_SYMBOLIC_LINK = "a symbolic link"
RULE_SUBMODULE = "a submodule"
RULES = (RULE_BYTES, RULE_CASE, RULE_TOOLCHAIN, RULE_SHORT_NAME, RULE_SYMBOLIC_LINK, RULE_SUBMODULE)
MODE_RULES = {SYMBOLIC_LINK: RULE_SYMBOLIC_LINK, SUBMODULE: RULE_SUBMODULE}


class Unreadable(Exception):
    pass


class ReplacementRefError(Exception):
    pass


def shown(path):
    return "".join(chr(byte) if byte in PRINTABLE else f"\\x{byte:02x}" for byte in path)


def is_absolute_folder(folder):
    return os.path.isabs(folder) and (os.name != "nt" or bool(os.path.splitdrive(folder)[0]))


def git_program():
    """git from an absolute PATH entry, never from the working directory."""
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        for name in GIT_NAMES if is_absolute_folder(folder) else ():
            candidate = os.path.join(folder, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    raise Unreadable("git is not on PATH")


def git(*args):
    try:
        result = subprocess.run([git_program(), "--no-replace-objects", *args], capture_output=True, check=False)
    except OSError as error:
        raise Unreadable(f"cannot run git: {type(error).__name__}") from None
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise Unreadable(message or f"git {args[0]} exited {result.returncode}")
    return result.stdout


def check_replacement_refs():
    if git("for-each-ref", "--format=%(refname)", "refs/replace/"):
        raise ReplacementRefError("the repository holds a ref under refs/replace/")


def tree_entries(rev):
    """Each entry of the tree, folders included, as (mode, path)."""
    check_replacement_refs()
    tree = git("rev-parse", "--verify", "--quiet", "--end-of-options", f"{rev}^{{tree}}").strip()
    listing = git("ls-tree", "-r", "-t", "-z", "--full-tree", tree.decode("ascii"))
    entries = []
    for entry in listing.split(b"\0"):
        if entry:
            meta, _, path = entry.partition(b"\t")
            entries.append((meta.split(b" ")[0], path))
    return entries


def findings(entries):
    found = []
    folded = {}
    for mode, path in entries:
        folded.setdefault(path.lower(), set()).add(path)
        segments = path.split(b"/")
        if any(byte not in PRINTABLE for byte in path):
            found.append((RULE_BYTES, path))
        if segments[-1].lower() == TOOLCHAIN_FILE:
            found.append((RULE_TOOLCHAIN, path))
        if any(SHORT_NAME.search(segment) for segment in segments):
            found.append((RULE_SHORT_NAME, path))
        if mode in MODE_RULES:
            found.append((MODE_RULES[mode], path))
    for variants in folded.values():
        if len(variants) > 1:
            found.extend((RULE_CASE, path) for path in variants)
    return sorted(found)


def report_lines(rev):
    return [f"refused ({rule}): {shown(path)}" for rule, path in findings(tree_entries(rev))]


def main(argv):
    parser = argparse.ArgumentParser(description="Refuse the path kinds a tree may not hold.")
    parser.add_argument("--rev", required=True)
    rev = parser.parse_args(argv).rev
    try:
        lines = report_lines(rev)
    except ReplacementRefError as error:
        print(f"::error::GRDR-GATE-0007 {error}", file=sys.stderr)
        return 2
    except Unreadable as error:
        print(f"::error::GRDR-GATE-0001 cannot read the tree of {rev!a}: {error}", file=sys.stderr)
        return 2
    for line in lines:
        print(line)
    return 1 if lines else 0


if __name__ == "__main__":
    try:
        status = main(sys.argv[1:])
    except Exception as error:
        print(f"::error::GRDR-GATE-0005 the tree check stopped: {type(error).__name__}", file=sys.stderr)
        status = 2
    sys.exit(status)
