"""List the paths that touch the trust core.

Usage: python3 -I trust_core_touched.py (--list <file> | --from-rev <rev>)
                                        (--diff <base> <head> | --paths <path>...)

Each line of the list matches as a git :(glob,icase) pathspec from the root, and git does the
matching; a folder line `x/**` also matches the path `x`. --from-rev reads the list and
check_tree.py from that revision's git objects; otherwise they come from the file named and from
beside this file. --diff takes the paths of git diff --name-only --no-renames
--ignore-submodules=none, so a rename gives both names, and then prints check_tree.py's findings on
<head>. Revisions are full object ids. git comes from an absolute PATH entry, runs with object
replacement turned off, and needs no working tree, so GIT_DIR may name the repository. Modes that
read revisions refuse when the repository holds a ref under refs/replace/. Exit 0 when nothing is
printed, 1 when something is, and 2 on an input error, a replacement ref, or any stop.
"""

import argparse
import dataclasses
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import types

HERE = pathlib.Path(__file__).resolve().parent
LIST_PATH = "security/trust-core.paths"
CHECK_TREE_PATH = ".github/actions/tree-paths/check_tree.py"
MAGIC = ":(top,glob,icase)"
EVERY_PATH = ":(top)"
FOLDER_SUFFIX = "/**"
FILE_MODE = "100644"
PRINTABLE = range(0x20, 0x7F)
GIT_NAMES = ("git.exe",) if os.name == "nt" else ("git",)
OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")

# Settings that change which paths git takes into an index or how it reads a pathspec, fixed so
# the answer does not depend on the host or the caller's environment.
GIT_SETTINGS = ["-c", "core.ignorecase=false", "-c", "core.protectNTFS=false", "-c", "core.protectHFS=false"]
PATHSPEC_ENVIRONMENT = ("GIT_LITERAL_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS", "GIT_ICASE_PATHSPECS")


class InputError(Exception):
    pass


class ReplacementRefError(Exception):
    pass


@dataclasses.dataclass
class IndexGroup:
    paths: set
    folders: set


@dataclasses.dataclass
class Rules:
    patterns: list
    check_tree: types.ModuleType


def is_absolute_folder(folder):
    return os.path.isabs(folder) and (os.name != "nt" or bool(os.path.splitdrive(folder)[0]))


def git_program():
    """git from an absolute PATH entry, never from the working directory."""
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        for name in GIT_NAMES if is_absolute_folder(folder) else ():
            candidate = os.path.join(folder, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    raise InputError("git is not on PATH")


def git(args, stdin=b"", index=None):
    environment = {key: value for key, value in os.environ.items() if key.upper() not in PATHSPEC_ENVIRONMENT}
    if index is not None:
        environment["GIT_INDEX_FILE"] = index
    try:
        result = subprocess.run(
            [git_program(), "--no-replace-objects", *GIT_SETTINGS, *args], input=stdin, env=environment,
            capture_output=True, check=False,
        )
    except OSError as error:
        raise InputError(f"cannot run git: {type(error).__name__}") from None
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise InputError(message or f"git {args[0]} exited {result.returncode}")
    return result.stdout


def check_replacement_refs():
    if git(["for-each-ref", "--format=%(refname)", "refs/replace/"]):
        raise ReplacementRefError("the repository holds a ref under refs/replace/")


def read_file(path):
    try:
        return pathlib.Path(path).read_bytes()
    except OSError as error:
        raise InputError(f"cannot read {path}: {type(error).__name__}") from None


def exact_rev(rev):
    """A full object id; a short name may resolve through another ref first."""
    if OBJECT_ID.fullmatch(rev):
        return rev
    raise InputError(f"{rev!a} is not a full object id")


def read_object(rev, path):
    return git(["cat-file", "blob", "--end-of-options", f"{rev}:{path}"])


def parse_list(text, origin):
    lines = [line.strip() for line in text.splitlines()]
    patterns = [line for line in lines if line and not line.startswith(b"#")]
    if not patterns:
        raise InputError(f"{origin} holds no pattern")
    if any(byte not in PRINTABLE for pattern in patterns for byte in pattern):
        raise InputError(f"{origin} holds a line outside printable ASCII")
    return [pattern.decode("ascii") for pattern in patterns]


def load_check_tree(source, origin):
    """Run check_tree.py's source as a module, so no bytecode file is read or written."""
    module = types.ModuleType("check_tree")
    module.__file__ = origin
    exec(compile(source, origin, "exec"), module.__dict__)
    return module


def read_rules(arguments):
    if arguments.from_rev is None:
        source = HERE / "check_tree.py"
        patterns = parse_list(read_file(arguments.list), arguments.list)
        return Rules(patterns, load_check_tree(read_file(source), str(source)))
    rev = exact_rev(arguments.from_rev)
    patterns = parse_list(read_object(rev, LIST_PATH), f"{rev}:{LIST_PATH}")
    return Rules(patterns, load_check_tree(read_object(rev, CHECK_TREE_PATH), f"{rev}:{CHECK_TREE_PATH}"))


def pathspecs(patterns):
    specs = []
    for pattern in patterns:
        specs.append(MAGIC + pattern)
        if pattern.endswith(FOLDER_SUFFIX):
            specs.append(MAGIC + pattern.removesuffix(FOLDER_SUFFIX))
    return specs


def folders_above(path):
    return {path[:at] for at, byte in enumerate(path) if byte == ord("/")}


def index_groups(paths):
    """Split the paths so that no group holds both a path and a path below it: one index cannot."""
    groups = []
    for path in paths:
        above = folders_above(path)
        group = next((g for g in groups if path not in g.folders and g.paths.isdisjoint(above)), None)
        if group is None:
            group = IndexGroup(set(), set())
            groups.append(group)
        group.paths.add(path)
        group.folders.update(above)
    return [group.paths for group in groups]


def fill_index(index, blob, paths):
    entries = b"".join(f"{FILE_MODE} {blob}\t".encode("ascii") + path + b"\0" for path in sorted(paths))
    git(["update-index", "--add", "-z", "--index-info"], stdin=entries, index=index)
    held = git(["ls-files", "-z", "--full-name", "--", EVERY_PATH], index=index)
    if set(held.split(b"\0")) - {b""} != paths:
        raise InputError("git did not take every path into the index")


def listed(index, patterns):
    specs = pathspecs(patterns)
    return set(git(["ls-files", "-z", "--full-name", "--", *specs], index=index).split(b"\0"))


def matched_sets(pattern_lists, paths):
    """For each list of patterns, the set of paths that one of its patterns matches."""
    blob = git(["hash-object", "-t", "blob", "--stdin"]).strip().decode("ascii")
    results = [set() for _ in pattern_lists]
    for group in index_groups(dict.fromkeys(paths)):
        with tempfile.TemporaryDirectory() as scratch:
            index = os.path.join(scratch, "index")
            fill_index(index, blob, group)
            for result, patterns in zip(results, pattern_lists):
                result |= listed(index, patterns) & group
    return results


def matching(patterns, paths):
    """Return the paths, in their first order and each once, that a pattern matches."""
    unique = list(dict.fromkeys(paths))
    if not unique:
        return []
    matched = matched_sets([patterns], unique)[0]
    return [path for path in unique if path in matched]


def changed_paths(base, head):
    names = git([
        "diff", "--name-only", "--no-renames", "--no-relative", "--ignore-submodules=none", "-z",
        "--end-of-options", base, head, "--",
    ])
    return [name for name in names.split(b"\0") if name]


def tree_findings(check_tree, head):
    replacement_error = getattr(check_tree, "ReplacementRefError", ())
    try:
        return check_tree.report_lines(head)
    except replacement_error as error:
        raise ReplacementRefError(str(error)) from None
    except check_tree.Unreadable as error:
        raise InputError(f"cannot read the tree of {head!a}: {error}") from None


def report_lines(arguments):
    if arguments.from_rev is not None or arguments.diff is not None:
        check_replacement_refs()
    rules = read_rules(arguments)
    shown = rules.check_tree.shown
    if arguments.diff is None:
        paths = [os.fsencode(path) for path in arguments.paths]
        return [shown(path) for path in matching(rules.patterns, paths)]
    base, head = (exact_rev(rev) for rev in arguments.diff)
    touched = matching(rules.patterns, changed_paths(base, head))
    return [shown(path) for path in touched] + tree_findings(rules.check_tree, head)


def main(argv):
    parser = argparse.ArgumentParser(description="List the paths that touch the trust core.")
    rules = parser.add_mutually_exclusive_group(required=True)
    rules.add_argument("--list")
    rules.add_argument("--from-rev")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--diff", nargs=2, metavar=("BASE", "HEAD"))
    source.add_argument("--paths", nargs="+", metavar="PATH")
    arguments = parser.parse_args(argv)
    try:
        lines = report_lines(arguments)
    except ReplacementRefError as error:
        print(f"::error::GRDR-GATE-0007 {error}", file=sys.stderr)
        return 2
    except InputError as error:
        print(f"::error::GRDR-GATE-0002 {error}", file=sys.stderr)
        return 2
    for line in lines:
        print(line)
    return 1 if lines else 0


if __name__ == "__main__":
    try:
        status = main(sys.argv[1:])
    except Exception as error:
        print(f"::error::GRDR-GATE-0005 the matcher stopped: {type(error).__name__}", file=sys.stderr)
        status = 2
    sys.exit(status)
