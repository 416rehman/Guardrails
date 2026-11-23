"""Fixture trees and process helpers for the tree-paths tests.

Each tree is built in a throwaway repository with git update-index --index-info, the stdin form of
--cacheinfo, so one index holds paths that differ only in case or carry any byte, on any host.
A path is a file unless it is given as (mode, path).
"""

import functools
import os
import pathlib
import shutil
import subprocess
import tempfile

GIT_SETTINGS = ["-c", "core.ignorecase=false", "-c", "core.protectNTFS=false", "-c", "core.protectHFS=false"]
IDENTITY = ["-c", "user.name=fixture", "-c", "user.email=fixture@example.com"]
FILE = "100644"
SYMBOLIC_LINK = "120000"
SUBMODULE = "160000"
SUBMODULE_COMMIT = "5e" * 20
GIT_BINARY_NAME = "git.exe" if os.name == "nt" else "git"
WINDOWS_CSC = (
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
)
PLANTED_CS = (
    "using System;\n"
    "using System.IO;\n"
    "class PlantedGit {\n"
    "    static int Main() {\n"
    '        var marker = Environment.GetEnvironmentVariable("GRDR_PLANTED_MARKER");\n'
    '        if (!string.IsNullOrEmpty(marker)) File.AppendAllText(marker, "planted\\n");\n'
    "        return 2;\n"
    "    }\n"
    "}\n"
)
PLANTED_RS = (
    "use std::fs::OpenOptions;\n"
    "use std::io::Write;\n"
    "fn main() {\n"
    '    if let Ok(path) = std::env::var("GRDR_PLANTED_MARKER") {\n'
    "        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {\n"
    '            let _ = file.write_all(b"planted\\n");\n'
    "        }\n"
    "    }\n"
    "    std::process::exit(2);\n"
    "}\n"
)
DROP_GIT_ENV = {
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "MSYS_NO_PATHCONV",
    "NODEFAULTCURRENTDIRECTORYINEXEPATH",
}

CLEAN = [b"README.md", b"Cargo.toml", b"rust-toolchain.toml", b"crates/a/Cargo.toml", b"crates/a/src/lib.rs"]

# Each seeded case, and the paths it must name.
SEEDED = {
    "case-variant-path": (CLEAN + [b"readme.md"], {b"README.md", b"readme.md"}),
    "case-variant-prefix": (CLEAN + [b"Crates/b/src/lib.rs"], {b"crates", b"Crates"}),
    "case-variant-nested-prefix": (CLEAN + [b"crates/A/x.rs"], {b"crates/a", b"crates/A"}),
    "byte-outside-ascii": (CLEAN + [b"docs/caf\xc3\xa9.md", b"docs/tab\there.md"],
                           {b"docs/caf\xc3\xa9.md", b"docs/tab\there.md"}),
    "toolchain-file-root": (CLEAN + [b"rust-toolchain"], {b"rust-toolchain"}),
    "toolchain-file-nested": (CLEAN + [b"crates/a/rust-toolchain"], {b"crates/a/rust-toolchain"}),
    "toolchain-file-variant": (CLEAN + [b"crates/a/Rust-Toolchain"], {b"crates/a/Rust-Toolchain"}),
    "tilde-digit-file": (CLEAN + [b"CARGO~1.TOM"], {b"CARGO~1.TOM"}),
    "tilde-digit-folder": (CLEAN + [b"crates/A~12/src/lib.rs"], {b"crates/A~12", b"crates/A~12/src/lib.rs"}),
    "symbolic-link": (CLEAN + [(SYMBOLIC_LINK, b"crates/b")], {b"crates/b"}),
    "symbolic-link-nested": (CLEAN + [(SYMBOLIC_LINK, b"crates/a/src/.cargo")], {b"crates/a/src/.cargo"}),
    "submodule": (CLEAN + [(SUBMODULE, b"crates/b")], {b"crates/b"}),
    "submodule-nested": (CLEAN + [(SUBMODULE, b"crates/a/src/v")], {b"crates/a/src/v"}),
}


class FixtureRepo:
    def __init__(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.root = self.scratch.name
        self.indexes = 0
        self.git("init", "-q")
        self.blob = self.git("hash-object", "-w", "--stdin", stdin=b"fixture\n").strip().decode("ascii")

    def git(self, *args, stdin=b"", index=None):
        environment = clean_git_env({"GIT_INDEX_FILE": index} if index is not None else None)
        result = subprocess.run(
            ["git", "--no-replace-objects", *GIT_SETTINGS, *args], cwd=self.root, input=stdin, env=environment,
            capture_output=True, check=True,
        )
        return result.stdout

    def plain_git(self, *args, stdin=b""):
        result = subprocess.run(
            ["git", *GIT_SETTINGS, *args], cwd=self.root, input=stdin, env=clean_git_env(),
            capture_output=True, check=False,
        )
        return result

    def replace(self, target, replacement):
        self.git("replace", target, replacement)

    def tree(self, items, contents=None):
        """Write a tree of the items, plus a file with those bytes for each path in contents."""
        self.indexes += 1
        index = os.path.join(self.root, ".git", f"fixture-index-{self.indexes}")
        blobs = {path: self.git("hash-object", "-w", "--stdin", stdin=text).strip().decode("ascii")
                 for path, text in (contents or {}).items()}
        lines = []
        for mode, path in map(entry, [*items, *blobs]):
            target = SUBMODULE_COMMIT if mode == SUBMODULE else blobs.get(path, self.blob)
            lines.append(f"{mode} {target}\t".encode("ascii") + path + b"\0")
        self.git("update-index", "--add", "-z", "--index-info", stdin=b"".join(lines), index=index)
        return self.git("write-tree", index=index).strip().decode("ascii")

    def commit(self, tree, *parents):
        """Write a commit of the tree and return its id."""
        parent_args = [arg for parent in parents for arg in ("-p", parent)]
        return self.git(*IDENTITY, "commit-tree", tree, *parent_args, "-m", "fixture").strip().decode("ascii")

    def listed(self, tree):
        """git's own record of a tree: every (mode, path) ls-tree -r -t gives, folders included."""
        listing = self.git("ls-tree", "-r", "-t", "-z", tree)
        records = []
        for record in listing.split(b"\0"):
            if record:
                meta, _, path = record.partition(b"\t")
                records.append((meta.split(b" ")[0].decode("ascii"), path))
        return records

    def close(self):
        self.scratch.cleanup()


def entry(item):
    return item if isinstance(item, tuple) else (FILE, item)


def path_of(item):
    return entry(item)[1]


def clean_git_env(extra=None):
    environment = {key: value for key, value in os.environ.items() if key.upper() not in DROP_GIT_ENV}
    if extra:
        environment.update(extra)
    return environment


def strip_once(text, old, new=""):
    if old not in text:
        raise AssertionError(f"expected substring missing from copy: {old!r}")
    updated = text.replace(old, new, 1)
    if updated == text:
        raise AssertionError(f"replacement did not change text for: {old!r}")
    return updated


@functools.cache
def windows_planted_git_bytes():
    with tempfile.TemporaryDirectory() as scratch:
        folder = pathlib.Path(scratch)
        exe = folder / "git.exe"
        csc = next((path for path in WINDOWS_CSC if os.path.isfile(path)), None)
        if csc is not None:
            source = folder / "planted.cs"
            source.write_text(PLANTED_CS, encoding="ascii")
            subprocess.run([csc, "/nologo", f"/out:{exe}", str(source)], capture_output=True, check=True)
            return exe.read_bytes()
        rustc = shutil.which("rustc")
        if rustc is None:
            raise AssertionError("no Windows compiler (csc.exe or rustc) to build planted git fixture")
        source = folder / "planted.rs"
        source.write_text(PLANTED_RS, encoding="ascii")
        subprocess.run([rustc, "-o", str(exe), str(source)], capture_output=True, check=True)
        return exe.read_bytes()


def plant_git(folder):
    target = pathlib.Path(folder) / GIT_BINARY_NAME
    if os.name == "nt":
        target.write_bytes(windows_planted_git_bytes())
        return target
    target.write_text('#!/bin/sh\nprintf "planted\\n" >> "$GRDR_PLANTED_MARKER"\nexit 2\n', encoding="ascii")
    os.chmod(target, 0o755)
    return target


def assert_planted_git_ignored(test, git_dir, script_path, run_fn, expected, extra_files=None):
    real_git_dir = str(pathlib.Path(shutil.which("git")).resolve().parent)
    bare_text = strip_once(pathlib.Path(script_path).read_text(encoding="ascii"), "[git_program(),", '["git",')
    with tempfile.TemporaryDirectory() as scratch:
        scratch_path = pathlib.Path(scratch)
        for name, content in (extra_files or {}).items():
            (scratch_path / name).write_bytes(content)
        bare_script = scratch_path / f"bare_{pathlib.Path(script_path).name}"
        bare_script.write_text(bare_text, encoding="ascii")
        for mode in ("cwd", "relative-path"):
            with test.subTest(mode=mode):
                work = scratch_path / mode
                work.mkdir()
                marker = scratch_path / f"marker-{mode}.txt"
                if mode == "cwd":
                    plant_git(work)
                    path_entries = ["", ".", real_git_dir]
                else:
                    rel_dir = work / "relbin"
                    rel_dir.mkdir()
                    plant_git(rel_dir)
                    path_entries = ["relbin", real_git_dir]
                env = clean_git_env({
                    "GIT_DIR": str(git_dir),
                    "GRDR_PLANTED_MARKER": str(marker),
                    "PATH": os.pathsep.join(path_entries),
                })
                real_result = run_fn(pathlib.Path(script_path), work, env)
                test.assertEqual((real_result.returncode, real_result.stdout), expected, real_result.stderr)
                test.assertFalse(marker.exists())
                run_fn(bare_script, work, env)
                test.assertTrue(marker.exists())
