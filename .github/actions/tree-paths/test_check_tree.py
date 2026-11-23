"""Tests for check_tree.py:
python -I -m unittest discover -s .github/actions/tree-paths -p "test_check_tree.py" -v

The oracle is git's own record of each fixture tree (git ls-tree -r -t), checked by a naive
all-pairs loop under an ASCII case-folding table written here, apart from check_tree.py.
"""

import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

import check_tree
from tree_fixtures import (
    CLEAN, SEEDED, FixtureRepo, assert_planted_git_ignored, clean_git_env, strip_once,
)

CHECK_TREE = pathlib.Path(__file__).resolve().parent / "check_tree.py"
ASCII_FOLD = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz")
TILDE_DIGIT = re.compile(rb"~[0123456789]")


def rendered(path):
    return "".join(chr(byte) if 0x20 <= byte <= 0x7E else "\\x%02x" % byte for byte in path)


def reference(records):
    expected = {rule: set() for rule in check_tree.RULES}
    paths = [path for _, path in records]
    for at, path in enumerate(paths):
        for other in paths[at + 1:]:
            if path != other and path.translate(ASCII_FOLD) == other.translate(ASCII_FOLD):
                expected[check_tree.RULE_CASE] |= {path, other}
    for mode, path in records:
        if any(byte < 0x20 or byte > 0x7E for byte in path):
            expected[check_tree.RULE_BYTES].add(path)
        if path.split(b"/")[-1].translate(ASCII_FOLD) == b"rust-toolchain":
            expected[check_tree.RULE_TOOLCHAIN].add(path)
        if any(TILDE_DIGIT.search(segment) for segment in path.split(b"/")):
            expected[check_tree.RULE_SHORT_NAME].add(path)
        if mode == "120000":
            expected[check_tree.RULE_SYMBOLIC_LINK].add(path)
        if mode == "160000":
            expected[check_tree.RULE_SUBMODULE].add(path)
    return {rule: {rendered(path) for path in found} for rule, found in expected.items()}


def printed(stdout):
    found = {rule: set() for rule in check_tree.RULES}
    for line in stdout.splitlines():
        rule, _, path = line.removeprefix("refused (").partition("): ")
        found[rule].add(path)
    return found


def run_script(script_path, rev, cwd, environment=None):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(script_path), f"--rev={rev}"],
        cwd=cwd, capture_output=True, text=True, check=False, env=environment,
    )


class CheckTreeTest(unittest.TestCase):
    def setUp(self):
        self.repo = FixtureRepo()
        self.addCleanup(self.repo.close)

    def run_check(self, rev, environment=None):
        return run_script(CHECK_TREE, rev, self.repo.root, environment)

    def test_clean_tree_passes(self):
        result = self.run_check(self.repo.tree(CLEAN))
        self.assertEqual((result.returncode, result.stdout), (0, ""))

    def test_each_seeded_case_is_refused(self):
        for name, (items, named) in SEEDED.items():
            with self.subTest(case=name):
                tree = self.repo.tree(items)
                result = self.run_check(tree)
                self.assertEqual(result.returncode, 1, result.stderr)
                found = printed(result.stdout)
                self.assertEqual(found, reference(self.repo.listed(tree)))
                every = set().union(*found.values())
                self.assertTrue({rendered(path) for path in named} <= every, every)

    def test_reads_git_objects_not_the_working_tree(self):
        tree = self.repo.tree(CLEAN)
        (pathlib.Path(self.repo.root) / "rust-toolchain").write_text("[toolchain]\n", encoding="ascii")
        self.assertEqual(self.run_check(tree).returncode, 0)

    def test_unreadable_revision_exits_2(self):
        for rev in ["0" * 40, "no-such-branch", "--output=x"]:
            with self.subTest(rev=rev):
                result = self.run_check(rev)
                self.assertEqual(result.returncode, 2)
                self.assertIn("GRDR-GATE-0001", result.stderr)

    def test_git_missing_exits_2(self):
        tree = self.repo.tree(CLEAN)
        result = self.run_check(tree, environment=clean_git_env({"PATH": ""}))
        self.assertEqual((result.returncode, result.stdout), (2, ""))

    def test_planted_git_in_cwd_or_relative_path_is_ignored(self):
        tree = self.repo.tree(CLEAN)
        assert_planted_git_ignored(
            self, pathlib.Path(self.repo.root) / ".git", CHECK_TREE,
            lambda script, work, env: run_script(script, tree, work, env),
            (0, ""),
        )


class ObjectViewTest(unittest.TestCase):
    def setUp(self):
        self.repo = FixtureRepo()
        self.addCleanup(self.repo.close)
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        source = CHECK_TREE.read_text(encoding="ascii")
        no_r8b = strip_once(source, "    check_replacement_refs()\n")
        seed = strip_once(no_r8b, '"--no-replace-objects", ')
        self.no_r8b_script = pathlib.Path(self.scratch.name) / "no_r8b_check_tree.py"
        self.seed_script = pathlib.Path(self.scratch.name) / "seed_check_tree.py"
        self.no_r8b_script.write_text(no_r8b, encoding="ascii")
        self.seed_script.write_text(seed, encoding="ascii")

    def assert_arm(self, rev, bad_tree, plain_probe):
        oracle_expected = reference(self.repo.listed(bad_tree))
        oracle_plain = self.repo.git(*plain_probe)
        self.assertNotEqual(self.repo.plain_git(*plain_probe).stdout, oracle_plain)

        env = clean_git_env()
        real_result = run_script(CHECK_TREE, rev, self.repo.root, env)
        self.assertEqual((real_result.returncode, real_result.stdout), (2, ""))
        self.assertIn("GRDR-GATE-0007", real_result.stderr)

        r8c_result = run_script(self.no_r8b_script, rev, self.repo.root, env)
        self.assertEqual(r8c_result.returncode, 1, r8c_result.stderr)
        self.assertEqual(printed(r8c_result.stdout), oracle_expected)

        seed_result = run_script(self.seed_script, rev, self.repo.root, env)
        self.assertNotEqual((seed_result.returncode, printed(seed_result.stdout)), (1, oracle_expected))

    def test_replacement_ref_on_commit(self):
        clean_commit = self.repo.commit(self.repo.tree(CLEAN))
        bad_tree = self.repo.tree(CLEAN + [b"rust-toolchain"])
        bad_commit = self.repo.commit(bad_tree)
        self.repo.replace(bad_commit, clean_commit)
        self.assert_arm(bad_commit, bad_tree, ("rev-parse", f"{bad_commit}^{{tree}}"))

    def test_replacement_ref_on_tree(self):
        clean_tree = self.repo.tree(CLEAN)
        bad_tree = self.repo.tree(CLEAN + [b"rust-toolchain"])
        bad_commit = self.repo.commit(bad_tree)
        self.repo.replace(bad_tree, clean_tree)
        self.assert_arm(bad_commit, bad_tree, ("ls-tree", "-r", "-t", "-z", "--full-tree", bad_tree))


if __name__ == "__main__":
    unittest.main()
