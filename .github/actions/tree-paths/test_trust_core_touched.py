"""Tests for trust_core_touched.py:
python -I -m unittest discover -s .github/actions/tree-paths -p "test_trust_core_touched.py" -v

The oracle is a reference matcher written here with no call to git: the :(glob,icase) rules over
ASCII-lower-cased paths, where a `**/` segment matches zero or more folders and a folder line
`x/**` also matches `x`. A differential run compares it with git's pathspec matching, pattern by
pattern, over every path of origin/main's and the head's trees with random ASCII case changes, an
instance of every list line, and the seeded trees of tree_fixtures.py. Both corpus revisions must
be listable.
"""

import os
import pathlib
import random
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

import check_tree
import trust_core_touched
from tree_fixtures import (
    CLEAN, SEEDED, SUBMODULE, FixtureRepo, assert_planted_git_ignored, clean_git_env, path_of,
    strip_once,
)

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MATCHER = HERE / "trust_core_touched.py"
CHECK_TREE = HERE / "check_tree.py"
TRUST_CORE = ROOT / "security" / "trust-core.paths"
RISK_TIERS = ROOT / ".claude" / "risk-tiers.toml"
STEP_FOUR = ROOT / ".claude" / "agents" / "eval-tier.md"
CORPUS_REVS = ["origin/main", "HEAD"]
CASE_VARIANTS = 16
MINIMUM_CASES = 10000
SEED = 1923
ASCII_FOLD = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz")
WILDCARDS = b"*?[\\"
STEP4_R8B_BLOCK = (
    'if [ -n "$(git for-each-ref --format=\'%(refname)\' refs/replace/)" ]; then\n'
    '  echo "::error::GRDR-GATE-0007 the repository holds a ref under refs/replace/" >&2\n'
    '  echo "step 4: cannot-evaluate"\n'
    "  exit 2\n"
    "fi\n"
)


def list_lines(path):
    lines = [line.strip() for line in path.read_text(encoding="ascii").splitlines()]
    return [line for line in lines if line and not line.startswith("#")]


def risk_tier_globs():
    tiers = tomllib.loads(RISK_TIERS.read_text(encoding="ascii"))
    return [glob for table in tiers.values() if isinstance(table, dict) for glob in table.get("paths", [])]


def reference_regex(pattern):
    """The :(glob) rules as a regular expression over folded bytes; brackets and escapes are refused."""
    if any(byte in b"[\\" for byte in pattern):
        raise ValueError(f"the reference model has no rule for {pattern!r}")
    parts, at = [], 0
    while at < len(pattern):
        rest = pattern[at:]
        at_segment_start = at == 0 or pattern[at - 1:at] == b"/"
        if at_segment_start and rest.startswith(b"**/"):
            parts.append(b"(?:.*/)?")
            at += 3
        elif at_segment_start and rest == b"**":
            parts.append(b".*")
            at += 2
        elif rest.startswith(b"*"):
            parts.append(b"[^/]*")
            at += len(rest) - len(rest.lstrip(b"*"))
        elif rest.startswith(b"?"):
            parts.append(b"[^/]")
            at += 1
        else:
            parts.append(re.escape(rest[:1]))
            at += 1
    return re.compile(b"".join(parts), re.DOTALL)


def reference_glob(folded_pattern, folded_path):
    if not any(byte in WILDCARDS for byte in folded_pattern):
        return folded_path == folded_pattern or folded_path.startswith(folded_pattern + b"/")
    return reference_regex(folded_pattern).fullmatch(folded_path) is not None


def reference_matches(pattern, path):
    """R1, and a folder line `x/**` matching the path `x` as well."""
    folded_pattern = pattern.encode("ascii").translate(ASCII_FOLD)
    folded_path = path.translate(ASCII_FOLD)
    if folded_pattern.endswith(b"/**") and reference_glob(folded_pattern[:-3], folded_path):
        return True
    return reference_glob(folded_pattern, folded_path)


def tree_paths(rev):
    result = subprocess.run(
        ["git", "--no-replace-objects", "ls-tree", "-r", "-z", "--name-only", "--full-tree", rev],
        cwd=ROOT, capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"the corpus revision {rev} cannot be listed: {result.stderr!r}")
    return [path for path in result.stdout.split(b"\0") if path]


def instance(pattern, rng):
    """A path the pattern is written to match, with random folders and names in its wildcards."""
    text = pattern.replace("**/", rng.choice(["", "a/", "a/b/"]))
    text = re.sub(r"/\*\*$", rng.choice(["", "/x", "/x/y.rs"]), text)
    text = text.replace("**", "w").replace("*", rng.choice(["n", "name-2"])).replace("?", "q")
    return text.encode("ascii")


def case_variant(path, rng):
    return bytes(byte ^ 0x20 if chr(byte).isascii() and chr(byte).isalpha() and rng.random() < 0.5 else byte
                 for byte in path)


def corpus(patterns):
    rng = random.Random(SEED)
    sources = {rev: tree_paths(rev) for rev in CORPUS_REVS}
    base = [path for paths in sources.values() for path in paths]
    base += [instance(pattern, rng) for pattern in patterns for _ in range(3)]
    base += [path_of(item) for items, _ in SEEDED.values() for item in items]
    cases = []
    for path in dict.fromkeys(base):
        cases.append(path)
        cases.extend(case_variant(path, rng) for _ in range(CASE_VARIANTS))
    return list(dict.fromkeys(cases)), {rev: len(paths) for rev, paths in sources.items()}


def run_matcher(*args, cwd=ROOT, env=None, script=MATCHER):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(script), *args],
        cwd=cwd, env=env, capture_output=True, text=True, check=False,
    )


def bash_program():
    """Git's own bash on Windows (never the WSL launcher), the PATH bash elsewhere."""
    if os.name != "nt":
        return shutil.which("bash")
    git = pathlib.Path(shutil.which("git") or ".").resolve()
    return next((str(folder / "bin" / "bash.exe") for folder in git.parents
                 if (folder / "bin" / "bash.exe").is_file()), None)


def step_four_block():
    match = re.search(r"## Step 4 command\n```\n(.*?)```\n", STEP_FOUR.read_text(encoding="utf-8"), re.S)
    if match is None:
        raise AssertionError("step 4 command block missing from eval-tier.md")
    return match.group(1)


class DifferentialTest(unittest.TestCase):
    def test_risk_tier_globs_have_no_brace_expansion(self):
        braces = [glob for glob in risk_tier_globs() if "{" in glob or "}" in glob]
        self.assertEqual(braces, [])

    def test_git_matching_agrees_with_the_reference_model(self):
        patterns = list(dict.fromkeys(list_lines(TRUST_CORE) + risk_tier_globs()))
        cases, sources = corpus(patterns)
        self.assertGreaterEqual(len(cases), MINIMUM_CASES)
        per_pattern = trust_core_touched.matched_sets([[pattern] for pattern in patterns], cases)
        mismatches = []
        for pattern, matched in zip(patterns, per_pattern):
            mismatches += [(pattern, path) for path in cases if (path in matched) != reference_matches(pattern, path)]
        print(f"\ndifferential: {len(patterns)} patterns, {len(cases)} cases from {sources}, "
              f"{len(mismatches)} mismatches", file=sys.stderr)
        self.assertEqual(mismatches[:20], [])

    def test_whole_list_agrees_with_the_reference_model(self):
        patterns = list_lines(TRUST_CORE)
        cases, _ = corpus(patterns)
        matched = set(trust_core_touched.matching(patterns, cases))
        expected = {path for path in cases if any(reference_matches(pattern, path) for pattern in patterns)}
        self.assertEqual(matched, expected)


class PathsModeTest(unittest.TestCase):
    def test_prints_each_matching_path_once_in_order(self):
        paths = [
            "docs/a.md", "LIMITS.TOML", "Cargo.toml", "crates/grdr-core/src/lib.rs",
            "LIMITS.TOML", "crates/x/BUILD.RS", "Cargo.lock", "crates/grdr-model/src/lib.rs",
        ]
        result = run_matcher("--list", str(TRUST_CORE), "--paths", *paths)
        self.assertEqual((result.returncode, result.stdout), (1, "LIMITS.TOML\ncrates/x/BUILD.RS\n"))

    def test_prints_nothing_when_no_path_matches(self):
        paths = [
            "docs/a.md", "crates/grdr-core/src/lib.rs", "Cargo.toml", "Cargo.lock",
            "rust-toolchain.toml", "rustfmt.toml", "crates/x/clippy.toml",
        ]
        result = run_matcher("--list", str(TRUST_CORE), "--paths", *paths)
        self.assertEqual((result.returncode, result.stdout), (0, ""))

    def test_a_path_and_a_path_below_it_are_both_matched(self):
        result = run_matcher("--list", str(TRUST_CORE), "--paths", "limits.toml", "limits.toml/x")
        self.assertEqual((result.returncode, result.stdout), (1, "limits.toml\nlimits.toml/x\n"))

    def test_a_folder_line_matches_the_folder_itself(self):
        folders = [".cargo", "crates/x/.cargo", "platform/macos", "crates/grdr-crypto", ".github/workflows"]
        result = run_matcher("--list", str(TRUST_CORE), "--paths", *folders)
        self.assertEqual((result.returncode, result.stdout.splitlines()), (1, folders))


class FromRevTest(unittest.TestCase):
    def setUp(self):
        self.repo = FixtureRepo()
        self.addCleanup(self.repo.close)
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.alone = pathlib.Path(self.scratch.name) / "matcher.py"
        self.alone.write_bytes(MATCHER.read_bytes())

    def rules(self, list_text=b"only/**\n", source=None):
        contents = {trust_core_touched.LIST_PATH.encode(): list_text,
                    trust_core_touched.CHECK_TREE_PATH.encode(): source or CHECK_TREE.read_bytes()}
        return self.repo.tree(CLEAN, contents)

    def run_alone(self, *args):
        return run_matcher(*args, cwd=self.repo.root, script=self.alone)

    def test_reads_the_list_and_the_tree_check_from_git_objects(self):
        result = self.run_alone("--from-rev", self.rules(), "--paths", "only/x", "Cargo.lock")
        self.assertEqual((result.returncode, result.stdout), (1, "only/x\n"))

    def test_tree_check_from_the_revision_runs_on_the_head(self):
        rules = self.rules()
        head = self.repo.tree(CLEAN + [b"rust-toolchain"])
        result = self.run_alone("--from-rev", rules, "--diff", rules, head)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("rust-toolchain", result.stdout)

    def test_a_revision_without_the_rules_exits_2(self):
        result = self.run_alone("--from-rev", self.repo.tree(CLEAN), "--paths", "only/x")
        self.assertEqual((result.returncode, result.stdout), (2, ""))

    def test_a_tree_check_that_stops_exits_2(self):
        rules = self.rules(source=b"raise RuntimeError\n")
        result = self.run_alone("--from-rev", rules, "--paths", "only/x")
        self.assertEqual((result.returncode, result.stdout), (2, ""))
        self.assertIn("GRDR-GATE-0005", result.stderr)

    def test_list_mode_without_the_tree_check_beside_it_exits_2(self):
        result = self.run_alone("--list", str(TRUST_CORE), "--paths", "limits.toml")
        self.assertEqual((result.returncode, result.stdout), (2, ""))

    def test_git_missing_exits_2(self):
        result = run_matcher(
            "--list", str(TRUST_CORE), "--paths", "limits.toml",
            cwd=ROOT, env=clean_git_env({"PATH": ""}),
        )
        self.assertEqual((result.returncode, result.stdout), (2, ""))


class InputErrorTest(unittest.TestCase):
    def test_input_errors_exit_2(self):
        with tempfile.TemporaryDirectory() as scratch:
            empty = pathlib.Path(scratch) / "empty.paths"
            empty.write_text("# only a comment\n\n", encoding="ascii")
            outside = pathlib.Path(scratch) / "outside.paths"
            outside.write_bytes("café/**\n".encode("utf-8"))
            for name, args in {
                "missing-list": ["--list", str(pathlib.Path(scratch) / "absent"), "--paths", "x"],
                "empty-list": ["--list", str(empty), "--paths", "x"],
                "list-outside-ascii": ["--list", str(outside), "--paths", "x"],
                "refused-path": ["--list", str(TRUST_CORE), "--paths", "../x"],
                "unknown-base": ["--list", str(TRUST_CORE), "--diff", "0" * 40, "HEAD"],
                "option-like-head": ["--list", str(TRUST_CORE), "--diff", "HEAD", "--output=x"],
                "full-ref-name": ["--list", str(TRUST_CORE), "--diff", "refs/heads/main", "HEAD"],
            }.items():
                with self.subTest(case=name):
                    result = run_matcher(*args)
                    self.assertEqual((result.returncode, result.stdout), (2, ""), result.stderr)


class StepFourTest(unittest.TestCase):
    """The real consumer: eval-tier's step 4 command, run as written, in a fixture repository."""

    def setUp(self):
        self.repo = FixtureRepo()
        self.addCleanup(self.repo.close)
        self.bash = bash_program()
        self.assertIsNotNone(self.bash, "no bash to run the step 4 command")
        rules = {
            trust_core_touched.LIST_PATH.encode(): TRUST_CORE.read_bytes(),
            trust_core_touched.CHECK_TREE_PATH.encode(): CHECK_TREE.read_bytes(),
            b".github/actions/tree-paths/trust_core_touched.py": MATCHER.read_bytes(),
        }
        self.rules = rules
        self.base = self.repo.commit(self.repo.tree(CLEAN, rules))
        self.repo.git("update-ref", "refs/heads/main", self.base)
        self.repo.git("remote", "add", "origin", self.repo.root)

    def step_four(self, head_items):
        head = self.repo.commit(self.repo.tree(head_items, self.rules), self.base)
        self.repo.git("update-ref", "--no-deref", "HEAD", head)
        for ref in ("refs/tags/origin/main", "refs/heads/origin/main"):
            self.repo.git("update-ref", ref, head)
        result = subprocess.run(
            [self.bash], input=step_four_block(), cwd=self.repo.root, capture_output=True,
            text=True, check=False, env=clean_git_env(),
        )
        return result.stdout.splitlines(), result.stderr

    def test_names_that_shadow_main_do_not_change_the_result(self):
        lines, stderr = self.step_four(CLEAN + [b"crates/grdr-crypto/src/lib.rs"])
        self.assertEqual(lines, ["crates/grdr-crypto/src/lib.rs", "step 4: trust core"], stderr)

    def test_a_change_outside_the_list_gives_no_trust_core_path(self):
        lines, stderr = self.step_four(CLEAN + [b"docs/new.md"])
        self.assertEqual(lines, ["step 4: no trust-core path"], stderr)

    def test_the_matcher_refuses_a_short_name(self):
        self.step_four(CLEAN + [b"docs/new.md"])
        for args in (
            ["--from-rev", "origin/main", "--paths", "x"],
            ["--from-rev", "refs/heads/main", "--paths", "x"],
            ["--from-rev", self.base, "--diff", "origin/main", "HEAD"],
        ):
            with self.subTest(args=args):
                result = run_matcher(*args, cwd=self.repo.root)
                self.assertEqual((result.returncode, result.stdout), (2, ""), result.stderr)

    def test_planted_git_in_cwd_or_relative_path_is_ignored(self):
        assert_planted_git_ignored(
            self, pathlib.Path(self.repo.root) / ".git", MATCHER,
            lambda script, work, env: run_matcher(
                "--list", str(TRUST_CORE), "--paths", "limits.toml", cwd=work, env=env, script=script,
            ),
            (1, "limits.toml\n"),
            extra_files={"check_tree.py": CHECK_TREE.read_bytes()},
        )


class DiffModeTest(unittest.TestCase):
    def setUp(self):
        self.repo = FixtureRepo()
        self.addCleanup(self.repo.close)
        self.base = self.repo.tree(CLEAN + [b"crates/grdr-crypto/src/lib.rs"])

    def diff(self, head_paths):
        head = self.repo.tree(head_paths)
        return run_matcher("--list", str(TRUST_CORE), "--diff", self.base, head, cwd=self.repo.root)

    def test_a_rename_reports_the_listed_name(self):
        result = self.diff(CLEAN + [b"docs/moved.rs", b".Cargo/config"])
        self.assertEqual((result.returncode, result.stdout), (1, ".Cargo/config\ncrates/grdr-crypto/src/lib.rs\n"))

    def test_tree_findings_on_the_head_follow_the_paths(self):
        for name, (paths, named) in SEEDED.items():
            with self.subTest(case=name):
                result = self.diff(paths + [b"crates/grdr-crypto/src/lib.rs"])
                lines = result.stdout.splitlines()
                self.assertEqual(result.returncode, 1, result.stderr)
                findings = [line for line in lines if line.startswith("refused (")]
                self.assertTrue(findings, lines)
                self.assertEqual(lines[len(lines) - len(findings):], findings)
                shown = {line.partition("): ")[2] for line in findings}
                self.assertTrue({check_tree.shown(path) for path in named} <= shown, shown)

    def test_a_submodule_the_working_tree_ignores_is_still_listed(self):
        (pathlib.Path(self.repo.root) / ".gitmodules").write_text(
            '[submodule "v"]\n\tpath = crates/grdr-crypto/v\n\turl = https://example.com/v.git\n\tignore = all\n',
            encoding="ascii",
        )
        result = self.diff(CLEAN + [b"crates/grdr-crypto/src/lib.rs", (SUBMODULE, b"crates/grdr-crypto/v")])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout.splitlines()[0], "crates/grdr-crypto/v")

    def test_a_change_outside_the_list_passes(self):
        result = self.diff(CLEAN + [b"crates/grdr-crypto/src/lib.rs", b"docs/new.md"])
        self.assertEqual((result.returncode, result.stdout), (0, ""))


class ObjectViewTest(unittest.TestCase):
    def setUp(self):
        self.bash = bash_program()
        self.assertIsNotNone(self.bash, "no bash to run the step 4 command")
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        scratch_path = pathlib.Path(self.scratch.name)

        self.matcher_real = MATCHER.read_text(encoding="ascii")
        self.matcher_no_r8b = strip_once(
            self.matcher_real,
            "    if arguments.from_rev is not None or arguments.diff is not None:\n        check_replacement_refs()\n",
        )
        self.matcher_seed = strip_once(self.matcher_no_r8b, '"--no-replace-objects", ')
        self.checker_real = CHECK_TREE.read_text(encoding="ascii")
        self.checker_no_r8b = strip_once(self.checker_real, "    check_replacement_refs()\n")
        self.checker_seed = strip_once(self.checker_no_r8b, '"--no-replace-objects", ')

        self.step4_real = step_four_block()
        self.step4_no_r8b = strip_once(self.step4_real, STEP4_R8B_BLOCK)
        self.step4_seed = strip_once(self.step4_no_r8b, " GIT_NO_REPLACE_OBJECTS=1")

        self.matcher_no_r8b_path = scratch_path / "matcher_no_r8b.py"
        self.matcher_no_r8b_path.write_text(self.matcher_no_r8b, encoding="ascii")
        self.matcher_seed_path = scratch_path / "matcher_seed.py"
        self.matcher_seed_path.write_text(self.matcher_seed, encoding="ascii")
        self.list_bytes = TRUST_CORE.read_bytes()

    def make_rules(self, variant, list_bytes=None):
        matcher_map = {"real": self.matcher_real, "r8c": self.matcher_no_r8b, "seed": self.matcher_seed}
        checker_map = {"real": self.checker_real, "r8c": self.checker_no_r8b, "seed": self.checker_seed}
        return {
            trust_core_touched.LIST_PATH.encode(): list_bytes or self.list_bytes,
            trust_core_touched.CHECK_TREE_PATH.encode(): checker_map[variant].encode("ascii"),
            b".github/actions/tree-paths/trust_core_touched.py": matcher_map[variant].encode("ascii"),
        }

    def init_step4_refs(self, repo, base, head):
        repo.git("update-ref", "refs/heads/main", base)
        repo.git("remote", "add", "origin", repo.root)
        repo.git("update-ref", "--no-deref", "HEAD", head)
        return base, head

    def run_step4(self, repo, block):
        return subprocess.run(
            [self.bash], input=block, cwd=repo.root, capture_output=True,
            text=True, check=False, env=clean_git_env(),
        )

    def assert_diff_arm(self, build_repo, plain_probe):
        oracle_out = ["crates/grdr-crypto/src/lib.rs"]
        oracle_step4 = ["crates/grdr-crypto/src/lib.rs", "step 4: trust core"]

        repo_real = FixtureRepo()
        self.addCleanup(repo_real.close)
        base_r, head_r = build_repo(repo_real, "real")
        probe_args = plain_probe(base_r, head_r)
        self.assertNotEqual(repo_real.plain_git(*probe_args).stdout, repo_real.git(*probe_args))

        env = clean_git_env()
        real_script = run_matcher("--from-rev", base_r, "--diff", base_r, head_r, cwd=repo_real.root, env=env)
        self.assertEqual((real_script.returncode, real_script.stdout), (2, ""))
        self.assertIn("GRDR-GATE-0007", real_script.stderr)
        real_s4 = self.run_step4(repo_real, self.step4_real)
        self.assertEqual(real_s4.returncode, 2)
        self.assertIn("GRDR-GATE-0007", real_s4.stderr)
        self.assertEqual(real_s4.stdout.splitlines()[-1], "step 4: cannot-evaluate")

        repo_r8c = FixtureRepo()
        self.addCleanup(repo_r8c.close)
        base_c, head_c = build_repo(repo_r8c, "r8c")
        r8c_script = run_matcher(
            "--from-rev", base_c, "--diff", base_c, head_c,
            cwd=repo_r8c.root, env=env, script=self.matcher_no_r8b_path,
        )
        self.assertEqual((r8c_script.returncode, r8c_script.stdout.splitlines()), (1, oracle_out), r8c_script.stderr)
        r8c_s4 = self.run_step4(repo_r8c, self.step4_no_r8b)
        self.assertEqual((r8c_s4.returncode, r8c_s4.stdout.splitlines()), (0, oracle_step4), r8c_s4.stderr)

        repo_seed = FixtureRepo()
        self.addCleanup(repo_seed.close)
        base_s, head_s = build_repo(repo_seed, "seed")
        seed_script = run_matcher(
            "--from-rev", base_s, "--diff", base_s, head_s,
            cwd=repo_seed.root, env=env, script=self.matcher_seed_path,
        )
        self.assertNotEqual((seed_script.returncode, seed_script.stdout.splitlines()), (1, oracle_out))
        seed_s4 = self.run_step4(repo_seed, self.step4_seed)
        self.assertNotEqual((seed_s4.returncode, seed_s4.stdout.splitlines()), (0, oracle_step4))

    def test_replacement_ref_on_main_commit(self):
        def build(repo, variant):
            rules = self.make_rules(variant)
            base = repo.commit(repo.tree(CLEAN, rules))
            head = repo.commit(repo.tree(CLEAN + [b"crates/grdr-crypto/src/lib.rs"], rules), base)
            fake_rules = self.make_rules(variant, b"only-unused/**\n")
            fake_base = repo.commit(repo.tree(CLEAN + [b"crates/grdr-crypto/src/lib.rs"], fake_rules))
            repo.replace(base, fake_base)
            return self.init_step4_refs(repo, base, head)

        self.assert_diff_arm(build, lambda b, h: ("diff", "--name-only", b, h))

    def test_replacement_ref_on_main_tree(self):
        def build(repo, variant):
            rules = self.make_rules(variant)
            base_tree = repo.tree(CLEAN, rules)
            base = repo.commit(base_tree)
            head = repo.commit(repo.tree(CLEAN + [b"crates/grdr-crypto/src/lib.rs"], rules), base)
            fake_rules = self.make_rules(variant, b"only-unused/**\n")
            fake_tree = repo.tree(CLEAN + [b"crates/grdr-crypto/src/lib.rs"], fake_rules)
            repo.replace(base_tree, fake_tree)
            return self.init_step4_refs(repo, base, head)

        self.assert_diff_arm(build, lambda b, h: ("diff", "--name-only", b, h))

    def test_replacement_ref_on_main_blob(self):
        def build(repo, variant):
            rules = self.make_rules(variant)
            base = repo.commit(repo.tree(CLEAN, rules))
            head = repo.commit(repo.tree(CLEAN + [b"crates/grdr-crypto/src/lib.rs"], rules), base)
            real_blob = repo.git("rev-parse", f"{base}:{trust_core_touched.LIST_PATH}").strip().decode("ascii")
            fake_blob = repo.git("hash-object", "-w", "--stdin", stdin=b"only-unused/**\n").strip().decode("ascii")
            repo.replace(real_blob, fake_blob)
            return self.init_step4_refs(repo, base, head)

        with self.subTest(blob="trust-core.paths"):
            self.assert_diff_arm(build, lambda b, _h: ("cat-file", "blob", f"{b}:{trust_core_touched.LIST_PATH}"))

        with self.subTest(blob="trust_core_touched.py"):
            repo_s4 = FixtureRepo()
            self.addCleanup(repo_s4.close)
            rules = self.make_rules("seed")
            base = repo_s4.commit(repo_s4.tree(CLEAN, rules))
            head = repo_s4.commit(repo_s4.tree(CLEAN + [b"crates/grdr-crypto/src/lib.rs"], rules), base)
            matcher_blob = repo_s4.git(
                "rev-parse", f"{base}:.github/actions/tree-paths/trust_core_touched.py",
            ).strip().decode("ascii")
            fake_matcher = repo_s4.git(
                "hash-object", "-w", "--stdin", stdin=b"import sys; sys.exit(0)\n",
            ).strip().decode("ascii")
            self.init_step4_refs(repo_s4, base, head)
            repo_s4.replace(matcher_blob, fake_matcher)
            s4_res = self.run_step4(repo_s4, self.step4_seed)
            self.assertNotEqual((s4_res.returncode, s4_res.stdout.splitlines()),
                                (0, ["crates/grdr-crypto/src/lib.rs", "step 4: trust core"]))

    def test_replacement_ref_on_head_commit(self):
        def build(repo, variant):
            rules = self.make_rules(variant)
            base = repo.commit(repo.tree(CLEAN, rules))
            head = repo.commit(repo.tree(CLEAN + [b"crates/grdr-crypto/src/lib.rs"], rules), base)
            fake_head = repo.commit(repo.tree(CLEAN + [b"docs/new.md"], rules), base)
            repo.replace(head, fake_head)
            return self.init_step4_refs(repo, base, head)

        self.assert_diff_arm(build, lambda b, h: ("diff", "--name-only", b, h))

    def test_replacement_ref_on_head_tree(self):
        def build(repo, variant):
            rules = self.make_rules(variant)
            base = repo.commit(repo.tree(CLEAN, rules))
            head_tree = repo.tree(CLEAN + [b"crates/grdr-crypto/src/lib.rs"], rules)
            head = repo.commit(head_tree, base)
            fake_tree = repo.tree(CLEAN + [b"docs/new.md"], rules)
            repo.replace(head_tree, fake_tree)
            return self.init_step4_refs(repo, base, head)

        self.assert_diff_arm(build, lambda b, h: ("diff", "--name-only", b, h))

    def test_replacement_ref_on_head_blob(self):
        oracle_out = ["crates/grdr-crypto/src/lib.rs"]
        env = clean_git_env()

        def setup(repo, variant):
            head = repo.commit(repo.tree(CLEAN, self.make_rules(variant)))
            real_blob = repo.git("rev-parse", f"{head}:{trust_core_touched.LIST_PATH}").strip().decode("ascii")
            fake_blob = repo.git("hash-object", "-w", "--stdin", stdin=b"only-unused/**\n").strip().decode("ascii")
            repo.replace(real_blob, fake_blob)
            return head

        repo_real = FixtureRepo()
        self.addCleanup(repo_real.close)
        head_r = setup(repo_real, "real")
        probe = ("cat-file", "blob", f"{head_r}:{trust_core_touched.LIST_PATH}")
        self.assertNotEqual(repo_real.plain_git(*probe).stdout, repo_real.git(*probe))
        real_script = run_matcher("--from-rev", head_r, "--paths", "crates/grdr-crypto/src/lib.rs",
                                  cwd=repo_real.root, env=env)
        self.assertEqual((real_script.returncode, real_script.stdout), (2, ""))
        self.assertIn("GRDR-GATE-0007", real_script.stderr)

        repo_r8c = FixtureRepo()
        self.addCleanup(repo_r8c.close)
        head_c = setup(repo_r8c, "r8c")
        r8c_script = run_matcher("--from-rev", head_c, "--paths", "crates/grdr-crypto/src/lib.rs",
                                 cwd=repo_r8c.root, env=env, script=self.matcher_no_r8b_path)
        self.assertEqual((r8c_script.returncode, r8c_script.stdout.splitlines()), (1, oracle_out), r8c_script.stderr)

        repo_seed = FixtureRepo()
        self.addCleanup(repo_seed.close)
        head_s = setup(repo_seed, "seed")
        seed_script = run_matcher("--from-rev", head_s, "--paths", "crates/grdr-crypto/src/lib.rs",
                                  cwd=repo_seed.root, env=env, script=self.matcher_seed_path)
        self.assertNotEqual((seed_script.returncode, seed_script.stdout.splitlines()), (1, oracle_out))


if __name__ == "__main__":
    unittest.main()
