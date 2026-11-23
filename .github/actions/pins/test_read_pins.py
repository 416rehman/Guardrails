"""Tests for read_pins.py: python3 -I .github/actions/pins/test_read_pins.py

The oracles are the runner's reading of GITHUB_OUTPUT (runner_outputs, modelled on
FileCommandManager in actions/runner), the real supply-chain/build-tools.toml, and the
steps.<id>.outputs.<key> references the workflows make.
"""

import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
READER = HERE / "read_pins.py"
PINS = ROOT / "supply-chain" / "build-tools.toml"
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))

DIGEST = "sha256:" + "c0" * 32
CLEAN = f"""
[tool.gitleaks]
version = "8.30.1"
licence = "MIT"
source = "https://github.com/gitleaks/gitleaks"
image = "ghcr.io/gitleaks/gitleaks@{DIGEST}"
config = "supply-chain/gitleaks.toml"
install = "docker pull ghcr.io/gitleaks/gitleaks@{DIGEST}"

[tool.semgrep-rules]
repository = "semgrep/semgrep-rules"
commit = "{"a5" * 20}"
severities = "WARNING ERROR"
"""

ACTION_STEP = re.compile(
    r"- id: (?P<id>\S+)\n\s+uses: \$/\.github/actions/pins\n\s+with:\n"
    r"\s+tool: (?P<tool>\S+)\n\s+keys: (?P<keys>[^\n]+)\n"
)
JOB_HEADER = re.compile(r"^  (?=[a-z][a-z0-9-]*:\s*$)", re.M)
ACTION_OUTPUT = re.compile(r"^  (\w+):\n    description: .*\n    value: \$\{\{ steps\.read\.outputs\.\1 \}\}$", re.M)
FORM_ENTRY = re.compile(r'^    "(\w+)": re\.compile\(', re.M)


def run_reader(path, tool, keys):
    return subprocess.run(
        [sys.executable, "-I", str(READER), str(path), tool, keys],
        capture_output=True, text=True, check=False,
    )


def runner_outputs(text):
    outputs, lines = {}, iter(text.split("\n"))
    for line in lines:
        if not line:
            continue
        equals, heredoc = line.find("="), line.find("<<")
        if equals > 0 and (heredoc < 0 or equals < heredoc):
            outputs[line[:equals]] = line[equals + 1:]
            continue
        name, delimiter = line[:heredoc], line[heredoc + 2:]
        body = []
        for part in lines:
            if part == delimiter:
                break
            body.append(part)
        outputs[name] = "\n".join(body)
    return outputs


def pin_steps():
    for workflow in WORKFLOWS:
        jobs = workflow.read_text(encoding="utf-8").partition("\njobs:\n")[2]
        for job in JOB_HEADER.split(jobs)[1:]:
            name = job.partition(":")[0]
            steps = list(ACTION_STEP.finditer(job))
            yield workflow.name, name, job, steps


def form_names():
    return set(FORM_ENTRY.findall(READER.read_text(encoding="utf-8")))


class Reader(unittest.TestCase):
    def fixture(self, text):
        content = text if isinstance(text, bytes) else text.encode("utf-8")
        handle = tempfile.NamedTemporaryFile("wb", suffix=".toml", delete=False)
        with handle:
            handle.write(content)
        self.addCleanup(pathlib.Path(handle.name).unlink)
        return handle.name

    def assert_refused(self, text, tool, keys, code):
        result = run_reader(self.fixture(text), tool, keys)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn(f"::error::{code} ", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return result.stderr

    def test_clean_fixture_gives_exactly_the_keys_asked_for(self):
        result = run_reader(self.fixture(CLEAN), "gitleaks", "image config")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(runner_outputs(result.stdout), {
            "image": f"ghcr.io/gitleaks/gitleaks@{DIGEST}",
            "config": "supply-chain/gitleaks.toml",
        })

    def test_multi_line_value_is_refused(self):
        seeded = CLEAN.replace(f'{DIGEST}"\n\n', f'{DIGEST}\\nsecond line"\n\n')
        self.assert_refused(seeded, "gitleaks", "image config", "GRDR-SUPPLY-0001")

    def test_carriage_return_is_refused(self):
        seeded = CLEAN.replace('licence = "MIT"', 'licence = "MIT\\rsecond line"')
        self.assert_refused(seeded, "gitleaks", "version", "GRDR-SUPPLY-0001")

    def test_other_line_separators_are_refused(self):
        for separator in ("\\u2028", "\\u0085", "\\f", "\\u000b"):
            with self.subTest(separator=separator):
                seeded = CLEAN.replace('version = "8.30.1"', f'version = "8.30.1{separator}x"')
                self.assert_refused(seeded, "gitleaks", "image", "GRDR-SUPPLY-0001")

    def test_value_not_of_its_form_is_refused(self):
        cases = {
            "image by tag": (f"gitleaks@{DIGEST}", "gitleaks:latest", "image"),
            "config outside the tree": ("supply-chain/gitleaks.toml", "../gitleaks.toml", "config"),
            "abbreviated commit": ("a5" * 20, "a5a5a5a", "commit"),
            "unknown severity": ("WARNING ERROR", "WARNING --config=x", "severities"),
            "repository with a path": ("semgrep/semgrep-rules", "semgrep/semgrep-rules/x", "repository"),
        }
        for label, (good, bad, key) in cases.items():
            with self.subTest(label):
                seeded = CLEAN.replace(good, bad, 1)
                tool = "gitleaks" if key in ("image", "config") else "semgrep-rules"
                self.assert_refused(seeded, tool, key, "GRDR-SUPPLY-0002")


    def test_two_and_three_part_versions_are_accepted(self):
        for good in ("0.106", "v1.2", "8.30.1", "v1.75.0"):
            with self.subTest(version=good):
                seeded = CLEAN.replace('version = "8.30.1"', f'version = "{good}"')
                result = run_reader(self.fixture(seeded), "gitleaks", "version")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(runner_outputs(result.stdout), {"version": good})

    def test_invalid_version_forms_are_refused(self):
        for bad in ("0.106-rc1", "1.2.3.4", "1..2", " 1.2", "1.2+b"):
            with self.subTest(version=bad):
                seeded = CLEAN.replace('version = "8.30.1"', f'version = "{bad}"')
                self.assert_refused(seeded, "gitleaks", "version", "GRDR-SUPPLY-0002")

    def test_missing_tool_key_or_form_is_refused(self):
        for tool, keys in (("grype", "version"), ("gitleaks", "commit"), ("gitleaks", "install"), ("gitleaks", "")):
            with self.subTest(tool=tool, keys=keys):
                self.assert_refused(CLEAN, tool, keys, "GRDR-SUPPLY-0003")

    def test_unparsable_file_is_refused(self):
        self.assert_refused('[tool.gitleaks]\nversion = "8.30.1\n', "gitleaks", "version", "GRDR-SUPPLY-0004")

    def test_file_that_is_not_utf8_is_refused_without_its_value(self):
        seeded = CLEAN.encode("utf-8").replace(b'"MIT"', b'"SECRET\xffVALUE"')
        stderr = self.assert_refused(seeded, "gitleaks", "image", "GRDR-SUPPLY-0004")
        self.assertNotIn("SECRET", stderr)

    def test_deeply_nested_value_is_refused(self):
        seeded = CLEAN + "deep = " + "[" * 100_000 + "]" * 100_000 + "\n"
        self.assert_refused(seeded, "semgrep-rules", "commit", "GRDR-SUPPLY-0004")


class Workflows(unittest.TestCase):
    def test_every_job_reads_the_real_pins_it_uses_and_no_others(self):
        tools = tomllib.loads(PINS.read_text(encoding="utf-8"))["tool"]
        seen = 0
        for workflow, job, text, steps in pin_steps():
            self.assertEqual(len(steps), text.count("/.github/actions/pins"), f"{workflow} {job}")
            for step in steps:
                seen += 1
                with self.subTest(workflow=workflow, job=job, step=step["id"]):
                    keys = step["keys"].split()
                    used = set(re.findall(rf"steps\.{re.escape(step['id'])}\.outputs\.([\w-]+)", text))
                    self.assertEqual(set(keys), used)
                    result = run_reader(PINS, step["tool"], step["keys"])
                    self.assertEqual(result.returncode, 0, result.stderr)
                    expected = {key: tools[step["tool"]][key] for key in keys}
                    self.assertEqual(runner_outputs(result.stdout), expected)
        self.assertGreater(seen, 0)

    def test_no_workflow_reads_the_pins_file_itself(self):
        for workflow in WORKFLOWS:
            for number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
                if not line.lstrip().startswith("#"):
                    self.assertNotIn("build-tools.toml", line, f"{workflow.name}:{number}")

    def test_action_declares_an_output_for_every_form(self):
        action = (HERE / "action.yml").read_text(encoding="utf-8")
        self.assertEqual(set(ACTION_OUTPUT.findall(action)), form_names())


if __name__ == "__main__":
    unittest.main()
