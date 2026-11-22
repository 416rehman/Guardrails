"""The workflow test is WorkflowTest in test_pinned_toolchain.py, with its reader workflow_reader.py and its rules
pin_rules.py. It reads the working-tree copies of the files in WORKFLOWS and ACTION_FILES, and PIN_ACTION_FILE, and
each of its rules is a text match. For a workflow or action in a form GitHub runs, whose working-tree copy is the
committed file byte for byte, it fails when, and claims to fail only when:
1. a job in a file in WORKFLOWS has an actions/checkout step, and the two steps after its first checkout are not
   the pin step and the write step;
2. a file in WORKFLOWS or ACTION_DEFINITIONS holds a layout, a character or a key the reader does not read, or
   PIN_ACTION_FILE, read as text with CR and CRLF taken as line breaks, holds one;
3. a file in WORKFLOWS or ACTION_DEFINITIONS holds a step, job, action or runs key outside the key sets in
   pin_rules.py, or a job's first checkout takes an input outside CHECKOUT_INPUTS;
4. a file it reads holds a form that a fixture of the test expects it to refuse, in the place that fixture holds
   it, outside the declared allowlists.
The fixtures are the list. The test claims nothing about a form no fixture expects it to refuse, even one of the
same kind as a fixture's. It claims nothing about a committed file whose working-tree copy differs from it. It is
a tripwire for drift and mistakes in workflow edits. Every file it reads is under .github/**, which is trust core,
and review of an edit there by the trust-core evaluator set is the control against a hostile edit (design/02
TB-11, D-63).
"""

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from pin_rules import (
    CHANNEL_OUTPUT, REFUSED_VARIABLES, action_problems, pin_action_problems, text_problems, workflow_problems,
)

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
READER = HERE / "pinned_toolchain.py"
PIN_ACTION_FILE = HERE / "action.yml"
WORKFLOWS = sorted(
    path for path in (ROOT / ".github" / "workflows").iterdir() if path.suffix.lower() in (".yml", ".yaml")
)
ACTION_FILES = sorted(
    path for path in (ROOT / ".github" / "actions").rglob("*")
    if path.is_file() and HERE not in path.parents and "__pycache__" not in path.parts
)
ACTION_DEFINITIONS = [path for path in ACTION_FILES if path.name in ("action.yml", "action.yaml")]

FULL = """[toolchain]
channel = "1.99.1"
components = ["rustfmt", "clippy"]
targets = ["wasm32-unknown-unknown"]
profile = "minimal"
"""
OTHER_CHANNEL = '[toolchain]\nchannel = "1.70.0"\n'

SEEDED = {
    "no-table": ('channel = "1.99.1"\n', "GRDR-GATE-0004"),
    "no-channel": ('[toolchain]\nprofile = "minimal"\n', "GRDR-GATE-0004"),
    "path-key": ('[toolchain]\npath = "/opt/tc"\n', "GRDR-GATE-0004"),
    "path-key-beside-channel": (FULL + 'path = "/opt/tc"\n', "GRDR-GATE-0004"),
    "channel-not-a-word": ('[toolchain]\nchannel = "/opt/tc"\n', "GRDR-GATE-0004"),
    "channel-two-lines": ('[toolchain]\nchannel = "1.99.1\\nX=1"\n', "GRDR-GATE-0004"),
    "channel-not-text": ("[toolchain]\nchannel = 1\n", "GRDR-GATE-0004"),
    "component-not-a-word": ('[toolchain]\nchannel = "1.99.1"\ncomponents = ["a b"]\n', "GRDR-GATE-0004"),
    "targets-not-a-list": ('[toolchain]\nchannel = "1.99.1"\ntargets = "x"\n', "GRDR-GATE-0004"),
    "does-not-parse": ("[toolchain\n", "GRDR-GATE-0003"),
    "not-utf-8": ("[toolchain]\nchannel = \"1.99.1\"\n# \udcff\n", "GRDR-GATE-0003"),
}

CHECKOUT = (
    "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
    "        with:\n"
    "          persist-credentials: false\n"
)
PIN = "      - id: toolchain\n        uses: $/.github/actions/tree-paths\n"
WRITE = (
    "      - name: Write RUSTUP_TOOLCHAIN to GITHUB_ENV\n"
    "        shell: bash\n"
    "        env:\n"
    "          CHANNEL: ${{ steps.toolchain.outputs.channel }}\n"
    '        run: echo "RUSTUP_TOOLCHAIN=${CHANNEL:?}" >> "$GITHUB_ENV"\n'
)
CARGO = "      - run: cargo test --workspace\n"
PINNED = CHECKOUT + PIN + WRITE
LOCAL_WORKFLOW_CALL = "name: fixture\non: push\njobs:\n  docs:\n    uses: ./.github/workflows/docs.yml\n"
ODD_CHARACTERS = {"NEL": "\x85", "LS": "\u2028", "PS": "\u2029", "FS": "\x1c", "VT": "\x0b", "tab": "\t", "CR": "\r"}

JOB_KEY_LINES = {
    "trailing-comment": ("  docs: # the API docs", "docs"),
    "double-quoted": ('  "docs":', "docs"),
    "single-quoted": ("  'docs':", "docs"),
    "space-before-colon": ("  docs :", "docs"),
    "underscore-and-capitals": ("  Build_Docs_2:", "Build_Docs_2"),
    "quoted-underscore-capitals-comment": ('  "Build_Docs_2" : # docs', "Build_Docs_2"),
}
UNPINNED = {
    "plain-cargo": CHECKOUT + CARGO,
    "no-cargo-at-all": CHECKOUT + "      - run: make docs\n",
    "cargo-by-path": CHECKOUT + "      - run: $HOME/.cargo/bin/cargo doc\n",
    "folded-cargo": CHECKOUT + "      - run: >-\n          cargo\n          doc --workspace\n",
    "cargo-from-python": CHECKOUT + "      - run: python3 -c \"import subprocess; subprocess.run(['cargo', 'doc'])\"\n",
    "checkout-through-a-quoted-key": '      - "uses": actions/checkout@0\n' + CARGO,
    "checkout-with-spaces-around-the-colon": "      - uses :   actions/checkout@0\n" + CARGO,
    "step-before-the-pin": CHECKOUT + CARGO + PIN + WRITE,
    "pin-without-the-write": CHECKOUT + PIN + CARGO,
    "write-without-the-pin": CHECKOUT + WRITE + CARGO,
    "pin-before-the-checkout": PIN + WRITE + CHECKOUT + CARGO,
    "checkout-of-another-repository": CHECKOUT + "          repository: example/other\n" + PIN + WRITE + CARGO,
    "checkout-of-another-ref": CHECKOUT + "          ref: other\n" + PIN + WRITE + CARGO,
    "checkout-into-a-path": CHECKOUT + "          path: other\n" + PIN + WRITE + CARGO,
}
DEFEATED = {
    "plus-toolchain": PINNED + "      - run: cargo +stable test\n",
    "plus-toolchain-quoted": PINNED + "      - run: cargo '+stable' test\n",
    "plus-toolchain-folded": PINNED + "      - run: >-\n          cargo\n          +stable test\n",
    "plus-toolchain-continued": PINNED + "      - run: |\n          cargo \\\n            +stable test\n",
    "plus-toolchain-upper-case": PINNED + "      - run: CARGO.EXE +stable test\n",
    "plus-toolchain-by-path": PINNED + "      - run: $HOME/.cargo/bin/cargo +stable build\n",
    "plus-toolchain-quoted-path": PINNED + '      - run: echo; "$HOME/.cargo/bin/cargo" +stable build\n',
    **{
        f"plus-toolchain-{proxy}": PINNED + f"      - run: {proxy} +stable --version\n"
        for proxy in ("rustc", "rustdoc", "rustfmt", "cargo-clippy", "cargo-fmt", "cargo-miri", "miri", "rls",
                      "rust-analyzer", "rust-gdb", "clippy-driver")
    },
    "rustup-run": PINNED + "      - run: rustup run stable cargo test\n",
    "rustup-quiet-run": PINNED + "      - run: rustup -q run stable cargo test\n",
    "rustup-verbose-run": PINNED + "      - run: rustup --verbose run stable cargo test\n",
    "rustup-default": PINNED + "      - run: rustup default stable\n",
    "rustup-override": PINNED + "      - run: rustup override set stable\n",
    "rustup-toolchain-link": PINNED + "      - run: rustup toolchain link local ./tc\n",
    "rustup-toolchain-install": PINNED + "      - run: rustup toolchain install stable\n",
    "rustup-by-path": PINNED + "      - run: ~/.cargo/bin/rustup.exe show\n",
    "step-env": PINNED + "      - env:\n          RUSTUP_TOOLCHAIN: stable\n        run: cargo test\n",
    "step-env-lower-case": PINNED + "      - env:\n          rustup_toolchain: stable\n        run: cargo test\n",
    "step-env-rustup-home": PINNED + "      - env:\n          RUSTUP_HOME: ./rustup\n        run: cargo test\n",
    "step-env-rustup-dist-server": PINNED + "      - env:\n          RUSTUP_DIST_SERVER: http://mirror.example\n        run: cargo test\n",
    **{
        f"step-env-{variable.lower()}": PINNED + f"      - env:\n          {variable}: ./tool\n        run: cargo test\n"
        for variable in REFUSED_VARIABLES
    },
    "step-env-rustc-wrapper-lower-case": PINNED + "      - env:\n          rustc_wrapper: ./tool\n        run: cargo test\n",
    "run-line-export": PINNED + "      - run: export RUSTUP_TOOLCHAIN=stable && cargo test\n",
    "run-line-rustc": PINNED + "      - run: RUSTC=./tool cargo build\n",
    "run-line-cargo-home": PINNED + "      - run: export cargo_home=./home; cargo build\n",
    "heredoc-write": PINNED + "      - run: |\n          cat >> \"$GITHUB_ENV\" <<EOF\n          RUSTUP_TOOLCHAIN=stable\n          EOF\n",
    "env-file-write": PINNED + '      - run: echo "RUSTC_WRAPPER=sccache" >> "$GITHUB_ENV"\n',
    "path-file-write": PINNED + '      - run: echo "$PWD/bin" >> "$GITHUB_PATH"\n',
    "path-file-write-lower-case": PINNED + "      - shell: pwsh\n        run: Add-Content $env:github_path ./bin\n",
    "add-path-command": PINNED + '      - run: echo "::add-path::./bin"\n',
    "set-env-command": PINNED + '      - run: echo "::set-env name=CC::./cc"\n',
    "continue-on-error-on-the-pin": CHECKOUT + PIN + "        continue-on-error: true\n" + WRITE + CARGO,
    "continue-on-error-on-the-write": PINNED + "        continue-on-error: true\n" + CARGO,
    "if-on-the-pin": CHECKOUT + PIN + "        if: false\n" + WRITE + CARGO,
    "if-on-the-write": PINNED + "        if: false\n" + CARGO,
    "env-on-the-pin": CHECKOUT + PIN + "        env:\n          GIT_DIR: other/.git\n" + WRITE + CARGO,
    "unknown-pin-input": CHECKOUT + PIN + "        with:\n          path: other\n" + WRITE + CARGO,
    "pin-id-is-a-prefix": CHECKOUT + PIN.replace("id: toolchain", "id: toolchain2") + WRITE + CARGO,
    "pin-in-a-heredoc": CHECKOUT
    + "      - id: toolchain\n        run: |\n          cat > /dev/null <<'EOF'\n"
    "          uses: $/.github/actions/tree-paths\n          EOF\n" + WRITE + CARGO,
    "write-without-the-empty-check": CHECKOUT + PIN + WRITE.replace("${CHANNEL:?}", "$CHANNEL") + CARGO,
    "write-in-another-shell": CHECKOUT + PIN + WRITE.replace("shell: bash", "shell: cmd") + CARGO,
    "write-of-another-output": CHECKOUT + PIN + WRITE.replace("outputs.channel", "outputs.other") + CARGO,
    "container-action-without-the-pin": PINNED + "      - uses: EmbarkStudios/cargo-deny-action@0\n",
    "unclassified-action": PINNED + "      - uses: dtolnay/rust-toolchain@0\n",
    "status-always": PINNED + "      - if: always()\n        run: cargo test\n",
    "status-always-capitals": PINNED + "      - if: ${{ Always() }}\n        run: cargo test\n",
    "status-failure": PINNED + "      - if: failure()\n        run: cargo test\n",
    "status-cancelled": PINNED + "      - if: ${{ !cancelled() }}\n        run: cargo test\n",
    "status-not-success": PINNED + "      - if: ${{ ! success() }}\n        run: cargo test\n",
    "status-allowed-action-with-a-run": PINNED + "      - if: always()\n        uses: actions/upload-artifact@0\n        run: cargo test\n",
    "status-on-an-unlisted-step": PINNED + "      - if: always()\n        uses: actions/upload-artifact@0\n",
}
DEFEATED_BY_ENV = {
    "job-env": ("", "    env:\n      RUSTUP_TOOLCHAIN: stable\n"),
    "job-env-from-the-pin-form": ("", "    env:\n      RUSTUP_TOOLCHAIN: ${{ env.RUSTUP_TOOLCHAIN }}\n"),
    "workflow-env": ("env:\n  RUSTUP_TOOLCHAIN: stable\n", ""),
    "workflow-rustup-home": ("env:\n  RUSTUP_HOME: ./rustup\n", ""),
    "workflow-rustup-dist-server": ("env:\n  RUSTUP_DIST_SERVER: http://mirror.example\n", ""),
    "workflow-rustc-wrapper": ("env:\n  RUSTC_WRAPPER: ./tool\n", ""),
    "workflow-bash-env": ("env:\n  BASH_ENV: ./setup.sh\n", ""),
}
UNLISTED_KEYS = {
    "parallel-group-holding-the-checkout": "      - parallel:\n          - uses: actions/checkout@0\n" + CARGO,
    "background-step-before-the-checkout": "      - id: early\n        background: true\n        run: sleep 60; cargo build\n"
    + PINNED + CARGO + "      - wait: early\n",
    "pin-inside-a-parallel-group": CHECKOUT + "      - parallel:\n          - id: toolchain\n"
    "            uses: $/.github/actions/tree-paths\n" + WRITE + CARGO,
    "background-write": PINNED + "        background: true\n" + CARGO,
    "wait-all": PINNED + "      - wait-all: true\n" + CARGO,
    "unknown-step-key": PINNED + "      - run: cargo test\n        frobnicate: true\n",
}
UNLISTED_JOB_KEYS = {
    "unknown-job-key": "    frobnicate: true\n",
    "job-container": "    container: rust:1.80\n",
    "job-continue-on-error": "    continue-on-error: true\n",
}
UNREADABLE = {
    **{
        f"line-break-{name}": f"    steps: # c{char}    a: |\n      - {{uses: actions/checkout@0}}\n"
        for name, char in ODD_CHARACTERS.items()
    },
    "escaped-line-break": '    name: "docs\\\n      more"\n    steps:\n      - uses: actions/checkout@0\n',
    "quoted-scalar-over-lines": '    name: "docs\n    steps:\n      - run: x"\n    steps:\n      - uses: actions/checkout@0\n',
    "escape-in-a-quoted-scalar": '    steps:\n      - uses: "actions/checkout@0\\x20"\n',
    "flow-step": "    steps:\n      - {uses: actions/checkout@0}\n",
    "flow-steps": "    steps: [{uses: actions/checkout@0}]\n",
    "anchor-and-alias": "    steps:\n      - &out\n        uses: actions/checkout@0\n      - *out\n",
    "alias-value": "    steps:\n      - uses: *out\n",
    "tag": "    steps:\n      - !!map\n        uses: actions/checkout@0\n",
    "explicit-key": "    steps:\n      - ? uses\n        : actions/checkout@0\n",
    "merge-key": "    steps:\n      - <<: {uses: actions/checkout@0}\n",
    "dash-alone": "    steps:\n      -\n        uses: actions/checkout@0\n",
    "spaces-after-the-dash": "    steps:\n      -   uses: actions/checkout@0\n",
    "plain-scalar-over-lines": "    steps:\n      - name: x\n          uses: actions/checkout@0\n",
    "second-document": "    steps:\n      - run: x\n---\njobs:\n  docs:\n    steps:\n      - uses: actions/checkout@0\n",
    "remote-reusable-workflow": "    uses: example/rust/.github/workflows/docs.yml@0\n",
}
NEEDS_ONE_REFUSAL = {
    **{f"{name}-in-a-comment": PINNED + f"      # note{char}more\n" + CARGO for name, char in ODD_CHARACTERS.items()},
    "checkout-beside-a-block-scalar": "      - run: |\n          echo\n        uses: actions/checkout@0\n" + CARGO,
    "repeated-key-checkout-first": "      - uses: actions/checkout@0\n        uses: actions/upload-artifact@0\n" + CARGO,
    "steps-at-the-key-indent": "    - uses: actions/checkout@0\n    - run: cargo doc\n",
    "keys-beside-the-steps": "      uses: actions/checkout@0\n      - run: cargo doc\n",
    "steps-as-a-mapping": "      checkout:\n        uses: actions/checkout@0\n      cargo:\n        run: cargo doc\n",
    "pin-step-of-another-action": CHECKOUT + "      - id: toolchain\n        uses: actions/upload-artifact@0\n" + WRITE + CARGO,
    "container-action-with-another-toolchain": PINNED
    + "      - uses: EmbarkStudios/cargo-deny-action@0\n        env:\n          RUSTUP_TOOLCHAIN: stable\n",
    "status-through-an-alias": PINNED + "      - name: &after always()\n        run: echo\n      - if: *after\n        run: cargo test\n",
}
LISTED_STATUS_STEP = "      - if: always()\n        uses: actions/upload-artifact@0\n"

COMPOSITE = "name: fixture\ndescription: fixture\nruns:\n  using: composite\n  steps:\n"
ECHO = "    - shell: bash\n      run: echo done\n"
ACTION_DEFEATS = {
    "env-file-write": "    - shell: bash\n      run: echo \"RUSTUP_TOOLCHAIN=stable\" >> \"$GITHUB_ENV\"\n",
    "plus-toolchain": "    - shell: bash\n      run: cargo +stable build\n",
    "rustup": "    - shell: bash\n      run: rustup default stable\n",
    "refused-variable": "    - shell: bash\n      env:\n        RUSTC: ./tool\n      run: cargo build\n",
    "status-condition": "    - if: always()\n      shell: bash\n      run: cargo build\n",
    "unknown-step-key": "    - shell: bash\n      background: true\n      run: cargo build\n",
    "unclassified-action": "    - uses: dtolnay/rust-toolchain@0\n",
}
ACTION_TEXT_DEFEATS = {
    "javascript-action": "name: fixture\ndescription: fixture\nruns:\n  using: node24\n  main: index.js\n",
    "steps-of-another-kind-of-action": COMPOSITE.replace("using: composite", "using: node24") + ECHO,
    "unknown-action-key": COMPOSITE + ECHO + "branding:\n  icon: x\n",
}


def run_reader(rev, cwd, env=None):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(READER), rev], cwd=cwd, env=env, capture_output=True, text=True, check=False,
    )


def git(repository, *args, stdin=b""):
    return subprocess.run(
        ["git", "-C", str(repository), *args], input=stdin, capture_output=True, check=True,
    ).stdout.decode("utf-8").strip()


def commit_files(repository, files):
    entries = []
    for name, text in sorted(files.items()):
        blob = git(repository, "hash-object", "-w", "--stdin", stdin=text.encode("utf-8", "surrogateescape"))
        entries.append(f"100644 blob {blob}\t{name}\n")
    tree = git(repository, "mktree", stdin="".join(entries).encode("utf-8"))
    return git(repository, "-c", "user.name=fixture", "-c", "user.email=fixture@example.test",
               "commit-tree", tree, "-m", "fixture")


def new_repository(scratch, name):
    repository = pathlib.Path(scratch) / name
    repository.mkdir()
    git(repository, "init", "-q")
    return repository


def env_file(text):
    return dict(line.split("=", 1) for line in text.splitlines())


def fixture(steps, key_line="  docs:", job_lines="", top_lines=""):
    return f"name: fixture\non: push\n{top_lines}jobs:\n{key_line}\n    runs-on: ubuntu-26.04\n{job_lines}    steps:\n{steps}"


class ReaderTest(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.scratch = scratch.name
        self.repository = new_repository(scratch.name, "repository")

    def read(self, files):
        return run_reader(commit_files(self.repository, files), self.repository)

    def test_full_table(self):
        result = self.read({"rust-toolchain.toml": FULL})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(env_file(result.stdout), {
            "RUSTUP_TOOLCHAIN": "1.99.1",
            "TOOLCHAIN_PROFILE": "minimal",
            "TOOLCHAIN_COMPONENTS": "rustfmt,clippy",
            "TOOLCHAIN_TARGETS": "wasm32-unknown-unknown",
        })

    def test_values_left_out_are_empty(self):
        result = self.read({"rust-toolchain.toml": '[toolchain]\nchannel = "stable"\n'})
        self.assertEqual(env_file(result.stdout), {
            "RUSTUP_TOOLCHAIN": "stable", "TOOLCHAIN_PROFILE": "", "TOOLCHAIN_COMPONENTS": "", "TOOLCHAIN_TARGETS": "",
        })

    def test_the_repository_file(self):
        result = run_reader("HEAD", ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(env_file(result.stdout)["RUSTUP_TOOLCHAIN"], r"^[0-9]+\.[0-9]+\.[0-9]+$")

    def test_seeded_files_are_refused(self):
        for name, (text, code) in SEEDED.items():
            with self.subTest(case=name):
                result = self.read({"rust-toolchain.toml": text})
                self.assertEqual((result.returncode, result.stdout), (1, ""))
                self.assertIn(code, result.stderr)

    def test_a_commit_without_the_file_is_refused(self):
        result = self.read({"rust-toolchain": FULL, "rust-toolchain.toml.orig": FULL})
        self.assertEqual((result.returncode, result.stdout), (1, ""))
        self.assertIn("GRDR-GATE-0003", result.stderr)

    def test_an_unknown_revision_is_refused(self):
        result = run_reader("0" * 40, self.repository)
        self.assertEqual((result.returncode, result.stdout), (1, ""))
        self.assertIn("GRDR-GATE-0003", result.stderr)

    def test_the_working_tree_does_not_change_the_channel(self):
        git(self.repository, "update-ref", "HEAD", commit_files(self.repository, {"rust-toolchain.toml": FULL}))
        (self.repository / "rust-toolchain.toml").write_text(OTHER_CHANNEL, encoding="utf-8")
        (self.repository / "rust-t~1.tom").write_text(OTHER_CHANNEL, encoding="utf-8")
        result = run_reader("HEAD", self.repository)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(env_file(result.stdout)["RUSTUP_TOOLCHAIN"], "1.99.1")

    def test_the_callers_git_variables_do_not_change_the_channel(self):
        git(self.repository, "update-ref", "HEAD", commit_files(self.repository, {"rust-toolchain.toml": FULL}))
        planted = new_repository(self.scratch, "planted")
        git(planted, "update-ref", "HEAD", commit_files(planted, {"rust-toolchain.toml": OTHER_CHANNEL}))
        environment = dict(os.environ, GIT_DIR=str(planted / ".git"), GIT_WORK_TREE=str(planted))
        self.assertIn("1.70.0", subprocess.run(["git", "show", "HEAD:rust-toolchain.toml"], cwd=self.repository,
                                               env=environment, capture_output=True, text=True, check=True).stdout)
        result = run_reader("HEAD", self.repository, environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(env_file(result.stdout)["RUSTUP_TOOLCHAIN"], "1.99.1")

    def test_a_replacement_ref_is_refused(self):
        pinned = commit_files(self.repository, {"rust-toolchain.toml": FULL})
        other = commit_files(self.repository, {"rust-toolchain.toml": OTHER_CHANNEL})
        git(self.repository, "replace", pinned, other)
        self.assertNotEqual(git(self.repository, "rev-parse", f"{pinned}^{{tree}}"),
                            git(self.repository, "--no-replace-objects", "rev-parse", f"{pinned}^{{tree}}"))
        result = run_reader(pinned, self.repository)
        self.assertEqual((result.returncode, result.stdout), (1, ""))
        self.assertIn("GRDR-GATE-0007", result.stderr)

    def replaced_blob(self):
        pinned = commit_files(self.repository, {"rust-toolchain.toml": FULL})
        git(self.repository, "replace", pinned, commit_files(self.repository, {"rust-toolchain.toml": OTHER_CHANNEL}))
        blob = f"{pinned}:rust-toolchain.toml"
        self.assertEqual(git(self.repository, "cat-file", "blob", blob), OTHER_CHANNEL.strip())
        return blob

    def run_with_the_reader(self, script, *args):
        prelude = "import os, subprocess, sys; sys.path.insert(0, sys.argv[1]); import pinned_toolchain as reader; "
        return subprocess.run([sys.executable, "-I", "-B", "-c", prelude + script, str(HERE), *args],
                              cwd=self.repository, capture_output=True, check=False)

    def test_the_git_command_turns_replacement_off(self):
        scrub_only = "reader.git_environment = lambda: {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}; "
        result = self.run_with_the_reader(
            scrub_only + "sys.stdout.buffer.write(reader.git('cat-file', 'blob', sys.argv[2]))", self.replaced_blob())
        self.assertEqual((result.returncode, result.stdout.decode("utf-8")), (0, FULL), result.stderr)

    def test_the_git_environment_turns_replacement_off(self):
        result = self.run_with_the_reader(
            "sys.stdout.buffer.write(subprocess.run(['git', 'cat-file', 'blob', sys.argv[2]], env=reader.git_environment(),"
            " capture_output=True, check=True).stdout)", self.replaced_blob())
        self.assertEqual((result.returncode, result.stdout.decode("utf-8")), (0, FULL), result.stderr)


class WorkflowTest(unittest.TestCase):
    def test_every_workflow_keeps_the_pin(self):
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.name):
                text = workflow.read_bytes().decode("ascii", "replace")
                self.assertEqual(workflow_problems(text, workflow.name), [])

    def test_every_local_action_leaves_the_pin_alone(self):
        for path in ACTION_FILES:
            with self.subTest(path=str(path.relative_to(ROOT))):
                text = path.read_bytes().decode("ascii", "replace")
                problems = action_problems(text, path.name) if path in ACTION_DEFINITIONS else text_problems(text, set(), path.name)
                self.assertEqual(problems, [])

    def test_the_pin_action_outputs_only_the_readers_channel(self):
        action = PIN_ACTION_FILE.read_text(encoding="utf-8")
        self.assertEqual(pin_action_problems(action), [])
        self.assertIn('rustup toolchain install "$CHANNEL"', action)
        self.assertIn("RUSTUP_TOOLCHAIN: ${{ steps.read.outputs.RUSTUP_TOOLCHAIN }}", action)
        changed = {
            "literal-channel": action.replace(f"value: {CHANNEL_OUTPUT}", "value: 1.70.0"),
            "second-output": action.replace("outputs:\n  channel:", "outputs:\n  other:\n    value: x\n  channel:"),
            "third-step": action + "    - shell: bash\n      run: echo \"RUSTUP_TOOLCHAIN=1.70.0\" >> \"$GITHUB_OUTPUT\"\n",
            "read-step-changed": action.replace("pinned_toolchain.py\" HEAD", "pinned_toolchain.py\" HEAD~1"),
            "env-write": action.replace("        rustup toolchain install", "        echo x >> \"$GITHUB_ENV\"; rustup toolchain install"),
        }
        for name, text in changed.items():
            with self.subTest(case=name):
                self.assertNotEqual(text, action)
                self.assertNotEqual(pin_action_problems(text), [])

    def test_a_pinned_job_passes(self):
        self.assertEqual(workflow_problems(fixture(PINNED + CARGO)), [])
        self.assertEqual(workflow_problems(fixture(PINNED + "      - name: Show the toolchain\n        run: cargo --version\n")), [])
        self.assertEqual(workflow_problems(fixture("      - run: cargo doc\n")), [])
        second_checkout = CHECKOUT + "          repository: example/rules\n          path: rules\n"
        self.assertEqual(workflow_problems(fixture(PINNED + second_checkout + CARGO)), [])
        self.assertEqual(workflow_problems(LOCAL_WORKFLOW_CALL), [])
        self.assertEqual(action_problems(COMPOSITE + ECHO), [])

    def test_a_job_is_read_whatever_its_key_line(self):
        for name, (key_line, job_id) in JOB_KEY_LINES.items():
            with self.subTest(case=name):
                pinned = fixture(PINNED + CARGO, key_line="  pinned:") + f"{key_line}\n    steps:\n"
                self.assertEqual(workflow_problems(pinned + PINNED), [])
                problems = workflow_problems(pinned + CHECKOUT + CARGO)
                self.assertEqual(len(problems), 1, problems)
                self.assertTrue(problems[0].startswith(f"{job_id}: "), problems)

    def test_a_job_that_checks_out_without_the_pin_is_refused(self):
        for name, steps in UNPINNED.items():
            with self.subTest(case=name):
                self.assertNotEqual(workflow_problems(fixture(steps)), [])

    def test_a_pin_that_something_else_overrides_is_refused(self):
        for name, steps in DEFEATED.items():
            with self.subTest(case=name):
                self.assertNotEqual(workflow_problems(fixture(steps)), [])
        for name, (top_lines, job_lines) in DEFEATED_BY_ENV.items():
            with self.subTest(case=name):
                self.assertNotEqual(workflow_problems(fixture(PINNED + CARGO, job_lines=job_lines, top_lines=top_lines)), [])

    def test_a_key_outside_the_allowlists_is_refused(self):
        for name, steps in UNLISTED_KEYS.items():
            with self.subTest(case=name):
                self.assertNotEqual(workflow_problems(fixture(steps)), [])
        for name, job_lines in UNLISTED_JOB_KEYS.items():
            with self.subTest(case=name):
                self.assertNotEqual(workflow_problems(fixture(PINNED + CARGO, job_lines=job_lines)), [])

    def test_a_workflow_the_reader_does_not_read_is_refused(self):
        for name, job in UNREADABLE.items():
            with self.subTest(case=name):
                self.assertNotEqual(workflow_problems(f"name: fixture\non: push\njobs:\n  docs:\n{job}"), [])

    def test_each_refusal_has_a_fixture_that_needs_it(self):
        for name, steps in NEEDS_ONE_REFUSAL.items():
            with self.subTest(case=name):
                self.assertNotEqual(workflow_problems(fixture(steps)), [])

    def test_only_the_listed_step_runs_after_a_failure(self):
        listed = fixture(PINNED + CARGO + LISTED_STATUS_STEP, key_line="  baseline:")
        self.assertEqual(workflow_problems(listed, "dast.yml"), [])
        self.assertNotEqual(workflow_problems(listed, "verify.yml"), [])
        self.assertNotEqual(workflow_problems(listed + "        run: cargo test\n", "dast.yml"), [])

    def test_a_local_action_that_works_past_the_pin_is_refused(self):
        for name, steps in ACTION_DEFEATS.items():
            with self.subTest(case=name):
                self.assertNotEqual(action_problems(COMPOSITE + steps), [])
        for name, text in ACTION_TEXT_DEFEATS.items():
            with self.subTest(case=name):
                self.assertNotEqual(action_problems(text), [])

    def test_only_the_pin_action_reads_or_installs_the_toolchain(self):
        for path in [*WORKFLOWS, *ACTION_FILES]:
            self.assertNotIn("pinned_toolchain.py", path.read_bytes().decode("ascii", "replace"), path.name)
        action = PIN_ACTION_FILE.read_text(encoding="utf-8")
        self.assertIn('pinned_toolchain.py" HEAD >> "$GITHUB_OUTPUT"', action)
        self.assertNotIn("GITHUB_ENV", action.partition("\nruns:\n")[2])


if __name__ == "__main__":
    unittest.main()
