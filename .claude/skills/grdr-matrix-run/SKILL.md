---
name: grdr-matrix-run
description: Test on an operating system, architecture or kernel you are not running on. Use for any change under OS adapter crates, `bpf/` or `platform/`.
license: Apache-2.0
metadata:
  version: "2"
  owner: agent-kit
  requires: the matrix runner (WI-0013)
  closes-by: evidence
---

# Test on a system you are not running on

Agent sessions run in a Linux container, and native Windows has no Claude Code sandbox (team/03
section 8). Windows, macOS, arm64 and every kernel other than the container's are tested on real
runners, and only a runner's result counts for that system. A cross-target build, a Linux run of the
same tests, WSL, or your reading of the platform's documentation is not a result for that platform.

The item is issue `#<n>`, named in your prompt. Read it with `gh issue view <n> --comments` to see which
cells its acceptance criteria name, its write set and its tier.

## Where results come from

| Source | What runs | For which commits |
|---|---|---|
| Pull-request checks | `.github/workflows/verify.yml`: the gates of `grdr-verify` on Linux for pull requests, and on Linux, macOS and Windows for `main` and nightly (team/05 section 4; owner instructions 22 and 28) | Every push to a pull request, and every commit on `main` |
| Matrix runner, tier A | Hosted runners, the repository being public from its first push: both architectures, the x64 kernel matrix under KVM, Windows with Defender | The head of an open pull request or a commit on `main`, and nightly |
| Matrix runner, tier B | Registered self-hosted machines, in snapshot-revert guests | Pull-request heads under evaluation and `main` only (D-64) |
| Tier C | HLK and licensed incumbents for the optional Windows driver | Refused until a tier C host is registered (team/05 QG-19) |

The runner refuses any other commit (team/05 section 19). So:

- **Implementers** get OS results for their own change from the pull-request checks; `eval-platform`
  then runs the matrix cells on it. Use the runner yourself to look at `main`: to reproduce a reported
  failure on the target before you change code, or to read the baseline of a cell your change will
  affect.
- **Evaluators** (`eval-platform`, `eval-adversarial`) run the cells on the branch head of the change
  under review.

## Write the code so the target edge is thin

Write platform code in the Linux container. Keep the logic behind its port (`SensorBackend`,
`Actuator`, `SandboxBackend`, `KeyStore`, `SecretStore`) so it is tested on Linux against the reference
model; only the adapter edge needs the target. For `bpf/`, test the program's logic through its
user-space model with differential tests against the kernel path (h09). `unsafe` belongs only in OS
adapter crates and `grdr-ffi`, each block with a `// SAFETY:` comment.

A cross-target `cargo check -p <crate> --target <triple>` catches compile errors early where the
toolchain has that target. It proves the code compiles, nothing more. `rust-toolchain.toml` is
gate configuration outside your write set: a missing target becomes its own issue, named in your report.

## Pick the cells

Cells come from `support.toml`, which is gate data; jobs come from `lab/jobs/*.toml`, which the lab
squad's items change. Read both and edit neither from this skill. Tier 1 cells are release-blocking
(D-50).

| Your change touches | Run at least |
|---|---|
| An OS adapter crate | Every cell for that system in the crate's support entry, on both architectures |
| `bpf/` | The kernel matrix of design/10, every kernel from the oldest (Ubuntu 22.04, 5.15). One kernel's verifier rejection fails the change |
| `platform/macos/` | The macOS arm64 cells. Signing and notarisation cells need Apple's Developer Program; without it they report not run (D-18) |
| `platform/windows/` | Windows 11 x64 and ARM64 with Defender active, and Server cells where the support entry lists them |
| Shared code an OS adapter calls | The Tier 1 cells: `--cells tier1` |

A missing cell in `support.toml` or a missing job is filed as a new issue for `lead-lab` (skill
`grdr-handoff`). Never stand in for either with a local
run.

## Run

Run the matrix runner for the job, the cell filter and the commit, as WI-0013 defines its command.

Write the expected result before you run it. The runner reports the cells passed and failed, the first
error and a log path. Read the log at that path for
detail; never rerun a cell only to see more output.

| Result | Means | In the report |
|---|---|---|
| pass | The cell ran and every check in it passed | The command, its exit code and the log path |
| fail | The cell ran and a check failed | The command and exit code, plus your reading of the first error. A failure on a cell you did not expect to touch is still yours to explain |
| not run (requires hardware) | No registered machine can host the cell | Listed under what was not verified. Never a pass; an evaluator reports the cell `cannot-evaluate` |
| refused | The commit is not a pull-request head or on `main`, or the job needs tier C | Not verified, with the reason |

An acceptance criterion that needs a cell you could not run is `not-run`, never `pass`. If it is the
last criterion left, report `blocked` and name the cell.

Rerun a failing cell at most once, and report both runs. A cell that fails and then passes is flaky,
not green; report it, and quarantine is its own issue (team/05 section 17), not yours.

## Never

- Drive kernel tracing (bpftrace, perf, ftrace, ETW sessions, DTrace) on a registered tier B machine
  or any other shared host. It can take the machine down (h09). Use the user-space model and
  the kernel matrix.
- Log into, configure or register a runner. Registering a tier B machine is a one-time setup on that
  machine, outside any agent session (team/06 section 11 item 12); no cell waits on it.
- Compare numbers from different machines. Performance results cite the host pinned in
  `lab/reference-hosts.toml` (team/05 section 19).
- Run a model-driven cell that needs another vendor's model or account. It is reported not run; the
  model rule allows only the three Claude models.
- Count a cell from an earlier commit for a later one. Evidence names the commit it ran on.

Finish with the gates of `grdr-verify` and `grdr-handoff`.

## Commands this skill names

A command that has not landed yet shows as an unknown subcommand.

| Command | Added by | Until it exists |
|---|---|---|
| The matrix runner | WI-0013 (team/01 TO-06, team/05 QG-12); its free runners need a public repository, which this one is from its first push | No cell can run. List every target cell you would have run as not verified, with the reason, and do not substitute a local run. The pull-request checks are then the only OS results; before the main repository exists there are none, so every non-Linux result is not verified |
| Tier B runners | team/06 section 11 item 12, set up on the machine itself | Tier B cells report not run (requires hardware) |
