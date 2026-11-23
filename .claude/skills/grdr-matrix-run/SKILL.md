---
name: grdr-matrix-run
description: Test on an operating system, architecture or kernel you are not running on. Use for any change under OS adapter crates, `bpf/` or `platform/`.
license: Apache-2.0
metadata:
  version: "3"
  owner: agent-kit
  closes-by: evidence
---

# Test on a system you are not running on

Agent sessions run in a Linux container or on a single development host, and native Windows has no sandbox (`team/03`). Windows, macOS, arm64 and target kernels are tested on real runners, and only a runner's result counts for that system. A cross-target build, a Linux run of the same tests, WSL, or reading platform documentation is not a result for that platform.

The item is issue `#<n>`, named in your prompt. Read it with `gh issue view <n> --comments` to see which cells its acceptance criteria name, its write set and its tier.

## Where results come from

| Source | What runs | For which commits |
|---|---|---|
| `verify.yml` dispatch runs (#454) | `.github/workflows/verify.yml`: `fmt`, `clippy`, tests and `cargo-deny` on `ubuntu-26.04`, `macos-26` and `windows-2025` | Dispatched on the branch head (`workflow_dispatch`) and on `main` |
| `lab.yml` | `.github/workflows/lab.yml`: hosted lab cells (`linux-x64` on `ubuntu-26.04`, `macos-arm64` on `macos-26`, `windows-x64` with Defender active on `windows-2025`) running `lab/jobs/<job>.toml` | Dispatched on `--ref <branch>` or `main` (`workflow_dispatch`) |

## Write the code so the target edge is thin

Write platform code in your workspace and keep logic behind its port (`SensorBackend`, `Actuator`, `SandboxBackend`, `KeyStore`, `SecretStore`) so it is tested on Linux against the reference model; only the adapter edge needs the target. For `bpf/`, test the program's logic through its user-space model with differential tests against the kernel path. `unsafe` belongs only in OS adapter crates and `grdr-ffi`, each block with a `// SAFETY:` comment.

A cross-target `cargo check -p <crate> --target <triple>` catches compile errors early where the toolchain has that target. It proves the code compiles, nothing more. `rust-toolchain.toml` is gate configuration outside your write set: a missing target becomes its own issue, named in your report.

## Pick the cells

Cells come from `support.toml`, which is gate data; jobs come from `lab/jobs/*.toml`, which the lab squad owns. Read both and edit neither from this skill. Tier 1 cells are release-blocking (D-50).

| Your change touches | Run at least |
|---|---|
| An OS adapter crate | Every cell for that system in the crate's support entry |
| `bpf/` | The kernel matrix of `design/10`, every kernel from the oldest (Ubuntu 22.04, 5.15). One kernel's verifier rejection fails the change |
| `platform/macos/` | The macOS arm64 cells. Signing and notarisation cells need Apple's Developer Program; without it they report not run (D-18) |
| `platform/windows/` | Windows 11 x64 with Defender active, and Server or ARM64 cells where the support entry lists them |
| Shared code an OS adapter calls | The Tier 1 cells |

A missing cell in `support.toml` or a missing job in `lab/jobs/` is filed as a new issue for `lead-lab` (skill `grdr-handoff`). Never stand in for either with a local run.

## Run

Generic `workflow_dispatch` orchestration, run waiting and head-commit oracle checks live in `.claude/skills/grdr-work-issue/SKILL.md` and `.claude/skills/grdr-evaluate/SKILL.md`; follow those rules so the run matches `git rev-parse origin/<branch>`.

For `lab.yml` cells:

1. Write the expected result before running. Trigger a job on the branch:
   `gh workflow run lab.yml --ref <branch> -f job=<job> [-f systems=<system>]`
   (where `<branch>` is `issue/<n>-<slug>` and `<system>` is `all`, `linux-x64`, `macos-arm64` or `windows-x64`).
2. Find the run whose `headSha` equals `git rev-parse origin/<branch>`:
   `gh run list --workflow lab.yml --event workflow_dispatch --branch <branch> --json databaseId,headSha`
3. Inspect the cell jobs and download the evidence artefacts:
   `gh run view <id> --json jobs`
   `gh run download <id> -D target/lab/<id>`
4. Verify each cell's result: its job conclusion in `gh run view` plus `cell.json` inside `lab-<job>-<system>-<sha>`, whose `commit` field must equal `git rev-parse origin/<branch>`. On `windows-x64`, confirm `defender.json` records `AMServiceEnabled`, `AntivirusEnabled` and `RealTimeProtectionEnabled` as `true`. Read `run.log` for detail; never rerun a cell only to see more output.

| Result | Means | In the report |
|---|---|---|
| pass | The cell job concluded `success` and `cell.json` `commit` equals the head | The command, its exit code and the downloaded evidence path |
| fail | The cell job failed, or `cell.json` `commit` does not match the head | The command, exit code and first error from `run.log`. A failure on a cell you did not expect to touch is still yours to explain |
| not run (requires hardware) | Tier B self-hosted runners or Tier C hardware (HLK, licensed incumbents) until a self-hosted runner item exists | Listed under what was not verified. Never a pass; an evaluator reports the cell `cannot-evaluate` |
| refused | The plan job rejected the input or job file, or no run matched the head commit | Not verified, with the reason |

An acceptance criterion that needs a cell you could not run is `not-run`, never `pass`. If it is the last criterion left, report `blocked` and name the cell.

Rerun a failing cell at most once, and report both runs. A cell that fails and then passes is flaky, not green; report it, and quarantine is its own issue (`team/05`), not yours.

## Never

- Drive kernel tracing (`bpftrace`, `perf`, `ftrace`, ETW sessions, DTrace) on a Tier B machine or any other shared host. It can take the machine down. Use the user-space model and the kernel matrix.
- Log into, configure or register a runner. Registering a Tier B machine is a one-time setup on that machine, outside any agent session; no cell waits on it.
- Compare numbers from different machines. Performance results cite the host pinned in `lab/reference-hosts.toml` (`team/05`).
- Run a model-driven cell that needs another vendor's model or account without routing through the configured provider rules.
- Count a cell from an earlier commit for a later one. Evidence names the commit it ran on (`cell.json` `commit`).

Finish with the gates of `grdr-verify` and `grdr-handoff`.
