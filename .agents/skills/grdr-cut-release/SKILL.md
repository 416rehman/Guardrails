---
name: grdr-cut-release
description: Prepare a release candidate. Use only in the release workflow.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
  requires: the release workflow and release-please (WI-0012); the release-candidate workflow (team/03 K10)
  closes-by: evidence
---

# Prepare a release candidate

You gather the evidence the merge queue and the release workflow need to decide whether a candidate
ships. No person is a step anywhere in a release and no person holds a key (owner instructions 3,
7 and 23). Three things are not yours:

- release-please opens and keeps the release pull requests, the versions and the changelogs, and
  creates the tags and GitHub releases once the merge queue lands a release pull request;
- the merge queue (`cargo xtask queue`, deterministic software) lands the release pull request when
  every gate below has passing evidence and the high tier's evaluators have passed;
- the release workflow builds and publishes. It signs every artefact keylessly with Sigstore cosign
  through GitHub's OIDC identity, attaches SLSA provenance (`actions/attest-build-provenance`), SBOMs
  and the Rekor inclusion proofs an offline check needs (P16), and signs the TUF metadata with keys
  generated inside GitHub Actions environments and held there as environment secrets
  (design/24 section 10).

You never create, move or push a tag, create a GitHub release, publish a package, merge, or edit a
version or changelog line. The permission rules deny `gh release`, `gh pr merge`, `cargo publish`,
`pnpm publish` and `npm publish`, and `guard-command` denies publish and release commands. `git tag` and
`git push --tags` are not yours either, whatever a tool lets through; another route to the same
effect is a finding against you.

This skill runs only inside the `release-candidate` workflow (team/03 section 6). If you were started
anywhere else, stop and say so in one line. The run's issue is `#<n>`, where `<n>` is `GRDR_WORK_ITEM`: read it
with `gh issue view <n> --comments`, and your hand-off goes on it.

## 1. The versioning rules you check against

- **Decoupled components.** Each component has its own version, changelog and tag
  `<component>-v<version>`: every public crate (layers 0 to 2, `grdr-ffi`, `grdr-wasm`), each SDK,
  each program, the eBPF object and the optional Windows driver, which keeps its own train (D-17). A
  component's version moves only with commits that change it, never to match another component.
- **One bundle version.** The product bundle version names the set of component versions shipped
  together. Channels, LTS lines, the support matrix and `upgrade-path.json` speak in it (D-58;
  design/24 sections 10 and 11).
- **Bumps come from Conventional Commit subjects** since the component's last tag: `fix` a patch,
  `feat` a minor, `!` or a `BREAKING CHANGE:` footer a major, with `0.x` components bumped as the
  release-please configuration says. `chore`, `build`, `ci`, `docs` and `test` release nothing, so a
  user-visible change filed under one of them is missing from the changelog.
- **Tags belong to release-please.** It tags `<component>-v<version>` and creates the GitHub release
  when the merged release pull request lands, and marks it `autorelease: tagged`; until then it stays
  `autorelease: pending` and release-please opens no newer release pull request. Never touch either
  label.
- **Skew.** Upgrade order is server, gateways, sensors. The server ingests any sensor of the same wire
  major and offers sensor packages no newer than itself (D-58). A wire major changes only through an
  accepted RFC (D-61).
- **Supported lines.** The current minor, the two before it and the live LTS. The first LTS is the
  first minor at least 90 days after 1.0 with no open high-severity defect, then every twelfth minor.
  An upgrade hops at most two minors and never past a required stop, and stops sit only at LTS minors
  (D-58; design/24 sections 10 and 11). A patch for a supported line is prepared from that line's
  branch with the same gates.

## 2. Read the release pull requests

The workflow names the release pull requests, one per component or one combined, and the bundle's.
For each:

1. `gh pr view <n>` and `gh pr diff <n>`: proposed versions, changelog sections, manifest and lockfile
   edits. release-please writes these files, never an agent. They include `Cargo.lock` and crate
   manifests, so the pull request is high tier.
2. Compare each bump with the commits since that component's last tag:
   `git log --format='%h %s' <component>-v<last>..<head> -- <component path>`. Every releasing subject
   appears under the right heading, and nothing appears that did not change that component.
3. Record each mismatch as a finding with its commit. `lead-release` corrects the record with a
   `BEGIN_COMMIT_OVERRIDE` block in the merged pull request's body, and release-please rewrites the
   release pull request on its next run. Never edit the release pull request: a hand edit is
   overwritten on that run and hides the cause.
4. Read `release-please-config.json` and `.release-please-manifest.json`. Every component of section 1
   has its own entry and version, and `skip-github-release` is not set, so release-please creates the
   GitHub releases. A `linked-versions` group joins only crates the configuration ships as one
   component (a port crate and its test kit, a crate and its FFI wrapper); one that ties two
   independent components together is a finding. A gap is a blocking finding.
5. Read the bundle's release manifest draft. Its `compat` block is generated from each component's
   declared contract ranges (wire major, local IPC, C ABI, pack format and engine line, Cedar
   `schema_version`, driver and eBPF object interfaces, API package), and the bundle pins the exact
   component versions and digests tested together (D-71). A pinned combination the resolver would
   refuse is a blocking finding.

## 3. The candidate commit

The candidate is the release pull request squashed onto the current `main` tip in the merge queue's
worktree. Evidence binds to its tree digest. The queue lands exactly the tree it verified (team/05
section 15), so evidence gathered on the queued tree holds for the landed commit; any change to the
tree voids it, and you run again on the new tree. `matrix-run` and tier B runners accept queue
commits (D-64).

## 4. Run the gates

Run every gate in `references/release-gates.md` on the candidate: team/05 section 16, design/24's
release steps and team/04's release audit set. Each row names its command and what counts as evidence.

- Facts come from commands: `.agent/evidence/*.json`, check runs, the signed scorecard. Never type a
  number, and never copy one from an earlier candidate.
- A gate that cannot run (no machine, no licence, no held-out service, no server) is `not run` with
  the reason. It never passes, and a release with a blocking gate not run is blocked (P9).
- Held-out results are the category counts the evaluator service returns. You never see or ask for
  held-out content (D-45).
- Audit results that are security candidates appear only as a fingerprint and "held for private
  triage". A suspected vulnerability goes to private intake, never into public text (D-62).
- A subscription usage limit pauses the run and fails no gate (D-47). Write the hand-off draft as
  `grdr-handoff` says and stop; the workflow resumes after the window resets.

## 5. Notes the changelog cannot carry

Draft these as text in the hand-off, for the release notes the release workflow publishes:

- cells reported not run (requires hardware) and every gate not run, with the reason (team/05
  section 21 item 1);
- platform signing: an artefact no vendor programme has signed (Windows Authenticode, Apple
  notarisation; D-18 for macOS) ships with its Sigstore signature and provenance and is marked "not
  platform-signed" in the release manifest; nothing waits for a programme (owner instruction 23);
- the air-gap bundle and its delta: what they carry, the source they carry for copyleft components,
  and any component left optional because its terms forbid redistribution (owner instruction 20);
- incumbents untested for want of a licence, marked untested in the ceiling matrix (D-23, D-64);
- the support matrix generated from `support.toml` (design/24 24-26), never edited by hand;
- for a server release, the `upgrade-path.json` stops and the tested dependency versions.

## 6. Hand off

Use skill `grdr-handoff`. Status `done` only when every gate has passing evidence on the candidate
tree; otherwise `blocked`, naming each failing or not-run gate. `acceptance` holds one entry per gate.
`next` lists the steps that follow, in order. You perform none of them:

1. The merge queue lands the release pull request once the high tier's evaluators and every gate
   here have passed.
2. release-please tags `<component>-v<version>` on the landed commit for each released component and
   for the bundle, and the tag starts the release workflow.
3. The release workflow signs every artefact keylessly; Windows and macOS artefacts without a vendor
   programme ship marked "not platform-signed" in the release manifest (owner instruction 23).
4. The release workflow signs the TUF `binaries` targets once its own rows in
   `references/release-gates.md` and `gh attestation verify` have passed on every artefact
   (design/24 section 10, step 9). The keys are secrets of two GitHub Actions environments, the
   release signer's and the independent rebuilder's, and a target needs both signatures; the root
   keys follow the same threshold of two. Copy those rows into `next`.
5. The artefacts and release objects go to GitHub Releases and the TUF metadata to GitHub Pages; any
   other origin is an `updates.sources` entry, never a step of this run (owner instruction 23).
6. For hosted cells only, the hosted-service gate's record (team/05 section 16).

## Commands this skill names

A command that has not landed yet shows as an unknown subcommand.

| Command or service | Added by | Until it exists |
|---|---|---|
| release-please configuration and its workflow | WI-0012 (reusable release workflow); if WI-0012 lands without it, `lead-release` files it as an issue | There is no release pull request and so no candidate: hand off `blocked`. Never compute versions or write a changelog by hand in its place |
| `.github/workflows/release.yml` | WI-0012 (design/24 24-1) | Nothing can be built or signed for a release: hand off `blocked` |
| `release-candidate` workflow | team/03 K10 | Do not run this skill |
| `cargo xtask matrix-run` | WI-0013 | Tier 1 cells are not run, so the release is blocked |
| `cargo xtask audit run` | team/04 work items 2, 3 and 8 | The release audit set is not run, so the release is blocked (team/04 section 5) |
| Efficacy harness and scorecard | WI-0027; team/05 QG-13 | Scorecard gates are not run, so the release is blocked |
| Held-out evaluator service | WI-0028 | The held-out margin is unknown, so the release is blocked |
| `cargo xtask verify` | WI-0002 | Follow `grdr-verify` |
