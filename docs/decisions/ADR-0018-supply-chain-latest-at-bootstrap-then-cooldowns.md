# ADR-0018: Supply chain: latest at bootstrap, then cooldowns, audits, pinned actions and a do-not-use list

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-62, D-63; `design/02` SD-03, SD-12
- Requires: nothing
- RFC: not required: restates D-62 and D-63 as repository mechanism
- Work items: [WI-0004]

## Context
A security product that ships a compromised dependency harms every host it protects. Freshly published malicious releases are usually caught within days, and unpinned actions are mutable (briefs 32, h09). The owner asked for the newest versions at bootstrap and proactive vulnerability work (owner instruction 22).

## Decision
The seed pins the newest stable release of every dependency, tool, action and toolchain with no cooldown. After it, Dependabot proposes updates after a cooldown of 3 days for patch and minor releases and 7 for majors; security fixes skip the cooldown with `eval-security` reading the diff. Cargo's `min-publish-age` and pnpm's `minimumReleaseAge` are a second layer. Every crate is covered by `cargo vet`. Every action is pinned by full commit SHA. Licences come from an allow-list and banned crates from a do-not-use list. No tool needs a paid plan or a new account.

## Enforced by
`cargo deny` (`deny.toml`, `supply-chain/licences.toml`), `cargo vet`, zizmor, gitleaks, osv-scanner and Semgrep OSS in `verify` and `scan.yml`; `.github/dependabot.yml`; `supply-chain/build-tools.toml` with a digest per tool. Each gate has a seeded fixture it must fail on.

## Consequences
A dependency update is a pull request in the lane its diff earns. A new dependency or licence is an escalation and a protected change.

## Alternatives rejected
- Renovate: it needs an App account or a token, which owner instruction 23 rules out.
- No cooldown after bootstrap: it accepts releases before the ecosystem has looked at them.

## Revisit when
A reachable KEV-listed advisory waits behind a cooldown, or the weekly Scorecard falls below its floor.
