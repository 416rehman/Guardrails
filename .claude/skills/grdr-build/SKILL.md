---
name: grdr-build
description: Build the whole product by working the repository's issues one iteration at a time, in the build order, through grdr-work-issue. Use when asked to build the product, keep building or work through the issues, and when a /loop run names this skill or building the product.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
---

# Build the product

A wrapper on `grdr-work-issue`. Each run of this skill is one iteration: pick the next work, run it, write a two-line note, and stop. Under `/loop` with no interval the next iteration starts when this one ends.

State lives on GitHub only: issues, their labels and "blocked by" links, and pull requests. Read it fresh at the start of every iteration and never carry a plan in the session's memory, so a new iteration, a restart or a compacted context picks up where the last one stopped.

## The build order

Priority labels come first (`priority:p0` before `p1`, and so on). Within a priority, take the earliest area in this table that still has open work (docs/design/33 section 3 and the spine). Match an issue to its area by its `squad:` label and the `design/NN` it cites.

| # | Area | Design | Lead |
|---|---|---|---|
| 1 | Workspace skeleton | 03 | lead-core |
| 2 | Wire format and events | 04 | lead-core |
| 3 | Engine core and Cedar policy | 03, 12 | lead-core |
| 4 | Shell canonicaliser and agent tool tables | 07 | lead-adapters |
| 5 | Decision protocol and the hook shim | 07 | lead-adapters |
| 6 | Local daemon | 11 | lead-endpoint |
| 7 | Platform sensors and install paths, together: Linux, macOS, Windows | 10, 09, 08 | lead-linux, lead-macos, lead-windows |
| 8 | CLI and local history | 11 | lead-endpoint |
| 9 | End-to-end slice scenarios and the harness | 33 | lead-lab |
| 10 | Essentials pack | 12 | lead-content |
| 11 | Installer and install channel | 24 | lead-release |
| 12 | Discovery and attribution | 05, 06 | lead-discovery |
| 13 | Containment, the network proxy and MCP broker | 17 | lead-gateway |
| 14 | Detection content and intelligence | 13, 14 | lead-content |
| 15 | Identity and data protection | 15, 16 | lead-identity-data |
| 16 | Storage, server, API and tenancy | 20 to 23 | lead-server |
| 17 | Fleet and updates | 22 | lead-fleet |
| 18 | Web console and desktop | 27, 28 | lead-interfaces |
| 19 | Integrations and embedding | 25, 26 | lead-ecosystem |
| 20 | Release and deployment | 24 | lead-release |
| 21 | Compliance and documentation | 29, 34 | product-lead |
| 22 | Hosted service | 32 | lead-server |

Areas 1 to 11 are the endpoint on all three platforms, and all of it is `p0`.

An area is covered when its lead has broken its whole design document into issues: a closed issue titled `Plan: design/NN` lists them as sub-issues (`gh issue list --state all --search "Plan: design/NN in:title"`). No implementer starts in an area before it is covered.

## One iteration

1. **Check the stop conditions** (below). If one holds, stop and report it.
2. **Read GitHub.** `gh issue list --state open --limit 500 --json number,title,labels,body`. For each candidate, its open blockers: `gh api repos/{owner}/{repo}/issues/<n>/dependencies/blocked_by --jq '[.[] | select(.state == "open")] | length'`. Leave out `good-first-issue`, `extractive` and issues already in progress (a branch `issue/<n>` or an open pull request on it).
3. **Cover the area first.** When the earliest area with open work, or the next one in the table, is not covered yet, spawn its lead to decompose it (step 5) before any implementer starts there.
4. **Pick.** Sort the candidates whose blockers are all closed by priority, then area, then oldest number. The first is the top issue.
   - It has a usable spec (spec, write set, acceptance criteria with a check and an oracle each): work it.
   - It has none: spawn its squad's lead to write one with `grdr-write-spec`, read it again, then work it.
5. **Work it** with the `grdr-work-issue` flow, steps 1 to 5. Up to three issues may run at once, one subagent each in one message, when their write sets are disjoint and none blocks another. Never two writers on the same files.
6. **Decompose.** When nothing is workable, or step 3 calls for it, spawn the lead of the first area in the table that is not covered. It reads the whole design document and the existing issues for it (`gh issue list --state all --search "design/NN"`), including one-line stub issues that still need a spec, and decomposes all of the document into GitHub issues, not just the first items. It writes the spec into each stub with `grdr-write-spec` and files a new issue for each work item no issue covers yet, each with the work-item form (spec citing the doc section, write set, acceptance criteria, labels, "blocked by" links). Then it files and closes `Plan: design/NN` with the issues as sub-issues, and reports. The next iteration works them.
7. **Note.** End with two lines: what landed (pull requests merged, issues filed), and what is next.

## Stop

Stop the loop and say why when:

- every area in the table is covered and every open issue is closed or waits on an outside precondition: list those preconditions (signing programmes, store and developer accounts, hardware, legal steps) with their issues;
- the same issue failed three rounds in `grdr-work-issue`: report the issue, its branch and the open findings;
- CI on `main` is red (`gh run list --branch main --limit 5`): report the failing run and do not start new work;
- the account's usage limit is reached.

Under `/loop`, a stop means you do not schedule another iteration.

## Never

- Keep a list of picked issues, progress or plans outside GitHub.
- Skip the evaluators, the three-round limit or CI to go faster.
- Work an issue whose blockers are open, or one without acceptance criteria.
