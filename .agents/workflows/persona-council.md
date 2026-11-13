# persona-council

The persona council's review of one design change (team/02 section 8, team/01 section 11, team/03 section 6). Nine seats walk their persona journeys on the artefact, each seat posts its verdict as a comment on the design issue, and a chair merges the verdicts for the product lead. The council reviews artefacts, never code, and never approves or votes. The Claude Code implementation is `.agents/kit/workflows/persona-council.js`, rendered to `.claude/workflows/persona-council.js`.

## Inputs

| Input | Meaning |
|---|---|
| `issue` | The design issue in the repository (default: `[github] repository` of `.agents/harness.toml`, which the context step reads) |
| `artefact` | Paths, a pull request or a preview build; otherwise what the issue body names |
| `seats` | A subset of seats; otherwise the seats the issue names, otherwise all nine |
| `round`, `repo`, `dryRun`, `force` | Override the round; another repository; build comments without posting; run a round that is already complete at this commit |

## Models

Seats run on Sonnet 5.5 at medium effort, the chair on Opus 5.5 at high effort, and the context and posting steps on Sonnet at low effort. No step runs on Fable or Haiku.

## Steps

1. **Context.** Read the design issue, the artefact under review and its commit (the pull request's head, or `HEAD`), the seats it names and the markers of earlier council comments.
2. **Round.** Round 1 is the review. Round 2 is the one re-review, of the sections changed since round 1. A round whose chair comment exists at this commit is not run again, and a seat already posted for this round and commit is not run again; its verdict is read from its marker. There is no third round.
3. **Seats.** The seats are `persona-solo-dev`, `persona-it-admin`, `persona-soc-analyst`, `persona-msp-operator`, `persona-oem-partner`, `persona-privacy-officer`, `persona-contributor`, `persona-simplicity` and `persona-intl`. A seat that judges a screen loads `ui-architect`, `frontend-design`, `modern-web-guidance` for a web screen, then `grdr-interface`. Each follows its role body in `.agents/templates/agents/<seat>.md` (persona, journeys, inputs, steps), except that it writes no file and returns its verdict to the workflow. For each journey step it writes what it expects before it acts, then what happened and where it would give up; a journey it cannot walk is "could not walk", never a pass. It returns accept, accept with changes, or block, at most five findings (journey step, problem, evidence, smallest fix) and any broken spine floor (P8, D-51, D-31). In a re-review it reads only the changed sections and its earlier findings.
4. **Seat comments.** As soon as a seat returns, its comment goes on the design issue: verdict, findings, journeys, its `handoff.v1` in a collapsed section and a hidden marker. Seat text is rendered inert: mentions are broken, HTML comments escaped, and the dot of a kit record name (`handoff.v1`) written as an entity, since guard-command refuses a body that quotes a record.
5. **Chair.** Once every seat has returned, the chair merges the findings, removes duplicates while naming every seat behind each one, lists each block with the written disposition it needs from `product-lead`, lists every spine-floor break, and lists tensions between seats without resolving them. It never drops or softens a block.
6. **Chair comment.** The chair's comment goes on the design issue with a seat table. A spine-floor break is named at the top, because it goes straight to the chief architect and the product lead as an escalation; it never waits on a person (owner instruction 7).

## Outcome

Done when every seat the item names has a verdict. Each block still needs `product-lead`'s written disposition before the design or screen spec is accepted; a block never stops a merge. A seat that does not return stops the run before the chair; resuming posts nothing twice.

## Not yet available

The seat briefs in `.agents/council/` do not exist yet; each role body names the review files to read instead. The rendered `persona-*` agent definitions are not needed: the workflow points each seat at its role body directly.
