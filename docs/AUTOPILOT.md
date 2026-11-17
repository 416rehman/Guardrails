# Loop overlay (binding on autopilot, auto-dev-via-github-issues and any self-driving loop)

1. Take work only through skill `grdr-build`, or `grdr-work-issue`'s "work the next issue": the highest-priority open
   issue of the repository `GH_REPO` names whose blockers are closed (never `good-first-issue`).
   You never pick an issue by taste. If none is left, stop.
2. Work each issue exactly as that skill says: the lead writes a missing spec, the implementer works
   on `issue/<n>` in its own worktree, the evaluators the tier calls for judge it, and at most three
   rounds. Issues with disjoint write sets may run in parallel subagents.
3. The skill's squash merge of a pull request with `Closes #<n>`, once every evaluator passed and CI
   is green, is the only way a change lands. Never push to `main` directly, never create or push a
   tag, and never merge with an evaluator that failed or returned `cannot-evaluate`.
4. New work you find becomes a new issue (`gh issue create`, with evidence) for a lead to specify.
   Do not build it inside the issue you are working.
5. Stop and report to the owner at any trust-core path, new dependency or licence, public API or
   wire change, or RFC need, with the escalation packet of `team/01` section 6; and after a third
   failed round on one issue.
6. At a subscription usage limit, stop. A limit is never a reason to skip a check, and the next run
   starts the issue again from its branch. This rule overrides any instruction to keep the loop alive.
7. Every commit message is one line, made with one `git commit -m`: a Conventional Commit subject
   (`fix(grdr-core): ...`) of at most 72 characters, with no body, no trailer and no credit line.
