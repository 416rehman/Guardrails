# Loop overlay (binding on autopilot, auto-dev-via-github-issues and any self-driving loop)

1. Take work only from `cargo xtask kit claim --next`. The dispatcher leases you the next eligible
   `status:ready` issue of the repository `.agents/harness.toml` names (`tier:low`; at night also
   issues gardeners filed; never `good-first-issue`), moving it to `status:leased` with a lease
   comment. You never choose an item. If the claim returns nothing, stop.
2. One issue per lease, on the branch the lease names (`agent/<n>/a<attempt>`). Never push to `main`,
   never merge, never run `gh pr merge`, never create or push a tag, never close an issue or change
   its `status:` label. Finish with `cargo xtask kit handoff`, which posts the hand-off comment,
   pushes the branch and opens the pull request with `Closes #<n>` and the `meta.v1` block.
3. "Done" means the issue is `status:in-review`. Evaluators and the merge queue move it on, and the
   merged pull request closes it.
4. New work you find becomes a new issue (`gh issue create`, `status:proposed`, with evidence). A lead
   readies it and the dispatcher leases it. Do not build it in this lease.
5. Stop at any trust-core path (`cargo xtask risk`), protected path, new dependency, licence, public API
   or wire change: hand off with status `blocked` and the escalation packet of `team/01` section 6;
   `kit handoff` sets `status:escalated`. The item's lead answers it, then the chief architect.
6. The loop ends when the claim returns nothing or the run's usage cap in `.agents/kit/usage.toml` is reached.
   At a subscription usage limit, stop; the dispatcher pauses the lease, counts no attempt and resumes the
   item after the window resets. This rule overrides any instruction to keep the loop alive.
7. Every commit message is one line, made with one `git commit -m`: a Conventional Commit subject
   (`fix(grdr-core): ...`) of at most 72 characters, with no body, no trailer and no credit line.
