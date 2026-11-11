# Models and orchestration for the agent team

_2026-11-10. The owner's instruction: at most one Fable 5.2 agent, Opus 5.5 for medium-to-heavy work, Sonnet 5.5 for everything else. This file binds `team/01`, `team/02`, `team/03`, `team/05`, spine D-47 and D-63, and `PLAN.md` section 10._

## Model rule

| Model | Id | Used by | Limit |
|---|---|---|---|
| Fable 5.2 | `claude-fable-5-2` | `chief-architect` only | Exactly one agent identity, one session at a time, on demand: spine and RFC changes, architecture review of trust-core and public-interface changes, settling disputes between squad leads. Never in a loop, never scheduled, never as a worker |
| Opus 5.5 | `claude-opus-5-5` | Medium-to-heavy reasoning: `product-lead`; the 18 squad leads; `impl-kernel`; any worker on a trust-core path or a high-risk-tier change; `eval-security`; `eval-adversarial`; the persona-council chair; the refuting pass of every scheduled audit; the cross-model review of changes Sonnet wrote | Concurrency set by the dispatcher within the subscription's usage windows |
| Sonnet 5.5 | `claude-sonnet-5-5` | Everything else: `programme-manager`; `impl-rust`, `impl-apple`, `impl-web`, `impl-content` and `impl-docs` on low and medium tiers; `eval-acceptance`, `eval-ux`, `eval-performance`, `eval-api`, `eval-platform`, `eval-docs`, `eval-licence`, `eval-tier`; the cross-model review of changes Opus wrote; council seats; every gardener's find pass; intake triage; the operations agents | Same |

- **No Haiku and no other vendor's model.** The earlier small tier (T3) folds into Sonnet; the earlier cross-model tier (X, another vendor) is replaced by the rule below.
- **Cross-model review.** A change is always reviewed by a model other than the one that wrote it: Opus reviews what Sonnet wrote, and Sonnet reviews what Opus wrote, each in a clean context. Trust-core changes are also reviewed by `eval-security` (Opus, clean context) and by the buddy.
- **Which model a worker uses** is decided by the dispatcher from the change's risk tier and paths, not by the worker: trust-core path or high tier means Opus; otherwise Sonnet. `impl-kernel` is always Opus.
- **Effort** stays per agent as `team/02` sets it.
- `.agents/models.toml` binds three names, `fable`, `opus` and `sonnet`, to these ids. The renderer refuses a second agent bound to `fable`.

## Orchestration

| Layer | What it is | Model |
|---|---|---|
| Owner and buddy | Decide, approve high-tier changes, sign merge batches, hold keys, carry the pager | People |
| Chief architect | Keeps the spine true; writes RFCs and decision records; reviews architecture; never writes code | Fable 5.2 |
| Programme manager | Keeps the work graph moving: ready set, concurrency proposal, daily digest; never writes code | Sonnet 5.5 |
| Product lead and squad leads | Specify and plan work items with acceptance criteria and oracles; never write code | Opus 5.5 |
| Dispatcher | Deterministic software, not an agent (`cargo xtask dispatch`, following the Symphony draft semantics in `team/01`). It reads the work graph in the repository, leases each ready item to exactly one worker, starts a headless Claude Code session with the agent definition and model (`claude -p --agent <name> --model <id>`) in a disposable VM and worktree, enforces turn and wall-clock caps, detects stalls, and keeps the number of concurrent sessions inside the subscription's usage windows. When a usage limit is reached it stops starting sessions, lets running ones finish, and resumes after the window resets | None |
| Workers | One writer per work item; return a structured hand-off | Sonnet 5.5, or Opus 5.5 by the rule above |
| Evaluators | Clean-context checks that drive the built product; publish check runs, never approvals | As in the model rule |
| Merge queue | Deterministic software: rebase, gate, squash, stage; lands only on the owner's or the buddy's signature | None |
| Gardeners | Scheduled maintenance agents (GitHub Actions cron, or Claude Code scheduled tasks for private work) | Sonnet 5.5 find pass, Opus 5.5 refute pass |
| Fan-out work | Research, audits and broad reviews that need many agents at once run as a Claude Code multi-agent workflow started by the chief architect or the programme manager inside one session | Each agent as in the model rule |

**Where sessions run.** On the owner's or the buddy's machines and on CI runners, all authenticated with the owner's Claude subscription. In CI, Claude Code uses a subscription token created with `claude setup-token` and held as a secret; check the subscription's current terms before relying on it.

**Concurrency.** Start small, for example two writers and two evaluators at once, and let the dispatcher raise it only while the usage windows hold and the owner's review queue stays short. Fable sessions count against a separate, smaller allowance and never block other work.
