# Owner answers and what they change

_2026-11-10. The owner answered three of the spine's questions and gave one instruction. This file says what changes. It binds every document._

## The answers

1. **Legal entity: Loonaro.** Loonaro holds the Apple, Microsoft, GitHub and signing accounts, the trademarks and the domains.
2. **Budget: zero. The agent team runs on the owner's Claude subscription.** There is no money for model API usage, lab hardware, paid audits, paid certifications or hosted infrastructure.
3. **The second person: the owner's buddy.** The buddy is the second human: trust-core reviewer, second maintainer, second approver where two people are required, and on-call partner.

## The instruction: no timelines and no milestones

The plan describes the complete product, not a schedule. Remove from every document:

- milestone labels and gates: M0 to M5, the H track, R1 or "first usable release", exit gates, "self-hosted 1.0" used as a phase;
- horizon tags (Now, Next, Later) and their milestone mappings;
- schedules and durations of the work: dates, "week one", "first two weeks", "by month N", calendars, lead-time timing, "within N days" for project activity, budgets per milestone;
- phrases that put product scope in a phase ("ships at M3", "arrives later", "deferred to M4").

Keep:

- **dependencies**: where one component cannot work without another, state it as a prerequisite ("requires the server", "requires the Apple Endpoint Security entitlement", "requires an embedding partner"), by component, work item or decision, never as a phase;
- **external preconditions**: things outside the team's control (Apple's entitlement, Microsoft's driver programme, an antivirus-programme partner for WESP), stated as conditions, not dates;
- **product behaviour durations**: timeouts, latency targets, retention periods, support windows, key and certificate lifetimes, cooldowns, rotation intervals, rate limits, bake times inside rollout rings;
- **work items and acceptance criteria**: drop their milestone tags; add a "Requires" note only where ordering genuinely matters;
- **experiments (spikes)** with pass criteria, and the decision each can change, without scheduling them.

Every capability in every document is part of the product. Nothing is "later" or "deferred"; where a capability depends on an external precondition, say so.

## Consequences of a zero budget and a Claude subscription

| Area | Before | Now |
|---|---|---|
| Agent team model usage | Token budgets in US dollars per milestone and per work item | One Claude subscription. Work is measured in share of the subscription's usage windows, not dollars. The dispatcher runs within the subscription's limits: it caps concurrent agents, pauses when a usage limit is reached, resumes after the window resets, and never fails work because of a limit. Every recurring agent has a usage cap per run |
| Cross-model review | Review by a second vendor's model | A second Claude model (a different model or tier from the one that wrote the change) with clean context. No other vendor's model is required |
| CI for agents | API-key-based agents in CI | Claude Code in CI authenticated with the owner's subscription (a long-lived token created with `claude setup-token`, held as a CI secret); verify the current terms and limits before relying on it. Scheduled and cloud routines act under the owner's account |
| Test lab | Owned Macs, an x64 virtualisation host, rented arm64, paid incumbent licences | Free hosted CI runners for a public repository (Linux x64 and arm64, Windows x64 and arm64, macOS arm64), the owner's and the buddy's own machines as optional self-hosted runners, and incumbent EDR licences only through design partners or free vendor programmes. Tests that need hardware nobody has are marked "requires hardware" and run when a machine is available |
| Security audits | Paid external audits per component | The buddy reviews the trust core. External audits come from free programmes for open-source projects (for example OSTIF, OpenSSF Alpha-Omega and similar funds) when granted. A kernel component leaves the internal ring only after review by the buddy plus either a free external audit or a documented review by a qualified volunteer |
| Code signing | Paid certificates and services | Windows user-mode binaries through a free open-source signing programme (for example SignPath Foundation), verified at setup. macOS signing, notarisation, system extensions and the Endpoint Security entitlement require Apple's Developer Program, which has an annual fee: this is the one unavoidable cost. Without it macOS ships unsigned with the userspace tier only. The optional Windows kernel driver requires an EV certificate and Microsoft's hardware programme, so it depends on a sponsor or partner |
| Certifications | SOC 2 Type I and II, ISO 27001 for the hosted service | Paid certifications require revenue or a sponsor. The control library, evidence export and project-level obligations (SLSA provenance, SBOM, OpenSSF Best Practices, OSPS Baseline) cost nothing and stay |
| Hosted service | A separate track behind two people on call | Two people on call is now met (owner and buddy). The hosted service still needs infrastructure money, so it requires revenue, sponsorship or donated cloud credits. Self-hosting is the default way to run the platform |
| Legal opinions | Counsel before paid offers | Counsel is required before any paid offer; until then Loonaro offers nothing paid. Free legal help for open-source projects (foundation legal programmes) is the first route |
| Owner time | Ten hours a week of review | Unchanged as a cap on the owner's review queue; the buddy shares trust-core review and on-call |

## Spine questions still open

The spine's questions 4 to 9 remain: the project name, the foundation, the server-licence review, licensing of the owner's own skills, pseudonym issuance, and (now narrowed) whether to pay Apple's annual developer fee.
