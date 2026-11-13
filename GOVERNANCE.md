# Governance

This file says who decides what in Guardrails ADR. It changes only through an
RFC. COVENANT.md sits above it: nothing here can weaken the covenant.

## Principles

- The project is open source: Apache-2.0 for code and content, with the
  exceptions stated in CONTRIBUTING.md. Nothing is withheld.
- AI agents plan, build, review and release the project, and no step
  needs a person. The merge queue, which is deterministic software, lands
  every change once its checks and the reviews its risk requires pass. An
  agent never reviews its own change and never holds a code-owner entry or
  a vote in the steering group.
- People may contribute, review and maintain. A person's review adds
  evidence; it is never a required step.
- Decisions and their reasons are public, in docs/decisions/ and rfcs/,
  except security work under embargo (see SECURITY.md).

## Roles

Steward: Loonaro, the company that started the project. It holds the
project's assets (listed in COVENANT.md) until they move to a neutral
foundation and holds the project's accounts. Releases are signed by the
release pipeline without any person holding a key; the steward adds
platform signatures with the signing identities it holds.

Owner: one person from the steward. The owner sets the project's
direction in written instructions and, until the steering group exists,
decides the foundation application and the transfer date. The owner
signs and approves nothing that lands.

Second maintainer: a maintainer named by the owner in MAINTAINERS.md who
holds the owner's account-level duties when the owner is absent.
The Succession section below and COVENANT.md state how.

Chief architect: the agent that owns the decision spine. It accepts,
rejects or postpones RFCs after the review council and the architecture
evaluator have reviewed them, and writes down why.

Release manager: the release agent of each release line. It keeps the
release pull request and checklist green and owns backports; the release
tooling creates the tags, and the merge queue lands the release pull
request.

Maintainers: people listed in MAINTAINERS.md for one or more areas, with
their affiliation. They review changes in their areas, appear in
CODEOWNERS (which requests their review and does not require it),
shepherd RFCs and vote on new maintainers.

Trust-core maintainers: maintainers approved for the paths listed in
security/trust-core.paths (kernel programs, privileged services, updater,
cryptography, policy semantics, tenancy, gate and release configuration).
They review changes on those paths when they can. A trust-core change
lands on two independent passing reviews by agents on different models;
a maintainer's review adds evidence.

Content reviewers: people approved to review content (rules, fingerprints,
packs) in a domain. They may be volunteers or maintainers.

Contributors: anyone who follows CONTRIBUTING.md and AI_POLICY.md.

Agents: the roster agents in .agents/roster.toml. They file, ready and
implement work items, review as evaluators and draft RFCs. They never
merge (the merge queue does), never review their own change, and never
hold a code-owner entry, an entry in MAINTAINERS.md or a steering vote.

## Steering group

The steering group forms when the second maintainer from outside the
steward is added. Every maintainer has a seat up to five seats. Above five,
maintainers elect five members each year, one vote per maintainer.

The steward holds at most two seats. While the group has fewer than five
members, the steward holds fewer than half of the seats. When more
steward maintainers are eligible than the cap allows, they choose among
themselves who sits.

The steering group decides:
- adding maintainers when there is an objection, and adding trust-core
  maintainers;
- code of conduct reports escalated to it (members with a conflict recuse);
- the foundation application and the transfer date under COVENANT.md.

It gates nothing in building, reviewing, landing or releasing. The gates
in AI_POLICY.md change only through an RFC to docs/design/00-decisions.md.

It decides by lazy consensus: a proposal posted publicly passes after seven
days without objection. Any member may call a vote instead; a simple
majority decides.

Until the steering group forms, the owner decides the foundation
application and the transfer date, and the chief architect decides the
rest. Every decision is written to docs/decisions/ with its reason.

## RFCs

An RFC is required to change:
- docs/design/00-decisions.md (the decision spine);
- the public crates (schema, core, ports and shared libraries, the C ABI
  and the WebAssembly binding);
- wire formats: protobuf packages, the pack format, the provider protocol
  and the host contract;
- the Cedar schema;
- a stability class in surfaces.toml, or a new dependency edge between
  crates in the same layer;
- this file, CONTRIBUTING.md, AI_POLICY.md, COVENANT.md, the licence policy,
  the release and support policy, or removal of an entry from the
  do-not-read list.

How it works:
1. Open a pull request adding rfcs/NNNN-title.md from the template
   rfcs/0000-template.md.
2. When the text is ready, the review council and the architecture
   evaluator review it, and anyone may comment in the pull request.
3. The chief architect accepts, rejects or postpones it and writes the
   reasons in the pull request. There is no waiting period; a later
   comment that shows a defect opens a new RFC.
4. Accepted RFCs are implemented through linked work items. CI refuses a
   change to an RFC-gated surface whose pull request body does not name
   the RFC on a line `RFC: <nnnn>`. The gated paths are listed in
   governance/rfc-required.toml.

Every RFC names its author, agent or person, and the harness and model
that drafted it. Commenting needs no account on any service other than the
code host.
A fix for an embargoed vulnerability may change a public surface without an
RFC; a retroactive RFC opens when the fix is disclosed.

## Becoming a maintainer

- Vouched contributor: one merged content contribution, an accepted issue
  with a reproducer, or a maintainer's vouch.
- Content reviewer: about ten merged content contributions over at least
  three months and five substantive reviews in the domain. Nominated in a
  public issue; accepted if no maintainer objects within seven days.
- Maintainer: about six months of activity and twenty merged changes or
  reviews in the area. Nominated in a public issue; accepted after 14 days
  by a majority of the maintainers who vote. Once the steering group
  exists, an objection that is not resolved in the issue moves the
  decision to it.
- Trust-core maintainer: a maintainer whose ten shadowed trust-core reviews
  matched the review agents' findings; accepted by the steering group.

Maintainers and reviewers use hardware-backed two-factor authentication
and declare their affiliation.

After six months without activity a maintainer becomes emeritus: rights
end, the name stays in MAINTAINERS.md. The steering group may remove a
maintainer for cause; the person concerned does not vote.

## Succession

If the owner is absent, the second maintainer named in MAINTAINERS.md
holds the owner's account-level duties: the repositories' settings under
the owner's account and the covenant assets. They hold them until a new
owner is named. No landing or release waits on the owner or the second
maintainer: the merge queue and the release pipeline keep running on
their gates. COVENANT.md states the same rule, and no governance body can
weaken it.

## Releases and support

Release lines and support windows are published in the support statement
and change only by RFC. Before 1.0 the latest minor release is supported.
From 1.0 the supported lines are the current minor, the two before it and
the live long-term support line. Security fixes for supported lines are
never paid for.

## Conflicts of interest

Members declare their employer and any paid relationship with the steward.
The first-response and merge-time metrics in community/health.md are
reported by affiliation so that anyone can check that outside
contributions are not handled more slowly.

## Code of conduct

CODE_OF_CONDUCT.md applies in every project space. Reports go to the
address in that file and are handled privately; the project publishes only
counts.
