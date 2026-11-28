# Governance

This file says who decides what in Guardrails ADR. It changes only through an
RFC. [docs/governance/COVENANT.md](docs/governance/COVENANT.md) sits above it: nothing here can weaken the covenant.

## Principles

- The project is open source: Apache-2.0 for code and content, with the
  exceptions stated in [CONTRIBUTING.md](CONTRIBUTING.md). Nothing is withheld.
- AI agents plan, build, review and release the project, and no step
  needs a person. A change lands as a squash merge once its checks and
  the reviews its risk requires pass. An
  agent never reviews its own change and never holds a code-owner entry or
  a vote in the steering group.
- People may contribute, review and maintain. A person's review adds
  evidence; it is never a required step.
- Decisions and their reasons are public, in [docs/decisions/](docs/decisions/) and [rfcs/](rfcs/),
  except security work under embargo (see [SECURITY.md](SECURITY.md)).

## Roles

Steward: Loonaro, the company that started the project. It holds the
project's assets (listed in [docs/governance/COVENANT.md](docs/governance/COVENANT.md)) until they move to a neutral
foundation and holds the project's accounts. Releases are signed by the
release pipeline without any person holding a key; the steward adds
platform signatures with the signing identities it holds.

Owner: one person from the steward. The owner sets the project's
direction in written instructions and, until the steering group exists,
decides the foundation application and the transfer date. The owner
signs and approves nothing that lands.

Second maintainer: a maintainer named by the owner in [docs/governance/MAINTAINERS.md](docs/governance/MAINTAINERS.md) who
holds the owner's account-level duties when the owner is absent.
[docs/governance/COVENANT.md](docs/governance/COVENANT.md) states succession.

Chief architect: the agent that owns the decision spine. It accepts,
rejects or postpones RFCs after the review council and the architecture
evaluator have reviewed them, and writes down why.

Release manager: the release agent of each release line. It keeps the
release pull request and checklist green and owns backports; the release
pull request lands like any other, and the release tooling creates the
tags.

Maintainers: people listed in [docs/governance/MAINTAINERS.md](docs/governance/MAINTAINERS.md) for one or more areas, with
their affiliation. They review changes in their areas, appear in
[.github/CODEOWNERS](.github/CODEOWNERS) (which requests their review and does not require it),
shepherd RFCs and vote on new maintainers.

Trust-core maintainers: maintainers approved for the paths listed in
[security/trust-core.paths](security/trust-core.paths) (kernel programs, privileged services, updater,
cryptography, policy semantics, tenancy, gate and release configuration).
They review changes on those paths when they can. A trust-core change
lands on two independent passing reviews by agents on different models;
a maintainer's review adds evidence.

Content reviewers: people approved to review content (rules, fingerprints,
packs) in a domain. They may be volunteers or maintainers.

Contributors: anyone who follows [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/governance/AI_POLICY.md](docs/governance/AI_POLICY.md).

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
- the foundation application and the transfer date under [docs/governance/COVENANT.md](docs/governance/COVENANT.md).

It gates nothing in building, reviewing, landing or releasing. The gates
in [docs/governance/AI_POLICY.md](docs/governance/AI_POLICY.md) change only through an RFC to [docs/design/00-decisions.md](docs/design/00-decisions.md).

It decides by lazy consensus: a proposal posted publicly passes after seven
days without objection. Any member may call a vote instead; a simple
majority decides.

## RFCs

An RFC is required to change:
- [docs/design/00-decisions.md](docs/design/00-decisions.md) (the decision spine);
- the public crates (schema, core, ports and shared libraries, the C ABI
  and the WebAssembly binding);
- wire formats: protobuf packages, the pack format, the provider protocol
  and the host contract;
- the Cedar schema;
- a stability class in [contracts/surfaces.toml](contracts/surfaces.toml), or a new dependency edge between
  crates in the same layer;
- this file, [CONTRIBUTING.md](CONTRIBUTING.md), [docs/governance/AI_POLICY.md](docs/governance/AI_POLICY.md), [docs/governance/COVENANT.md](docs/governance/COVENANT.md), the licence policy,
  the release and support policy, or removal of an entry from the
  do-not-read list.

How it works:
1. Open a pull request adding `rfcs/NNNN-title.md` from [rfcs/0000-template.md](rfcs/0000-template.md).
2. When the text is ready, the review council and the architecture
   evaluator review it, and anyone may comment in the pull request.
3. The chief architect accepts, rejects or postpones it and writes the
   reasons in the pull request. There is no waiting period; a later
   comment that shows a defect opens a new RFC.
4. Accepted RFCs are implemented through linked work items. CI refuses a
   change to an RFC-gated surface whose pull request does not name an
   accepted RFC.

Every RFC names its author, agent or person.
A fix for an embargoed vulnerability may change a public surface without an
RFC; a retroactive RFC opens when the fix is disclosed.

## Becoming a maintainer

- Vouched contributor: one merged content contribution, an accepted issue
  with a reproducer, or a maintainer's vouch.
- Content reviewer: about ten merged content contributions over at least
  three months and five substantive reviews in the domain. Nominated in a
  public issue; approved if no maintainer objects within seven days.
- Maintainer: about six months of activity and twenty merged changes or
  reviews in the area. Nominated in a public issue; approved after 14 days
  by a majority of the maintainers who vote. Once the steering group
  exists, an objection that is not resolved in the issue moves the
  decision to it.
- Trust-core maintainer: a maintainer whose ten shadowed trust-core reviews
  matched the review agents' findings; approved by the steering group.

Maintainers and reviewers use hardware-backed two-factor authentication
and declare their affiliation.

After six months without activity a maintainer becomes emeritus: rights
end, the name stays in docs/governance/MAINTAINERS.md. The steering group may remove a
maintainer for cause; the person concerned does not vote.

## Releases and support

Release lines and support windows are published in the support statement
and change only by RFC. Security fixes for supported lines are never paid
for.

## Conflicts of interest

Members declare their employer and any paid relationship with the steward.
The first-response and merge-time metrics in [docs/community/health.md](docs/community/health.md) are
reported by affiliation so that anyone can check that outside
contributions are not handled more slowly.

## Code of conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies in every project space. Reports go to the
address in that file and are handled privately; the project publishes only
counts.
