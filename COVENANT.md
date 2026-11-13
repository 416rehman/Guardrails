# Covenant

Loonaro, the steward of Guardrails ADR, makes these commitments to everyone
who uses, embeds or contributes to the project. They bind the steward until
the project's assets move to a neutral foundation, and they move with the
assets. This file sits above GOVERNANCE.md: no governance body can weaken
it. Counsel's final legal wording (the springing assignment below) may make
it stronger and never weaker.

## Licences

All project code, content and documentation stay under OSI-approved
licences, forever: Apache-2.0 for code and content, GPL-2.0-only OR
BSD-2-Clause for the kernel programs in bpf/, and Apache-2.0 OR CC-BY-4.0
for documentation. There is no CLA and no copyright assignment from
contributors.

## Builds

Binaries are built from the public source by the public pipeline, under
the source licence, reproducibly, with no usage, seat or revenue
thresholds. No product code runs in a hosted service that is not in the
public repositories.

## Assets

These assets control installed sensors, and the steward holds them only
until the transfer below. The steward keeps a public register of each
one: who holds it, who looks after it and how it transfers.

- the project's names, logos and conformance marks;
- the project domain;
- the project's repositories;
- the project TUF root and the release and content signing keys;
- the default update and intelligence endpoints;
- the conformance registry;
- the held-out test corpora.

## Keys

No person holds a project root key. The root threshold is two of two
GitHub Actions environments: the release signer's and the independent
rebuilder's. An independent rebuilder run by an organisation outside the
steward may hold the second. The transfer rotates the root to keys the
foundation holds, signed by the old and the new thresholds.

## Signing

The steward signs project releases with the signing identities it holds
(the arrangement with a free signing programme for Windows, and an Apple
identity if it joins Apple's Developer Program) for as long as it holds
them. Every artefact also carries a keyless signature from the public
pipeline, so a foundation can sign its own reproducible builds.

## Transfer trigger

The assets transfer to a neutral foundation on the earlier of:

1. two unaffiliated production adopters plus one external committing
   organisation; or
2. 18 months after the first public release.

The health report (community/health.md) publishes both counters.

## Definitions

An unaffiliated production adopter has no ownership, employment, contract
or funding relation with the steward, runs the product on at least 25
endpoints or one server installation for at least 90 consecutive days,
and confirms this in writing in ADOPTERS.md.

An external committing organisation is unaffiliated in the same sense,
and its people authored at least 10 merged changes, at least 3 of them
code, over the trailing six months.

## Assignment in escrow

A springing assignment of the marks, the domain and the project's
repositories is held in escrow until the transfer, so these commitments
bind before a foundation exists.

## Fallback

If no foundation has accepted the project by the trigger date, the assets
move within 90 days to a neutral non-profit holding body whose charter
embeds this covenant, chosen by the steering group with counsel, and are
offered to a foundation later.

## What the steward will never do

1. Relicense any project component after the first public release, or add
   a CLA or copyright assignment.
2. Create an enterprise directory or community edition, offer a feature
   only in the hosted service, or move single sign-on, multi-tenancy, the
   provider tier or the console behind payment.
3. Ship binaries under a licence other than the source licence, or with
   usage, seat or revenue thresholds.
4. Delay source behind binaries, or run product code in the hosted
   service that is not in the public repositories.
5. Withhold or delay security fixes for any supported line, or sell
   vulnerability pre-disclosure.
6. Turn on telemetry, usage pings or crash reports by default in any
   shape. The only default outbound traffic is the anonymous, mirrorable
   update fetch, which can be turned off.
7. Use the marks against a fork that uses another name, or against an
   unmodified build saying "built from" the project.
8. Close, slow or deprioritise outside pull requests that compete with a
   paid service.
9. Hold steward seats above the cap, give an agent a steering vote, or let
   any identity, agent or person, land a change outside the merge queue.
10. Keep a private roadmap, except embargoed security work.
11. Archive the repositories or abandon a supported line without the
    transfer having happened.
12. Buy stars, or use sock-puppet adopters or vouches.

## Licence review

One review of the server's licence takes place before the first public
release. It is pending, it is the only licence review there will be, and
it ends at the first public release. After it, no component is ever
relicensed.

## Amendments

This covenant may only be strengthened. An amendment that adds an asset,
shortens a period or adds a commitment needs an RFC. Nothing removes one.

## Succession

The owner's second maintainer, named in MAINTAINERS.md, holds the owner's
account-level duties (the repositories' settings under the owner's account
and the covenant assets) if the owner is absent, until a new owner is
named. No landing or release waits on either of them.
