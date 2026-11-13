# Security policy

Report a vulnerability in Guardrails ADR privately. Never put one in a public issue, discussion
or pull request.

## How to report

1. **GitHub private vulnerability reporting** (preferred): open the repository's Security tab and
   choose "Report a vulnerability", or go to
   https://github.com/416rehman/Guardrails/security/advisories/new. The report becomes a private
   advisory with a temporary private fork, and GitHub can assign the CVE.
2. **Email** security@guardrailshq.com once the project domain's mail is set up. Until then, use
   the first channel.

These are the `[addresses.security]` values of `brand/brand.toml`, written out here. When the brand
manifest changes, this file changes with it.

## What to include

- The component and version (`grdr --version`), operating system and architecture, and install
  profile.
- A reproducer: steps, input or a proof of concept. AI-assisted reports are accepted on the same
  terms.
- What you expected, what happened, and the impact you see.

## What happens next

| Step | Target |
|---|---|
| Acknowledge the report | 2 working days |
| Classify it | 5 working days |
| Fix ready on every supported line, from classification | V1: 7 days. V2: 14 days. V3: the next minor release, at most 60 days. V4: best effort |
| Patched release for an advisory in a bundled dependency, from the advisory | 7 days, on every supported line |
| Public disclosure, from classification | At most 90 days, unless you agree to longer |

Severities V1 to V4 are defined in `docs/design/35-product-security-programme.md` section 4.3. A
report shows a vulnerability when a component fails the guarantee it documents: its contract, its
fail-safe behaviour, or the assurance level the product reports for it. A detection that misses a
technique the product never claimed to catch is a content gap and is handled in public.

Each fix ships with a CSAF advisory, VEX statements per supported line and a CVE where one
applies. You are credited unless you ask not to be. Actively exploited vulnerabilities are also
reported to the authorities the EU Cyber Resilience Act names, on its clocks.

Embargoed fixes are made in the advisory's private fork by the project's agents with network
tools off. Report text never enters an agent session that can write in public or hold secrets.
An embargoed fix may change a public surface without an RFC; a retroactive RFC opens when the fix
is disclosed (GOVERNANCE.md).

## Supported versions

No version has been released yet. From the first release, the supported lines are the current
minor release, the two before it and the live long-term support line.
