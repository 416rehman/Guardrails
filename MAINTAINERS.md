# Maintainers

The people who maintain Guardrails ADR, per area, with their affiliation.
Only people are listed: no agent identity or bot holds an entry, and
`cargo xtask governance-check` fails on one. `.github/CODEOWNERS` is
generated from this list; it requests a listed person's review and never
requires it.

## Maintainers

```toml
[[maintainer]]
name = "416rehman"
handle = "416rehman"
affiliation = "Loonaro"
role = "owner"
areas = ["*"]
trust_core = false
since = "2026-11"
```

## Roles

- `owner`: the person from the steward who sets direction (GOVERNANCE.md).
- `second-maintainer`: holds the owner's account-level duties if the
  owner is absent (GOVERNANCE.md, Succession).
- `maintainer`: reviews changes in `areas`, shepherds RFCs and votes on
  new maintainers.
- `trust-core-reviewer`: reviews trust-core changes when available; the
  review adds evidence and never gates.
- `emeritus`: inactive for six months; rights end, the name stays.

Each entry has `name`, `handle` (the GitHub login), `affiliation`,
`role`, `areas` (path globs), `trust_core` and `since`. A new maintainer
is added by the ladder in GOVERNANCE.md.
