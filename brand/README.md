# Brand manifest

`brand.toml` is the brand manifest of decision D-66 (`docs/design/00-decisions.md`): the product
name, short name, category, legal entity, project domain, repository and every public address of
Loonaro's distribution of Guardrails ADR. Code, configuration defaults, documentation builds and
release tooling read these values from here; no other file holds a brand string or one of these
addresses (owner instruction 26, gate S7).

- Each address carries `value`, used now, and `on_domain`, its value once DNS for `identity.domain` is set
  up. Until then the values are GitHub-hosted (GitHub Pages and GitHub Releases on the repository),
  and an empty `value` means the address is not set up yet.
- A white-label or partner build replaces this file (D-41 L6). Brand overrides of the design tokens
  live in `brand/tokens/` (ARCH-009).
- A self-hosted deployment does not edit this file. It sets its own hosts, origins and addresses
  in boot configuration and runtime settings, and never contacts Loonaro's domain.
- The directory is a protected path, so a change to it is its own protected-change work item
  (owner instruction 7).
