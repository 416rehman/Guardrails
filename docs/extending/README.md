# Extending Guardrails ADR

Guardrails ADR separates dynamic domain content from compiled core engines. Follow these contributor walkthroughs depending on the extension surface you want to add:

- [Adding an Agent Harness Manifest](adding-an-agent-manifest.md): Declare discovery fingerprints and hook dialects in manifests without touching core enums.
- [Adding a Rule or Policy Pack](adding-a-rule-or-pack.md): Author Cedar policies, signed packs, and benign/adversarial replay fixtures.
- [Adding a Port Adapter](adding-a-port-adapter.md): Implement storage, bus, blob, relational, sandbox, or sensor traits behind `crates/grdr-ports` and verify against `crates/grdr-ports-testkit`.
- [Workspace Crate Map](../crates/README.md): Layering rules (`0..4` and `tool`), `grdr-crypto` cryptographic boundary, and design notes per crate.
- **RFC Process (`rfcs/README.md`):** Open an RFC from `rfcs/0000-template.md` when modifying governed public surfaces or contracts.
