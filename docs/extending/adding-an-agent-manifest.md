# Adding an Agent Harness Manifest

AI coding agents, CLI harnesses, and MCP clients are described in declarative manifests loaded dynamically by `crates/grdr-agents` rather than hardcoded Rust `enum` variants.

## Steps

1. Inspect [crates/grdr-agents/src/catalogue.rs](../../crates/grdr-agents/src/catalogue.rs) and existing harness manifests to confirm field schema.
2. Add the agent's typed discovery patterns (binary paths, config files, MCP registry locations, and hook dialect identifiers). Never include commands to execute, remote URLs to fetch, or environment mutations in a content manifest (`CONTRIBUTING.md`).
3. Supply at least one benign negative fixture and one positive match fixture with synthetic inputs.
4. Run full verification:

```powershell
cargo test -p grdr-agents --locked
node scripts/check-architecture.mjs
```
