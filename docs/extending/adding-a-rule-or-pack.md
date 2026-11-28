# Adding a Rule or Policy Pack

Policy rules and Essentials baselines evaluate typed actions against Cedar policies and signed packs.

## Safety & Review Invariants

- All content starts in `Watch` mode during initial validation before promotion (`CONTRIBUTING.md`).
- Never reproduce or paraphrase rules from [security/supply-chain/do-not-read.toml](../../security/supply-chain/do-not-read.toml).
- Provide inert positive (must match) and negative (must not false-positive) fixtures.
- Rules permitting `Block` or containment responses require two independent reviews per repository root `GOVERNANCE.md`.

## Verification Commands

```powershell
cargo test -p grdr-core -p grdr-engine --locked
node scripts/licence-lint.mjs
```
