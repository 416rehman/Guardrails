# Lab 1: Developer Endpoint Enforcement & Receipt Audit

## Objectives

1. Discover local AI harnesses via `cargo run -p grdr -- scan --json`.
2. Preview (without applying) Claude Code hook installation via `cargo run -p grdr -- hook install --agent claude-code`.
3. Evaluate a sensitive control-file write using `cargo run -p grdr -- check --action file.write --target .claude/settings.json` and confirm `Block` output.
4. Pipe an inert JSON hook event into `cargo run -p grdr-hook` and verify deterministic fail-closed evaluation.
5. Verify hash-chained local receipts using `cargo run -p grdr -- audit verify --json`.
