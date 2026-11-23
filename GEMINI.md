# GEMINI.md

@[AGENTS.md](AGENTS.md)

## Gemini and Antigravity specifics
- Build and ship code directly on `feat/<slug>` / `fix/<slug>` branches following `AGENTS.md`.
- `.agents/hooks.json` enforces branch naming, no direct push to `main`, and published-docs hygiene on `run_command`.
- Always set `$env:GH_REPO = "416rehman/Guardrails"; $env:GH_PROMPT_DISABLED = "1"; $env:CARGO_TERM_COLOR = "never"` in PowerShell commands interacting with `gh` or `cargo`.
- Load `ui-architect` and `frontend-design` before UI changes, `grdr-structure` before Rust changes, and verify all Rust, Web, and hook checks cleanly before pushing.
