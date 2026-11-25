# GEMINI.md

@[AGENTS.md](AGENTS.md)

## Gemini and Antigravity specifics
- Build and ship code directly on `feat/<slug>` / `fix/<slug>` branches following `AGENTS.md`.
- `.agents/hooks.json` enforces branch naming, no direct push to `main`, published-docs hygiene, beta engineering principles, visual-audit stamps (`visual-audit-check.mjs`), and non-UI security/safe-coding judge stamps (`security-audit-check.mjs`) via `agy-pre-tool-use.mjs` on file edits and `run_command`.
- Always set `$env:GH_REPO = "416rehman/Guardrails"; $env:GH_PROMPT_DISABLED = "1"; $env:CARGO_TERM_COLOR = "never"` in PowerShell commands interacting with `gh` or `cargo`.
- Load `ui-architect`, `frontend-design`, `signs-of-ai-design`, and `grdr-visual-audit` before UI changes, `grdr-structure` and `grdr-security-audit` for Rust and non-UI changes, and stamp the verified `research` judge pass via `node .claude/hooks/security-audit-check.mjs --record` after all Rust, Web, and hook checks pass. PR screenshots (`grdr-visual-audit`) apply strictly to UI-changing PRs (`web/`, `desktop/grdr-desktop/`, `crates/grdr-ui-model/`, `contracts/interface/brand/`); report non-UI verification and Security Judge verdicts strictly in markdown text (never synthetic CI/terminal screenshots).
- Follow the 9 pre-release Engineering principles and 6 Platform Personality Pillars in `AGENTS.md` (dropping Rule 1 once the product ships out of beta; push back directly under Rule 9 whenever a requested change would hurt extensibility, modularity, or the end product).
