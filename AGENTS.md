# AGENTS.md

Guardrails ADR is an open-source agent detection and response (ADR) platform (`grdr`).

## Shipping & workflow
- Build directly from the architecture design docs (`docs/design/00-decisions.md`, `03`, `11`, `12`, `20`, `23`, `27`). Follow issue-first development: create self-contained GitHub issue(s) before starting implementation (quoting the user request, design doc refs, exact scope, and verification commands so any cold agent can execute them; split multi-part work into separate issues). Multi-issue waves can run in parallel isolated `Workspace: "share"` worktrees.
- Link every PR via `Closes #<n>` in the PR body, and close with verification summary comments. Screenshots must NEVER be committed in git; upload verified screenshots directly to PRs and issues via `gh pr comment <n> --attach <png>` / `gh issue comment <n> --attach <png>`.
- Work on descriptive feature/fix branches (`feat/<slug>`, `fix/<slug>`, `chore/<slug>`, `docs/<slug>`, `refactor/<slug>`), never pushing directly to `main`, and open a clean PR to merge.
- Keep commit messages to a single short Conventional Commit line (`feat(web): ...`), max 72 chars, no body, no AI trailers.

## Engineering rules
- **Rust safety & quality:** No `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, indexing that can panic, or `process::exit` in non-test code. Use checked or saturating arithmetic where `clippy::arithmetic_side_effects` is denied. Keep `unsafe` out of product code unless explicitly isolated with a `// SAFETY:` comment.
- **Structure (`grdr-structure`):** Keep source files focused (<500 lines outside tests), declare types before `impl`s, represent lifecycles as explicit enums rather than boolean flags, and include `GRDR-<AREA>-<NNNN>` error codes.
- **Privacy (P8) & Vocabulary:** Respect data classes and never leak local secrets or untrusted prompt/agent text into logs or raw HTML. Use Guardrails terminology (`Mode`: `Off`/`Watch`/`Ask`/`Block`, `Verdict`, `Assurance level`, `Grant`, `Receipt`, `Finding`, `Incident`; never "posture" or "case").
- **Web & Desktop UI (`web/`, `desktop/grdr-desktop/`):** Use `pnpm` only (never `npm`, `npx`, `yarn`, or `bun`). Enforce the 6 Platform Personality Pillars and Porcelain Light / Carbon Obsidian palette in `.claude/skills/signs-of-ai-design/SKILL.md` and `.claude/skills/grdr-visual-audit/SKILL.md` across both Web and Desktop (`360°` minimal rings, slender matching-legend bars, quiet inline statuses, un-underlined resting `EntityLink`, zero wallpaper/stripe/pill clutter). Follow `ui-architect` principles: exponential spacing tokens, Lucide icons (never emojis), smart defaults (never empty forms), ethical friction on high-stakes approvals, inert rendering for untrusted text, zero third-party CDN trackers or fonts. All Web UI MUST be responsive across mobile (`390px+`), tablet (`768px+`), and desktop (`1280px+`) viewports with zero page-level horizontal overflow, touch-friendly controls, and adaptive navigation and grids.
- **No direct edits to `.git` internals or unpinned external CI actions.**
- **Plan / Design Doc Alignment Gate:** Every non-trivial feature, refactor, or PR must cite its governing `docs/design/` document or decision/principle IDs (`D-01`..`D-71`, `P1`..`P17`) alongside `Closes #<n>`. Never deviate silently from the planned architecture or introduce unapproved frameworks (`next`, `nuxt`, `express`, `fastify`, `koa`, `@nestjs/*`, `prisma`, `drizzle-orm`, `mongodb`, `mongoose`) into `web/`; update `docs/design/` first before changing any chosen architecture component.

## Engineering principles
1. **(Pre-release / Beta dev lifecycle only; drop this rule at GA release):** Do not maintain backward compatibility with previous unreleased dev versions of this platform. Delete outdated code outright with no compatibility layers, migration scripts, or fallback shims (still model data schemas and versioned contracts cleanly for future post-GA compatibility).
2. Choose the simplest implementation that meets current needs. No speculative abstractions or configuration layers added "just in case".
3. Grow the system in layers: get a minimal end-to-end slice working first, then extend it. Never tear down working code because of hypothetical future complexity.
4. Keep components modular with clear separation of concerns.
5. Prefer mature, maintained third-party libraries; do not rewrite them yourself without a compelling reason.
6. Inspect existing project dependencies first before adding a new package or writing custom code.
7. Make architectural decisions for the long term. No "make it work for now and deal with it later" stopgaps.
8. Research how mature products in our space solve the problem and adopt proven patterns rather than inventing from scratch.
9. Push back on harmful changes: if a requested task or change would hurt the end product more than it helps (for example, hard-coding compile-time types in a way that breaks data-driven extensibility or destroys modularity), push back directly, explain the concrete harm, and propose a better alternative before implementing it.

## Verification gates
Run these before opening or merging a PR:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --locked --all-targets -- -D warnings`
- `cargo test --workspace --locked`
- `cargo deny check`
- For `web/`: `pnpm --dir web run typecheck`, `pnpm --dir web run test`, `pnpm --dir web run build`
- For hooks: `node --test .claude/hooks/branch-check.test.mjs .claude/hooks/ci-stop.test.mjs .claude/hooks/docs-check.test.mjs .claude/hooks/structure-check.test.mjs .agents/hooks/agy-pre-tool-use.test.mjs`
