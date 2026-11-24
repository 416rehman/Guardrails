---
name: grdr-visual-audit
description: Principal UI/UX Designer screenshot audit workflow. Inspects live Web and Desktop PNG screenshots for visual anomalies, component consistency, clarity, interactivity, beauty, and missing UX affordances, gating UI commits via visual-audit-check.mjs.
---

# Guardrails Visual UI/UX Designer Audit

Code linters catch syntax. Only visual inspection of real screenshots catches truncated text, misaligned baselines, awkward card density, confusing copy, or missing affordances.

## Mandatory Visual Audit Loop

Whenever any UI file (`web/packages/`, `web/apps/`, `desktop/grdr-desktop/src/`, `crates/grdr-ui-model/`) or screenshot changes:

1. **Capture fresh local screenshots (gitignored, never committed to git; attach to GitHub issues or PRs only):**
   - Desktop GPU (`--scene <name> --size 1280x820 --snap desktop/screenshots/desktop-<name>.png`)
   - Web Console & Operator at **both** Desktop (`1440x900@2x`) AND Mobile (`390x844@2x` `*-mobile.png`) into `web/screenshots/*.png`
2. **Invoke an independent UI/UX Visual Design Judge subagent (`research`):**
   - Instruct the judge to open and visually inspect **every** screenshot (Desktop, Web desktop, and Web mobile) directly using `read_file`.
   - Ask the judge to evaluate with Principal Product Designer rigor (no checkbox rubber-stamping):
     0. **Holistic Aesthetics & Platform Personality Gate (Mandatory First Pass):** Inspect ALL Web and Desktop screenshots together as one unified product and judge bluntly: does any screen look ugly, cluttered, amateur, or off-brand? Automatically **FAIL** any violation of the 6 Personality Pillars in `.claude/skills/signs-of-ai-design/SKILL.md`:
        - Rogue off-palette colors (unapproved teal, neon cyan, purple, rainbow gradients)
        - Legend-to-visual color mismatch (legend badge/dot color differing from bar/ring/edge color, or unlabelled chart lines)
        - Amateur or noisy chart chrome (car-odometer half-arcs or tick spokes, grey battery-slot bar tubes, striped bar caps, dot-matrix/hatch wallpaper, empty ghost hex lattices)
        - Pill vomit or heavy chrome (solid saturated table badges where `icon/dot + text` belongs, permanent underlines on resting `EntityLink`s, striped ribbons on cards/modals)
        - Visual drift between Web Console, Operator, and Native Desktop
     1. **Visual anomalies & layout:** Truncation, text wrapping collisions, clip/overflow bugs, uneven baseline alignment, spacing imbalance, contrast issues in Light/Dark modes, broken or blank charts/graphs.
     2. **Component consistency:** Confirm every dropdown, checkbox, toggle, dialog, pagination bar, and button uses the single canonical component style across pages.
     3. **Customer-facing clarity & restraint:** Flag raw technical jargon (`AL0` to `AL4`, `G1/G2`, internal binary names), em dashes, semicolon-joined sentences, AI writing clichés, verbose paragraphs, or redundant chrome.
     4. **Beauty, hierarchy & interactivity:** Does one clear primary focus lead each view? Do visualizations read cleanly at a glance?
     5. **Discrete Iconography & Rich Entity Links:** Flag naked plaintext OS names (`macOS`, `Linux`, `Windows`), dead unclickable `device`/`agent`/`session`/`rule`/`mcp` identifiers, or discrete badges (severity, lifecycle, transport, pinning, profile) lacking intuitive geometric/brand icons.
     6. **Proactive missing features / affordances:** Spot missing UX quality-of-life controls on sight (e.g., collapse sidebar toggle, clear tooltips, empty-state actions, keyboard discoverability).
     7. **Proactive Additions, Removals & Vision Evolution:** Read `docs/design/27-web-console-ux.md`, `docs/design/28-desktop-and-developer-experience.md`, and `docs/design/11-interface-system.md` alongside the screenshots, AND think beyond them as an independent product designer. Propose both plan-aligned refinements and **original net-new ideas not yet thought of in `docs/design/`** across **`additions`** (new interactive controls, intuitive workflows, scale-ready visualizations), **`removals`** (redundant sections, low-signal noise, duplicate metrics, unnecessary chrome), and **`docUpdates`** (which `docs/design/*.md` sections to update if accepted).
     8. **Responsive Design (Mobile + Desktop):** Inspect both desktop (`1440x900`) and mobile (`390x844` `*-mobile.png`) screenshots for page-level horizontal overflow, crushed multi-column grids, nav bars consuming the viewport, clipped buttons/modals, or unreadable tables.
3. **Caller Acceptance & Living Docs:**
   - The caller evaluates every proposed addition and removal and decides whether to accept it into the product and plan or decline it.
   - For every accepted recommendation, implement focused improvements immediately (or schedule multi-view work into the milestone backlog) AND update the relevant `docs/design/*.md` specification so accepted new ideas become part of the living plan.
4. **Resolve ALL findings & re-audit:**
   - Action **every** reported finding from the judge, not just blocking ones: fix **every** item in `blockingIssues` AND **every** item in `polishSuggestions`, plus every accepted `addition` and `removal`.
   - Rebuild and re-capture every affected screenshot, then have the judge inspect again until `verdict: "pass"` with `0` unresolved `blockingIssues` AND `0` unresolved `polishSuggestions`.
5. **Stamp the verified audit (hook-enforced):**
   ```powershell
   node .claude/hooks/visual-audit-check.mjs --record --verdict pass --unresolved 0 --unresolved-polish 0 --summary "<concise summary>"
   ```
   `.claude/hooks/visual-audit-check.mjs` hashes all local screenshots into `.git/grdr-visual-audit.json` (while rejecting any staged/committed screenshots under `web/screenshots/`, `desktop/screenshots/`, or `**/__screenshots__/`) and blocks `git commit` or `gh pr create` for any UI change without a fresh audit stamp showing zero unresolved blocking or polish findings.
