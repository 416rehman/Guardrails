---
name: grdr-visual-audit
description: Principal UI/UX Designer screenshot audit workflow. Inspects live Web and Desktop PNG screenshots for visual anomalies, component consistency, clarity, interactivity, beauty, and missing UX affordances, gating UI commits via visual-audit-check.mjs.
---

# Guardrails Visual UI/UX Designer Audit

Code linters catch syntax. Only visual inspection of real screenshots catches truncated text, misaligned baselines, awkward card density, confusing copy, or missing affordances.

## Mandatory Visual Audit Loop

Whenever any UI file (`web/packages/`, `web/apps/`, `desktop/grdr-desktop/src/`, `crates/grdr-ui-model/`) or screenshot changes:

1. **Capture fresh screenshots:**
   - Desktop GPU (`--scene <name> --size 1280x820 --snap desktop/screenshots/desktop-<name>.png`)
   - Web Console & Operator (live Chrome CDP `@2x` into `web/screenshots/*.png`)
2. **Invoke an independent UI/UX Visual Design Judge subagent (`research`):**
   - Instruct the judge to open and visually inspect **every** screenshot directly using `read_file`.
   - Ask the judge to evaluate with Principal Product Designer rigor (no checkbox rubber-stamping):
     1. **Visual anomalies & layout:** Truncation, text wrapping collisions, clip/overflow bugs, uneven baseline alignment, spacing imbalance, contrast issues in Light/Dark modes, broken or blank charts/graphs.
     2. **Component consistency:** Confirm every dropdown, checkbox, toggle, dialog, pagination bar, and button uses the single canonical component style across pages.
     3. **Customer-facing clarity & restraint:** Flag raw technical jargon (`AL0` to `AL4`, `G1/G2`, internal binary names), em dashes, semicolon-joined sentences, AI writing clichés, verbose paragraphs, or redundant chrome.
     4. **Beauty, hierarchy & interactivity:** Does one clear primary focus lead each view? Do visualizations read cleanly at a glance?
     5. **Proactive missing features / affordances:** Spot missing UX quality-of-life controls on sight (e.g., collapse sidebar toggle, clear tooltips, empty-state actions, keyboard discoverability).
     6. **Proactive Additions, Removals & Vision Evolution:** Read `docs/design/27-web-console-ux.md`, `docs/design/23-desktop-ux.md`, and `docs/design/11-interface-system.md` alongside the screenshots, AND think beyond them as an independent product designer. Propose both plan-aligned refinements and **original net-new ideas not yet thought of in `docs/design/`** across **`additions`** (new interactive controls, intuitive workflows, scale-ready visualizations), **`removals`** (redundant sections, low-signal noise, duplicate metrics, unnecessary chrome), and **`docUpdates`** (which `docs/design/*.md` sections to update if accepted).
3. **Caller Acceptance & Living Docs:**
   - The caller evaluates every proposed addition and removal and decides whether to accept it into the product and plan or decline it.
   - For every accepted recommendation, implement focused improvements immediately (or schedule multi-view work into the milestone backlog) AND update the relevant `docs/design/*.md` specification so accepted new ideas become part of the living plan.
4. **Resolve & re-audit:**
   - Fix **every** reported defect and accepted enhancement or removal.
   - Rebuild and re-capture every affected screenshot, then have the judge inspect again until `verdict: "pass"` with `0` unresolved blocking issues.
5. **Stamp the verified audit (hook-enforced):**
   ```powershell
   node .claude/hooks/visual-audit-check.mjs --record --verdict pass --summary "<concise summary>"
   ```
   `.claude/hooks/visual-audit-check.mjs` hashes all current screenshots into `.git/grdr-visual-audit.json` and blocks `git commit` or `gh pr create` for any UI change whose screenshots lack a fresh matching audit stamp.
