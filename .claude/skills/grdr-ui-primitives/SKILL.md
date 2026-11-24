---
name: grdr-ui-primitives
description: Enforce single canonical UI components (Astryx, UI-SDK, rune-kit), plain customer-facing terminology, collapsible navigation, exponential spacing, and accessible keyboard support across Web and Desktop UI.
---

# Guardrails UI Component & Clarity Standards

## 1. One Canonical Component Per Pattern (No Rebuilding)
- **Web (`web/packages/ui`):** Every button, badge, banner, card, modal dialog (`Dialog`), dropdown (`Selector` / `GrdrSelect`), checkbox (`CheckboxInput`), switch (`Switch`), tooltip (`Tooltip`), keyboard badge (`Kbd`), progress bar (`ProgressBar`), pagination bar (`Pagination`), icon button (`IconButton`), and segmented control (`UiSdkSegmentedControl`) MUST come from `@astryxdesign/core` or `@ui-sdk/react` wrapped in `@grdr/ui`.
- **Forbidden in `web/apps/` and `web/packages/kit/`:** Raw `<select>`, `<input>`, `<textarea>`, `<dialog>`, or hand-rolled modal backdrops. Always import from `@grdr/ui` so focus trapping, ARIA roles, keyboard navigation (`Escape`, Arrow keys, `Tab`), logical spacing, and theme tokens are guaranteed uniformly on every page.
- **Desktop (`desktop/grdr-desktop`):** Use `rune_kit` primitives (`Button`, `IconButton`, `SegmentedControl`, `Divider`, `Progress`, `Table`) styled via `StudioTheme`.

## 2. Customer-Facing Clarity (Zero Internal Jargon or AI Writing Tells)
- Never surface internal engineering or architecture codes in user-facing copy:
  - Do NOT display `AL0`..`AL4`, `G1/G2`, `D-50`, or internal binary names (`grdr-approve`) in customer-facing screens or badges.
  - Translate assurance into plain words people immediately grasp: `Observed`, `App hook`, `Tool proxy`, `Sandboxed`, `Enforced`.
- Zero AI writing tells in UI copy and comments:
  - Never use em dashes or en dashes.
  - Never join prose sentences with semicolons (`;`). Write short direct sentences instead.
  - Never use AI cliché framing (`delve`, `effortlessly`, `seamless`, `not just X, but Y`, `elevate your`, `crafted`, `cutting-edge`, `next-gen`).
- Keep headlines, subtitles, and badges crisp and scannable with zero filler or overexplaining.

## 3. Navigation, Layout & Alignment
- Sidebars in both Web (`Console`, `Operator`) and Desktop MUST provide a collapsible toggle (`IconButton` with `panel-left-close` / `panel-left-open`) so users can reclaim horizontal canvas for complex fleet visualizations and execution graphs.
- Respect the exponential 4px spacing scale, optical alignment, self-hosted `DM Sans` + `IBM Plex Mono`, and zero raw `#hex` colors or hand-drawn `<svg>` markup.

Automated enforcement runs via `.claude/hooks/design-check.mjs` across Claude Code and Antigravity.
