---
name: signs-of-ai-design
description: Mandatory anti-AI-slop visual review and Guardrails Studio brand manual adapted from febbhav/signs-of-ai-design (CC BY-SA 4.0). Enforce before writing or changing any Web, Console, Operator, or Rune Desktop UI.
---

# Signs of AI Design (Anti-Slop + Guardrails Studio Spec)

This skill encodes the `febbhav/signs-of-ai-design` rules alongside Guardrails ADR's committed **"Guardrails Studio"** aesthetic ("the Wealthsimple of ADRs": calm authority, architectural clarity, zero anxiety chrome).

Automated enforcement lives in `.claude/hooks/design-check.mjs` across both Claude Code (`PreToolUse`) and Antigravity (`agy-pre-tool-use.mjs`).

## Guardrails Studio Committed Identity & 6 Personality Pillars

1. **Porcelain Light Default, Carbon Obsidian Dark:**
   - Light (default): Crisp white reading canvas `#FFFFFF`, quiet porcelain rail `#F8F9FB`, recessed surface `#F4F5F7`, deep slate ink `#0F172A`, secondary `#475569`, hairline `#E5E7EB`, single committed Signal Cobalt accent `#2563EB`.
   - Dark: Carbon Obsidian `#0B0D10`, rail `#0F1216`, elevated surface `#12161C`/`#161B22`, crisp off-white ink `#F1F5F9`, hairline `#1F242D`, Signal Cobalt `#3B82F6`.
   - Canonical source: `interface/tokens.json`. Never hardcode raw `#hex` colors anywhere outside token owners (`interface/tokens.json`, `web/packages/tokens/`, `desktop/grdr-desktop/src/theme.rs`).

2. **6 Non-Negotiable Platform Personality Pillars:**
   1. **Calm Precision Over Spectacle:** Never add decorative dot-matrix wallpaper, diagonal hatch/stripe backgrounds, broken dashed ribbons, noisy tick rings, or ambient background glows. Texture and elevation serve structure only, with one scoped sculptural silk hero ribbon (`HeroWaveBackdrop` / `hero_wave_*`, paired Light + Dark raster artwork dissolving cleanly into canvas) reserved exclusively for the Home hero stage while lower sections remain crisp and unobstructed.
   2. **Strict Palette Lock:** Zero rogue hues (no unapproved teal, neon cyan, violet, or rainbow multi-series gradients). Every surface, ring, bar, and badge pulls strictly from `interface/tokens.json`. Decision velocity bars and legends use Signal Cobalt Blue (`Allowed`), Crisp Golden Yellow (`Ask`), and Crimson Red (`Blocked`).
   3. **Exact Legend-to-Visual Color Truth:** Every bar segment, arc progress ring, graph edge, and legend marker/badge must match color pixel-for-pixel. Zero unlabelled trend overlays or mismatched legend tones.
   4. **Restraint-First Data Visualization:** Use clean full `360°` rings (never car-odometer semi-arcs or tick spokes), clean slender solid bars (never grey battery-slot tube backgrounds or striped bar caps), and iconic circular node graphs (never cramped wireframe rectangles or empty dashed ghost lattices).
   5. **Quiet Inline Signals Over Pill Vomit:** Dense table statuses use `icon/dot + plain text` (`StatusInline`); status pills use soft translucent fills with `1px` tinted hairlines (never solid neon/primary fills, except the crisp circular golden-yellow pending-action counter `--attention-pill-bg` / `--attention-pill-ink` in primary navigation such as `Respond [1]` / `Home [1]`); active primary nav uses soft Signal Cobalt wash (`--accent-soft` / `--accent-primary`); whole-element `SelectableTile` toggle rows replace square checkboxes in selection matrices; subtle gradual left-to-right red wash gradients (`--attention-surface-gradient` / `attention_wash_start`) draw calm focus to waiting approvals and blind spots without heavy flat boxes; `EntityLink` renders as clean un-underlined text at rest and illuminates only on hover/focus.
   6. **Cross-Platform Unity:** Web Console, Operator, and Native Desktop share identical Porcelain/Obsidian tokens, ring/bar geometry, quiet chip restraint, and generous breathing room.

3. **Typography Hierarchy:**
   - **DM Sans** (self-hosted OFL) for upright bold confident status headers (`700` weight, never thin hairlines or oversized italic serifs) and crisp UI copy.
   - **IBM Plex Mono** (self-hosted OFL) strictly for literal paths, command targets, JSON receipts, and rule IDs inside `<Quoted>`, never as hacker-flavored body copy.
3. **Calm Surface Discipline (Escape the 10 AI Tells):**
   - **No indigo/purple gradients or dark glow shadows** (`#6366F1`, `#8B5CF6`, `#A855F7`, neon `box-shadow`).
   - **No cream+emerald second-wave reflex.**
   - **No card wrapping every piece of data.** Let KPI metrics, primary action lists, and policy ledgers sit directly on the clean architectural canvas separated by 1px hairline rules and generous breathing room (`36px 48px` outer stage rhythm).
   - **Vary hierarchy and radii intentionally.** One dominant status stage + interactive action surface per screen; subordinate checklists/summaries sit quietly below hairlines. Mix sharp `4px` tags, `8px` controls, `12px` overlays, and pill buttons where appropriate.
   - **Zero decorative live indicators or fake status chrome.** Only display SSE connection state when a real reconnect condition occurs.
   - **Zero left-border colored accent stripes on ordinary cards/rows.** Reserve colored accents for semantic alerts (`Banner`, verdict indicators) and active state pills.
   - **Zero decorative emojis** in product UI (use Lucide / `rune_kit` geometric icons sparingly where they aid scanning).
   - **Zero placeholder stats or AI writing tells:** Never use em dashes or en dashes in UI copy or comments, never join UI prose clauses with semicolons (use crisp separate sentences instead), never use AI cliché constructions ("not just X, but Y", "it's not about", "more than just") or buzzwords ("world-class", "enterprise-grade", "streamline", "supercharge", "unleash", "seamless", "empower", "delve", "effortless", "effortlessly", "cutting-edge", "next-gen", "game-changing", "revolutionary", "leverage", "crafted", "bespoke", "holistic", "elevate your", "frictionless"), and never use the legacy term "posture" (use `Mode`, `Assurance level`, `Verdict`, `Grant`, `Receipt`, `Finding`, `Incident`).
   - **Honest domain microcopy:** Name the actual enrolled endpoint, agent, rule, and next step.
   - **Never hand-draw SVGs:** Zero inline `<svg>` or `<path d="...">` strings authored by hand. Always use real source PNG brand assets, official icon libraries (`lucide-react`, `@icons-pack/react-simple-icons`, generated upstream Lucide for Rune), and real visualization/graph libraries (`echarts`, `@xyflow/react`, `@dagrejs/dagre`).
