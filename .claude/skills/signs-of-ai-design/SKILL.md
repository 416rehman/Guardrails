---
name: signs-of-ai-design
description: Mandatory anti-AI-slop visual review and Guardrails Studio brand manual adapted from febbhav/signs-of-ai-design (CC BY-SA 4.0). Enforce before writing or changing any Web, Console, Operator, or Rune Desktop UI.
---

# Signs of AI Design (Anti-Slop + Guardrails Studio Spec)

This skill encodes the `febbhav/signs-of-ai-design` rules alongside Guardrails ADR's committed **"Guardrails Studio"** aesthetic ("the Wealthsimple of ADRs": calm authority, architectural clarity, zero anxiety chrome).

Automated enforcement lives in `.claude/hooks/design-check.mjs` across both Claude Code (`PreToolUse`) and Antigravity (`agy-pre-tool-use.mjs`).

## Guardrails Studio Committed Identity (Deliberate Choices)

1. **Architectural Light Default, Nocturne Graphite Dark:**
   - Light (default): Crisp white reading canvas `#FFFFFF`, quiet stone rail `#F7F7F5`, recessed surface `#F3F3F0`, primary graphite ink `#111111`, secondary `#52524E`, hairline `#E6E6E0`, single committed Signal Cobalt accent `#0F52BA`.
   - Dark: Nocturne graphite `#121211`, rail `#181816`, recessed `#1F1F1C`, off-white ink `#F4F4F0`, hairline `#2A2A26`, Signal Cobalt `#5B9BFF`.
   - Canonical source: `interface/tokens.json`. Never hardcode raw `#hex` colors anywhere outside token owners (`interface/tokens.json`, `web/packages/tokens/`, `desktop/grdr-desktop/src/theme.rs`).
2. **Typography Hierarchy:**
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
