# Web console stack and the Astryx design system

_Researched 2026-11-09_

Method note: the shared web-search budget for this run was already exhausted, so nothing here comes from a search engine. Everything was read directly: the Astryx site and repository (`gh api`), the npm registry, the Rune repository, IETF datatracker, ITI, designtokens.org and TanStack docs. Version numbers are registry values on 2026-11-09. Items I could not read first-hand are listed under "Could not verify".

## TL;DR

- **Astryx: use with conditions.** MIT, very broad, the best agent tooling of any design system I have read, and it needs no StyleX build step. But it is a 0.x beta that has been public for 20 weeks, ships a stable release every 3 days on average, and 0.7.0 alone carried 26 breaking migrations.
- **Latest is 0.7.11 (2026-11-07), not 0.7.0.** 47 stable releases since first publish on 2026-06-24, plus roughly hourly canaries (3,262 published versions). Pin exact versions.
- **Astryx covers the console chrome well, and the data-heavy parts poorly.** Stable: AppShell, SideNav/TopNav, Table with 13 plugins, CommandPalette, PowerSearch, TreeList, Dialog/AlertDialog/Drawer, Toast, forms, date inputs, CodeBlock, Markdown, Chat. Canary only: charts, CodeEditor, DiffViewer, LogStream, Sankey. Absent: graph view, timeline.
- **Astryx Table virtualisation is narrow**: fixed row height, flat rows, single-line content, falls back to full rendering otherwise. Use TanStack Table v9 + TanStack Virtual for the event and alert grids.
- **No accessibility conformance report exists for Astryx** (no VPAT/ACR text anywhere in the repo, no stated WCAG level). The engineering is serious (pattern-contract tests citing WCAG 2.2 and APG), but our ACR is ours to produce.
- **Stack**: Vite 8 + React 19 SPA, TanStack Router and Query, OpenAPI 3.1 typed client, SSE for live updates, TanStack Table v9 + Virtual, ECharts 6, React Flow 12 (+ Sigma 4 for large graphs), CodeMirror 6, Zod 4, Vitest 5 + Storybook 10 + Playwright 1.65 + axe-core 4.14.
- **Auth**: Backend-for-Frontend. This is now RFC 10017 / BCP 212 (August 2026), which "strongly recommend[s]" BFF for business applications. No tokens in the browser.
- **Do not build the console on Rune's web target.** It is experimental, WebGPU-only with no WebGL fallback, one canvas and one app per page. Rune itself was created 2026-10-22, has no releases and takes no pull requests.
- **Tokens**: one DTCG-format source of truth, compiled by Style Dictionary into (a) an Astryx `defineTheme` module and CSS variables and (b) Rune's JSON theme file (`palette` / `light` / `dark` / `numbers`). Both targets take data, so this is a small generator, not a framework.
- **Embedding**: three layers. Public API, a published React kit themed by CSS variables, and sandboxed iframes with a postMessage contract for hosts that are not React or not trusted.
- **Licence traps**: `ag-grid-enterprise` is Commercial, `@cosmograph/cosmos` is CC-BY-NC-4.0, `elkjs` is EPL-2.0. None fits an "everything open source, embeddable by vendors" product without care.

## Findings

### 1. Astryx

**What it is.** Meta's design system, open-sourced in 2026. The README says it "grew inside Meta over the last eight years" and powers "13,000+ apps" there (internally XDS; the changelog header still reads `@xds/core`). Repo created 2026-01-09; first npm publish 2026-06-24; 20,634 stars, 1,564 forks, 7,349 merged PRs, 295 open issues, 361 open PRs on 2026-11-09. Top committer has 3,545 commits; the next has 752. ([repo](https://github.com/meta/astryx), [npm](https://registry.npmjs.org/@astryxdesign/core))

**Licence.** MIT, copyright Meta Platforms, on the repo and every published package. No CLA is mentioned in the contributing guide. ([LICENSE](https://github.com/meta/astryx/blob/main/LICENSE))

**Packages.** Stable on `latest`: `@astryxdesign/core`, `cli`, `build`, `richtext` (Lexical-based), and seven `theme-*` packages (neutral, butter, chocolate, matcha, stone, gothic, y2k). Canary only, "never released as a stable version": `charts` (d3-based), `vega`, `lab`, `native`. Their `latest` tag is a `0.0.0-bootstrap.0` placeholder. ([README](https://github.com/meta/astryx/blob/main/README.md))

**Requirements and setup.** Peer deps: `react` and `react-dom` >= 19.0.0, `@stylexjs/stylex` ^0.19.0. Despite the StyleX peer, consumers import pre-built CSS: `reset.css`, `astryx.css`, then a theme's `theme.css`, in cascade layers `reset` → `astryx-base` → `astryx-theme`. No Babel or PostCSS plugin. Overrides go through `className` with any styling approach; a `tailwind-theme.css` bridge maps tokens to Tailwind utilities. ([core README](https://github.com/meta/astryx/blob/main/packages/core/README.md))

**Component coverage against a security console.**

| Need | Astryx status (0.7.11) |
|---|---|
| App shell, navigation | Stable: AppShell, SideNav, TopNav, NavMenu, Breadcrumbs, TabList, Resizable, Toolbar |
| Data table | Stable `Table` with plugins: sortable (multi-column), filtering, columnResize, columnSettings, stickyColumns, selection, pagination, groupedRows, rowExpansion, tree, rowStatus, rowIndex, virtualization |
| Virtualisation | `useTableRowsVirtualization`: fixed `rowHeight` + `viewportHeight`, flat rows, single-line content; anything else gets "ordinary full rendering". Unmounted rows "are not promised screen-reader discovery" |
| Query/filter bar | Stable: PowerSearch, Tokenizer, Typeahead, MultiSelector |
| Command palette | Stable: CommandPalette |
| Tree | Stable: TreeList, Table tree plugin |
| Forms, dialogs, toasts | Stable: Field, FormLayout, 10+ inputs, date/time/range, Dialog, AlertDialog, Drawer, Popover, Toast, Banner |
| Code display | Stable: CodeBlock (per-language subpaths), Markdown |
| Code/policy editor | Lab only (canary): CodeEditor, built on the CSS Custom Highlight API. DiffViewer and LogStream also lab-only |
| Charts | Canary only: `@astryxdesign/charts`; lab has Chart, Sankey, Radial, Stat |
| Graph view, timeline | None |

The architecture record for list windowing (approved 2026-11-06) says the shared windowing module "does not exist" yet and that Selector and Chat render every item, while `plugins/virtualization/useTableWindow.ts` (21 KB) is present in the source tree. Treat Table virtualisation as new and unproven. ([list-windowing](https://github.com/meta/astryx/blob/main/docs/architecture/list-windowing.md), [virtualization doc](https://github.com/meta/astryx/blob/main/packages/core/src/Table/useTableRowsVirtualization.doc.mjs))

**Accessibility.** No published conformance level and no VPAT (a code search for "VPAT" returns 0 files). What exists is engineering evidence: an internal `a11y-spec` package of "standards-traceable" contracts per widget pattern (switch, tabs, listbox, menu, modal dialog, combobox and more) run in jsdom and Chromium against the real accessibility tree; 143 files reference WCAG 2.2; 135 reference `forced-colors`; a reduced-motion theme setting; RTL audit records; 30 shipped locales plus a pseudo-locale. The 0.7.0 notes claim WCAG AA only for one element (`Kbd` text). 31 open issues carry the accessibility label. ([a11y-spec README](https://github.com/meta/astryx/tree/main/internal/a11y-spec), [0.7.0 post](https://astryx.atmeta.com/blog/astryx-v0-7-0))

**Theming and white-label.** `defineTheme({name, extends, tokens, components, icons, typography, radius, motion, adaptations, localTokens, ...})`. Tokens are keyed by CSS custom property and accept `[light, dark]` tuples. `components` restyles named component targets and can add new variants with generated TypeScript augmentations. `<Theme theme mode>` providers nest, and the nearest wins; only the root writes to `<html>`. Two delivery modes matter for multi-tenancy:

- **Runtime themes**: the provider compiles and injects CSS in the browser via `useInsertionEffect`. Works for per-tenant themes fetched at login; component overrides are client-only and can flash under SSR.
- **Built themes**: `astryx theme build` emits `<name>.css`, `.js`, `.d.ts`; `--family` builds one keyed stylesheet for a base theme and its descendants. This is the route for an MSP's fixed set of brands.

A `theme palette generate` command makes 21-stop light/dark ramps from seed colours. There is no one-click "theme from a brand colour". Upstream rejects brand-specific themes ("publish independently instead"), which suits us. ([theme docs](https://astryx.atmeta.com/docs/theme), [theme-application](https://github.com/meta/astryx/blob/main/docs/architecture/theme-application.md))

**Token format and export.** Canonical tokens are StyleX `defineVars` declarations in `tokens.stylex.ts`; names follow a strict grammar (`--color-<property>-<role>`, `--color-<intent>`, `--color-on-<fill>`, `--spacing-N` = N × 0.25rem, `--radius-inner|element|container`, `--duration-*`). Non-CSS consumers use `resolveThemeTokens(theme, {mode})`, `tokenVar()` and `useTheme()`. There is no DTCG or Style Dictionary export: code search for "DTCG", "tokens.json" and "style-dictionary" returns 0 files. `@astryxdesign/native` is a Swift/SwiftUI experiment covering 12 component contracts; nothing targets Rust. ([theme-tokens](https://github.com/meta/astryx/blob/main/docs/architecture/theme-tokens.md), [native README](https://github.com/meta/astryx/blob/main/packages/native/README.md))

**Server rendering and frameworks.** Documented setups: Next.js (App Router), Next + Tailwind, Next + StyleX, Vite, and a no-build CDN/import-map page. Every component module I sampled (`Button`, `Table`, `Theme`) starts with `'use client'`, so React Server Components gain nothing beyond the shell. Built themes are recommended for SSR.

**Size and performance.** `astryx.css` is one stylesheet for all components: 269 KB raw, about 40 KB gzip (measured from jsDelivr, 0.7.11). JS is per-component ESM subpaths (`@astryxdesign/core/Button`), so it tree-shakes; the largest modules are the Markdown parser (140 KB raw), gesture host (136 KB) and animator (123 KB). The package is 28.9 MB unpacked across 4,726 files because it also ships `src/`. Weekly downloads: 661,968 (2026-11-02 to 11-08), a figure likely inflated by hourly canaries and CI.

**Release cadence and breakage.** 0.1.0 → 0.7.11 in 136 days. Minor bumps: 0.2 (Jul 30), 0.3 (Aug 5), 0.4 (Aug 13), 0.5 (Aug 24), 0.6 (Sep 10), 0.7 (Oct 13). The 0.7.0 post lists 26 breaking migrations: 4 manual, 10 CLI changes, 4 visual/token changes, 8 handled by `astryx upgrade` codemods. The changelog also has "breaking" mentions inside patch releases 0.7.1, 0.7.6 and 0.7.8. No written semver policy for the beta and no 1.0 date were found; the contributing wiki says the team may make "breaking changes, without requiring contributor consent". Releases are built from immutable tags with npm provenance via OIDC trusted publishing. ([release.md](https://github.com/meta/astryx/blob/main/docs/release.md), [changelog](https://github.com/meta/astryx/blob/main/packages/core/CHANGELOG.md))

**Governance.** Meta-owned. "The Astryx team holds final decision authority." Bug and accessibility fixes need an issue first. Any change to `packages/core/` needs an RFC and a nine-phase specification protocol; new components start in `lab`. Rejected outright: core PRs without a design brief, components adding external dependencies, brand themes. RFC response target is one week. API disputes are settled by "vibe testing" (measured agent/human discoverability) plus written conventions. ([Contributing wiki](https://github.com/meta/astryx/wiki/Contributing))

**Agent tooling, concretely.**

- **CLI** (`@astryxdesign/cli`): `search`, `component`, `hook`, `docs`, `template`, `build "<idea>"`, `theme`, `swizzle` (eject a component's source), `upgrade --apply` (codemods), `doctor`, `discover`/`integration` (third-party packages register docs and guidance), `gap-report`, `manifest --json`. Every command has `--json` with a typed envelope `{apiVersion, type, data, meta.answeredBy}` and append-only error codes (`ERR_UNKNOWN_COMPONENT` etc.). `--dense` and `--detail brief|compact|full` control token cost.
- **`init`** writes a managed block (component index, rules, CLI reference) into `AGENTS.md`, `CLAUDE.md`, `.cursorrules` or a Cursor rule file, and `init --user` installs a global skill at `~/.agents/skills/astryx/SKILL.md`.
- **MCP**: a remote Streamable HTTP server at `https://astryx.atmeta.com/mcp` with exactly two tools, `search(query, limit)` and `get(name)`, served by the docsite. It is a hosted docs lookup, not a local server, so it always answers for the latest docs rather than our pinned version, and it needs internet. The CLI is the better interface for pinned, offline or air-gapped builds.

([CLI README](https://github.com/meta/astryx/blob/main/packages/cli/README.md), [working with AI](https://astryx.atmeta.com/docs/working-with-ai), [MCP route](https://github.com/meta/astryx/blob/main/apps/docsite/src/app/mcp/route.ts))

### 2. Rune's web target

Rune (`anomalyco/rune`, MIT, 5,950 stars) describes itself as a "native GPU-rendered Rust UI framework for macOS, Windows, Linux and the web". It was created 2026-10-22, has no tagged release ("Pin a rev of `dev`") and states "We don't take pull requests". Its `WEB.md` calls the web target experimental: one canvas rendered through WebGPU, "no WebGL fallback", no overlays, extra windows, native audio/video or networking layer, and "one app runs per page at a time". A DOM mirror provides landmarks, headings, links and selectable text in `web_document` mode; text input uses a hidden textarea; real-device Safari testing is listed as still needed. ([README](https://github.com/anomalyco/rune), [WEB.md](https://github.com/anomalyco/rune/blob/dev/WEB.md))

Verdict: not for the console. Reasons, in order of weight: accessibility conformance for a canvas application is unproven and would dominate ACR work; WebGPU is absent or blocklisted in many managed browsers and VDI sessions; no ecosystem for grids, charts or editors; OEM hosts cannot restyle or compose a canvas; the framework is three weeks old. A fair later experiment is mounting a single Rune view (`App::canvas_id(...).fit_content_height()`) inside the React console for one shared visualisation.

### 3. Standards that shape the stack

- **BFF**: `draft-ietf-oauth-browser-based-apps` was published as RFC 10017 / BCP 212 in August 2026. It ranks BFF first, token-mediating backend second, browser-side OAuth client last. ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/))
- **Accessibility reporting**: the current template is VPAT 2.5Rev (2025-04-24) in four editions: 508 (Revised Section 508, WCAG 2.0), EU (EN 301 549, WCAG 2.1), WCAG (2.2) and INT (all three). ([ITI](https://www.itic.org/policy/accessibility/vpat))
- **Design tokens**: DTCG Format Module 2025.10 is the published version; the editors' draft is dated 2026-09-08. Files are `.tokens` or `.tokens.json`, media type `application/design-tokens+json`, with `{alias}` and `$ref` references and `$extends`. ([designtokens.org](https://www.designtokens.org/tr/drafts/format/))

## Matrix

Recommended stack. Versions are npm `latest` on 2026-11-09.

| Concern | Choice | Version, licence | Why, and the fallback |
|---|---|---|---|
| Build, framework | Vite + React SPA | vite 8.3.7, react 19.3.1, MIT | Static assets embed in a single server binary; no Node runtime in self-hosted installs. Astryx is all client components, so Next.js 16 adds cost without benefit |
| Router | TanStack Router | 1.170.46, MIT | Typed routes and typed, validated search params: filters, time range and selection live in the URL. Fallback: React Router 8.5 |
| Server state | TanStack Query | 5.107.1, MIT | Caching, invalidation, optimistic updates |
| Typed API | OpenAPI 3.1 + `openapi-typescript` / `openapi-fetch` / `openapi-react-query` | 7.13.0 / 0.17.0 / 0.5.4, MIT | Type-only, tiny runtime. `@hey-api/openapi-ts` 0.99 generates Query hooks and Zod but is still 0.x |
| Real time | Server-Sent Events into the Query cache; WebSocket only for interactive sessions | platform | Works with cookie sessions, HTTP/2 and proxies. TanStack DB is 1.0.0-rc: watch, do not adopt |
| Components | Astryx behind our own `ui` package | 0.7.11, MIT | Fallback: React Aria Components 1.22.1 (Apache-2.0) or Base UI 1.9.0 (MIT) with the same CSS variables |
| Large tables | TanStack Table v9 + TanStack Virtual | 9.3.1 / 3.14.26, MIT | Headless, about 25 KB for all features, tree-shakable. Astryx Table for small lists. Avoid AG Grid: grouping and server-side row model sit in the Commercial package |
| Charts | Apache ECharts | 6.1.0, Apache-2.0 | Canvas, large series, heatmap, sankey. Wrap it so Astryx charts can replace it when stable |
| Graph | React Flow; Sigma + graphology above a few thousand nodes | 12.12.1 MIT; 4.0.5 MIT | DOM nodes are themable and focusable. Layout: `@dagrejs/dagre` 3.1.3 (MIT); `elkjs` is EPL-2.0 |
| Timeline | Own component on TanStack Virtual + d3-scale | MIT / ISC | No maintained OSS React timeline fits; `vis-timeline` 8.5.6 is the stopgap |
| Editor | CodeMirror 6 + `@codemirror/merge` | view 6.43.15, MIT | Small, modular, keyboard and screen-reader friendly. Monaco 0.57 only if we need a full IDE |
| Client state | URL first, then React state; Zustand for a few global stores | 5.1.0, MIT | |
| Forms, validation | TanStack Form + Zod | 1.33.5 / 4.6.7, MIT | Value-first `handleChange` matches Astryx inputs. Fallback: react-hook-form 7.91 |
| i18n | FormatJS (`react-intl`) or Lingui, ICU MessageFormat | 12.1.7 BSD-3 / 6.12.0 MIT | Astryx localises its own strings (30 locales) via `intl-messageformat` ^11 |
| Unit, component | Vitest with browser mode; Testing Library | 5.1.0 / 16.3.3, MIT | |
| Stories | Storybook + addon-vitest + addon-a11y | 10.6.6, MIT | |
| E2E, visual | Playwright, `toHaveScreenshot` baselines in-repo | 1.65.0, Apache-2.0 | Argos or Chromatic are optional hosted services |
| A11y automation | `@axe-core/playwright` | 4.14.0, MPL-2.0 | |
| API mocking | MSW | 3.0.4, MIT | |
| Tokens | DTCG source + Style Dictionary | 5.8.0, Apache-2.0 | Fallback: Terrazzo CLI 2.10 |

## Weak points, gaps and risks

- **Astryx churn.** A stable release every three days and breaking changes in minors, sometimes patches. AI coding agents will also have no training data for it; all knowledge must come from the CLI at build time.
- **Single-vendor control.** Meta decides everything. We cannot land a component or an external dependency upstream on our schedule.
- **Astryx gaps are exactly our differentiators.** Graphs, timelines, editors and dense virtualised grids are all ours to build.
- **Monolithic CSS.** 40 KB gzip is acceptable for a console; it is heavy for a small embedded widget.
- **Accessibility evidence is ours.** No vendor ACR to cite; canvas charts and WebGL graphs need text or table equivalents.
- **Pre-1.0 pieces in the recommended stack**: `openapi-fetch` 0.17, `openapi-react-query` 0.5, TanStack Hotkeys 0.23. All are small and replaceable.
- **Rune is three weeks old.** Its theme JSON shape may change; the token generator must be versioned against a pinned Rune revision.
- **Embedded sessions.** Third-party-cookie restrictions break cookie sessions inside cross-site iframes unless cookies are partitioned or the embed uses its own short-lived token.

## Implications for our design

1. **Adopt Astryx behind a boundary.** Create `packages/ui` that re-exports the Astryx components we approve and holds our composites. Lint-ban `@astryxdesign/*` imports elsewhere. Swapping the base library then touches one package.
2. **Pin and gate upgrades.** Exact versions, `latest` tag only, never `canary` or `lab` in shipped code. An upgrade is a scripted job: bump, `astryx upgrade --from <old> --apply`, typecheck, Playwright visual diff, axe scan, human sign-off on visual changes. Batch to one upgrade per fortnight.
3. **Give agents the pinned CLI, not the hosted MCP.** Commit the `init` block to `AGENTS.md`/`CLAUDE.md`; add the `astryx` npm script; allow the MCP server only as a convenience for exploration.
4. **Make our tokens canonical.** DTCG files in `packages/tokens` (primitive → semantic → component; modes light, dark, high-contrast; one folder per brand). Name semantic tokens after Astryx's grammar to keep the mapping mechanical.
5. **Generate both themes from that source.**
   - Web: a `defineTheme({name, extends: neutralTheme, tokens: {'--color-accent': [light, dark], ...}})` module, compiled with `astryx theme build` to CSS for first-party brands.
   - Desktop: Rune's theme file, `{"name", "blend": {"mode": "srgb", "over": "bg"}, "palette", "light", "dark", "numbers"}`, per `crates/rune/src/theme.rs`. Rune's `srgb` blend mode exists so CSS-authored translucent colours composite as a browser would, which is what makes one palette safe for both.
   - Also emit an ECharts theme, a CodeMirror theme and Rust constants for spacing, radius and type.
   - Conversions: rem → logical px at a 16 px root; colours to 8-digit sRGB hex; motion as named intents mapped to CSS durations on web and springs in Rune.
6. **Per-tenant themes at runtime.** A tenant theme is a small validated token document (accent, neutrals, radius, font, logo). The server rejects it if contrast pairs fail WCAG AA, then serves it as an Astryx runtime theme to the web and as Rune JSON to the desktop app.
7. **Auth through a BFF.** The API server runs the OIDC code flow with PKCE, stores tokens server-side and issues a `__Host-` HttpOnly, SameSite cookie. Add a CSRF header check and `Origin`/Fetch-Metadata validation. SSE rides the same cookie.
8. **Three embedding layers.**
   - The console uses only the public OpenAPI; OEMs can build their own UI on it.
   - Publish `tokens` and `ui` (including composites such as the session timeline and policy editor) for React hosts, themed by CSS variables.
   - For everyone else, sandboxed iframe embeds with a signed short-lived embed token, per-tenant `frame-ancestors`, and a versioned postMessage contract. Use the same iframe mechanism in reverse for third-party panels inside our console. Keep Module Federation (2.9.3) for trusted first-party builds only, because federated code shares our origin and session.
9. **Plan the ACR from day one.** Target WCAG 2.2 AA; publish a VPAT 2.5Rev INT report per release line for the web console and a separate one for the desktop app; keep the evidence (axe runs, pattern-contract tests, manual NVDA, JAWS and VoiceOver passes) in the repo.
10. **Fit to the owner's UI rules.** AppShell with conventional navigation; Lucide icons through the neutral theme; spacing only from tokens, restricted to a geometric subset of Astryx's linear 4 px scale; `Skeleton` for loading; `AlertDialog` for destructive actions; secondary actions in `MoreMenu`. _Applying: Safety principle, Zen of Clarity, Ethical Friction, exponential spacing._

## Ideas worth stealing and whitespace

- **Astryx's agent contract.** A CLI whose every command has a typed JSON envelope, append-only error codes, a `manifest --json` for discovery, dense doc variants and a `gap-report` command. Our own CLI and MCP server should copy this shape.
- **Architecture records as data.** Astryx's docs carry front matter with owners, `applies_to` paths, `verified_by` tests and numbered invariants that trigger review. This is a strong pattern for a codebase written by agents.
- **Pattern-level accessibility contracts.** One contract per widget pattern, bound to each implementing component, run against the browser's accessibility tree. Apply the same to our composites and, through Rune's headless tree dump, to the desktop app.
- **Portable component contracts.** `@astryxdesign/native` splits each component's props into a portable core and a web-only part. Use that idea to keep web and Rune versions of our composites in step.
- **Whitespace.** No open design system ships security-console composites: process and agent-session trees, a session timeline, an attack-path graph, a policy editor with dry-run diff. No project shares one token source across a React console and a GPU-rendered Rust app. No open-source security console publishes its ACR and evidence. Runtime tenant theming with enforced contrast gates is also unclaimed.

## Could not verify / open questions

- No web search was possible in this run; third-party reviews, benchmarks and incident reports about Astryx were not consulted.
- `https://astryx.atmeta.com/docs/accessibility` returned 404; I found no accessibility statement page. A conformance statement may exist under another URL.
- Astryx Table virtualisation was read, not run. Its behaviour at 100k rows, with sticky columns and resize, needs a spike.
- Whether Astryx's global layered CSS works inside Shadow DOM (for Web Component embeds) is untested.
- Astryx beta versioning policy and 1.0 timing: not found in the wiki page, release doc or 0.7.0 post. The wiki "Release Process" page was not read.
- The RFC number (10017) and BCP number (212) come from one read of the datatracker page; confirm before citing in a design document.
- The current EN 301 549 version and whether the VPAT EU edition has moved to WCAG 2.2 were not confirmed.
- DTCG Resolver module (modes and theming) status was not confirmed from the page read.
- Rune's `rune-i18n` message format, and so whether ICU catalogs can be shared with the web, was not examined.
- Claims about how existing EDR consoles host partner UI were not researched here (see the embed/OEM brief).

## Sources

- https://astryx.atmeta.com — Astryx home (read 2026-11-09)
- https://github.com/meta/astryx — repository, README, LICENSE, releases (2026-11-09)
- https://github.com/meta/astryx/blob/main/packages/core/README.md — core quick start
- https://github.com/meta/astryx/blob/main/packages/cli/README.md — CLI and JSON API
- https://astryx.atmeta.com/docs/cli — CLI docs
- https://astryx.atmeta.com/docs/working-with-ai — MCP and agent setup
- https://github.com/meta/astryx/blob/main/apps/docsite/src/app/mcp/route.ts — MCP server source
- https://astryx.atmeta.com/docs/theme — theming guide
- https://github.com/meta/astryx/blob/main/docs/architecture/theme-application.md — theme application record (approved 2026-08-30)
- https://github.com/meta/astryx/blob/main/docs/architecture/theme-tokens.md — token architecture record (approved 2026-08-30)
- https://github.com/meta/astryx/blob/main/docs/architecture/list-windowing.md — windowing record (approved 2026-11-06)
- https://github.com/meta/astryx/blob/main/docs/architecture/internationalization.md — i18n record
- https://github.com/meta/astryx/tree/main/internal/a11y-spec — accessibility contract tests
- https://github.com/meta/astryx/blob/main/packages/native/README.md — native experiment
- https://github.com/meta/astryx/blob/main/docs/release.md — release mechanics
- https://github.com/meta/astryx/blob/main/packages/core/CHANGELOG.md — changelog
- https://astryx.atmeta.com/blog/astryx-v0-7-0 — 0.7.0 release post (2026-10-12)
- https://github.com/meta/astryx/wiki/Contributing — governance
- https://registry.npmjs.org/@astryxdesign/core — versions, dates, peer deps (2026-11-09)
- https://cdn.jsdelivr.net/npm/@astryxdesign/core@0.7.11/dist/astryx.css — size measurement
- https://github.com/anomalyco/rune — Rune README (2026-11-09)
- https://github.com/anomalyco/rune/blob/dev/WEB.md — Rune web target
- https://github.com/anomalyco/rune/blob/dev/crates/rune/src/theme.rs — Rune theme file format
- https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/ — OAuth 2.0 for Browser-Based Applications (RFC, August 2026)
- https://www.itic.org/policy/accessibility/vpat — VPAT 2.5Rev (2025-04-24)
- https://www.designtokens.org/tr/drafts/format/ — DTCG Format Module (draft dated 2026-09-08)
- https://tanstack.com/table/latest/docs/overview — TanStack Table v9
- https://registry.npmjs.org — version and licence for every package in the matrix (2026-11-09)

## Independent verification

_Checked 2026-11-09 (2026-11-10 UTC) by a separate fact-checker. Method: npm registry metadata, the unpacked `@astryxdesign/core@0.7.11` tarball, the jsDelivr file listing for the CLI and the current canary, the Astryx wiki (git clone), repository files and PRs through the GitHub API, the Rune repository, and rfc-editor.org. GitHub code search was rate-limited part-way, so zero-hit searches were re-checked by grepping the released package and the wiki._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Astryx is MIT (Meta Platforms, 2026) across repo and published packages | Confirmed | Root `LICENSE` is MIT, "Copyright (c) 2026 Meta Platforms, Inc.". The ten package manifests read (build, charts, cli, core, lab, native, richtext, vega, theme-neutral, theme-probe) declare MIT; every one of the 3,262 core versions on npm is MIT. The only third-party notice covers syntax colour palettes, all MIT. No CLA in `CONTRIBUTING.md`. | [LICENSE](https://github.com/meta/astryx/blob/main/LICENSE), [third-party notice](https://github.com/meta/astryx/blob/main/packages/core/src/theme/syntax/THIRD_PARTY_LICENSES.md), [npm](https://registry.npmjs.org/@astryxdesign/core) |
| 2 | core latest 0.7.11 (2026-11-07); first publish 2026-06-24; 47 stable; about 3,262 versions; hourly canaries | Confirmed | `latest` = 0.7.11, published 2026-11-07T14:58Z. Package created 2026-06-24T17:07Z. 47 versions without a pre-release tag (0.0.15 through 0.7.11). 3,262 versions in total. The last 30 canaries are about one hour apart. | [npm](https://registry.npmjs.org/@astryxdesign/core) |
| 3 | 0.7.0 had 26 breaking migrations (4/10/4/8); no beta versioning policy or 1.0 date published | Corrected | The 26 and the 4/10/4/8 split are right. A 0.x versioning policy **is** published: the wiki's Release Process and Distribution pages and `docs/release.md` state that a `[breaking]` change bumps the minor, a patch release refuses breaking work (CI-enforced), and `[experimental]` surfaces may change incompatibly in a patch. No 1.0 date exists ("When we hit 1.0" with no date). The "breaking" mentions the brief cites in 0.7.1, 0.7.6 and 0.7.8 read "without breaking", "non-breaking" and "not a breaking change". Patch-level `Breaking Changes` sections last appeared in 0.4.7 and 0.1.x. | [Release Process](https://github.com/meta/astryx/wiki/Release-Process), [Distribution](https://github.com/meta/astryx/wiki/Distribution), [release.md](https://github.com/meta/astryx/blob/main/docs/release.md), [0.7.0 post source](https://github.com/meta/astryx/blob/main/apps/docsite/src/content/blog/posts/astryx-v0-7-0.md) |
| 4 | No build plugin; reset.css + astryx.css + theme.css; peers React >=19.0.0 and StyleX ^0.19.0; component modules are `'use client'` | Corrected | Setup and peers are right (`react-dom` >=19.0.0 is also a peer; StyleX is a required runtime peer, imported by 278 dist files). The `'use client'` part is overstated: the rule is "files that use a hook". In 0.7.11, 539 of 1,101 dist JS files carry the directive, and these components do not: AspectRatio, Badge, Blockquote, Card, Center, Code, EmptyState, Grid, HStack, VStack, Stack, Indicator, NavIcon, Section, Skeleton, VisuallyHidden. "All client components" is wrong; the SPA choice does not depend on it. | [core 0.7.11 tarball](https://registry.npmjs.org/@astryxdesign/core/-/core-0.7.11.tgz), [RSC Compatibility](https://github.com/meta/astryx/wiki/RSC-Compatibility) |
| 5 | charts, vega, lab, native are canary-only; core has no graph or timeline | Confirmed | On npm each has `latest` = `0.0.0-bootstrap.0` and zero stable versions; manifests are `private: true` and say "never released as a stable (latest) version". Lab holds CodeEditor, DiffViewer, LogStream, Sankey. None of core's 122 source directories is a graph or timeline. Note the root README still says lab "is not published to npm"; the registry shows 3,049 canary versions. | [lab on npm](https://registry.npmjs.org/@astryxdesign/lab), [lab manifest](https://github.com/meta/astryx/blob/main/packages/lab/package.json) |
| 6 | Table virtualisation is fixed-height, flat, single-line with full-render fallback; shared windowing module recorded as not built | Corrected | The limits are right, and the record does say "No module exists yet". But the record is stale: PR #10656 (merged 2026-11-08) added `packages/core/src/utils/listWindow.ts` and the Table hook. More important: **none of it is in 0.7.11**. The released package has 12 Table plugins and no `virtualization` directory or `useTableRowsVirtualization` symbol. The feature sits behind pending changesets and ships only in `0.7.12-canary.*`; the 1k/10k/100k release-evidence PR (#10659) is still open. | [PR #10656](https://github.com/meta/astryx/pull/10656), [pending changeset](https://github.com/meta/astryx/blob/main/.changeset/table-fixed-height-windowing.md), [core 0.7.11 tarball](https://registry.npmjs.org/@astryxdesign/core/-/core-0.7.11.tgz) |
| 7 | Themes are custom-property overrides via `defineTheme`; nested providers; runtime injection vs `astryx theme build`, including family mode | Confirmed | `defineTheme` input has `tokens`, `localTokens`, `components`, `icons`, `typography`, `radius`, `motion`, `adaptations`. The application record states nearest provider wins, only the root writes `<html>`, built themes skip runtime generation and injection. Released `Theme.js` uses `useInsertionEffect`. `family.mjs` is present in the released CLI 0.7.11 and needs at least two theme files. | [theme-application](https://github.com/meta/astryx/blob/main/docs/architecture/theme-application.md), [family.mjs](https://github.com/meta/astryx/blob/main/packages/cli/api/theme/build/family.mjs) |
| 8 | No DTCG or Style Dictionary export; no VPAT or stated WCAG level; code search returns zero | Confirmed | Code search: 0 files for DTCG, style-dictionary, "Style Dictionary", VPAT, tokens.json, "Accessibility Conformance Report". Grep of the released package and the wiki agrees. Caveat: the wiki's Accessibility Checklist and Component Audit Rubric set **WCAG 2.2 AA** as the bar contributors must meet. That is an internal engineering target, not a published conformance claim, so the ACR is still ours to produce. | [Accessibility Checklist](https://github.com/meta/astryx/wiki/Accessibility-Checklist), [theme-tokens](https://github.com/meta/astryx/blob/main/docs/architecture/theme-tokens.md) |
| 9 | Rune web target is experimental, one WebGPU canvas, no WebGL fallback, one app per page; created 2026-10-22; no releases; no PRs accepted | Confirmed | GitHub API: created 2026-10-22T05:51Z, 0 releases, 0 tags, default branch `dev`. `WEB.md` text matches. "We don't take pull requests" is the stated policy for outsiders; the team itself works through PRs (449 so far, authored by members). | [WEB.md](https://github.com/anomalyco/rune/blob/dev/WEB.md), [README](https://github.com/anomalyco/rune/blob/dev/README.md) |
| 10 | Rune themes are JSON with name, blend, palette, light, dark, numbers; a generator can target them directly | Corrected | The core format is right: `Theme::from_json` reads exactly those keys (`palette` optional; colours must be `#rgb`, `#rrggbb` or `#rrggbbaa`; `numbers` are f32; token names are free-form). But `rune-kit` components do not read the JSON. They take a typed `Kit` (Palette, Elevation, Type, Radius, Motion, Glyphs) that a Rust theme crate fills from the JSON, or `Kit::from_palette` from three seed colours. The shipped OpenCode theme also carries a `shadows` key parsed by the kit, not by core. The generator must emit the JSON **and** a Rust mapping onto `Kit`. | [rune-kit README](https://github.com/anomalyco/rune/blob/dev/crates/rune-kit/README.md), [theme.rs](https://github.com/anomalyco/rune/blob/dev/crates/rune/src/theme.rs), [opencode theme.json](https://github.com/anomalyco/rune/blob/dev/themes/opencode/assets/theme.json) |

Further statements checked in the brief:

| Statement | Verdict | Note | Source |
|---|---|---|---|
| Coverage table and TL;DR: at 0.7.11, stable `Table` has 13 plugins including virtualization | Refuted | 0.7.11 ships 12 plugins: columnResize, columnSettings, filtering, groupedRows, pagination, rowExpansion, rowIndex, rowStatus, selection, sortable, stickyColumns, tree. Virtualization exists only in `0.7.12-canary.*`. Under implication 2 ("never canary in shipped code") Astryx offers no table windowing at all today, which strengthens the TanStack Table + Virtual choice. | [core 0.7.11 tarball](https://registry.npmjs.org/@astryxdesign/core/-/core-0.7.11.tgz), [canary file list](https://data.jsdelivr.com/v1/packages/npm/@astryxdesign/core@0.7.12-canary.0f6f37e?structure=flat) |
| Risks: "breaking changes in minors, sometimes patches" | Overstated | Under the current, CI-enforced 0.x rule, stable-surface breaking changes ship only in minors. The 0.7.x patch "breaking" mentions are all negations. The real patch-level risk is narrower: surfaces marked `[experimental]` may change incompatibly in a patch. | [Release Process](https://github.com/meta/astryx/wiki/Release-Process), [changelog](https://github.com/meta/astryx/blob/main/packages/core/CHANGELOG.md) |
| OAuth browser-based-apps draft is RFC 10017 / BCP 212 (August 2026) | Confirmed | rfc-editor.org lists RFC 10017, "OAuth 2.0 for Browser-Based Applications", BCP 212, Best Current Practice. The datatracker shows August 2026 and draft -27 as the predecessor. The brief's open question on this number can be closed. | [RFC 10017](https://www.rfc-editor.org/info/rfc10017) |

Spot check: every stack-matrix version looked up matches npm `latest` as of this check (34 packages; react-hook-form, Terrazzo and TanStack Hotkeys were not looked up). `astryx.css` in 0.7.11 measures 269,224 bytes raw and 42,288 bytes gzip.
