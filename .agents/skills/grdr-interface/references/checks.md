# Interface checks, lint rules and gates

Sources: P17, D-42, D-44, D-69 and owner instruction 21 in `docs/design/00-decisions.md` and `docs/design/_review/04-owner-kit-instructions.md`; `docs/team/05` sections 3, 8 and 12. Where this file and those differ, they win and the difference is a finding against this file.

## Interface checks UX1 to UX8 (gate V26)

They run in `post-edit` on the edited file, in `stop-gate`, and in V26 (changed files in the fast form, every file in the full form), on every path of the interface entry of `.agents/kit/path-skills.toml` and in every crate whose `[package.metadata.grdr]` sets `renders`. Generated outputs are excluded. A finding blocks the edit, the stop and the gate. There is no exemption file and no inline suppression.

| Check | Finds | Fix the message states |
|---|---|---|
| UX1 | A raw visual value (colour, length, radius, font, line height, shadow, z-index, duration or easing literal) in CSS, a `style` value, TSX or a Rust UI crate, outside generated token modules | Use the token by name (`space-3`, `color-text-danger`, `motion-quick`); add a semantic token in `interface/tokens/` if none fits |
| UX2 | A one-off building block: in `web/apps/**`, `web/extension/**` and `site/src/**` a stylesheet, a `style` prop, a `className` string, or a raw interactive or layout element; in Rust UI crates a Rune element constructor outside `grdr-desktop/src/kit/`, or `print!`, `println!`, `eprint!`, `eprintln!` or an ANSI escape outside `term` | Compose the kit's parts; if none fits, `cargo xtask scaffold pattern <id>` |
| UX3 | Hand-written text: a string literal that reaches JSX text, `aria-label`, `title`, `alt`, `placeholder`, an Astryx text prop, a Rust renderer or output call, or a notification or email template; a product name outside `brand/` | `cargo xtask scaffold token <id>` and call its accessor; the product name is `:grdr:brand` |
| UX4 | Assembled or hand-formatted text: an accessor result concatenated, interpolated or joined with other text; `Intl.*` or `toLocale*` outside `@grdr/i18n`; `format!` building person-facing text; a date, number, list or plural formatted outside `grdr-strings` | Make the sentence one token with typed arguments and format through its functions |
| UX5 | An enum or icon rendered by hand: a `match` or `switch` over a presentation-registry enum in renderer code; a Lucide name outside `Icon`; an emoji in a token, JSX or a Rust UI string; an icon key with no entry or no `mirror` value in `interface/icons.toml` | Call `present(value, level)`; pass the meaning key to `Icon` |
| UX6 | Physical direction: a physical CSS property or value (`margin-left`, `left:`, `text-align: left`, `float: right`), `text-transform`, or a Rust layout that fixes a side | Use the logical property (`margin-inline-start`); write casing in the message |
| UX7 | An unregistered or stateless pattern: an export of `@grdr/kit`, `grdr-desktop/src/kit/` or `term` absent from `interface/patterns.toml`; a registered pattern without a fixture for each declared `ViewState`; a screen that renders data without exactly one `ViewState` | Register it with fixtures (`cargo xtask scaffold pattern`), or use the registered one |
| UX8 | Hand-rolled navigation or confirmation: an application mutation not called through `useAction`; a confirmation dialog in application code; a route, link or destination title not taken from `interface/routes.toml`; a shortcut not in `interface/shortcuts.toml` | Call `useAction(Service.Method)`; link by route id; register the shortcut |

`cargo xtask interface check` is part of V26. It validates the language tokens (section 15a step 3 of design/34, plus duplicate-source, unused and missing tokens), the presentation registry (words for each disclosure level, an icon present at the Lucide pin, a tone, a CLI word and a tray glyph; no glyph with two meanings unless the row declares `same_as`), routes (a title token and an icon each), shortcuts (no key bound twice in one scope), notifications (channels, a budget rule and token ids), patterns (states, tokens, an accessibility contract and renderers, with fixtures valid against `grdr.ui.v1alpha1`), and that generated outputs equal a fresh generation.

## Interface lint rules (gate V04, dependency-cruiser)

| Code | Rule | Fix the message states |
|---|---|---|
| ARCH-101 | Only `web/packages/ui` imports `@astryxdesign/*` | Import the component from `@grdr/ui` |
| ARCH-102 | `web/packages/kit` imports only `@grdr/ui`, `@grdr/tokens`, `@grdr/i18n` and React; `kit` and `ui` share no export name | Compose the part from `@grdr/ui`; a component Astryx lacks is an exception registry entry in `ui` |
| ARCH-103 | `react-aria-components`, `react-aria` and every specialised widget library (ECharts, CodeMirror, React Flow, Sigma, TanStack Virtual) are imported only by files that `web/packages/ui/exceptions.toml` lists; `lucide-react` only by `Icon` in `@grdr/ui` | Use the Astryx component, or file the exception with its gap and exit condition; pass the meaning key to `Icon` |
| ARCH-104 | `web/apps/*`, `web/extension/` and `site/src/` import interface code only from `@grdr/kit`, `@grdr/ui`, `@grdr/i18n`, `@grdr/tokens` and `@grdr/api` (plus Docusaurus's own theme in `site/`) | Use the kit part, or add it to the kit |
| ARCH-105 | `fetch`, `XMLHttpRequest` and `EventSource` appear only in `web/packages/api` | Call the generated client |
| ARCH-106 | No message runtime (FormatJS, `intl-messageformat`, i18next, Fluent) in any web package except inside `ui`, where Astryx carries its own | Use the generated `@grdr/i18n` accessor |

An exception entry carries: `need`, `astryx_version`, `gap` (the component and its release notes or upstream issue), `why_not_compose`, `exit`, `owner`, and the `eval-ux` and `lead-interfaces` check runs that agreed to it.

## Interface gates (team/05 section 12)

| Gate | Fails when |
|---|---|
| U01 | An axe WCAG 2.2 AA violation on any route, story or extension page |
| U02 | A pattern contract assertion fails against the accessibility tree, on the web or in the Rune headless runtime |
| U03 | More than 0.1% of a story's pixels differ from its baseline in `en` or `ar-XB`, or a Rune `--snap` golden differs; baselines change only after `eval-ux` posts a passing `ux-review` check with the diff images |
| U04 | A pseudo-locale (`en-XA`, `ar-XB`, `ja-XC`) or shipped locale truncates, overflows, clips, misses a glyph, leaves a placeholder unisolated or a layout unmirrored |
| U05 | A semantic token is missing from an output, a locked token is changed by a theme, or a pair falls under 4.5:1 (text) or 3:1 (non-text) |
| U06 | A performance budget of design/27 is exceeded on seeded data |
| U07 | The UX evaluator (ui-architect, then this skill) finds a never rule or a cohesion violation |
| U08 | A registered pattern's fixture lacks a story or a Rune headless golden, including its `scale` fixture |
| U09 | A screen-reader journey cannot complete, or an announcement is missing or wrong (`eval-a11y`) |
| U10 | Vale finds a vocabulary or content-standard problem in the exported English tokens or docs |
| U11 | ICU4X and the browsers' `Intl` format the parity corpus differently outside `parity-allow.toml` |

Gate V27 fails on a new clone of 60 tokens or 8 lines against `quality/clones-baseline.json`; tree-wide duplication may only fall.
