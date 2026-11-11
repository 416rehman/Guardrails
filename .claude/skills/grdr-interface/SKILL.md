---
name: grdr-interface
description: Build or change anything a person or an agent reads, from the one interface system. Use after ui-architect, before writing or editing any screen, desktop view, tray menu, approval dialog, CLI human output, block or agent message, notification, email, report, docs component, extension UI, installer text or language token, and whenever a hook or gate reports an interface check UX1 to UX8.
license: Apache-2.0
metadata:
  version: "1"
  owner: interfaces
  requires: "K15 (the interface checks in post-edit, stop-gate and gate V26), WI-0041 (the interface system foundation)"
  closes-by: lint
---

# Build every surface from the interface system

One object has one name, one icon, one set of words and states, and one confirmation on every surface (P17). A person who meets a dialog, a table or a mode control twice should not have to read it twice. This skill says how a surface is built so that holds; the checks UX1 to UX8 reject the rest.

## Load order

1. `ui-architect`: what the surface must do, and the never rules.
2. `frontend-design`, for a new screen or a new pattern only.
3. `modern-web-guidance`, for anything under `web/`, `site/` or the browser extension: platform features, compatibility, the security topics.
4. This skill: how it is built here.

`.agents/kit/path-skills.toml` holds the order for each path, and the `PreToolUse` hook repeats it the first time you edit a matching file. Where the skills disagree, D-44, the D-51 disclosure floor and D-31's OS-native approvals win, then the plan's stack in `docs/design/27`, then the guidance.

## Astryx first

Every interface element on the web is an Astryx component (owner instruction 21).

- `@grdr/ui` is a thin layer over Astryx for theme, tokens, language tokens and brand defaults. It wraps; it never reimplements an Astryx component.
- `@grdr/kit` composites (mode control, approval card, setup list, timeline, triage and the rest of `interface/patterns.toml`) are compositions of `@grdr/ui` components and nothing else.
- Imports, enforced by ARCH-101 to ARCH-104: `@astryxdesign/*` only inside `web/packages/ui`; `web/packages/kit` imports only `@grdr/ui`, `@grdr/tokens` and `@grdr/i18n`; applications import interface code only from `@grdr/kit`, `@grdr/ui`, `@grdr/i18n`, `@grdr/tokens` and `@grdr/api`; `react-aria-components` and `react-aria` only in files listed in the exception registry.
- Large tables use Astryx Table with its virtualisation plugin. The embeddable kit for partner products (D-41, D-42) renders Astryx inside a shadow root with Astryx's stylesheet adopted there. The operator plane is web, so it uses Astryx directly through `@grdr/ui`.

**The exception registry**, `web/packages/ui/exceptions.toml`, is the only route to anything else. Each entry names the need, the Astryx gap at the pinned version (component name, and its release notes or upstream issue), why composing Astryx components cannot meet it, the exit condition ("replace when Astryx ships X") and the owning squad. An entry lands only when `eval-ux` and `lead-interfaces` both agree in check runs. Specialised widgets Astryx does not ship as stable (charts on ECharts behind one `Chart` component, CodeMirror, React Flow and Sigma graphs, TanStack Virtual if spike WEB-04 shows the table plugin fails the event grids) enter the same way, are wrapped once in `@grdr/ui` and styled from the tokens. A gardener checks each Astryx release against the registry and files the migration issue when an exit condition is met. If you think you need an exception, you file it as a `status:proposed` issue with those fields; you never write one into your item.

**Beyond the web.** The Rune desktop, the tray, the approval dialogs and email cannot render Astryx. They use Astryx's component names, anatomy, variants and states and the same tokens, through their own kits (`grdr-desktop/src/kit/`, the notification kit, the terminal kit `term`), so a dialog behaves the same everywhere.

## The rules

1. **Look before you build.** Search `interface/patterns.toml`, `interface/presentation.toml`, `interface/routes.toml`, `interface/strings/src/common.mf2.toml` and the `term` tokens, in that order, and reuse what exists. A second component, word, icon or route for a registered thing is a defect.
2. **Compose, never style.** Application code uses only kit parts. No stylesheet, `style` prop, `className` string or raw `button`, `input`, `select`, `a`, `table`, `dialog` or layout `div` in `web/apps/*`, `web/extension/**` or `site/src/**`. The container owns spacing by token name (`gap="space-3"`), never margins on children (UX1, UX2).
3. **Every visible string is a language token** (D-69, below and `references/strings.md`). Never concatenate, never format a date, number, list or plural yourself, never write the product name or a vocabulary term as a literal (UX3, UX4).
4. **Enums go through `present(value, level)`.** Words, icon, tone, CLI word and tray glyph come from the registry row. Icons by meaning key through `Icon`; no emoji; one glyph, one meaning (UX5).
5. **One `ViewState` per screen and data-bearing pattern:** `loading`, `ready`, `empty` (`nothing-yet`, `could-not-look`, `no-match`), `partial`, `stale`, `lagging`, `unreachable`, `unavailable` (`requires-server`, `requires-internet`, `not-configured`), `error`, `read-only`. "Could not look" is never drawn as zero (UX7, P9).
6. **Mutations go through `useAction(Service.Method)`,** which renders the method's confirmation class (`none`, `consequence`, `typed`, `propose`, `quorum`). Never build a confirmation (UX8).
7. **Link by route id.** Titles and icons come from `interface/routes.toml`, shortcuts from `interface/shortcuts.toml` (UX8).
8. **Direction-neutral layout.** Logical properties only; identifiers, paths, hashes and the canonical call in a left-to-right isolate; agent-, tool- and model-written text only through `Quoted` from the untrusted envelope (UX6, SR-36).
9. **Register a new pattern; never write a one-off.** `cargo xtask scaffold pattern <id>` writes the entry (anatomy, tokens, token ids, states, accessibility contract, renderers) and one fixture per state. The same change adds a story and a Rune golden per fixture and an implementation for every renderer the entry lists (UX7, U02, U08).
10. **Never edit generated output** (`grdr-messages`, `@grdr/i18n`, `@grdr/tokens`, token modules). Change the source and run `cargo xtask interface gen`.
11. **Before the hand-off** run `cargo xtask interface check` and `cargo xtask verify --fast`. Fix each finding as its message says. There is no exemption file and no inline suppression for UX1 to UX8; a false positive is fixed in the check by an agent-kit item.

## Language tokens (D-69)

- A token is one keyed Unicode MessageFormat 2 message in `interface/strings/src/<namespace>.mf2.toml`, with `msg`, `desc` (what it means and where it shows), `max` (graphemes) and `risk` (`normal`, or `safety` for approvals, widening, block messages, privacy disclosure and legal text). `cargo xtask scaffold token <id>` writes it and its accessor; you call the accessor.
- Three tiers: `term.*` (the spine's vocabulary from `schema/vocabulary.toml`, one approved form per locale), `common.*` (any string used on two or more surfaces) and the surface namespaces. Ids are `<namespace>.<area>.<name>` in lower snake case.
- One sentence is one token with typed arguments. Every external variable is declared with `.input` and a function, and carries `grdr:class=<data class>` where it holds data; a `content`-class argument in `notify.*` or `email.*` fails compilation (P8).
- The product name is `{:grdr:brand}` and a vocabulary term `{name :grdr:term}`; both resolve at compile time from `brand/brand.toml` and the vocabulary.
- Two tokens with the same English source need `desc` values that state different meanings, or the check tells you to use `common.<key>`.
- Formatting happens only in `grdr-strings` (Rust) and `@grdr/i18n` (browsers): `:number`, `:integer`, `:datetime`, `:unit`, `:grdr:relative`, `:grdr:duration`, `:grdr:list`. Times are stored in UTC and shown in the viewer's zone.
- Stored records and view-models carry a `MessageRef` (id and typed arguments), never formatted text, so each reader sees their own locale.
- Stays English and is never a translated token: identifiers, codes, Cedar, CLI nouns, verbs and flags, configuration keys, logs, `--json`, `Status.message`, and every `agent.*` message. Agent-facing text is plain English, three lines, at most 600 characters (design/28 section 11). Mode labels and other identifiers shown to people get a translated label from the presentation registry; the identifier never changes.
- Translations are written by `impl-l10n` and judged by `eval-l10n` and the gates; no person is a step. You write only English source tokens.

## Checks and their fixes

`references/checks.md` lists UX1 to UX8, the interface lint rules ARCH-101 to ARCH-106 and gates U01 to U11 with the fix each message states. The checks run in `post-edit` on files under an interface path, in `stop-gate`, and in gate V26; duplicate code is gate V27. A finding prints as `ERROR V26 UX3: ...` with the line "load the ui-architect skill, then grdr-interface".

## Applying

Every rule above applies a ui-architect principle: the Safety Principle and familiarity (one name, icon and confirmation per object), Zen of Clarity (one glyph, one meaning), Prioritize Intent (one `ViewState`), Ethical Friction (confirmation classes), Smart Defaults and Exponential Scaling (tokens, never values).
