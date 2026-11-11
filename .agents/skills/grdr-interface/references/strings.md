# Language tokens: the format

Source: D-69 in `docs/design/00-decisions.md` and design/34 section 15a. They win where this file differs.

## Files

| Path | Holds |
|---|---|
| `schema/vocabulary.toml` | The spine's vocabulary as data; generates the `term.*` tokens. A change follows the spine's route |
| `interface/strings/locales.toml` | Tag, tier (`shipped`, `preview`, `pseudo`), script, direction, numbering system, fallback chain |
| `interface/strings/src/<namespace>.mf2.toml` | English source: `msg`, `desc`, `max`, `risk` |
| `interface/strings/tr/<locale>/<namespace>.mf2.toml` | Translations: `msg`, `source_hash`, `verdict`; written by `impl-l10n` only |
| `interface/strings/style/<locale>.toml` | Register, quotation marks, casing rules |
| `interface/strings/parity-allow.toml` | Listed ICU4X-against-`Intl` differences, each with its reason |

## Namespaces

| Group | Namespaces |
|---|---|
| Vocabulary and shared | `term`, `common` |
| Applications | `console`, `operator`, `desktop`, `tray`, `approve`, `cli` |
| Messages and output | `notify`, `email`, `report`, `install`, `docs` |
| Keyed by registry id | `code` (message and fix per error code, `code.GRDR-CFG-0007.fix`), `health` (per condition id) |
| English only, never translated | `agent` |
| In packs | `pack.<rule id>.<field>` |

## Functions and markup

A closed set. MF2's `:string`, `:number`, `:integer`, `:offset`, `:currency`, `:percent`; the draft functions `:datetime`, `:date`, `:time` and `:unit` with their option subsets pinned to the LDML version D-69 names; ours, `:grdr:relative`, `:grdr:duration`, `:grdr:list`, `:grdr:term` and `:grdr:brand` (the last two resolved at compile time). Markup: `link to=<route id>`, `code`, `strong`, `kbd`.

## Example

```toml
[console.tile.new_agents]
desc = "Home tile; count of agent types first seen this week"
max = 120
risk = "normal"
msg = '''
.input {$count :integer}
.input {$devices :integer}
.match $count
one {{{$count} new agent appeared this week on {$devices} devices; {sponsor :grdr:term} missing.}}
*   {{{$count} new agents appeared this week on {$devices} devices; {sponsor :grdr:term} missing.}}
'''
```

The generated accessors are `msg::console::tile::new_agents(&loc, count, devices)` in Rust (`grdr-messages`) and `t.console.tile.newAgents({count, devices})` on the web (`@grdr/i18n`). A missing key or a wrongly typed argument fails `cargo check` or `tsc`.

## Formatting rules

- Instants are UTC in storage and shown in the viewer's zone with its offset; exports, logs and the API use RFC 3339 UTC.
- `:grdr:relative` under seven days, an absolute date beyond.
- Identifiers, versions, ports, addresses, hashes and references use ASCII digits in a left-to-right isolate.
- Sentences switch to compact numbers at 10,000; tables show exact figures.
- Free text a person writes is stored as written, with its language tag, and never machine-translated.

## Pseudo-locales

`en-XA` (accents, 40% expansion, bracketed ends) tests truncation; `ar-XB` (right-to-left, mirrored) tests placeholder isolation; `ja-XC` (full width and CJK) tests font stacks, line height and line breaking. They run on every route, story, Rune screen and CLI golden.
