# What S1 to S7 count, and worked fixes

The kit binary is authoritative: if a finding and this file disagree, the finding's message wins and this file is wrong, so say so in the hand-off. The checks read the file as it is on disk after your edit; S3 and S6 read only the lines your diff adds. S6 and S7 skip test code: `#[cfg(test)]` items, `tests/` and `benches/`, files named `tests.rs`, `*_tests.rs` or `testkit.rs`, and `*.test.*`, `*.spec.*`, `__tests__/` and `e2e/` on the script side.

## S1: code lines

A code line is a line that is not blank, not a comment and not inside the test module (`#[cfg(test)] mod tests { ... }` in Rust; `*.test.ts` and `*.spec.ts` files in TypeScript count as tests). Doc comments are comments. The limit is 500.

Approximate count before the check runs (Rust, ignores block comments and the test module, so subtract the test module by hand):

```sh
grep -cvE '^\s*($|//)' crates/<crate>/src/<file>.rs
```

Worked fix. `engine.rs` holds request decoding, policy evaluation and verdict encoding, 780 code lines. Split it into `decode.rs`, `evaluate.rs` and `encode.rs` under `engine/`, each with the types it owns, and keep in `engine.rs` only the public entry point that wires them. Not `engine_a.rs` and `engine_b.rs`, and not `types.rs` plus `functions.rs`: those are kinds, not responsibilities, and `eval-diff` fails a mechanical split.

## S2: order

Top level means items directly in the file, not inside a function or `impl`. After the first top-level `impl` block or free function, no `struct`, `enum`, `type`, `trait`, `const` or `static` may follow, except inside the test module. `use` and `mod` lines belong before everything else.

Worked fix. A `const RETRY_LIMIT` sits above the one function that uses it, at line 300. Move it to the constants section at the top; if it is a bound on a queue, map, cache, body size or recursion depth, it belongs in `limits.toml` instead (protected: request it in the hand-off).

## S3: comments on the diff

S3 flags added comment lines that:

- narrate what the next line does (`// increment the counter`, `// now we parse the header`);
- record history (`// changed to fix the timeout`, `// added for #142`, `// previously this used X`);
- number steps (`// Step 2: validate`);
- are code that was commented out;
- are a `TODO` or `FIXME` with no work-item id.

Kept: invariants (`// The digest covers the resolved path, so a swapped script fails the re-check`), external constraints (`// Windows rejects paths over 260 chars without the \\?\ prefix`), links to a spec, decision record or RFC, and `// SAFETY:` on every `unsafe` block.

Worked fix. `// loop over the rules and skip disabled ones` above a loop: delete it and make the loop say it, `for rule in rules.iter().filter(|r| r.is_enabled())`.

## S4: implicit state machines

S4 matches three patterns:

1. A struct, class or interface with three or more `bool` fields.
2. A field named `state`, `status`, `phase`, `stage` or `mode` whose type is a string, an integer or `bool`.
3. Two or more `Option` fields whose presence the code checks together (`a.is_some() && b.is_none()`, `if let (Some(x), None) = (..)`).

The fix is `references/state-types.md`. A true false positive goes through the exemption route of `SKILL.md`: its own protected-change item, which `lead-agent-kit` implements and which lands only after `eval-architecture` agrees in a check run (owner instruction 7).

Not a fix: an enum `Status { A, B, C }` placed beside the same `Option` fields. If data is valid only in one status, it moves into that variant.

## S5: nesting

Depth counts the blocks a line sits in inside one function body: `if`, `else`, `match` arms, loops, closures and nested blocks. The function body itself is depth zero. More than four is a warning.

Worked fix. Five levels of `if let` while decoding a frame: return early on each failure with `let Some(x) = .. else { return Err(..) };`, or move the inner body into a function named for what it decodes.

## S6: panic paths on the diff

S6 flags, on added lines outside test code:

- `.unwrap()`, `.expect(..)`, `.unwrap_err()` and `.expect_err(..)`;
- `panic!`, `todo!`, `unimplemented!` and `unreachable!`;
- `process::exit`;
- indexing or slicing after an expression, `args[0]`, `&bytes[4..]`, `&s[..n]`, because it panics when the input is shorter than the code assumed. A single string key, `value["name"]`, is a map lookup and passes; so do array types, array literals, slice patterns and macros such as `vec![..]`;
- in scripts, `process.exit`, `process.abort` and `Deno.exit`.

The workspace lints (`unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `unreachable`, `indexing_slicing`, `string_slice`, `exit` at deny) catch the Rust half again when the crate builds; S6 tells you at the edit.

Worked fix. `let id = parts[2].parse::<u32>().unwrap();` on a header line becomes `let Some(field) = parts.get(2) else { return Err(Error::header(line)) };` followed by `field.parse::<u32>().map_err(Error::header_id)?`, each error carrying its `GRDR-<AREA>-<NNNN>` code. When the panic guarded a case that cannot happen, make the type unable to hold it (a non-empty vector type, an enum without the variant) instead of handling a case that does not exist.

## S7: hard-coded values

S7 reads every string, template and markup text outside test code, and the numbers in bound positions.

- **Endpoints.** A URL with a real host (`https://{host}/v1` and a bare `https://` pass), an email address, an IPv4 or IPv6 address, `localhost`, and a dotted name whose last label is a public suffix (`api.vendor.io`; `main.rs`, `Cargo.toml` and `std::fs` pass). Module specifiers, `import x from 'socket.io'` and `include_str!("..")`, are not values.
- **Names.** Every brand name in `brand/brand.toml` (keys `name`, `*_name`, `entity`, `*_entity`) and every vendor `name` and `aliases` entry in `.agents/kit/vendors.toml` outside `[sources]`, matched case-sensitively as whole words.
- **Bounds.** A number other than 0 and 1 as the argument of a `Duration` constructor, `with_capacity`, `bounded`, `channel`, `sync_channel`, `timeout`, `sleep` or the wait of `setTimeout` and `setInterval`; as the value of a binding, field or property whose name has a bound word as a segment (`max`, `min`, `limit`, `timeout`, `deadline`, `retry`, `retries`, `attempts`, `capacity`, `cap`, `threshold`, `budget`, `interval`, `delay`, `backoff`, `ttl`, `quota`, `margin`, `cooldown`, `grace`, `burst`, `ceiling`, `depth`, `elapsed`, `port` and the time units); as one side of a comparison whose other side has such a name. A numeric constant is flagged where it is defined when its name has a bound word, when it is a `Duration`, or when the file uses it as one of those arguments or as the bound of `take`, `min`, `max`, `clamp`, `truncate`, `reserve`, `slice`, `substring` or a comparison. Structural counts (`parts.len() >= 4`, `.take(2)`) and index arithmetic pass.
- **Visual values.** In stylesheets, style objects (`style={{ .. }}`, `style: { .. }`) and CSS-in-JS templates, a colour (hex, colour functions, the basic named colours) or a spacing length (`margin`, `padding`, `gap`, `inset` and their longhands); in any script string, a hex colour with a letter in it or a colour function.
- **Readable text.** In TSX and JSX, element text, a string child (`{"Save"}`) and the string of a shown or announced attribute (`aria-label`, `title`, `alt`, `placeholder`, `label`, `description` and the like).

Worked fix, a bound. `const PRINTED_FINDINGS: usize = 9;` used in `.take(PRINTED_FINDINGS)` becomes `printed_findings = 9` under the module's table in `.agents/kit/limits.toml` (a protected change), a field on that area's type in the loader, and `.take(limits.printed_findings)` where the code receives the loaded limits.

Worked fix, an endpoint. `client.get("https://feeds.vendor.io/v1")` becomes a configuration key, `intel.feed_url`, whose default the brand manifest supplies, read once at start and passed to the client. An air-gapped or self-hosted site overrides it; nothing compiled names the host.
