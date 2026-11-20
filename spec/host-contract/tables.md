<!-- SPDX-License-Identifier: Apache-2.0 OR CC-BY-4.0 -->

# Fast-path table blob

This document fixes the byte format of the fast-path table blob, `table_format` 1: the header,
the body sections, the validation rules the library applies before use, and what the library does
with a blob it accepted. It specifies design/26 section 2 (Tables, Where tables come from, What the
protected process still takes from the sidecar, Swapping tables, Constraints) over the floor rows
and cache scopes of design/12 section 8. The C functions over the blob are in `c-abi.md`.

Spine: D-05, D-14, D-15, D-20, D-41, D-60, P9, P14; ruling R-05. The writer is `compile_fastpath`
in `grdr-core`; the readers are `grdr-fastpath` and, through it, `grdr-fastpath-ffi`.

## 1. Conventions

- Every multi-byte integer is unsigned and little-endian. Digests are 32 raw bytes, compared
  bytewise.
- Offsets are byte offsets from the first byte of the blob. Every section starts at a multiple of
  8, so the host must place the blob at an 8-aligned address (`c-abi.md`; a misaligned base is an
  argument error, not a rule below).
- Inside a record, a 2-byte field sits at an even offset, a 4-byte field at a multiple of 4 and an
  8-byte field at a multiple of 8. Record sizes below are exact.
- Padding bytes are zero. So is every field a record's kind does not use.
- Strings live in the string pool section and are referenced by `(offset, length)`, where a pool
  offset counts from the first byte of the pool. A UTF-8 length counts bytes; a UTF-16LE length
  counts 16-bit code units and its offset is even.
- Counts, offsets and lengths are computed in 64-bit unsigned arithmetic. A blob is at most
  4,294,967,295 bytes, so every value a reader needs fits in 32 bits once the rules of section 4
  hold, on 32-bit and 64-bit targets alike.

## 2. Header

The header is 224 bytes. Bytes 0 to 19 are the stable prefix: they have this layout in every
`table_format`, so a library can refuse a blob from a newer compiler with the right status before
it knows that format.

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 8 | `magic` | bytes | `89 67 72 64 72 66 70 0A`. The high byte catches 7-bit transfers, the final `0A` catches newline translation |
| 8 | 4 | `table_format` | u32 | `1` for this document |
| 12 | 4 | `abi_min` | u32 | The oldest fast-path ABI that can read the blob, as `major << 16 \| minor` (`grdr_fp_abi_version`). `0x00000001` (0.1) for this document |
| 16 | 4 | `blob_len` | u32 | Total length of the blob in bytes |
| 20 | 4 | padding | | Zero |
| 24 | 32 | `bundle_digest` | digest | SHA-256 of the verified bundle the blob was compiled from, as `VerifiedBundle` holds it |
| 56 | 2 | `compiler_version.major` | u16 | Version of the `grdr-core` that wrote the blob |
| 58 | 2 | `compiler_version.minor` | u16 | |
| 60 | 2 | `compiler_version.patch` | u16 | |
| 62 | 2 | padding | | Zero |
| 64 | 32 | `effective_hash` | digest | The bundle manifest's `effective_hash` (design/12 sections 7 and 10) |
| 96 | 80 | section directory | 10 entries | Entry `i` is at `96 + 8 * i`: `count` (u32, records in section `i`), then `offset` (u32, byte offset of its first record) |
| 176 | 4 | `eval_cap` | u32 | Per-call cap on evaluation steps (section 5) |
| 180 | 2 | `action_class_count` | u16 | Highest action class number the blob uses; valid numbers are 1 to this value |
| 182 | 1 | `principal_kind_count` | u8 | Highest principal kind number; valid numbers are 1 to this value |
| 183 | 1 | padding | | Zero |
| 184 | 8 | `session_rule_classes` | u64 | Bit `n` set when a session rule of the bundle matches actions of class `n` (design/12 section 8, cache scope `none`) |
| 192 | 8 | `path_fold_classes` | u64 | Bit `c` set when path entries of resource class `c` compare ASCII letters without case |
| 200 | 8 | `expiry_bundle_ns` | u64 | Expiry a `bundle`-scope verdict carries, in nanoseconds; 0 means no bound beyond the scope |
| 208 | 8 | `expiry_session_ns` | u64 | Expiry a `session`-scope verdict carries, in nanoseconds; 0 means no bound beyond the scope |
| 216 | 4 | `path_max_units` | u32 | Longest target path the fast path accepts, in code units of the input's encoding |
| 220 | 4 | padding | | Zero |

The compiler writes `eval_cap`, the two expiries and `path_max_units` from `limits.toml` rows, and
`action_class_count`, `principal_kind_count`, `session_rule_classes` and `path_fold_classes` from
the bundle and the device facts it compiles against (P14). The library holds none of these values.

## 3. Body sections

Directory index, section and record size:

| Index | Section | Record size |
|---|---|---|
| 0 | Floor rows | 64 |
| 1 | Path classifier | 16 |
| 2 | Host classifier | 40 |
| 3 | Executable classifier | 40 |
| 4 | Interest set: process scope | 48 |
| 5 | Interest set: paths | 16 |
| 6 | Interest set: hosts | 40 |
| 7 | Interest set: ports | 4 |
| 8 | Reason-code table | 16 |
| 9 | String pool | 1 |

A section's length is `count * record size`. An empty section has `count` 0 and `offset` 0. The
compiler writes non-empty sections in directory order, each at the first multiple of 8 at or after
the end of the one before it (the first at 224), and `blob_len` is the end of the last one.

### 3.1 Floor rows

One row is `(action class, principal kind, resource class mask, required labels, forbidden labels,
grant digest) -> deny | step_up` (design/12 section 8).

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 2 | `action_class` | u16 | The class number `c-abi.md` gives (spine section 3 order, `exec` = 1) |
| 2 | 1 | `principal_kind` | u8 | 0 matches any kind; otherwise the kind number of `c-abi.md` |
| 3 | 1 | `outcome` | u8 | 2 `deny`, 3 `step_up` (the verdict numbers of `c-abi.md`) |
| 4 | 4 | `reason` | u32 | Index into the reason-code table |
| 8 | 8 | `resource_classes` | u64 | Every bit set here must be set in the input's class bits |
| 16 | 8 | `required_labels` | u64 | Every bit set here must be set in the input's label bits |
| 24 | 8 | `forbidden_labels` | u64 | No bit set here may be set in the input's label bits |
| 32 | 32 | `grant_digest` | digest | All zero: no grant lifts the row. Otherwise the rule's grant key; an input carrying the same digest lifts the row |

A row never has the outcome `pass`. Floor rows come only from forbid rules (design/12 section 7,
the ceiling argument), and `pass` is what the table returns when no row objects. Rows are sorted by
action class, then by rule id, so each action class is one run of consecutive rows.

Label bit `n` is the `n`th entry of the bundle's label table, the same indexing the engine uses for
the label projection it emits as an `Effect`. The grant key is 32 bytes the compiler takes from the
rule's own grant clause (`unless { context.grants.contains("<its id>") }`); the engine names the same
bytes in the grant effects it sends the host. The format treats both as opaque.

### 3.2 Path classifier

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 4 | `utf8_off` | u32 | Pool offset of the UTF-8 pattern |
| 4 | 4 | `utf16_off` | u32 | Pool offset of the UTF-16LE pattern |
| 8 | 2 | `utf8_len` | u16 | Bytes |
| 10 | 2 | `utf16_len` | u16 | Code units |
| 12 | 1 | `class_bit` | u8 | Resource class this entry sets, 0 to 63 |
| 13 | 3 | padding | | Zero |

A pattern uses the glob grammar of the engine's path classifier (#221 R1 and R2: segments joined by
`/`, `*` and `?` inside a segment, `\` escaping `*`, `?` and `\`, and `**` as a whole segment), with
every template already resolved by the compiler, so a pattern starts with `/` or with a `**`
segment. The two forms hold the same characters; the compiler writes both so that nothing is
transcoded at evaluation.

### 3.3 Host classifier

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 8 | `class_mask` | u64 | Resource classes this entry sets |
| 8 | 1 | `kind` | u8 | 1 exact name, 2 wildcard name, 3 IPv4 block, 4 IPv6 block, 5 any destination |
| 9 | 1 | `prefix_len` | u8 | Block prefix length (kinds 3 and 4) |
| 10 | 2 | `port_lo` | u16 | Lowest destination port the entry covers |
| 12 | 2 | `port_hi` | u16 | Highest; 0 to 65535 covers every port |
| 14 | 2 | `name_len` | u16 | Bytes (kinds 1 and 2) |
| 16 | 4 | `name_off` | u32 | Pool offset of the name (kinds 1 and 2) |
| 20 | 4 | padding | | Zero |
| 24 | 16 | `addr` | bytes | Network byte order (kinds 3 and 4); an IPv4 block uses bytes 24 to 27 |

Names are in the canonical form of the engine's host classifier (#222 R1). A wildcard entry stores
the name after `*.`, and matches a name with one or more labels before it, never the name itself
(#222 R3).

### 3.4 Executable classifier

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 32 | `digest` | digest | The executable digest the bundle's executable classes name |
| 32 | 8 | `class_mask` | u64 | Resource classes this executable has |

Entries are sorted by digest in strictly ascending bytewise order, so a lookup is a binary search.

### 3.5 Interest set

Design/12 names the interest set (D-05) but gives it no byte format; this section is that format,
and `grdr_fp_interest` hands the host pointers into it to compile into its own filters.

Process scope, the processes whose events the host sends:

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 4 | `utf8_off` | u32 | Pool offset of the UTF-8 value (kinds 2 to 4) |
| 4 | 4 | `utf16_off` | u32 | Pool offset of the UTF-16LE value (kinds 2 to 4) |
| 8 | 2 | `utf8_len` | u16 | Bytes |
| 10 | 2 | `utf16_len` | u16 | Code units |
| 12 | 1 | `kind` | u8 | 1 executable digest, 2 executable path pattern, 3 signing identity, 4 package or bundle identity |
| 13 | 3 | padding | | Zero |
| 16 | 32 | `digest` | digest | Kind 1 only |

A kind 2 value is a path pattern of section 3.2; kinds 3 and 4 are compared exactly, in the meaning
design/05 gives the identifier on the host's operating system.

Paths use the path classifier record with `class_bit` zero. Hosts use the host classifier record
with `class_mask` zero. Ports are `(port_lo u16, port_hi u16)` at offsets 0 and 2 of a 4-byte
record.

### 3.6 Reason-code table

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 4 | `reason_off` | u32 | Pool offset of the reason code, UTF-8 |
| 4 | 4 | `rule_off` | u32 | Pool offset of the instantiated rule id `<layer>/<pack>@<version>/<rule>`, UTF-8 |
| 8 | 2 | `reason_len` | u16 | Bytes |
| 10 | 2 | `rule_len` | u16 | Bytes |
| 12 | 4 | padding | | Zero |

One entry per rule that has rows. A verdict names the entry by its index.

### 3.7 String pool

Bytes, referenced by the records above. The pool has no structure of its own.

## 4. Validation rules

The library applies these rules before use. The outcome of a blob is the first rule that fails, in
number order, where each rule is applied only to a blob that passed every rule before it; an
implementation may check in another order if it reports that rule. No rule is checked lazily:
every rule passes before `grdr_fp_load` returns a table handle. `grdr_fp_arena_size` applies TV-1
to TV-14, which read the header alone; `grdr_fp_load` applies all of them. TV-3 gives `GRDR_E_ABI`;
every other rule gives `GRDR_E_BUNDLE`.

Header:

- **TV-1.** The blob is shorter than the 20-byte stable prefix.
- **TV-2.** `magic` is not `89 67 72 64 72 66 70 0A`.
- **TV-3.** `abi_min` is greater than the library's `grdr_fp_abi_version()`, compared as u32.
  `GRDR_E_ABI`.
- **TV-4.** The library does not read this `table_format`.
- **TV-5.** The blob is shorter than the header of its `table_format` (224 bytes for format 1).
- **TV-6.** `blob_len` differs from the length the host passed.
- **TV-7.** A header padding byte (bytes 20 to 23, 62, 63, 183 and 220 to 223) is not zero.
- **TV-8.** A header parameter is out of range: `eval_cap` is 0; `action_class_count` is 0 or above
  63; `principal_kind_count` is 0; `path_max_units` is 0; or `session_rule_classes` has bit 0 or a
  bit above `action_class_count` set.
- **TV-9.** A section's `count` times its record size is above 4,294,967,295.
- **TV-10.** A non-empty section's `offset` is not a multiple of 8.
- **TV-11.** A non-empty section's `offset` is below 224, inside the header, or an empty section's
  `offset` is not 0.
- **TV-12.** A non-empty section's `offset` plus its length is greater than `blob_len`.
- **TV-13.** Two non-empty sections overlap or lie out of directory order: a non-empty section
  starts before the end of the previous non-empty section in directory order.
- **TV-14.** A byte that lies neither in the header nor in a section is not zero.

Body:

- **TV-15.** A host record (host classifier or interest hosts) has a `kind` other than 1 to 5, or a
  process-scope record has a `kind` other than 1 to 4.
- **TV-16.** A record has a non-zero padding byte, or a non-zero field its kind does not use: in a
  host record, the name fields of kinds 3 to 5, `addr` and `prefix_len` of kinds 1, 2 and 5, and
  `class_mask` in interest hosts; in a process-scope record, the string fields of kind 1 and
  `digest` of kinds 2 to 4; in an interest path record, `class_bit`.
- **TV-17.** A string a record uses is empty or ends past the string pool, or a UTF-16LE string
  starts at an odd pool offset. This covers every reference from the path, host, process-scope and
  reason-code records.
- **TV-18.** A UTF-8 string is not valid UTF-8, or a UTF-16LE string is not the UTF-16LE encoding of
  the same characters as its record's UTF-8 string.
- **TV-19.** A path pattern (path classifier, interest paths, process-scope kind 2) breaks the
  grammar of section 3.2: it neither starts with `/` nor has `**` as its first segment; it has an
  empty, `.` or `..` segment; `**` shares a segment with other characters; or a `\` is followed by
  anything but `*`, `?` or `\`, or ends the pattern.
- **TV-20.** A name (host kinds 1 and 2) is not canonical: a character other than `a` to `z`, `0` to
  `9`, `-` and `.`; an empty label or one longer than 63 bytes; a label that starts or ends with
  `-`; more than 253 bytes; or a last label that is all digits or starts with `0x`, which is an IPv4
  address in name form (#222 R2).
- **TV-21.** An address block is malformed: an IPv4 prefix above 32 or an IPv6 prefix above 128; a
  bit after the prefix is set; an IPv4 block with a non-zero byte in `addr` bytes 4 to 15; or an
  IPv6 block of prefix length 96 or more inside the IPv4-mapped prefix (RFC 4291 section 2.5.5.2) or
  the NAT64 well-known prefix (RFC 6052 section 2.1), which section 5 turns into IPv4 before matching.
- **TV-22.** A port range has `port_lo` above `port_hi` (host classifier, interest hosts, interest
  ports).
- **TV-23.** A path classifier entry has a `class_bit` above 63, or a host or executable classifier
  entry has a `class_mask` of zero.
- **TV-24.** An executable classifier digest or a process-scope kind 1 digest is all zero, or the
  executable classifier is not in strictly ascending digest order.
- **TV-25.** A floor row's `action_class` is 0 or above `action_class_count`.
- **TV-26.** Floor rows are not sorted by `action_class`: a row's class is below the class of the row
  before it.
- **TV-27.** A floor row's `principal_kind` is above `principal_kind_count`.
- **TV-28.** A floor row's `outcome` is neither 2 nor 3.
- **TV-29.** A floor row's `reason` is not below the reason-code table's `count`.
- **TV-30.** A floor row's `required_labels` and `forbidden_labels` share a bit, so the row can never
  match.
- **TV-31.** A floor row's `resource_classes` has a bit that no classifier entry can set: not the
  `class_bit` of a path classifier entry and not in the `class_mask` of a host or executable
  classifier entry.

The cases design/26 and #245 R3 name, and the rule that covers each:

| Case | Rule |
|---|---|
| Blob shorter than the header | TV-1, TV-5 |
| Wrong magic | TV-2 |
| Unknown `table_format` | TV-4 |
| `abi_min` above the library's ABI | TV-3 |
| A section offset, or offset plus length, past the blob end | TV-12 (TV-11 for an offset inside the header) |
| Overlapping sections | TV-13 |
| A row count times row size that overflows | TV-9 |
| A misaligned section | TV-10 |
| A classifier or interest-set reference outside its section | TV-17 |
| A reason-code index outside the reason-code table | TV-29 |

A rule that fails leaves the host with no new table handle; the tables it loaded before stay in
use, and the host applies the class's declared `on_failure` (D-15) and reports the status.

## 5. Evaluation over a valid blob

This is what the library does with the tables, so the compiler and the library read the same
bytes the same way.

**Classes.** The input's class bits are the union of:

- path: `1 << class_bit` for every path classifier entry whose pattern matches the target path, in
  the form of the input's encoding. Matching follows #221 R2 and the vectors of #221 R9, against the
  canonical path of #221 R4. Entries of a class whose bit is set in `path_fold_classes` compare the
  ASCII letters `A` to `Z` and `a` to `z` without case; every other code unit is compared exactly.
- host: the `class_mask` of every host classifier entry that matches the destination and whose port
  range holds the destination port. An IPv6 destination in the IPv4-mapped or NAT64 well-known
  prefix is first replaced by its embedded IPv4 address. A name never matches an address entry and an
  address never matches a name entry; kind 5 matches any destination that is present.
- executable: the `class_mask` of the entry whose digest equals the input's, found by binary search.

An empty path, an absent destination or an all-zero executable digest contributes no bits.

**Rows.** Only the run of the input's action class is read. A row matches when its `principal_kind`
is 0 or equals the input's, every bit of `resource_classes` is in the class bits, every bit of
`required_labels` is in the label bits, no bit of `forbidden_labels` is, and it is not lifted. A row
is lifted when its `grant_digest` is not all zero and equals the input's grant digest. Any matching
`deny` row gives `deny`; otherwise any matching `step_up` row gives `step_up`; otherwise the verdict
is `pass`. The verdict's rule index is the index, in the floor-row section, of the first row in
table order with the winning outcome, and its reason code is that row's `reason`.

`pass` is not `ALLOW`: no floor row objects, and the action goes on to the content engine or, if
the engine cannot answer in time, to the class's declared `on_failure` (D-15).

**Cache scope** (design/12 section 8), over every row of the action class's run:

1. `none` for a `step_up` verdict, when a row was lifted (it matched in every other respect), or when
   the action class's bit is set in `session_rule_classes`;
2. otherwise `call` when a row of the run has a non-zero `required_labels` or `forbidden_labels`;
3. otherwise `session` when a row of the run has a non-zero `principal_kind`;
4. otherwise `bundle`.

The expiry is `expiry_bundle_ns` for `bundle`, `expiry_session_ns` for `session`, and 0 for `call`
and `none`, which a host never caches. A bundle swap clears the host's cache.

## 6. Run-time bounds

- Every walk is bounded by the counts recorded in the header and checked by TV-9 to TV-13.
- Evaluation is O(rows touched): it reads one action class's run, each classifier entry at most
  once, and the executable classifier by binary search. One step is one floor row read, one
  classifier entry examined, one binary-search probe or one code-unit comparison of the path
  matcher, which takes at most `(path units + 1) * (pattern units + 1)` comparisons for one entry
  (#221 R8). An evaluation that would exceed `eval_cap` steps stops and returns `GRDR_E_BUNDLE`,
  never `pass` and never partial class bits.
- A target path longer than `path_max_units` is refused with `GRDR_E_ARG` before any matching.
- The library never copies the blob. It reads the blob and writes only the host's arena, and only in
  `grdr_fp_load`.
- The host's arena size comes from `grdr_fp_arena_size` on the same header: the library computes it
  from the header alone (the section counts and `action_class_count`), and two calls on the same
  header in the same library give the same size. What the arena holds (the table handle and the
  per-action-class row index) is the library's own layout and is not part of this format.

## 7. Label pairing

Enforcing-label bits and grant digests reach the protected process as `Effect`s from the content
engine (design/26 section 5), as they do in our daemon. Label bits are indexed by the label table of
the bundle they were produced under, so each input carries `labels_bundle_tag`: the first eight
bytes of that bundle's digest, read as a little-endian u64. A tag that differs from the first eight
bytes of the loaded table's `bundle_digest`, read the same way, gives `GRDR_E_STATE` on every call
until the labels and the tables come from the same bundle. A compromised sidecar can therefore
withhold a label but cannot change a row, and a label projection from an older bundle is never read
against the bits of a newer one.

## 8. Where tables come from

A protected process is its host's tamper anchor and takes policy only from what its own verifier
accepted; the core verifies nothing (design/03 section 3). So:

- The host's privileged service compiles the tables on the device from a bundle its own verifier
  accepted, never the sidecar (R-05). Our own daemon does the same and signs the fast-path and
  fail-safe tables with the device-local artefact key (D-14; design/21's key table).
- Only for an embedded host that cannot compile on the device does the partner's relay pipeline
  (design/26 section 6) compile them, per bundle and per host operating system and architecture,
  signed under the partner's root. Rows that need per-device facts are not compiled there and stay
  in the content engine.
- The format carries no signature field. A blob from `grdr_engine_compile_fastpath` is unsigned and
  is for unprivileged hosts and tests. A signed blob travels inside its channel's own envelope, and
  the host verifies that envelope before it calls `grdr_fp_arena_size`.

## 9. Swapping tables

The host loads a new blob into a new arena, swaps one pointer atomically and frees the old blob and
arena after its own quiescence point, when no `grdr_fp_eval` on the old tables can still be
running. There is no unload call. An arena that live tables use is never passed to `grdr_fp_load`.

## 10. Versioning

`table_format` 1 is this document; it is experimental under D-60. A new section, a new record field
or any other incompatible layout is a new `table_format` value, decided by RFC (design/30 section
3). The stable prefix of section 2 never changes, so a library that meets a newer blob refuses it
with `GRDR_E_ABI` (TV-3) when the blob needs a newer library, and with `GRDR_E_BUNDLE` (TV-4) when
the format is one it does not read, rather than misreading it.

## 11. What the compiler guarantees beyond the rules

The library cannot check these, so the compiler holds them and its tests prove them (#414):

- The same bundle and device facts give the same bytes on every target, laid out as section 3
  states.
- Rows of one action class are ordered by rule id, so a rule index is stable for a given bundle.
- Templates are resolved from the device facts. A pattern whose template has no device-wide value
  (`$WORKSPACE`, `$SESSION_TMP`) is not compiled, and the floor report lists its rule.
- A rule that needs more than 64 resource classes or 64 labels is not compiled, never truncated,
  and the floor report lists it. So is a path entry of a fold class that has a non-ASCII literal,
  which ASCII-only folding cannot decide.

## 12. Data classes

The header, rows, masks, counts and reason-code table are compiled policy: `structural` (P8).
Digests are `identifier` (design/04: digests of public artefacts). Path patterns are pack data, but
a template the compiler resolved from the device facts puts the device's own directory names in the
string pool, and a home directory can carry an account name, so a device-compiled blob is handled as
`content` (`content_kind` argument): it is never logged and never leaves the device, which R-05
already requires. A relay-compiled blob holds no resolved roots.
