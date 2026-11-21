<!-- SPDX-License-Identifier: Apache-2.0 OR CC-BY-4.0 -->

# Fast-path table blob

This document fixes the byte format of the fast-path table blob, `table_format` 1: the header,
the body sections, their canonical form, the validation rules the library applies before use, what
the library does with a blob it accepted, and what the host must do for that to hold. It specifies
design/26 section 2 (Tables, Where tables come from, What the protected process still takes from
the sidecar, Swapping tables, Constraints) over the floor rows and cache scopes of design/12
section 8. The C functions over the blob are in `c-abi.md`.

Spine: D-05, D-14, D-15, D-20, D-25, D-41, D-60, P9, P14; ruling R-05. The writer is
`compile_fastpath` in `grdr-core`; the readers are `grdr-fastpath` and, through it,
`grdr-fastpath-ffi`.

## 1. Conventions

- Every multi-byte integer is unsigned and little-endian. Digests are 32 raw bytes, compared
  bytewise.
- Offsets are byte offsets from the first byte of the blob. Every section starts at a multiple of
  8, and the host places the blob at an 8-aligned address: `grdr_fp_interest` hands the host
  pointers to records inside the blob, and an aligned base is what lets a C host read their u16,
  u32 and u64 fields through a struct without a misaligned access. A misaligned base is an argument
  error (`c-abi.md`), not a rule below.
- Inside a record, a 2-byte field sits at an even offset, a 4-byte field at a multiple of 4 and an
  8-byte field at a multiple of 8. Record sizes below are exact.
- Padding bytes are zero. So is every field a record's kind does not use.
- Strings live in the string pool section and are referenced by `(offset, length)`, where a pool
  offset counts from the first byte of the pool. A UTF-8 length counts bytes; a UTF-16LE length
  counts 16-bit code units and its offset is even.
- A character is one Unicode scalar value: one to four bytes in UTF-8, one code unit or one
  surrogate pair in UTF-16LE. Pattern matching and its cost count characters, so the two encodings
  of one path give the same result.
- Counts, offsets and lengths are computed in 64-bit unsigned arithmetic. A blob is at most
  4,294,967,295 bytes, so every value a reader needs fits in 32 bits once the rules of section 5
  hold, on 32-bit and 64-bit targets alike.

**Vocabulary numbers.** The action class is the number of `grdr.common.v1alpha1.ActionClass`, in
spine section 3 order: `exec` 1, `file.read` 2, `file.write` 3, `file.delete` 4, `net.connect` 5,
`net.request` 6, `llm.request` 7, `mcp.connect` 8, `mcp.call` 9, `cred.use` 10, `agent.spawn` 11,
`config.change` 12, `elevate` 13, `ui.act` 14, `data.flow` 15; 0 is unspecified. Fast-path ABI 0.1
carries numbers 1 to 15; a later minor that adds a spine class raises that ceiling. The principal
kind is the Cedar principal type a floor row can name (design/12 section 2): `Session` 1, `Process`
2. It is not `Principal.kind` of design/04 section 2. The verdict numbers are `pass` 1, `deny` 2,
`step_up` 3; `c-abi.md` uses the same numbers.

## 2. Header

The header is 224 bytes. Bytes 0 to 19 are the stable prefix: they have this layout in every
`table_format`, so a library can refuse a blob from a newer compiler with the right status before
it knows that format.

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 8 | `magic` | bytes | `89 67 72 64 72 66 70 0A`. The high byte catches 7-bit transfers, the final `0A` catches newline translation |
| 8 | 4 | `table_format` | u32 | `1` for this document |
| 12 | 4 | `abi_min` | u32 | The oldest fast-path ABI that can read the blob, as `major << 16 \| minor` (`grdr_fp_abi_version`): the oldest whose action-class numbers reach `action_class_count`. `0x00000001` (0.1) while the count is at most 15 |
| 16 | 4 | `blob_len` | u32 | Total length of the blob in bytes |
| 20 | 4 | padding | | Zero |
| 24 | 32 | `bundle_digest` | digest | SHA-256 of the verified bundle the blob was compiled from, as `VerifiedBundle` holds it |
| 56 | 2 | `compiler_version.major` | u16 | Version of the `grdr-core` that wrote the blob |
| 58 | 2 | `compiler_version.minor` | u16 | |
| 60 | 2 | `compiler_version.patch` | u16 | |
| 62 | 2 | padding | | Zero |
| 64 | 32 | `effective_hash` | digest | The bundle manifest's `effective_hash` (design/12 sections 7 and 10) |
| 96 | 80 | section directory | 10 entries | Entry `i` is at `96 + 8 * i`: `count` (u32, records in section `i`), then `offset` (u32, byte offset of its first record) |
| 176 | 4 | `eval_cap` | u32 | Per-call cap on evaluation steps (section 7) |
| 180 | 2 | `action_class_count` | u16 | Size of the action-class vocabulary the blob was compiled against (15 for spine section 3), whether or not every class has rows |
| 182 | 1 | `principal_kind_count` | u8 | Size of the principal-kind vocabulary the blob was compiled against (2) |
| 183 | 1 | padding | | Zero |
| 184 | 8 | `session_rule_classes` | u64 | Bit `n` set when a session rule of the bundle matches actions of class `n` (design/12 section 8, cache scope `none`) |
| 192 | 8 | `path_fold_classes` | u64 | Bit `c` set when path entries of resource class `c` compare ASCII letters without case |
| 200 | 8 | `expiry_bundle_ns` | u64 | How long a `bundle`-scope verdict may be reused, in nanoseconds; `0xFFFFFFFFFFFFFFFF` means until the scope ends |
| 208 | 8 | `expiry_session_ns` | u64 | The same for a `session`-scope verdict |
| 216 | 4 | `path_max_units` | u32 | Longest target path the fast path accepts, in code units of the input's encoding |
| 220 | 4 | padding | | Zero |

`path_max_units` counts code units, not characters, because the library checks it before it decodes
anything; a path has no more characters than code units, so a bound on units bounds characters too.

The compiler writes four fields from `limits.toml` and the rest from the bundle and the device
facts it compiles against (P14); the library holds none of these values:

| Field | Source |
|---|---|
| `eval_cap` | `fastpath.eval_cap_steps` |
| `path_max_units` | `fastpath.path_max_units` |
| `expiry_bundle_ns` | `fastpath.expiry_bundle_ns` |
| `expiry_session_ns` | `fastpath.expiry_session_ns` |
| `action_class_count`, `principal_kind_count` | The vocabularies of the bundle's schema |
| `session_rule_classes` | The `on` action classes of the bundle's session rules |
| `path_fold_classes` | The device's volume facts (section 13) |

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

A section's length is `count * record size`. An empty section has `count` 0 and `offset` 0.

### 3.1 Floor rows

One row is `(action class, principal kind, resource class mask, required labels, forbidden labels,
grant digest) -> deny | step_up` (design/12 section 8).

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 2 | `action_class` | u16 | Action class number (section 1) |
| 2 | 1 | `principal_kind` | u8 | 0 matches any kind; otherwise a principal kind number (section 1) |
| 3 | 1 | `outcome` | u8 | 2 `deny`, 3 `step_up` |
| 4 | 4 | `reason` | u32 | Index into the reason-code table |
| 8 | 8 | `resource_classes` | u64 | Every bit set here must be set in the input's class bits |
| 16 | 8 | `required_labels` | u64 | Every bit set here must be set in the input's label bits |
| 24 | 8 | `forbidden_labels` | u64 | No bit set here may be set in the input's label bits |
| 32 | 32 | `grant_digest` | digest | All zero: no grant lifts the row. Otherwise the rule's grant key; an input carrying the same digest lifts the row |

A row never has the outcome `pass`. Floor rows come only from forbid rules (design/12 section 7,
the ceiling argument), and `pass` is what the table returns when no row objects.

Label bit `n` is the `n`th entry of the bundle's label table, the same indexing the engine uses for
the label projection it emits as an `Effect`. The grant key is 32 bytes the compiler takes from the
rule's own grant clause (`unless { context.grants.contains("<its id>") }`); the engine names the same
bytes in the grant effects it sends the host. The format treats both as opaque; section 8 says what
they can and cannot be trusted for.

### 3.2 Path classifier

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 4 | `utf8_off` | u32 | Pool offset of the UTF-8 pattern |
| 4 | 4 | `utf16_off` | u32 | Pool offset of the UTF-16LE pattern |
| 8 | 2 | `utf8_len` | u16 | Bytes |
| 10 | 2 | `utf16_len` | u16 | Code units |
| 12 | 1 | `class_bit` | u8 | Resource class this entry sets, 0 to 63 |
| 13 | 3 | padding | | Zero |

A pattern is a sequence of segments joined by `/`. It either starts with `/`, or its first segment
is `**`; the compiler has already replaced every template with its value. Inside a segment, `*`
matches any run of characters other than `/`, including none; `?` matches exactly one character
other than `/`; `\` makes the next `*`, `?` or `\` literal; every other character is literal. A
segment that is exactly `**` matches zero or more whole path segments. The two forms hold the same
characters, in Unicode normalisation form C, so nothing is transcoded at evaluation. This is the
grammar of the engine's path classifier, counted in characters.

### 3.3 Host classifier

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 8 | `class_mask` | u64 | Resource classes this entry sets |
| 8 | 1 | `kind` | u8 | 1 exact name, 2 wildcard name, 3 IPv4 block, 4 IPv6 block, 5 any destination |
| 9 | 1 | `prefix_len` | u8 | Block prefix length in bits (kinds 3 and 4) |
| 10 | 2 | `port_lo` | u16 | Lowest destination port the entry covers |
| 12 | 2 | `port_hi` | u16 | Highest; 0 to 65535 covers every port |
| 14 | 2 | `name_len` | u16 | Bytes (kinds 1 and 2) |
| 16 | 4 | `name_off` | u32 | Pool offset of the name (kinds 1 and 2) |
| 20 | 4 | padding | | Zero |
| 24 | 16 | `addr` | bytes | Kinds 3 and 4, in network byte order: an IPv4 block uses `addr[0..4]` and leaves `addr[4..16]` zero |

Address bit `i` is bit `7 - (i mod 8)` of `addr[i / 8]`, so bit 0 is the most significant bit of
the first byte. A block of prefix length `p` covers every address whose bits 0 to `p - 1` equal the
entry's.

A name is in canonical form, the form design/13 section 8's host classifier produces (WHATWG URL
host parsing, UTS 46 processing to A-labels, lower case, trailing dot removed): ASCII only, lower
case, labels of 1 to 63 bytes of `a` to `z`, `0` to `9` and `-` joined by `.`, no label starting or
ending with `-`, at most 253 bytes, no trailing `.`, and a last label that is neither all digits nor
`0x` followed by hex digits (those are IPv4 addresses in name form, written as kind 3). A wildcard
entry stores the name after `*.` and matches a name with one or more labels before it, never the
name itself.

### 3.4 Executable classifier

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 32 | `digest` | digest | The executable digest the bundle's executable classes name |
| 32 | 8 | `class_mask` | u64 | Resource classes this executable has |

Entries are sorted by digest in strictly ascending bytewise order, so a lookup is a binary search.

### 3.5 Interest set

Design/12 names the interest set (D-05) but gives it no byte format; this section is that format
and its meaning. `grdr_fp_interest` hands the host pointers into it, and the host compiles it into
its own filters.

Process scope:

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 4 | `utf8_off` | u32 | Pool offset of the UTF-8 value (kinds 2 to 4) |
| 4 | 4 | `utf16_off` | u32 | Pool offset of the UTF-16LE value (kinds 2 to 4) |
| 8 | 2 | `utf8_len` | u16 | Bytes |
| 10 | 2 | `utf16_len` | u16 | Code units |
| 12 | 1 | `kind` | u8 | 1 executable digest, 2 executable path pattern, 3 signing identity, 4 package identity |
| 13 | 3 | padding | | Zero |
| 16 | 32 | `digest` | digest | Kind 1 only |

A kind 1 entry selects a process whose executable has that digest. A kind 2 entry selects a process
whose executable path matches the pattern by the rules of section 6. Kinds 3 and 4 are compared
exactly, with the meaning design/05 gives the identifier on the host's operating system: a signing
identity is the signer of the executable; a package identity is its package owner, package family
name or application identifier.

Paths use the path classifier record with `class_bit` zero. Hosts use the host classifier record
with `class_mask` zero. Ports are `(port_lo u16, port_hi u16)` at offsets 0 and 2 of a 4-byte
record.

**What the interest set selects.** An event is of interest when any of these holds; the tables
combine by union, and an empty table selects nothing on its own:

- its process is in scope: it matched a process-scope entry when it started, or it descends from a
  process that did, by the host's process lineage (D-25; design/11's lineage tag, inherited at fork
  and kept across exec) until it exits;
- it is a file event whose path matches an interest path. Interest paths always compare ASCII
  letters without case, since selecting more events costs only work;
- it is a connection whose destination matches an interest host entry with its port in that
  entry's range, or whose destination port lies in an interest port range.

The host evaluates the floor at its control points for every action of interest, and the compiler
writes an interest set that selects every action a floor row can match (section 13).

### 3.6 Reason-code table

| Offset | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 4 | `reason_off` | u32 | Pool offset of the reason code, UTF-8 |
| 4 | 4 | `rule_off` | u32 | Pool offset of the instantiated rule id `<layer>/<pack>@<version>/<rule>`, UTF-8 |
| 8 | 2 | `reason_len` | u16 | Bytes |
| 10 | 2 | `rule_len` | u16 | Bytes |
| 12 | 4 | padding | | Zero |

One entry per rule that has rows. A verdict names the entry by its index. Both strings are
identifiers made of the visible ASCII characters `!` to `~`, so a host can show or log them without
a control or bidirectional formatting character reaching a person.

### 3.7 String pool

Bytes, referenced by the records above. The pool has no structure of its own, and every string in
it is referenced exactly once (section 4).

## 4. Canonical form

One bundle and one set of device facts give one blob, byte for byte, whatever order the rules,
lists and entries arrive in. The compiler writes this form:

1. **Records, each section sorted and free of duplicates.** Byte strings compare bytewise, shorter
   first on a common prefix.
   - Reason-code table: by rule id; one entry per rule id.
   - Floor rows: by `action_class`, then `reason`, then the 64 record bytes; identical rows appear
     once. Because the reason-code table is sorted by rule id, a rule index is stable for a bundle.
   - Path classifier: by `class_bit`, then UTF-8 pattern; one entry per pair.
   - Host classifier and interest hosts: by `kind`, then the name (kinds 1 and 2) or `addr` and
     `prefix_len` (kinds 3 and 4), then `port_lo`, then `port_hi`. Entries with equal keys are one
     entry whose `class_mask` is the union of theirs.
   - Executable classifier: by digest; one entry per digest, masks merged.
   - Interest process scope: by `kind`, then digest (kind 1) or UTF-8 value; one entry per pair.
   - Interest paths: by UTF-8 pattern; one entry per pattern.
   - Interest ports: by `port_lo`; overlapping or adjacent ranges are merged into one.
2. **String pool.** Built by visiting the records in this order: path classifier, host classifier,
   process scope, interest paths, interest hosts, reason-code table; inside each record its strings
   in field order, UTF-8 before UTF-16LE. Each string is appended, after one zero byte when it is
   UTF-16LE and the pool length is odd. Strings are never shared, so validating the pool costs work
   in proportion to its length, not to the number of references.
3. **Placement.** Non-empty sections appear in directory order, the first at offset 224 and each
   next one at the first multiple of 8 at or after the end of the one before it. The gaps are zero.
   `blob_len` is the end of the last non-empty section, or 224 when every section is empty.

The validator enforces placement (TV-13 to TV-15), the pool layout (TV-18), and every order a
verdict depends on: rows (TV-27), the reason-code table (TV-33) and executable digests (TV-25). So
a verdict's rule index and reason code are fixed by the blob's content. It does not check the order
or merging of the other sections. Those change the bytes, never a verdict, cache scope or expiry,
so a blob that breaks them is accepted and evaluates the same; byte identity is the compiler's
guarantee, which #414's tests prove by compiling permuted inputs.

## 5. Validation rules

The library applies these rules before use. The outcome of a blob is the first rule that fails, in
number order, where each rule is applied only to a blob that passed every rule before it; an
implementation may check in another order if it reports that rule. No rule is checked lazily:
every rule passes before `grdr_fp_load` returns a table handle. TV-1 to TV-14 read only the length
and the 224-byte header, and `grdr_fp_arena_size` applies those; TV-15 to TV-33 read the body, and
`grdr_fp_load` applies all 33. TV-3 gives `GRDR_E_ABI`; every other rule gives `GRDR_E_BUNDLE`.
The work of every rule is linear in the blob's length.

Header (`grdr_fp_arena_size` and `grdr_fp_load`):

- **TV-1.** The blob is shorter than the 20-byte stable prefix.
- **TV-2.** `magic` is not `89 67 72 64 72 66 70 0A`.
- **TV-3.** `abi_min` is greater than the library's `grdr_fp_abi_version()`, compared as u32.
  `GRDR_E_ABI`.
- **TV-4.** The library does not read this `table_format`.
- **TV-5.** The blob is shorter than the header of its `table_format` (224 bytes for format 1).
- **TV-6.** `blob_len` differs from the length the host passed.
- **TV-7.** A header padding byte (bytes 20 to 23, 62, 63, 183 and 220 to 223) is not zero.
- **TV-8.** A header parameter is out of range: `eval_cap` is 0; `action_class_count` is 0, above
  63, or above the highest action class the library's ABI carries (section 1); `principal_kind_count`
  is 0; `path_max_units` is 0; `expiry_bundle_ns` or `expiry_session_ns` is 0; or
  `session_rule_classes` has bit 0 or a bit above `action_class_count` set.
- **TV-9.** A section's `count` times its record size is above 4,294,967,295.
- **TV-10.** A non-empty section's `offset` is not a multiple of 8.
- **TV-11.** A non-empty section's `offset` is below 224, inside the header, or an empty section's
  `offset` is not 0.
- **TV-12.** A non-empty section's `offset` plus its length is greater than `blob_len`.
- **TV-13.** Two non-empty sections overlap or lie out of directory order: a non-empty section
  starts before the end of the previous non-empty section in directory order.
- **TV-14.** Placement is not canonical (section 4, item 3): a non-empty section does not start at
  the first multiple of 8 at or after the end of the previous non-empty section (224 for the
  first), or `blob_len` is not the end of the last non-empty section (224 when every section is
  empty).

Body (`grdr_fp_load` only):

- **TV-15.** A padding byte between two sections is not zero.
- **TV-16.** A host record (host classifier or interest hosts) has a `kind` other than 1 to 5, or a
  process-scope record has a `kind` other than 1 to 4.
- **TV-17.** A record has a non-zero padding byte, or a non-zero field its kind does not use: in a
  host record, the name fields of kinds 3 to 5, `addr` and `prefix_len` of kinds 1, 2 and 5, and
  `class_mask` in interest hosts; in a process-scope record, the string fields of kind 1 and
  `digest` of kinds 2 to 4; in an interest path record, `class_bit`.
- **TV-18.** The strings do not tile the pool (section 4, item 2): visiting the records in that
  order, a string a record uses is empty, does not start where the previous string ended (after
  one zero byte when it is UTF-16LE and that position is odd), or the last string does not end at
  the end of the pool. This also covers every reference from a path, host, process-scope or
  reason-code record that points outside the pool.
- **TV-19.** A string's characters are not allowed: a UTF-8 string is not valid UTF-8; a UTF-16LE
  string is not the UTF-16LE encoding of the same characters as its record's UTF-8 string; a
  reason code or rule id holds a byte outside `!` to `~`; or a process-scope identity (kinds 3 and
  4) holds a control character (U+0000 to U+001F, U+007F to U+009F) or a bidirectional formatting
  character (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069).
- **TV-20.** A path pattern (path classifier, interest paths, process-scope kind 2) breaks the
  grammar of section 3.2: it neither starts with `/` nor has `**` as its first segment; it has an
  empty, `.` or `..` segment; `**` shares a segment with other characters; or a `\` is followed by
  anything but `*`, `?` or `\`, or ends the pattern.
- **TV-21.** A name (host kinds 1 and 2) is not in the canonical form of section 3.3.
- **TV-22.** An address block is malformed: an IPv4 prefix above 32 or an IPv6 prefix above 128; an
  address bit at or after the prefix length is set; an IPv4 block with a non-zero byte in
  `addr[4..16]`; or an IPv6 block of prefix length 96 or more inside the IPv4-mapped prefix (RFC
  4291 section 2.5.5.2) or the NAT64 well-known prefix (RFC 6052 section 2.1), which section 6 turns
  into IPv4 before matching.
- **TV-23.** A port range has `port_lo` above `port_hi` (host classifier, interest hosts, interest
  ports).
- **TV-24.** A path classifier entry has a `class_bit` above 63, or a host or executable classifier
  entry has a `class_mask` of zero.
- **TV-25.** An executable classifier digest or a process-scope kind 1 digest is all zero, or the
  executable classifier is not in strictly ascending digest order.
- **TV-26.** A floor row's `action_class` is 0 or above `action_class_count`.
- **TV-27.** Floor rows are not in strictly ascending order by `action_class`, then `reason`, then
  their 64 bytes, so two rows are equal or out of order.
- **TV-28.** A floor row's `principal_kind` is above `principal_kind_count`.
- **TV-29.** A floor row's `outcome` is neither 2 nor 3.
- **TV-30.** A floor row's `reason` is not below the reason-code table's `count`.
- **TV-31.** A floor row's `required_labels` and `forbidden_labels` share a bit, so the row can never
  match.
- **TV-32.** A floor row's `resource_classes` has a bit that no classifier entry can set: not the
  `class_bit` of a path classifier entry and not in the `class_mask` of a host or executable
  classifier entry.
- **TV-33.** The reason-code table is not in strictly ascending rule-id order.

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
| A classifier or interest-set reference outside its section | TV-18 |
| A reason-code index outside the reason-code table | TV-30 |

A rule that fails leaves the host with no new table handle; the tables it loaded before stay in
use, and the host applies the class's declared `on_failure` (D-15) and reports the status.

## 6. Evaluation over a valid blob

This is what the library does with the tables, so the compiler and the library read the same
bytes the same way. `c-abi.md` gives the input checks that come first; section 11 gives the input
forms the host owes.

**Vocabulary.** An input action class of 0, or above the highest class the library's ABI carries,
is an argument error. A class within the ABI but above `action_class_count` belongs to a vocabulary
newer than the tables: no row can name it, so the verdict is `pass` with scope `none`, and no class
bits are computed. A principal kind of 0 or above `principal_kind_count` is an argument error,
because rows that name a kind would silently stop matching it.

**Target path.** The path must be in the form of section 11 and well-formed in its encoding (valid
UTF-8, or UTF-16LE with no unpaired surrogate). A path that is not, or that has more code units than
`path_max_units`, is an argument error.

**Classes.** The input's class bits are the union of:

- path: `1 << class_bit` for every path classifier entry whose pattern, in the form of the input's
  encoding, matches the target path. The pattern's segments must match the path's segments from
  first to last: a `**` segment takes zero or more whole path segments, and any other segment takes
  exactly one, matched character by character with the rules of section 3.2. In an entry whose class
  bit is set in `path_fold_classes`, the ASCII letters `A` to `Z` and `a` to `z` match without case;
  every other character matches only itself.
- host: the `class_mask` of every host classifier entry that matches the destination and whose port
  range holds the destination port. An IPv6 destination whose first 96 bits are the IPv4-mapped or
  the NAT64 well-known prefix is first replaced by the IPv4 address in its last four bytes. That
  replacement comes first, so an IPv6 block never matches an address in either prefix, even a block
  that contains it, as in the engine; a rule about IPv4 hosts names IPv4 blocks. Kind 1 matches a
  name destination with the same bytes; kind 2 matches a name that ends with `.` and the stored name
  and has at least one byte before that `.`; kinds 3 and 4 match an address of their family whose
  first `prefix_len` bits equal the entry's; kind 5 matches any destination that is present. A name
  never matches an address entry and an address never matches a name entry.
- executable: the `class_mask` of the entry whose digest equals the input's, found by binary search.

An empty path, an absent destination or an all-zero executable digest contributes no bits.

**Rows.** Only the run of the input's action class is read. A row matches when its `principal_kind`
is 0 or equals the input's, every bit of `resource_classes` is in the class bits, every bit of
`required_labels` is in the label bits, no bit of `forbidden_labels` is, and it is not lifted. A row
is lifted when its `grant_digest` is not all zero and equals the input's grant digest; a lifted row
does not match. Any matching `deny` row gives `deny`; otherwise any matching `step_up` row gives
`step_up`; otherwise the verdict is `pass`. The verdict's rule index is the position, in the
floor-row section, of the first matching row in table order whose outcome is the verdict, and its
reason code is that row's `reason`. A `pass` names no row.

`pass` is not `ALLOW`: no floor row objects, and the action goes on to the content engine or, if
the engine cannot answer in time, to the class's declared `on_failure` (D-15).

**Cache scope** (design/12 section 8), over every row of the action class's run:

1. `none` for a `step_up` verdict; for an action class above `action_class_count`; when the class's
   bit is set in `session_rule_classes`; or when a row with a non-zero `grant_digest` matched in
   every respect but its grant, whether or not the input lifted it, because a grant can change that
   verdict and a cached `deny` would block the approved retry;
2. otherwise `call` when a row of the run has a non-zero `required_labels` or `forbidden_labels`;
3. otherwise `session` when a row of the run has a non-zero `principal_kind`;
4. otherwise `bundle`.

The verdict's expiry is `expiry_bundle_ns` for `bundle` and `expiry_session_ns` for `session`, where
`0xFFFFFFFFFFFFFFFF` means until the scope ends, and 0 for `call` and `none`, where 0 means the
verdict is never reused. Neither header expiry can be 0 (TV-8), so the two meanings never meet.

## 7. Run-time bounds

- Every walk is bounded by the counts recorded in the header and checked by TV-9 to TV-14.
- Evaluation is O(rows touched): it reads one action class's run, each classifier entry at most
  once, and the executable classifier by binary search.
- The cost of one evaluation is a fixed number of steps, computed from the input and the header
  before any matching, so every implementation counts the same:
  - one step per row of the action class's run;
  - with a path: for each path classifier entry, `(P + 1) * (L + 1)` steps, where `P` is the path's
    length and `L` the pattern's length, both in characters;
  - with a destination: one step per host classifier entry;
  - with a non-zero executable digest: the bit length of the executable classifier's `count` (0 for
    an empty section).
- The sum is computed in saturating 64-bit arithmetic, and an evaluation whose cost exceeds
  `eval_cap` returns `GRDR_E_BUNDLE` without matching, never `pass` and never partial class bits.
- The cost is also a requirement on the matcher: matching one entry makes at most `(P + 1) * (L + 1)`
  character comparisons for every input. A backtracking matcher whose work can exceed that does not
  conform; a matcher that keeps one resume point for the last `*` in a segment and one for the last
  `**` does. The conformance vectors include a pattern of `/` followed by `k` repetitions of `*a` and
  a final `b`, against `/` followed by `n` letters `a`; and a pattern of `k` repetitions of `**/a`
  followed by `/b`, against `n` segments `a`. On both, the counted comparisons stay within the bound
  for every `k` and `n` the test draws.
- The library never copies the blob. It reads the blob and writes only the host's arena, and only in
  `grdr_fp_load`.
- The host's arena size comes from `grdr_fp_arena_size` on the same header: the library computes it
  from the header alone (the section counts and `action_class_count`), and two calls on the same
  header in the same library give the same size. What the arena holds (the table handle and the
  per-action-class row index) is the library's own layout and is not part of this format.

## 8. Labels and grants

Enforcing-label bits and grant digests reach the protected process as `Effect`s from the content
engine (design/26 section 5), as they do in our daemon. The fast path trusts them as given; this is
what that means.

**Label pairing.** Label bits are indexed by the label table of the bundle they were produced under,
so each input carries `labels_bundle_tag`: the first eight bytes of that bundle's digest, read as a
little-endian u64. A tag that differs from the first eight bytes of the loaded table's
`bundle_digest`, read the same way, gives `GRDR_E_STATE` on every call until the labels and the
tables come from the same bundle, so a projection from one bundle is never read against another's
bits.

**Labels.** Whoever supplies the label bits decides every row that reads them. A compromised
sidecar cannot change a row, but it can stop any row that reads labels from objecting, both by
withholding a label a row requires and by setting a label a row forbids. Rows that read no label
are unaffected (design/26, Security and privacy). The fast path cannot tell a forged bit from a
true one; the host's protection is the sidecar's isolation and the cross-check of D-13.

**Grants.** A grant key belongs to a rule, not to an action: an input that carries it lifts that
rule's rows for any action of the class. The fast path checks no signature, expiry, use count,
lineage or action digest. The host therefore passes a non-zero grant digest only for a grant its own
verifier accepted for this exact action, by design/12 section 6 (signed by an accepted key,
unexpired, unspent, bound to this session's lineage and action digest, issued at the current label
epoch), and spends a use when the action proceeds. A grant key taken from an unverified source,
the sidecar included, lifts the rule for every action of its class. Section 6 gives such verdicts
scope `none`, so a grant never reaches a cache.

## 9. Where tables come from

A protected process is its host's tamper anchor and takes policy only from what its own verifier
accepted; the core verifies nothing (design/03 section 3). So:

- The host's privileged service compiles the tables on the device from a bundle its own verifier
  accepted, never the sidecar (R-05). Our own daemon does the same and signs the fast-path and
  fail-safe tables with the device-local artefact key (D-14; design/21's key table).
- Only for an embedded host that cannot compile on the device does the partner's relay pipeline
  (design/26 section 6) compile them, per bundle and per host operating system and architecture,
  signed under the partner's root. Rows that need per-device facts are not compiled there and stay
  in the content engine. A relay has no volume facts, so it sets every bit of `path_fold_classes`,
  which only widens matching.
- The format carries no signature field. A blob from `grdr_engine_compile_fastpath` is unsigned and
  is for unprivileged hosts and tests. A signed blob travels inside its channel's own envelope, and
  section 11 says what the host checks before it loads one.

## 10. Swapping tables and the host's cache

The host loads a new blob into a new arena and publishes it in this order:

1. Install the new interest set in its filters beside the old one, so the union is selected.
2. Swap the one tables pointer atomically.
3. After its own quiescence point, when no `grdr_fp_eval` on the old tables can still be running,
   remove the filter entries only the old interest set had, then free the old blob and arena.

There is no unload call. An arena that live tables use is never passed to `grdr_fp_load`. Pointers
from `grdr_fp_interest` point into the blob and are valid only while it is; the host's filters
keep their own copy of what they need.

A cached verdict belongs to the tables that produced it. The host keys every cache entry by a
generation number it assigns to each tables handle it loads, and reads only entries of the current
generation. A verdict computed against the old tables and inserted after the swap is then never
read, and the cache needs no clearing to be correct.

## 11. Host obligations

The library cannot check these; a host that skips one loses the property the section names.
`c-abi.md` states each at the function it concerns.

- **Custody.** The bytes the host verified are the bytes it loads: it reads the blob once into
  private memory that no less privileged process can write, checks the envelope over that copy, and
  keeps the copy unchanged until it frees the blob. It never loads from a file or a shared mapping
  that can change after the check.
- **Binding.** Before it loads, the host checks that the envelope names its own operating system and
  architecture, that `bundle_digest` equals the digest of the bundle its verifier accepted (the one
  its content engine runs), and that the envelope's sequence number is not lower than the one it
  holds, so neither an older bundle nor an older compile of the same bundle replaces newer tables.
- **Cap.** The host refuses a blob whose `eval_cap` exceeds its own ceiling, taken from its
  configuration, so a blob cannot raise the latency it accepts.
- **Path form.** The target path is that of the object the OS resolved, in the canonical form of
  design/13 section 8's path canonicaliser: symbolic links and junctions resolved; on Windows the
  final long name, with no short 8.3 name, no trailing dot or space, no `\\?\` or other alternate
  prefix, and no stream suffix, so a named or default stream is judged as its file; `/` separators,
  starting with `/`, with no empty, `.` or `..` segment and no trailing `/`; and Unicode
  normalisation form C. On a case-insensitive volume the host also writes every character that the
  volume's own case mapping makes equal to an ASCII letter as that letter in lower case. With the
  ASCII folding of fold classes, an ASCII pattern then matches every name the volume treats as
  equal to it.
- **Destination form.** A name destination is in the canonical form of section 3.3, which design/13
  section 8's host classifier also produces. A name the WHATWG IPv4 parser reads as an address
  (decimal, octal or hexadecimal parts) is passed as an IPv4 destination, never as a name. An IPv6
  destination the host knows to carry an IPv4 address under a prefix other than the two the
  library converts (the local-use NAT64 prefix of RFC 8215, or a network-specific prefix of RFC 6052
  that the network uses) is passed as that IPv4 address. The deprecated IPv4-compatible form is
  matched as IPv6, as in the engine.
- **Labels and grants.** As section 8.
- **Cache and swap.** As section 10.

## 12. Versioning

`table_format` 1 is this document; it is experimental under D-60. Its layout never grows: no field,
section, kind value or meaning is added to format 1. `abi_min` rises within format 1 only when the
blob uses an action class that only a later fast-path ABI carries. A new section, field, kind or
meaning is a new `table_format` value, decided by RFC (design/30 section 3), whose blobs carry the
`abi_min` of the first library that reads them. The stable prefix of section 2 never changes, so a
library that meets a newer blob refuses it with `GRDR_E_ABI` (TV-3) when the blob needs a newer
library, and with `GRDR_E_BUNDLE` (TV-4) when the format is one it does not read, rather than
misreading it.

## 13. What the compiler does beyond the rules

The library cannot check these, so the compiler holds them and its tests prove them (#414):

- It writes the canonical form of section 4, with every pattern in normalisation form C.
- It writes `eval_cap` from `fastpath.eval_cap_steps` and refuses to compile, naming that key, when
  the worst-case cost of section 7 for any action class exceeds it, taking `P` as `path_max_units`.
  A blob it wrote therefore never reaches the cap; the run-time check holds blobs from anywhere
  else.
- It writes an interest set that selects every action a floor row can match. A row naming `Session`
  is covered by a process scope that selects every session the bundle's catalogue opens. For any
  other row, each path classifier entry of a class the row requires is also an interest path, each
  host classifier entry such a class uses is also an interest host with the same ports, and each
  executable digest is also a kind 1 process-scope entry. A row that requires no resource class is
  covered by match-all entries: the path pattern `**`, a kind 2 process-scope pattern `**`, and a
  kind 5 interest host over every port.
- It resolves templates from the device facts and escapes `*`, `?` and `\` in each resolved value,
  so a directory name holding one stays literal. A pattern whose template has no device-wide value
  (`$WORKSPACE`, `$SESSION_TMP`) is not compiled, and the floor report lists its rule.
- It maps every host entry the engine's host classifier accepts onto one of the five kinds (an
  address in any accepted form becomes kind 3 or 4), and every path pattern the engine accepts onto
  the grammar of section 3.2, so it never writes an entry TV-20 to TV-22 would reject. An entry it
  cannot map is not compiled, and the floor report lists its rule.
- It drops, and lists in the floor report, a row TV-31 or TV-32 would reject: one whose label
  conditions contradict each other, or one that needs a class no entry sets. Neither row can match,
  so dropping it changes no verdict.
- A rule that needs more than 64 resource classes or 64 labels is not compiled, never truncated,
  and the floor report lists it.
- It sets a class's bit in `path_fold_classes` when any volume the class's patterns can reach on the
  device is case-insensitive; a pattern starting with `**` reaches every volume. The engine folds
  per input path from the volume it lies on; the fast-path input carries no such mark (design/26
  section 2), so the floor folds per class. Given the path form of section 11, a fold class matches
  every name the volume treats as equal to an ASCII pattern, and on a case-sensitive volume it can
  match more names than the volume would. It never matches fewer, and floor rows only forbid, so
  folding errs toward `deny`. A fold-class entry with a non-ASCII literal, which ASCII folding
  cannot decide, is not compiled and is listed.

## 14. Data classes

| Part | Class (P8) |
|---|---|
| Header, floor rows (masks, kinds, outcomes, indices), port ranges | `structural` |
| `bundle_digest`, `effective_hash`, grant digests, executable and process-scope digests | `identifier` (design/04: digests of public artefacts) |
| Reason-code table and its strings; host names; signing and package identities | `structural` (pack and catalogue data) |
| Path patterns with no resolved template (path classifier, interest paths, process-scope kind 2) | `structural` (pack data) |
| Path patterns holding a template the compiler resolved from the device facts | `content` (`content_kind` argument): a home directory can carry an account name |

A string in the pool takes the class of the record field that references it. A device-compiled blob
that holds a resolved template is therefore handled as `content`: it is never logged and never
leaves the device, which R-05 already requires. A relay-compiled blob holds no resolved template.
