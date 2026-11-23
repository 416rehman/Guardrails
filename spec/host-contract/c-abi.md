<!-- SPDX-License-Identifier: Apache-2.0 OR CC-BY-4.0 -->

# The two C interfaces

This document fixes the two C interfaces a host links: `grdr_fastpath.h`, the fast path a
protected process calls (crate `grdr-fastpath-ffi`), and `grdr.h`, the content engine's C ABI
(crate `grdr-ffi`). It gives every function's signature, contract and status codes, the struct
layouts, and the memory, threading, transaction, panic and version rules. It specifies design/26
sections 2 (C interface) and 3 (C ABI, Memory ownership, Threading, Error model, Versioning) and
ruling R-22. The status codes are data in `status-codes.toml`; the table blob `grdr_fp_load` reads
is `tables.md`.

Spine: D-05, D-09, D-15, D-41, D-60, D-71, P5, P9, P14. The generated headers of EM-2 and EM-4 are
diffed against this text, declaration by declaration and offset by offset, as RFC 0004 section 5
describes (design/03 section 7).

## 1. Common rules

- **Status.** `typedef uint32_t grdr_status;`. Every function returns `grdr_status` except the
  version, string and free functions. The values are the rows of `status-codes.toml`, and both
  headers define the type and the constants behind the same include guard, `GRDR_STATUS_DEFINED`,
  so a host can include both.
- **Outputs on failure.** A function that returns anything but `GRDR_OK` writes no output argument:
  no verdict field, no view, no blob header, no buffer, no handle.
- **Pointers.** A null pointer where the contract needs one returns `GRDR_E_ARG`. A null pointer with
  a zero length is an empty input.
- **`struct_size`.** Every input struct starts with `uint32_t struct_size`, which the caller sets to
  `sizeof` the struct it was compiled with. A minor ABI version adds functions and trailing fields
  only. A `struct_size` below the struct's base size (the fields of the minor that introduced it),
  or one that ends inside a field, returns `GRDR_E_ARG`. A trailing field the caller's `struct_size`
  does not cover takes its stated default. A `struct_size` larger than the library knows is accepted
  and its extra bytes are not read, so a caller that depends on a field added in minor `m` calls the
  version check of its interface for `m` first.
- **Output structs** (`grdr_fp_verdict`, `grdr_fp_interest_view`, `grdr_fp_blob_header`,
  `grdr_buf`) carry no `struct_size` and never change within a major. More output in a minor
  arrives through a new function.
- **Versions.** `grdr_fp_abi_version` and `grdr_abi_version` return `major << 16 | minor`. The two
  interfaces are versioned apart, because `libgrdr_fastpath` and `grdr-ffi` are separate artefacts.
- **Numbers.** The action class is the number of `grdr.common.v1alpha1.ActionClass`, which follows
  spine section 3: `exec` 1, `file.read` 2, `file.write` 3, `file.delete` 4, `net.connect` 5,
  `net.request` 6, `llm.request` 7, `mcp.connect` 8, `mcp.call` 9, `cred.use` 10, `agent.spawn` 11,
  `config.change` 12, `elevate` 13, `ui.act` 14, `data.flow` 15; 0 is unspecified. The principal
  kind is the Cedar principal type a floor row can name (design/12 section 2): `Session` 1,
  `Process` 2. It is not `Principal.kind` of design/04 section 2.

## 2. Fast path: `grdr_fastpath.h`

The header declares its structs between `#pragma pack(push, 8)` and `#pragma pack(pop)`, so a host
that compiles with a smaller packing still gets the layout of this section. Generated compile-time
layout assertions sit in `include/grdr_fastpath_layout.c` and `src/grdr_fastpath_abi.rs` for every
supported target on `surfaces.toml` (RFC 0004 sections 6 and 11).

```c
typedef struct grdr_fp_tables grdr_fp_tables;   /* opaque; lives in the host's writable, address-pinned arena */

uint32_t    grdr_fp_abi_version(void);
grdr_status grdr_fp_blob_info(const uint8_t *blob, size_t len, grdr_fp_blob_header *out);
grdr_status grdr_fp_arena_size(const uint8_t *blob, size_t len, size_t *out);
grdr_status grdr_fp_load(const uint8_t *blob, size_t len, void *arena, size_t arena_len,
                         const grdr_fp_tables **out);
grdr_status grdr_fp_eval(const grdr_fp_tables *t, const grdr_fp_input *in,
                         grdr_fp_verdict *out);
grdr_status grdr_fp_interest(const grdr_fp_tables *t, grdr_fp_interest_view *out);
```

Although `grdr_fp_eval` and `grdr_fp_interest` take `const grdr_fp_tables *t`, the arena holding the
tables handle MUST stay writable by the host's process (never mapped read-only), address-pinned, and
unshared at another address because either call makes one atomic store with release ordering to the
handle record's sticky changed flag when returning `GRDR_E_CHANGED`.

| Function | Contract | Returns |
|---|---|---|
| `grdr_fp_abi_version` | The fast-path ABI as `major << 16 \| minor`. This document is 0.1 | No status |
| `grdr_fp_blob_info` | Checks its arguments (`blob` and `out` non-null, `blob` 8-aligned, `len` at most `PTRDIFF_MAX`, `out` disjoint from `blob`), applies TV-1 to TV-14 of `tables.md` to the blob header, and writes the fixed 64-byte header summary into `*out` on `GRDR_OK` only | `GRDR_OK`; `GRDR_E_ARG` (null pointer, `blob` not 8-aligned, `len` above `PTRDIFF_MAX`, or `out` overlapping `blob`); `GRDR_E_ABI` (TV-3); `GRDR_E_BUNDLE` (any other TV-1 to TV-14 rule) |
| `grdr_fp_arena_size` | Checks its arguments (`blob` and `out` non-null, `blob` 8-aligned, `len` at most `PTRDIFF_MAX`, `out` disjoint from `blob`), applies TV-1 to TV-14 of `tables.md` to the header and writes the arena size the blob and handle record need | `GRDR_OK`; `GRDR_E_ARG` (null pointer, `blob` not 8-aligned, `len` above `PTRDIFF_MAX`, or `out` overlapping `blob`); `GRDR_E_ABI` (TV-3); `GRDR_E_BUNDLE` (any other TV-1 to TV-14 rule) |
| `grdr_fp_load` | Checks its arguments (non-null pointers, `blob` and `arena` 8-aligned, `len` and `arena_len` at most `PTRDIFF_MAX`, `blob` and `arena` disjoint, `out` disjoint from both, `arena_len` at least the arena size), applies TV-1 to TV-14, applies TV-15 to TV-33, then builds the handle record and run indices in the arena and writes a table handle that points into it. The host keeps the blob and the whole arena, the tables handle included, in memory no less privileged process can write and its own process can (writable, address-pinned, never mapped read-only or shared at another address), unchanged from `grdr_fp_load` until its quiescence point after it retires the tables, except for the fast path's own atomic flag store (sections 4 and 5). It never copies the blob and touches no memory but the blob, the arena and its own stack | `GRDR_OK`; `GRDR_E_ARG` (null pointer, `blob` or `arena` not 8-aligned, byte length above `PTRDIFF_MAX`, overlapping ranges, or `arena_len` below the arena size); `GRDR_E_ABI` (TV-3); `GRDR_E_BUNDLE` (TV-1, TV-2 or TV-4 to TV-33) |
| `grdr_fp_eval` | Deterministic while the blob and arena are unchanged: checks its arguments and handle record, copies the covered input fields once, verifies label pairing and checks remaining field/length/overlap/unresolved bounds before evaluating (`tables.md` section 6). Callable concurrently from any number of threads on the same tables | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_STATE`; `GRDR_E_BUNDLE` (cost exceeds `eval_cap`); `GRDR_E_CHANGED` |
| `grdr_fp_interest` | Checks `t` and `out` non-null, verifies the handle record before reading its addresses, verifies `out` is disjoint from the checked blob and arena ranges, and writes pointers into the blob: the process scope, path, host and port tables of `tables.md` section 3.5, and the string pool their entries refer to. Deterministic while the blob and arena are unchanged and callable concurrently on the same tables | `GRDR_OK`; `GRDR_E_ARG` (null pointer or `out` overlapping the blob or arena); `GRDR_E_CHANGED` |

Across all six fast-path functions, pointer and address checks run before any dereference through
the checked pointer, the handle record's flag and integrity check copy pass before any read through
the record's addresses, and every length bound is checked before any slice is formed (`PTRDIFF_MAX`
is the largest permitted byte length for `blob`, `arena`, `path` bytes including checked `path_len * 2`
for UTF-16LE, and `dest_name`, and `253` is the maximum `dest_name_len`). Overlapping `blob` and
`arena`, any output parameter overlapping `blob` or `arena`, or any input struct (`grdr_fp_input`) or
input byte buffer (`path`, `dest_name`) overlapping `arena` returns `GRDR_E_ARG`.

`grdr_fp_eval` checks in this order and stops at the first failure:

1. A null pointer (`t`, `in` or `out` is null): `GRDR_E_ARG`.
2. The handle record's sticky changed flag (acquire load), followed by one checked copy of the rest
   of the handle record into a local (verifying the stored address equals `t` and recomputing the
   32-byte check word over its fields). On failure, sets the sticky changed flag by one atomic store
   (release) if the copy's stored address equals `t` and returns `GRDR_E_CHANGED`. Nothing is read
   through any address the record holds until this copy passes, and the call reads the record only
   through the copy.
3. Address checks against the checked copy's blob and arena ranges (`out` overlaps the blob or arena,
   or `in`'s base-size range overlaps the arena), then `in->struct_size` below the base size,
   ending inside a field, or covering a range that overlaps the arena: `GRDR_E_ARG`.
4. One copy of the input struct's covered fields into local storage before any further check, so each
   field is read once from host memory.
5. Label pairing (`check_pairing`): a failed storage re-check RC1 returns `GRDR_E_CHANGED`; otherwise
   a `labels_bundle_tag` differing from the first eight bytes of the tables' `bundle_digest` (both
   read as little-endian `u64`) returns `GRDR_E_STATE` on every call until labels and tables agree.
6. Remaining argument, length, range and syntactic form checks (`GRDR_E_ARG`), with every length
   checked before any slice is formed: `action_class` is `0` or above the highest class the library's
   ABI carries (`15` at ABI 0.1); `principal_kind` is `0` or above `principal_kind_count`; `path_encoding`
   is outside `{1, 2}` when `path_len` is non-zero; `dest_kind` is above `3`; `unresolved` holds any
   bit outside `{1, 2, 4}` or sets a bit whose corresponding value in the struct is non-absent
   (`path_len` non-zero, `dest_kind` non-zero, or non-zero `exe_digest`); for a resolved path
   (`path_len > 0`), null `path`, `path_len` above `path_max_units`, byte length above `PTRDIFF_MAX`
   (including `path_len * 2` overflow for UTF-16LE), `path` bytes overlapping the arena, or a path
   outside the library's syntactic canonical form (`tables.md` section 6: valid UTF-8 or even-length
   UTF-16LE with no unpaired surrogate or U+0000, starting with `/`, no empty, `.` or `..` segment,
   and no trailing `/`); for a resolved name destination (`dest_kind == GRDR_FP_DEST_NAME`), null
   `dest_name`, empty or `dest_name_len` above `253` or `PTRDIFF_MAX`, `dest_name` overlapping the
   arena, or a name outside the canonical form of `tables.md` section 3.3 and `TV-21`.
7. Vocabulary ceiling check (`tables.md` section 6): an `action_class` within the ABI (`<= 15`) but
   above the tables' `action_class_count` returns `GRDR_FP_PASS` with `cache_scope`
   `GRDR_FP_CACHE_NONE`, `rule_index` `UINT32_MAX`, `reason_code` `UINT32_MAX` and `expiry_ns` `0`,
   with no cost check and no read of the blob or arena.
8. Cost check (`tables.md` section 7): a failed re-check of what the cost reads returns
   `GRDR_E_CHANGED` before any cap result; a cost that exceeds `eval_cap` returns `GRDR_E_BUNDLE`,
   never `pass`.
9. Evaluation (`tables.md` section 6): class-bit computation and floor-row matching, where any failed
   re-check at first read of what it guards returns `GRDR_E_CHANGED`.

### 2.1 `grdr_fp_input`

Fields in the order design/26 section 2 gives, with `uint32_t unresolved` declared after
`dest_port`. Offsets below are for 64-bit targets (`wasm32` base size is 144); another 32-bit target
lays out the same declaration under its own C ABI (on i386 System V, where `uint64_t` aligns to 4
inside a struct, `unresolved` shifts later fields and the base size is 144). Fast-path ABI 0.1 is
unpublished until this specification lands, so `unresolved` at offset 108 belongs to ABI 0.1's base
size of 160 bytes and no host built to 0.1 lacks it; after publication, additions go only at the end
of the struct behind `struct_size`.

```c
typedef struct grdr_fp_input {
    uint32_t       struct_size;        /*   0 [structural] */
    uint16_t       action_class;       /*   4 [structural] ActionClass number, section 1 */
    uint16_t       principal_kind;     /*   6 [structural] Session 1, Process 2 */
    uint64_t       process_key;        /*   8 [identifier] the host's stable process identifier */
    uint8_t        exe_digest[32];     /*  16 [identifier; binary] all zero: none supplied, unless unresolved says it could not be resolved */
    const void    *path;               /*  48 [content, argument; encoding in path_encoding, no terminator] already resolved by the host */
    size_t         path_len;           /*  56 [structural] code units of path_encoding; 0: no path */
    uint32_t       path_encoding;      /*  64 [structural] GRDR_FP_PATH_UTF8 1, GRDR_FP_PATH_UTF16LE 2 */
    uint32_t       dest_kind;          /*  68 [structural] NONE 0, NAME 1, IPV4 2, IPV6 3 */
    const uint8_t *dest_name;          /*  72 [identifier; UTF-8, no terminator] dest_kind 1: canonical name, no terminator */
    size_t         dest_name_len;      /*  80 [structural] bytes */
    uint8_t        dest_addr[16];      /*  88 [identifier; network byte order] dest_kind 2 and 3: network order */
    uint16_t       dest_port;          /* 104 [structural] 0 when the action has no port */
    uint32_t       unresolved;         /* 108 [structural] bitmask of GRDR_FP_UNRESOLVED_*; 0: none unresolved */
    uint64_t       label_bits;         /* 112 [derived] enforcing-label projection from the engine */
    uint64_t       labels_bundle_tag;  /* 120 [identifier] first eight bytes of that bundle's digest */
    uint8_t        grant_digest[32];   /* 128 [identifier; binary] all zero: no grant */
} grdr_fp_input;                       /* 160 bytes; the base size of fast-path ABI 0.1 */
```

Before populating fields, the caller zero-initialises the entire `grdr_fp_input` struct so implicit
padding bytes (bytes 106 and 107 on 64-bit targets) and any future trailing fields start zeroed, and
sets `struct_size` to the struct size (`memset(&in, 0, sizeof(in)); in.struct_size = (uint32_t)sizeof(in);`,
or C23 `{0}` followed by setting `in.struct_size`). When `path_len` is 0, `path` and `path_encoding`
are not read.

The `unresolved` bitmask uses `GRDR_FP_UNRESOLVED_PATH` (`1u`) for the target path,
`GRDR_FP_UNRESOLVED_DEST` (`2u`) for the destination, and `GRDR_FP_UNRESOLVED_EXE` (`4u`) for the
executable digest. Setting a bit requires its corresponding value in the struct to be absent
(`path_len` 0, `dest_kind` 0, or an all-zero `exe_digest`); any unknown bit, or a set bit paired
with a non-absent value, returns `GRDR_E_ARG`. A host that has a path, destination or executable
digest it could not resolve, or cannot pass in the form this section and `tables.md` sections 3.3
and 6 state (such as a path exceeding `path_max_units`, a destination name it cannot normalise, or
an executable it could not hash), sets its bit in `unresolved` and passes the absent form, never an
absent input (`tables.md` section 11).

The path is the host's resolved path in the canonical form of `tables.md` sections 6 and 11, UTF-8
or UTF-16LE, read code unit by code unit at any alignment. An IPv4 destination uses
`dest_addr[0..4]`. Fields a `dest_kind` does not use are not read. The fast path reads `process_key`
for no row (design/12 section 8); it is in the input so the host and the engine name the same process.

### 2.2 `grdr_fp_verdict`

```c
typedef struct grdr_fp_verdict {
    uint32_t verdict;       /*  0 [derived] GRDR_FP_PASS 1, GRDR_FP_DENY 2, GRDR_FP_STEP_UP 3 */
    uint32_t rule_index;    /*  4 [structural] index of the winning floor row; UINT32_MAX for pass */
    uint32_t reason_code;   /*  8 [structural] index into the reason-code table; UINT32_MAX for pass */
    uint32_t cache_scope;   /* 12 [structural] NONE 0, CALL 1, SESSION 2, BUNDLE 3 */
    uint64_t expiry_ns;     /* 16 [structural] nanoseconds from the call; 0: never reused; UINT64_MAX: until the scope ends */
} grdr_fp_verdict;          /* 24 bytes */
```

No verdict is 0, so a host that reads a verdict it never received sees an invalid value, not
`pass`. Scope `none` is 0, so the same mistake never caches. The scope and expiry rules are those of
`tables.md` section 6. A host caches a floor verdict only under its scope, keyed by the generation of
the tables that gave it (`tables.md` section 10) and the input's resource identity: action class,
path, destination, executable digest and the `unresolved` bits, plus the principal kind and session
for `session`. A verdict over an unresolved value has scope `none` and is never inserted, so an
input with an `unresolved` bit set never meets a cached verdict. A `step_up` verdict also carries
`cache_scope` `GRDR_FP_CACHE_NONE` (0) and `expiry_ns` `0`.

**`pass` is not `ALLOW`.** It means no floor row objects. The action goes on to the content engine
or, if the engine cannot answer in time, to the class's declared `on_failure` (D-15).

### 2.3 `grdr_fp_interest_view`

```c
typedef struct grdr_fp_span {
    const uint8_t *ptr;         /*  0 [structural; binary] first record, inside the blob */
    uint32_t       count;       /*  8 [structural] records */
    uint32_t       record_size; /* 12 [structural] bytes per record, as tables.md section 3 */
} grdr_fp_span;                 /* 16 bytes */

typedef struct grdr_fp_interest_view {
    grdr_fp_span   process_scope;  /*  0 [structural] */
    grdr_fp_span   paths;          /* 16 [structural] */
    grdr_fp_span   hosts;          /* 32 [structural] */
    grdr_fp_span   ports;          /* 48 [structural] */
    const uint8_t *strings;        /* 64 [structural; binary] string pool the entries' offsets count from */
    size_t         strings_len;    /* 72 [structural] */
} grdr_fp_interest_view;           /* 80 bytes */
```

The pointers stay valid as long as the blob does. An empty table has `ptr` null and `count` 0, and
an empty string pool has `strings` null and `strings_len` 0.

### 2.4 Constants

The header defines the fast-path ABI version it describes and a name for every value section 2
gives a field. A host that compiled against major `M` and minor `m` loads the library only when
`grdr_fp_abi_version() >> 16 == M` and `(grdr_fp_abi_version() & 0xFFFF) >= m`; the same major
and an equal or later minor. `GRDR_FP_ABI_VERSION` is the packed value the host compiled with.

```c
#define GRDR_FP_ABI_MAJOR 0u
#define GRDR_FP_ABI_MINOR 1u
#define GRDR_FP_ABI_VERSION ((GRDR_FP_ABI_MAJOR << 16) | GRDR_FP_ABI_MINOR)
#define GRDR_FP_PATH_UTF8 1u
#define GRDR_FP_PATH_UTF16LE 2u
#define GRDR_FP_DEST_NONE 0u
#define GRDR_FP_DEST_NAME 1u
#define GRDR_FP_DEST_IPV4 2u
#define GRDR_FP_DEST_IPV6 3u
#define GRDR_FP_PASS 1u
#define GRDR_FP_DENY 2u
#define GRDR_FP_STEP_UP 3u
#define GRDR_FP_CACHE_NONE 0u
#define GRDR_FP_CACHE_CALL 1u
#define GRDR_FP_CACHE_SESSION 2u
#define GRDR_FP_CACHE_BUNDLE 3u
#define GRDR_FP_UNRESOLVED_PATH 1u
#define GRDR_FP_UNRESOLVED_DEST 2u
#define GRDR_FP_UNRESOLVED_EXE 4u
```

### 2.5 `grdr_fp_blob_header`

Fixed 64-byte output struct returned by `grdr_fp_blob_info` after TV-1 to TV-14 pass on the blob
header, allowing a C host to verify `bundle_digest`, host `eval_cap` and `path_max_units` ceilings,
`abi_min` and `loss_closed_classes` from its private copy of the blob before calling `grdr_fp_load`
(`tables.md` section 11). Like every output struct (section 1), it carries no `struct_size` and
never changes within a major version.

```c
typedef struct grdr_fp_blob_header {
    uint8_t  bundle_digest[32];    /*  0 [identifier; binary] digest of the bundle compiled into the blob */
    uint64_t labels_bundle_tag;    /* 32 [identifier] first eight bytes of bundle_digest, little-endian u64 */
    uint64_t loss_closed_classes;  /* 40 [structural] bitmask of classes closed when the floor cannot answer */
    uint32_t eval_cap;             /* 48 [structural] per-call evaluation cost cap */
    uint32_t path_max_units;       /* 52 [structural] maximum target path length in encoding code units */
    uint32_t table_format;         /* 56 [structural] table blob format number (1 for this spec) */
    uint32_t abi_min;              /* 60 [structural] minimum fast-path ABI minor version required */
} grdr_fp_blob_header;             /* 64 bytes */
```

## 3. Engine: `grdr.h`

The header declares its structs between `#pragma pack(push, 8)` and `#pragma pack(pop)`, so a host
that compiles with a smaller packing still gets the layout of this section. Generated compile-time
layout assertions sit in `include/grdr_layout.c` and `src/grdr_abi.rs` for every supported target on
`surfaces.toml` (RFC 0004 sections 6 and 11).

```c
typedef struct grdr_engine grdr_engine;   /* opaque */

typedef struct grdr_buf {
    uint8_t *ptr; /*  0 [structural; binary] */
    size_t   len; /*  8 [structural] */
} grdr_buf;       /* 16 bytes on 64-bit */

typedef struct grdr_engine_config {
    uint32_t struct_size;                                              /*  0 [structural] */
    void *(*alloc)(void *ctx, size_t size, size_t align);              /*  8 [structural] */
    void *(*realloc)(void *ctx, void *ptr, size_t old_size, size_t align,
                     size_t new_size);                                 /* 16 [structural] */
    void  (*free)(void *ctx, void *ptr, size_t size, size_t align);    /* 24 [structural] */
    void    *alloc_ctx;                                                /* 32 [structural; not read by the library] */
    uint64_t memory_cap;                                               /* 40 [structural] bytes */
    uint64_t step_budget;                                              /* 48 [structural] rule evaluations per call */
} grdr_engine_config;                                                  /* 56 bytes on 64-bit */

uint32_t    grdr_abi_version(void);
const char *grdr_engine_version(void);
grdr_status grdr_abi_check(uint16_t major, uint16_t min_minor);
grdr_status grdr_engine_new(const grdr_engine_config *cfg, grdr_engine **out);
grdr_status grdr_engine_load(grdr_engine *e, const uint8_t *bundle, size_t bundle_len,
                             const uint8_t *host_profile, size_t host_profile_len,
                             grdr_buf *report);
grdr_status grdr_engine_step(grdr_engine *e, const uint8_t *input, size_t input_len,
                             int64_t now_unix_ns, const uint8_t entropy[32], grdr_buf *output);
grdr_status grdr_engine_interest(grdr_engine *e, const uint8_t *session_id,
                                 size_t session_id_len, grdr_buf *out);
grdr_status grdr_engine_compile_fastpath(grdr_engine *e, grdr_buf *tables);
grdr_status grdr_engine_snapshot(grdr_engine *e, grdr_buf *state);
grdr_status grdr_engine_restore(grdr_engine *e, const uint8_t *bundle, size_t bundle_len,
                                const uint8_t *host_profile, size_t host_profile_len,
                                const uint8_t *state, size_t state_len);
void        grdr_buf_free(grdr_buf *buf);
void        grdr_engine_free(grdr_engine *e);
const char *grdr_status_str(grdr_status s);
grdr_status grdr_engine_last_error(grdr_engine *e, grdr_buf *diagnostic);
```

`grdr_engine_config`'s base size is 4 (`struct_size` alone). A caller zero-initialises the struct
(`memset(&cfg, 0, sizeof(cfg))`) before setting `struct_size` to `sizeof(cfg)` and any fields it
supplies, so implicit padding (bytes 4 to 7 on 64-bit) and omitted fields stay deterministic. A
`struct_size` that covers some but not all of `alloc`, `realloc`, `free` and `alloc_ctx` returns
`GRDR_E_ARG`, as does a set with one function null and another not. Uncovered or zero `memory_cap`
and `step_budget` take the defaults the library was built with from its `limits.toml` rows; uncovered
or null allocator fields mean the library's own allocator. Which minor first exports each function
and each trailing field (and the matching `GRDR_ABI_MAJOR`, `GRDR_ABI_MINOR` and `GRDR_ABI_VERSION`
constants, RFC 0004 section 9) is set by the engine-boundary RFC (#378); this document fixes their
signatures and contracts.

**Handle states.** A handle is in one of three states, an explicit type in `grdr-ffi` (#388 R4):

| State | Entered by | Calls allowed | Exit |
|---|---|---|---|
| `Created` | `grdr_engine_new` | `load`, `restore`, `last_error`, `free`; `step`, `interest`, `compile_fastpath` and `snapshot` return `GRDR_E_STATE` | `Loaded` on a successful `load` or `restore`; `free` |
| `Loaded` | A successful `load` or `restore` | Every function | `Loaded` on another successful `load` or `restore`; `Poisoned` on `GRDR_E_INTERNAL`; `free` |
| `Poisoned` | `GRDR_E_INTERNAL` | `last_error` and `free`; every other call returns `GRDR_E_POISONED` | `free`, then `new` and `restore` from the host's last persisted snapshot |

| Function | Contract | Returns |
|---|---|---|
| `grdr_abi_version` | The engine C ABI as `major << 16 \| minor` | No status |
| `grdr_engine_version` | The engine's semver as a static NUL-terminated string; never freed | No status |
| `grdr_abi_check` | `GRDR_OK` when the library's major equals `major` and its minor is at least `min_minor`. Needs no handle, so it fails before any handle exists | `GRDR_OK`; `GRDR_E_ABI` |
| `grdr_engine_new` | Validates `cfg` and writes a handle in `Created` | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_RESOURCE` |
| `grdr_engine_load` | `bundle` is the bytes of a verified bundle: the caller asserts it was verified, and this is the documented FFI entry ARCH-012 allows to construct a `VerifiedBundle`. `host_profile` is an encoded `grdr.embed.v1alpha1.HostProfile`. On success the engine uses the new pair and `report` holds an encoded `LoadReport`, listing skipped constructs and `not_evaluable` rules | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_BUNDLE` (undecodable or rejected bundle; the previous bundle stays); `GRDR_E_PROFILE` (undecodable or invalid profile; the previous profile stays); `GRDR_E_RESOURCE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` |
| `grdr_engine_step` | `input` is an encoded `grdr.embed.v1alpha1.Input`; `output` an encoded `Output`. The 32 `entropy` bytes seed a deterministic generator in `grdr_core::engine::boundary` for this call only, so a recorded seed replays exactly. Seed reuse is not detected by the library and yields repeated `Random128` identifiers, so the host must supply unique bytes per call | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_DECODE`; `GRDR_E_RESOURCE`; `GRDR_E_BUDGET`; `GRDR_E_STATE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` |
| `grdr_engine_interest` | The interest set for the bundle (empty `session_id`) or for one session, named by its id's string form (design/04 section 3) | `GRDR_OK`; `GRDR_E_ARG` (also a session the engine does not hold); `GRDR_E_STATE`; `GRDR_E_RESOURCE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` |
| `grdr_engine_compile_fastpath` | The unsigned table blob of `tables.md` for the loaded bundle using `Facts::Relay` and `FastpathLimits::from_limits()`; for unprivileged hosts and tests (`tables.md` section 9) | `GRDR_OK`; `GRDR_E_ARG` (null pointer, or refused narrowing once a limits input exists); `GRDR_E_STATE`; `GRDR_E_BUNDLE` (exceeds a blob format bound, worst-case cost exceeds `eval_cap`, or underlying `EffectiveCompileError` bundle fault; the loaded bundle stays); `GRDR_E_RESOURCE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` (invalid built-in limits or consistency check failure) |
| `grdr_engine_snapshot` | An encoded `EngineState` the host persists | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_STATE`; `GRDR_E_RESOURCE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` |
| `grdr_engine_restore` | Takes the same bundle and profile as `load` and the state bytes, as `Engine::restore` does (design/03 section 3), and replaces the handle's engine on success | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_DECODE` (undecodable state or unknown state format); `GRDR_E_BUNDLE`; `GRDR_E_PROFILE`; `GRDR_E_STATE` (state from another bundle); `GRDR_E_RESOURCE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` |
| `grdr_buf_free` | Frees `buf->ptr` and sets `buf` to `{NULL, 0}`; any thread may call it; a zeroed or null `buf` does nothing. A second free of a copy of the same buffer is undefined, as with `free` | No status |
| `grdr_engine_free` | Frees the handle in any state; null does nothing. Buffers it returned stay valid until `grdr_buf_free` | No status |
| `grdr_status_str` | A static NUL-terminated string: the code's `name` in `status-codes.toml`, or its `unknown_name` for a number with no row. Identifiers only; person-facing text comes from language tokens (D-69) | No status |
| `grdr_engine_last_error` | An encoded `grdr.embed.v1alpha1.Diagnostic` for the last failed call on this handle, in any state, or an empty buffer if no call has failed. A successful call does not clear it | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_RESOURCE` |

## 4. Memory ownership

- Inputs are borrowed for the duration of the call and never retained. For the fast path, the host
  keeps each input struct, and the memory its `path` and `dest_name` pointers reach, in memory no
  less privileged process can write, unchanged until the call returns. The fast path reads each field
  of an input struct once, before any check.
- Outputs are `grdr_buf { uint8_t *ptr; size_t len; }`, owned by the library until `grdr_buf_free`,
  which any thread may call.
- When the host supplies allocator callbacks, every engine allocation goes through them, buffers
  included. The callbacks and `alloc_ctx` stay valid until the handle is freed and every buffer it
  returned is freed, and they are callable from any thread that frees a buffer. A callback that
  returns null fails the call with `GRDR_E_RESOURCE`.
- The memory cap in `grdr_engine_config` applies with and without host callbacks. Reaching it
  returns `GRDR_E_RESOURCE` with the state unchanged.
- The fast path allocates nothing. It reads the blob, the input and what the input points to,
  writes the arena in `grdr_fp_load` only, and after `grdr_fp_load` writes only the handle record's
  sticky changed flag inside the arena by one atomic store (release ordering) when returning
  `GRDR_E_CHANGED` in `grdr_fp_eval` or `grdr_fp_interest` (when the checked copy's stored address
  equals `t`). Otherwise it writes only its output struct and touches no memory but its own stack.
  The host keeps the blob and the whole arena, the tables handle included, in memory no less
  privileged process can write and its own process can (never mapped read-only, address-pinned, and
  unshared at another address), unchanged from `grdr_fp_load` until its quiescence point after it
  retires the tables, except for that atomic flag store.

## 5. Threading

- A `grdr_engine` is used by one thread at a time: Rust `Send`, not `Sync`. The host serialises
  calls on one handle.
- The engine creates no threads and holds no thread-local or global mutable state, so several
  handles in one process are independent.
- `grdr_fp_eval` and `grdr_fp_interest` are deterministic while the blob and arena are unchanged and
  callable concurrently from any number of threads on the same tables. `grdr_fp_load` writes only
  its own arena, which no live tables may use (`tables.md` section 10).

## 6. Status codes

`status-codes.toml` holds one `[[status]]` row per code with its `name`, `value`, `meaning` and
`handle_after`, and the headers are generated from it or tested against it (EM-2, EM-4). Numbers are
never reused: a retired code keeps its row with `retired = true`, and a new code takes the next free
value. A new code, like a new function or field beyond design/26 sections 2 and 3, is an RFC (D-60).

The fast path uses five of them: `GRDR_E_ARG` for a null pointer, a misaligned blob or arena,
overlapping blob/arena/input/output ranges, a short `struct_size`, an invalid or conflicting
`unresolved` field, or a field or length out of range; `GRDR_E_ABI` when `abi_min` in the header
exceeds the library; `GRDR_E_BUNDLE` for a blob that fails validation or an evaluation whose cost
exceeds `eval_cap`; `GRDR_E_STATE` for a `labels_bundle_tag` mismatch; and `GRDR_E_CHANGED` when the
tables' blob, arena or handle record no longer reads as `grdr_fp_load` validated it, now or on an
earlier call on the same handle. Each row's `meaning` covers all uses.

## 7. Transactions and failure

- `grdr_engine_step` commits session state only on success, so a failed call leaves the snapshot
  byte-identical to the one before it and replay stays exact (D-09).
- The step budget counts rule evaluations, not time, so native and `wasm32` builds exhaust it at the
  same point.
- **Seeded randomness and additive `Output` changes (RFC 0009 constraint 2e).** `grdr_engine_step`
  accepts caller-supplied seed bytes `entropy[32]` and passes them to `grdr_core::engine::boundary`
  to seed a deterministic `Entropy` implementation for that call alone; neither `grdr-ffi` nor
  `grdr-wasm` calls `grdr-crypto`'s system generator. Seed reuse is not detected by the library, and
  a host that reuses a seed across calls gets repeated `Random128` identifiers, so a host MUST pass
  unique bytes on every production call (recording seeds only for replay). If a failed draw in
  `Engine::step` needs a new member of `grdr.embed.v1alpha1.Output`, that wire change is additive by
  its own D-61 RFC (not an amendment of RFC 0009), bumps the engine ABI minor, and a host that does
  not know it applies the action class's declared `on_failure` (design/26 section 3).
- On any error for an `ActionRequest`, the host applies the action class's declared `on_failure`
  (D-15) and reports it as an event. On any status but `GRDR_OK` from `grdr_fp_eval`, and while it
  has no tables, the host answers the action as `tables.md` section 11 says when the floor cannot
  answer, and reports it as an event; when a call made again on `GRDR_E_STATE` or `GRDR_E_ARG`
  answers the action, the first status is still reported. A status from `grdr_fp_eval` other than
  `GRDR_E_CHANGED` answers that one action and changes no state.
- **`GRDR_E_CHANGED` and `reload-required`.** A handle that returned `GRDR_E_CHANGED` never answers
  again, and its `handle_after` (`reload-required`) defines the host state until a reload succeeds:
  - retire the handle at once and never call it again; its cache generation stops being current, no
    verdict cached under it is read, and the result of a call that was already running on it is
    discarded;
  - until a load from a freshly verified copy succeeds (never from the private copy that changed, and
    never returning to the retired tables), the floor is missing: answer as `tables.md` section 11
    says when the floor cannot answer (denying classes in the host's copied `loss_closed_classes`
    inside session containers, and on cold start with no tables since start denying every floor
    lookup inside session containers while never denying a person's own shell), keep the old
    interest filters installed, and report Degraded;
  - free the old blob and arena only after the host's quiescence point, when no call on them can
    still be running;
  - start the first reload attempt at once and bound further attempts with a retry policy, call
    timeout and probation settle period. Report every `GRDR_E_CHANGED` from a serving handle as a
    tamper finding naming `bundle_digest` (without user-identifying detail), leave state and
    findings unchanged on a late `GRDR_E_CHANGED` from an already-retired handle, and end reloading
    when a reloaded handle returns `GRDR_E_CHANGED` before serving through the settle period (a
    repeat), staying floor-missing until an activation, a recompile on changed device facts, or a
    restart.
- **Host mandatory invariants and host-chosen defaults.** A compliant host MUST enforce these floor
  and ABI invariants: keep the blob, writable/address-pinned arena, and inputs in custody
  (section 4, `tables.md` section 11); verify the envelope/bundle digest, target OS and
  architecture, non-decreasing sequence number, and host `eval_cap` / `path_max_units` ceilings
  before publishing tables; extract `eval_cap`, `path_max_units`, and `loss_closed_classes` from its
  private verified copy via `grdr_fp_blob_info` before `grdr_fp_load`; never treat floor `pass` as
  `ALLOW`; enforce `GRDR_E_CHANGED` retirement, cache-generation isolation, `unresolved` bit rules,
  at-most-once retry rules on `GRDR_E_STATE` / `GRDR_E_ARG` without caching retry answers, and
  floor-missing answers (`tables.md` sections 10 and 11); supply unique `entropy[32]` bytes per
  engine step; and report failures (including initial statuses before retry) as events. The host
  chooses its concrete policy defaults: its `eval_cap` and `path_max_units` ceilings, its reload
  retry backoff, call timeout and give-up thresholds, and its probation settle period (in Loonaro's
  daemon these sit in `limits.toml`, and cached verdicts are kept memory-only with bounded size and
  no persistence across retirement or restarts).
- `grdr_engine_last_error` text is `LogSafe`; no input bytes are echoed in it (P8).

## 8. Panics and the embedded profile

The `embedded` build profile sets `panic = "abort"` (design/03 section 8). No panic crosses the
boundary, but a panic ends the process. `GRDR_E_INTERNAL` is a consistency check that failed without
panicking, and it poisons the handle. Because a panic is fatal to its process, in-process linking of
the engine is offered only to unprivileged hosts; the sidecar or the WebAssembly module is the
recommended form. Only `libgrdr_fastpath`, which has no panic path (design/26 section 2), enters a
protected process.

## 9. Version negotiation

- At run time a host calls `grdr_abi_check(major, min_minor)` before it creates any handle; a
  mismatch fails with `GRDR_E_ABI`. For the fast path the host checks `grdr_fp_abi_version()` using
  `(grdr_fp_abi_version() >> 16) == GRDR_FP_ABI_MAJOR` and
  `(grdr_fp_abi_version() & 0xFFFF) >= GRDR_FP_ABI_MINOR`, and the library refuses a blob whose
  `abi_min` it does not meet (`tables.md` TV-3).
- Before activation, each artefact's build manifest declares the C ABI range it provides or
  requires, and the one resolver of D-71 refuses a combination outside it, naming the component and
  the contract. The run-time check and the not-evaluable rule are the run-time half.
- Both interfaces are experimental until one external embed pilot completes (D-60); `surfaces.toml`
  records the class.
