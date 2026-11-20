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
diffed against this text (design/03 section 7).

## 1. Common rules

- **Status.** `typedef uint32_t grdr_status;`. Every function returns `grdr_status` except the
  version, string and free functions. The values are the rows of `status-codes.toml`, and both
  headers define the type and the constants behind the same include guard, `GRDR_STATUS_DEFINED`,
  so a host can include both.
- **Outputs on failure.** A function that returns anything but `GRDR_OK` writes no output argument:
  no verdict field, no view, no buffer, no handle.
- **Pointers.** A null pointer where the contract needs one returns `GRDR_E_ARG`. A null pointer with
  a zero length is an empty input.
- **`struct_size`.** Every input struct starts with `uint32_t struct_size`, which the caller sets to
  `sizeof` the struct it was compiled with. A minor ABI version adds functions and trailing fields
  only. A `struct_size` below the struct's base size (the fields of the minor that introduced it),
  or one that ends inside a field, returns `GRDR_E_ARG`. A trailing field the caller's `struct_size`
  does not cover takes its stated default. A `struct_size` larger than the library knows is accepted
  and its extra bytes are not read, so a caller that depends on a field added in minor `m` calls the
  version check of its interface for `m` first.
- **Output structs** (`grdr_fp_verdict`, `grdr_fp_interest_view`, `grdr_buf`) carry no
  `struct_size` and never change within a major. More output in a minor arrives through a new
  function.
- **Versions.** `grdr_fp_abi_version` and `grdr_abi_version` return `major << 16 | minor`. The two
  interfaces are versioned apart, because `libgrdr_fastpath` and `grdr-ffi` are separate artefacts.
- **Numbers.** The action class is the number of `grdr.common.v1alpha1.ActionClass`, which follows
  spine section 3: `exec` 1, `file.read` 2, `file.write` 3, `file.delete` 4, `net.connect` 5,
  `net.request` 6, `llm.request` 7, `mcp.connect` 8, `mcp.call` 9, `cred.use` 10, `agent.spawn` 11,
  `config.change` 12, `elevate` 13, `ui.act` 14, `data.flow` 15; 0 is unspecified. The principal
  kind is the Cedar principal type a floor row can name (design/12 section 2): `Session` 1,
  `Process` 2. It is not `Principal.kind` of design/04 section 2.

## 2. Fast path: `grdr_fastpath.h`

```c
typedef struct grdr_fp_tables grdr_fp_tables;   /* opaque, lives in the host's arena */

uint32_t    grdr_fp_abi_version(void);
grdr_status grdr_fp_arena_size(const uint8_t *blob, size_t len, size_t *out);
grdr_status grdr_fp_load(const uint8_t *blob, size_t len, void *arena, size_t arena_len,
                         const grdr_fp_tables **out);
grdr_status grdr_fp_eval(const grdr_fp_tables *t, const grdr_fp_input *in,
                         grdr_fp_verdict *out);
grdr_status grdr_fp_interest(const grdr_fp_tables *t, grdr_fp_interest_view *out);
```

| Function | Contract | Returns |
|---|---|---|
| `grdr_fp_abi_version` | The fast-path ABI as `major << 16 \| minor`. This document is 0.1 | No status |
| `grdr_fp_arena_size` | Applies TV-1 to TV-14 of `tables.md` to the header and writes the arena size the blob needs | `GRDR_OK`; `GRDR_E_ARG` for a null `blob` or `out` or a `blob` not 8-aligned; `GRDR_E_ABI` (TV-3); `GRDR_E_BUNDLE` (any other TV rule) |
| `grdr_fp_load` | Checks its arguments, applies TV-1 to TV-14, checks `arena_len`, applies TV-15 to TV-31, then builds the indices in the arena and writes a table handle that points into it. The blob and arena must outlive the tables. It never copies the blob and touches no memory but the blob and the arena | `GRDR_OK`; `GRDR_E_ARG` for a null pointer, a `blob` or `arena` not 8-aligned, or an `arena_len` below the arena size; `GRDR_E_ABI`; `GRDR_E_BUNDLE` |
| `grdr_fp_eval` | Pure: evaluates one input against the tables (`tables.md` section 5). Callable concurrently from any number of threads on the same tables | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_STATE`; `GRDR_E_BUNDLE` when the evaluation reaches `eval_cap` |
| `grdr_fp_interest` | Writes pointers into the blob: the process scope, path, host and port tables of `tables.md` section 3.5, and the string pool their entries refer to | `GRDR_OK`; `GRDR_E_ARG` for a null pointer |

`grdr_fp_eval` checks in this order and stops at the first failure:

1. `t`, `in` or `out` is null, or `in->struct_size` is below the base size: `GRDR_E_ARG`.
2. `labels_bundle_tag` differs from the first eight bytes of the tables' `bundle_digest`, both read
   as little-endian u64: `GRDR_E_STATE`, on every call until labels and tables agree.
3. A field is outside its range: `GRDR_E_ARG`. The action class is 0 or above the tables'
   `action_class_count`; the principal kind is 0 or above `principal_kind_count`; a non-empty path
   has a null pointer, an encoding other than 1 or 2, more code units than `path_max_units`, or is
   not in the canonical form of #221 R4 (starts with `/`, no empty, `.` or `..` segment, no trailing
   `/`); `dest_kind` is above 3; a name destination is null, empty or not in the canonical form of
   `tables.md` TV-20.
4. Evaluation. Reaching `eval_cap` gives `GRDR_E_BUNDLE`, never `pass`.

### 2.1 `grdr_fp_input`

Fields in the order design/26 section 2 gives. Offsets are for 64-bit targets; a 32-bit target
lays out the same declaration under its own C ABI.

```c
typedef struct grdr_fp_input {
    uint32_t       struct_size;        /*   0 */
    uint16_t       action_class;       /*   4  ActionClass number, section 1 */
    uint16_t       principal_kind;     /*   6  Session 1, Process 2 */
    uint64_t       process_key;        /*   8  the host's stable process identifier */
    uint8_t        exe_digest[32];     /*  16  all zero: unknown */
    const void    *path;               /*  48  already resolved by the host */
    size_t         path_len;           /*  56  code units of path_encoding; 0: no path */
    uint32_t       path_encoding;      /*  64  GRDR_FP_PATH_UTF8 1, GRDR_FP_PATH_UTF16LE 2 */
    uint32_t       dest_kind;          /*  68  NONE 0, NAME 1, IPV4 2, IPV6 3 */
    const uint8_t *dest_name;          /*  72  dest_kind 1: canonical name, no terminator */
    size_t         dest_name_len;      /*  80  bytes */
    uint8_t        dest_addr[16];      /*  88  dest_kind 2 and 3: network order */
    uint16_t       dest_port;          /* 104  0 when the action has no port */
    uint64_t       label_bits;         /* 112  enforcing-label projection from the engine */
    uint64_t       labels_bundle_tag;  /* 120  first eight bytes of that bundle's digest */
    uint8_t        grant_digest[32];   /* 128  all zero: no grant */
} grdr_fp_input;                       /* 160 bytes; the base size of fast-path ABI 0.1 */
```

The path is the host's resolved path in the canonical form above, UTF-8 or UTF-16LE, read code
unit by code unit at any alignment; when `path_len` is 0, `path` and `path_encoding` are not read.
An IPv4 destination uses `dest_addr[0..4]`. Fields a `dest_kind` does not use are not read. The
fast path reads `process_key` for no row (design/12 section 8); it is in the input so the host and
the engine name the same process.

### 2.2 `grdr_fp_verdict`

```c
typedef struct grdr_fp_verdict {
    uint32_t verdict;       /*  0  GRDR_FP_PASS 1, GRDR_FP_DENY 2, GRDR_FP_STEP_UP 3 */
    uint32_t rule_index;    /*  4  index of the winning floor row; UINT32_MAX for pass */
    uint32_t reason_code;   /*  8  index into the reason-code table; UINT32_MAX for pass */
    uint32_t cache_scope;   /* 12  NONE 0, CALL 1, SESSION 2, BUNDLE 3 */
    uint64_t expiry_ns;     /* 16  nanoseconds from the call; 0: no bound beyond the scope */
} grdr_fp_verdict;          /* 24 bytes */
```

No verdict is 0, so a host that reads a verdict it never received sees an invalid value, not
`pass`. Scope `none` is 0, so the same mistake never caches. The scope and expiry rules are those of
`tables.md` section 5. A host caches a floor verdict only under its scope, keyed by the loaded tables
and the input's resource identity (action class, path, destination, executable digest), plus the
principal kind and session for `session`, and clears the cache on a table swap.

**`pass` is not `ALLOW`.** It means no floor row objects. The action goes on to the content engine
or, if the engine cannot answer in time, to the class's declared `on_failure` (D-15).

### 2.3 `grdr_fp_interest_view`

```c
typedef struct grdr_fp_span {
    const uint8_t *ptr;         /* first record, inside the blob */
    uint32_t       count;       /* records */
    uint32_t       record_size; /* bytes per record, as tables.md section 3 */
} grdr_fp_span;                 /* 16 bytes */

typedef struct grdr_fp_interest_view {
    grdr_fp_span   process_scope;  /*  0 */
    grdr_fp_span   paths;          /* 16 */
    grdr_fp_span   hosts;          /* 32 */
    grdr_fp_span   ports;          /* 48 */
    const uint8_t *strings;        /* 64  string pool the entries' offsets count from */
    size_t         strings_len;    /* 72 */
} grdr_fp_interest_view;           /* 80 bytes */
```

The pointers stay valid as long as the blob does. An empty table has `ptr` null and `count` 0.

## 3. Engine: `grdr.h`

```c
typedef struct grdr_engine grdr_engine;   /* opaque */
typedef struct grdr_buf { uint8_t *ptr; size_t len; } grdr_buf;

typedef struct grdr_engine_config {
    uint32_t struct_size;                                              /*  0 */
    void *(*alloc)(void *ctx, size_t size, size_t align);              /*  8 */
    void *(*realloc)(void *ctx, void *ptr, size_t old_size, size_t align,
                     size_t new_size);                                 /* 16 */
    void  (*free)(void *ctx, void *ptr, size_t size, size_t align);    /* 24 */
    void    *alloc_ctx;                                                /* 32 */
    uint64_t memory_cap;                                               /* 40  bytes */
    uint64_t step_budget;                                              /* 48  rule evaluations per call */
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

`grdr_engine_config`'s base size is 4 (`struct_size` alone). A `struct_size` that covers some but
not all of `alloc`, `realloc`, `free` and `alloc_ctx` returns `GRDR_E_ARG`, as does a set with one
function null and another not. Uncovered or zero `memory_cap` and `step_budget` take the defaults
the library was built with from its `limits.toml` rows; uncovered or null allocator fields mean the
library's own allocator. Which minor first exports each function and each trailing field is set by
the engine-boundary RFC (#378); this document fixes their signatures and contracts.

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
| `grdr_engine_step` | `input` is an encoded `grdr.embed.v1alpha1.Input`; `output` an encoded `Output`. The 32 entropy bytes seed a deterministic generator for this call only, so a recorded seed replays exactly | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_DECODE`; `GRDR_E_RESOURCE`; `GRDR_E_BUDGET`; `GRDR_E_STATE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` |
| `grdr_engine_interest` | The interest set for the bundle (empty `session_id`) or for one session, named by its id's string form (design/04 section 3) | `GRDR_OK`; `GRDR_E_ARG` (also a session the engine does not hold); `GRDR_E_STATE`; `GRDR_E_RESOURCE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` |
| `grdr_engine_compile_fastpath` | The unsigned table blob of `tables.md` for the loaded bundle; for unprivileged hosts and tests (`tables.md` section 8) | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_STATE`; `GRDR_E_BUNDLE` (the bundle exceeds a bound of the format; the loaded bundle stays); `GRDR_E_RESOURCE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` |
| `grdr_engine_snapshot` | An encoded `EngineState` the host persists | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_STATE`; `GRDR_E_RESOURCE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` |
| `grdr_engine_restore` | Takes the same bundle and profile as `load` and the state bytes, as `Engine::restore` does (design/03 section 3), and replaces the handle's engine on success | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_DECODE` (undecodable state or unknown state format); `GRDR_E_BUNDLE`; `GRDR_E_PROFILE`; `GRDR_E_STATE` (state from another bundle); `GRDR_E_RESOURCE`; `GRDR_E_POISONED`; `GRDR_E_INTERNAL` |
| `grdr_buf_free` | Frees `buf->ptr` and sets `buf` to `{NULL, 0}`; any thread may call it; a zeroed or null `buf` does nothing. A second free of a copy of the same buffer is undefined, as with `free` | No status |
| `grdr_engine_free` | Frees the handle in any state; null does nothing. Buffers it returned stay valid until `grdr_buf_free` | No status |
| `grdr_status_str` | A static NUL-terminated string: the code's `name` in `status-codes.toml`, or its `unknown_name` for a number with no row. Identifiers only; person-facing text comes from language tokens (D-69) | No status |
| `grdr_engine_last_error` | An encoded `grdr.embed.v1alpha1.Diagnostic` for the last failed call on this handle, in any state, or an empty buffer if no call has failed. A successful call does not clear it | `GRDR_OK`; `GRDR_E_ARG`; `GRDR_E_RESOURCE` |

## 4. Memory ownership

- Inputs are borrowed for the duration of the call and never retained.
- Outputs are `grdr_buf { uint8_t *ptr; size_t len; }`, owned by the library until `grdr_buf_free`,
  which any thread may call.
- When the host supplies allocator callbacks, every engine allocation goes through them, buffers
  included. The callbacks and `alloc_ctx` stay valid until the handle is freed and every buffer it
  returned is freed, and they are callable from any thread that frees a buffer. A callback that
  returns null fails the call with `GRDR_E_RESOURCE`.
- The memory cap in `grdr_engine_config` applies with and without host callbacks. Reaching it
  returns `GRDR_E_RESOURCE` with the state unchanged.
- The fast path allocates nothing. It reads the blob, the input and what the input points to,
  writes the arena (in `grdr_fp_load` only) and its output struct, and touches no other memory but
  its own stack.

## 5. Threading

- A `grdr_engine` is used by one thread at a time: Rust `Send`, not `Sync`. The host serialises
  calls on one handle.
- The engine creates no threads and holds no thread-local or global mutable state, so several
  handles in one process are independent.
- `grdr_fp_eval` and `grdr_fp_interest` are pure and callable concurrently on the same tables.
  `grdr_fp_load` writes only its own arena, which no live tables may use (`tables.md` section 9).

## 6. Status codes

`status-codes.toml` holds one `[[status]]` row per code with its `name`, `value`, `meaning` and
`handle_after`, and the headers are generated from it or tested against it (EM-2, EM-4). Numbers are
never reused: a retired code keeps its row with `retired = true`, and a new code takes the next free
value. A new code, like a new function or field beyond design/26 sections 2 and 3, is an RFC (D-60).

The fast path uses four of them: `GRDR_E_ARG` for a null pointer, a short `struct_size` or a field
out of range; `GRDR_E_ABI` when `abi_min` in the header exceeds the library; `GRDR_E_BUNDLE` for a
blob that fails validation or an evaluation that reaches `eval_cap`; `GRDR_E_STATE` for a
`labels_bundle_tag` mismatch. Each row's `meaning` covers both uses.

## 7. Transactions and failure

- `grdr_engine_step` commits session state only on success, so a failed call leaves the snapshot
  byte-identical to the one before it and replay stays exact (D-09).
- The step budget counts rule evaluations, not time, so native and `wasm32` builds exhaust it at the
  same point.
- On any error for an `ActionRequest`, and on any fast-path error, the host applies the action
  class's declared `on_failure` (D-15) and reports it as an event.
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
  mismatch fails with `GRDR_E_ABI`. For the fast path the host compares `grdr_fp_abi_version()`,
  and the library refuses a blob whose `abi_min` it does not meet (`tables.md` TV-3).
- Before activation, each artefact's build manifest declares the C ABI range it provides or
  requires, and the one resolver of D-71 refuses a combination outside it, naming the component and
  the contract. The run-time check and the not-evaluable rule are the run-time half.
- Both interfaces are experimental until one external embed pilot completes (D-60); `surfaces.toml`
  records the class.
