RFC: 0003
Title: The slice-0 public surface of grdr-wire: frame codec, local links, peer verification and the peer-reader seam
Author: chief-architect
Harness: Claude Code
Model: claude-opus-5-5
State: Review
Design issue: #1757
Spine: D-14, D-20, D-48, D-61, D-63, D-66, P1, P3, P5, P8, P9, P14, P17 (no spine text changes)
Surfaces: public crates `grdr-wire` (modules `frame`, `local`, `peer_auth`) and `grdr-wire-testkit`; new same-layer edges `grdr-wire` to `grdr-ports` and `grdr-wire-testkit` to `grdr-wire` (design/03 section 2); the `grdr-model` types `InstallProfile` and `Tamper`, through the RFC of #1710
Decision record: none yet

To comment, write on issue #1757 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

This is revision 3. It answers the round 1 and round 2 reviews; the comments headed "RFC 0003 round 2: dispositions" and "RFC 0003 round 3: dispositions" on #1757 list every finding and where it went. The text below is normative on its own. Where it differs from the items it serves, this RFC wins, and section 16 tells each lead what to write back.

## Summary
Slice 0 adds the first public items to `grdr-wire`:
- a pure frame codec;
- four seams the OS adapter crates implement: `Link`, `Connector` and `Acceptor` in a new layer 3 crate, `grdr-ipc-os`, and `PeerReader` in `grdr-peer-os`;
- endpoint resolution;
- the platform-neutral peer-authentication decision, and the connections that only that decision can produce.

`grdr-wire` makes no system call and links no OS binding; it decides, frames and gates. A program never holds an unverified link. The client gets a connection only from `open`, which checks and connects to one address. The server gets one only from `accept` and the first frame. This RFC states every signature, the rule each seam follows, the decision tables, every wait and its exit, the 22 error codes of the `WIRE` and `PEER` areas, what each refusal means as evidence, and what reaches a person and the server. Both crates enter as `experimental`. No spine text changes; section 15 proposes the amendments to design/03, design/07, design/11, `architecture.toml` and the ruling on #1743.

## Motivation
`grdr-wire` is a public layer 2 crate (design/03 section 2), so its surface changes only by RFC (D-61; design/30 section 3). Seven items build on it without one: #374, #375, #555, #1549, #1606, #683 and #684. The ruling on #1743 and #1671 moved every OS reader to `grdr-peer-os` and every listener to `grdr-os-service`, which leaves a seam between those crates and `grdr-wire` that no item states.

Read together, the items disagree in places that would become defects:
- #374 R4 makes the verifiers traits that any crate could implement, so any crate could mint a verified value.
- #374 R3 and #516 R1 each build an endpoint resolver, and nothing owns the expectation that sets the `tamper` grade.
- #375's table refuses a group- or other-writable socket. `connect(2)` needs write permission on the socket inode, so every correct Protected socket, which any local user must reach, would be refused. The round 1 evaluator confirmed this from unix(7).
- #375 checks only the socket's own directory, so a principal that can write a higher directory can rename the whole thing.
- #555 R1 re-reads `GetNamedPipeClientProcessId` to catch a reused pid. The call returns the pid stored at connect, so it cannot see reuse; a process identifier is valid only until the process ends (https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers, read 2026-11-20).
- #555 R2 has the shim open the service's process. A standard-user process gets `ERROR_ACCESS_DENIED` from `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` on a service. The round 1 evaluator showed this on six services, and section 7 reproduces it.
- On Linux and macOS a client's peer credentials name the process that called `listen(2)`, so under socket activation they name the service manager, not the daemon. The evaluator read this from `unix_listen` and `unix_stream_connect`. An executable check through those credentials cannot pass.
- No item gives connect, accept or a pipe read a deadline that ends. std's `UnixStream` has no connect timeout, and a Windows pipe read has none without overlapped I/O, which needs `unsafe`.

If nothing changes, four squads implement against conflicting signatures inside the trust core.

## Design

### 1. Rules
Terms:
- A **seam** is a trait of `grdr-wire` that another crate implements: `Link`, `Connector`, `Acceptor` and `PeerReader`.
- A **proof** is a value that only `grdr-wire` constructs and that grants a capability. The proofs are `ClientConn`, `ServerConn`, `PendingPeer`, `EndpointIdentity`, `PeerIdentity`, and the `Endpoint` that carries an expectation.
- An **observation** is what a reader saw, as plain data. The decision turns observations into a proof or a `Refusal`.
- **ARCH-nnn** is a rule of the architecture lint (design/03 section 2; `cargo run --locked -p grdr-archlint -- check`).

Rule 1. **Dependencies.** `grdr-wire` depends on `grdr-model`, `grdr-ports` (for `Clock` only, a new same-layer edge) and std. It has no third-party dependency, no Cargo feature (design/03 section 8) and `unsafe_code` forbidden. If RFC 0002 is decided with `Clock` in `grdr-model`, re-exported by `grdr-ports` as `Entropy` is, the edge goes and `grdr-ports` leaves the shim's closure. That is the preferred outcome (question 4).

Rule 2. **No OS calls.** `grdr-wire` makes no system call. Every socket, pipe, file-system read, credential read and service query sits behind a seam. The only OS types on the surface are std's `BorrowedFd`, `OwnedFd`, `BorrowedHandle` and `OwnedHandle` (ARCH-007; #1757 R2). The codec, the observations, the decision and the resolver compile on every target, so the decision for all three systems is tested on any host.

Rule 3. **Seams are called only by `grdr-wire`, one token per seam.** Each seam method takes a reference to that seam's own call token: `&LinkCall`, `&ConnectCall`, `&AcceptCall` or `&ReadCall`. A token has a private field, a `pub(crate)` constructor and no `Clone`, and an implementer receives a reference that lives only for the call. Acceptor `stop` is the one method without a token, because stopping grants nothing.
- What the types close (section 12):
  - Code outside `grdr-wire` cannot call a seam, so a program cannot read or write a link, connect, accept or read observations (f13 to f15).
  - An implementer cannot keep its token past the call (f04).
  - An implementer of one seam cannot call another, because it holds the wrong token: a link cannot call the reader, and a reader or an acceptor cannot write to a link (G2, G2b, G2c).
- What only ARCH-028 closes: a crate that implements a seam can lie. A program-defined `PeerReader`, alone (G1) or with a `Connector` that ignores its address (G3), mints a proof from invented observations, and those two attempts compile. ARCH-028 `wire-seams` closes this route. It holds `impl` blocks of the four seams to the crates `architecture.toml` lists (`grdr-ipc-os`, `grdr-peer-os`, `grdr-wire-testkit`) and to test targets, on the workspace and on the distribution build's resolved closure (#1593). It blocks the first program that calls `open` or `accept` (section 16). With the real reader, a connector that connects elsewhere alone is caught: the principal it reaches is not the expected one.

Rule 4. **Proofs are minted only in `grdr-wire`.** Proofs have private fields and `pub(crate)` constructors. None implements `Default`, `Clone`, `Deserialize` or a `From` (f01, f06 to f12, f16 to f18). A connection owns its link, so a proof cannot move to another link. A program never holds an unverified link: `open` connects to the address it checks, and `accept` takes the link from the acceptor and verifies it before the program sees it.

Rule 5. **Blocking calls with deadlines.** Every wait has a deadline, a `grdr_model::Monotonic` read through `Clock`. `grdr-wire` passes each seam call the time left, capped at `call_max`, and never zero. When nothing is left it returns `TimedOut` without calling. It calls again after a `TimedOut` that came back before the deadline, so the cap never ends a wait early. Section 8 lists every wait and its exits.
- One reading of the wall clock sits outside `Clock`. The Windows pipe acceptor stamps when a connect completed as Windows system time, which is only ever compared with another Windows system time, a process's creation time. The program acts on neither, so `Clock`'s rule (design/03 section 10) is not engaged; section 15 records the exception.
- There is no async API in slice 0 (Alternatives).

Rule 6. **Bytes only.** `grdr-wire` frames bytes and never decodes a protobuf body. The receiver decodes through `grdr-proto`, which is the IPC frame decoder ARCH-004 allows.

Rule 7. **Errors and enums.**
- Each failing type has one error enum, and `Coded` (#280) binds each variant to one code (section 9). Errors carry structural values only and implement `LogSafe` (#284).
- Every public enum is `#[non_exhaustive]`, except the three that implementers construct and only `grdr-wire` matches: `LinkFault`, `ReadFault` and `Accepted`. Callers act on a code's class and on `Refusal::evidence()`, never on a variant. Inside `grdr-wire`, the decision and the reference model match every variant.
- Evidence has one source: the `evidence` column of `schema/codes/peer.toml`. The generator emits it with each code, and `Refusal::evidence()` reads it through the variant's code. A test asserts that every `Refusal` variant's code carries an evidence value, and section 9's column only documents the registry (m7).
- Every observation that a reader can half-complete is one enum with an arm per outcome, never a set of `Option` fields read together (structure rule S4). Examples are `OpenedReading`, `ServiceProcess`, and the two pipe arms of `PeerRef` (M3).

Rule 8. **Bounds are parameters.** The frame cap, `call_max`, the read chunk, the first-frame wait and the suite's wait and margin come from `limits.toml` (section 11 names the keys). The 4-byte little-endian header of design/07 section 2 is a format constant, not a tunable.

Rule 9. **Nothing without a reference and a case.** Every method and variant has a reference implementation (`MemLink`, `MemNet`, the reference model), a named case (section 11) and a caller in slice 0 (section 16).

Data classes (P8):
- pid, uid, gid, SID, audit token and any path under a home directory are `identifier`. Node kind, mode, binding, integrity level, `Refusal`, `Evidence`, every fault and every code are `structural`.
- A frame body carries the classes of the message inside it and is never logged.
- The identity and observation types implement neither `LogSafe` nor `Display`. Their `Debug` exists for tests and cannot reach a log, because log macros take only `LogSafe` values.
- `PeerIdentity::pid` and `principal` are the accessors that expose identifiers. The daemon derives the process key from the hold (#25), and retention of a peer's pid, uid or SID is the daemon item's decision, stated with its `data_class`.
- The wire types carry no organisation. The daemon stamps it from its tenant context when it emits an event (seat 4).

Assurance effect (P1): the `tamper` grade of every decision delivered through a verified endpoint is set in one place, `resolve` (section 6): `admin` for Protected, `user` for User. No action class changes `visibility`, `control` or `on_failure`.

### 2. What lives where
| Concern | Crate | Squad |
|---|---|---|
| Frame codec, seams, connections, the link and acceptor suites | `grdr-wire` `frame`, `local` | core |
| Observations, the reader seam, endpoint resolution, the decision, `open`, `accept`, proofs | `grdr-wire` `peer_auth` (trust core) | security |
| `MemLink` and `MemNet`, the in-memory link, connector and acceptor | `grdr-wire-testkit` (layer 2, public, never in a layer 4 program's normal closure) | core |
| `Link`, `Connector` and `Acceptor` for Unix sockets (connect with `SO_SNDTIMEO`, accept with `poll(2)` and a wake pipe) and Windows pipes (overlapped I/O with `CancelIoEx`, `WaitNamedPipeW`, the connect time stamped first in the completion path) | `grdr-ipc-os`, new, layer 3, trust core under IPC peer authentication | endpoint |
| `PeerReader` on each system, and the hold-based lookups #1549 R1 needs | `grdr-peer-os` (trust core) | security |
| The service-manager seam; adopting the listeners a manager passes; creating every pipe instance, with `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first, `PIPE_REJECT_REMOTE_CLIENTS` on each, and the DACL and owner of section 15; handing them over as std `UnixListener`, `OwnedFd` or `OwnedHandle` | `grdr-os-service` | endpoint |
| Accept loops, handlers, `Clock` adapters, the shim's table path | the programs | endpoint, adapters |

The client side needs local stream code but not the service seam. The ruling on #1743 kept the two apart for the same reason, so they are separate crates (F6). `grdr-hook`, `grdr` and `grdr-tray` link `grdr-ipc-os` and `grdr-peer-os`, never `grdr-os-service`. The shim's closure gains `grdr-ipc-os`, the raw bindings already present through `grdr-peer-os`, and `grdr-ports` while Rule 1's edge stands. #377's 2 MiB binary-size criterion measures the cost. The daemon joins `grdr-os-service` to `grdr-ipc-os` through std types, so no layer 3 crate depends on another (ARCH-002).
- On Unix it passes the adopted `UnixListener` to the Unix acceptor.
- On Windows it builds the pipe acceptor with an instance source, `impl FnMut() -> io::Result<OwnedHandle> + Send`, a closure that calls `grdr-os-service`. The acceptor keeps `endpoint.pipe.instances` instances waiting and asks the source for the next one as each is taken. `grdr-ipc-os` never creates an instance, so the DACL and owner code exists once (m4).

### 3. Frame codec (`grdr_wire::frame`)
```rust
pub struct FrameCap { /* private: 1..=u32::MAX */ }
impl FrameCap { pub fn new(bytes: u32) -> Option<FrameCap>; pub fn get(self) -> u32; }
#[non_exhaustive]
pub enum Decoded<'a> {
    Frame { body: &'a [u8], consumed: usize },
    NeedMore { needed: usize },
    TooLarge { declared: u32, cap: FrameCap },
}
pub fn decode(input: &[u8], cap: FrameCap) -> Decoded<'_>;
pub fn encode(body: &[u8], cap: FrameCap) -> Result<Vec<u8>, BodyTooLarge>;
pub struct BodyTooLarge { pub len: usize, pub cap: FrameCap }
```
- A frame is a 4-byte little-endian length, then that many body bytes (design/07 section 2). A length of 0 is a valid empty frame.
- `decode` is pure and stateless:
  - With fewer than 4 bytes it returns `NeedMore { needed: 4 }`.
  - A declared length above the cap is `TooLarge`, as soon as the header is present, whatever follows.
  - Otherwise it returns `NeedMore { needed: 4 + len }` until the body is complete, then `Frame`.
  - Arithmetic is checked, and an overflow is `TooLarge`.
- `encode` refuses a body longer than the cap with `BodyTooLarge` and writes nothing.
- Callers: the connections (section 5) and #374's fuzz and differential targets.

### 4. Seams (`grdr_wire::local`)
```rust
pub struct LinkCall { /* private */ }      // also ConnectCall, AcceptCall, ReadCall: pub(crate) fn new, no Clone
pub struct FileTime(pub u64);              // Windows system time, 100 ns units since 1601 UTC
#[non_exhaustive]
pub enum PeerRef<'a> {
    #[cfg(unix)] Socket(BorrowedFd<'a>),
    #[cfg(windows)] PipeServer { pipe: BorrowedHandle<'a>, connected_at: FileTime },
    #[cfg(windows)] PipeClient { pipe: BorrowedHandle<'a> },
    Memory,
}
#[non_exhaustive]
pub enum Address { Socket(PathBuf), Pipe(String) }
pub enum LinkFault { TimedOut, Closed, Unavailable, Busy, Denied, Os { code: i32 } }

pub trait Link: Send {
    fn read(&mut self, buf: &mut [u8], within: Duration, call: &LinkCall) -> Result<usize, LinkFault>;
    fn write(&mut self, buf: &[u8], within: Duration, call: &LinkCall) -> Result<usize, LinkFault>;
    fn peer(&self, call: &LinkCall) -> PeerRef<'_>;
}
pub trait Connector: Send + Sync {
    type Link: Link;
    fn connect(&self, address: &Address, within: Duration, call: &ConnectCall) -> Result<Self::Link, LinkFault>;
}
pub enum Accepted<L> { Link(L), Stopped }
pub trait Acceptor: Send + Sync {
    type Link: Link;
    fn accept(&self, call: &AcceptCall) -> Result<Accepted<Self::Link>, LinkFault>;
    fn stop(&self);
}
pub struct WireLimits { /* private: FrameCap, call_max, read chunk */ }
impl WireLimits {
    pub fn new(frame_max: u32, call_max: Duration, read_chunk: usize) -> Option<WireLimits>;
    pub fn cap(&self) -> FrameCap;
    pub fn call_max(&self) -> Duration;
}
```
The `Link` contract, which `check_links` checks (section 11):
- **`read`.** Called with a non-empty `buf` and `within > 0`. It returns:
  - `Ok(n)` with `1 <= n <= buf.len()`;
  - `Ok(0)` when it returned early with nothing (a signal, a spurious wake-up);
  - `Err(Closed)` at end of stream, never `Ok(0)`;
  - `Err(TimedOut)` no earlier than `within` and no later than `within` plus the margin;
  - or another fault.

  It never returns `Interrupted`.
- **Rounding.** An implementation rounds `within` up to the smallest unit its OS wait takes, never down to zero. A zero `SO_RCVTIMEO` or `SO_SNDTIMEO` never times out (socket(7)), and a zero wait in `WaitNamedPipeW` means the server's default. It clamps to a finite value below the OS's "forever": `INFINITE` is `0xFFFFFFFF` ms. `grdr-wire` never passes more than `call_max`, so the clamp is only a backstop.
- **`write`.** The same contract. A write to a closed peer is `Err(Closed)`, never a signal: Rust programs ignore `SIGPIPE`, and the Unix link also sets `MSG_NOSIGNAL` or `SO_NOSIGPIPE`.
- **`peer`.** Returns the descriptor or handle the reader inspects. A Windows server link returns `PipeServer` with `connected_at`, which the acceptor took before anything else in its completion path; a client link returns `PipeClient`. `MemLink` returns `Memory`, and every real reader answers `Memory` with `Unsupported`.
- **Drop.** Dropping a link closes it.

The `Connector` contract:
- `connect` waits at most `within`. Linux sets `SO_SNDTIMEO` before `connect(2)`, and a timed-out connect is reported like a non-blocking one (socket(7)). macOS fails at once on a full backlog. Windows retries `ERROR_PIPE_BUSY` through `WaitNamedPipeW` with the time left, rounded up.
- A missing path or pipe, and no listener, are `Unavailable`. No free pipe instance at the deadline is `Busy`, and a refused open is `Denied`.
- The Windows connector opens the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, which std's `OpenOptionsExt::security_qos_flags` sets (https://doc.rust-lang.org/std/os/windows/fs/trait.OpenOptionsExt.html, read 2026-11-20). So a hostile server can identify the caller but not impersonate it.
- It asks for exactly `FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE`, never `GENERIC_WRITE`. `FILE_GENERIC_WRITE` includes `FILE_APPEND_DATA`, which has the same value as `FILE_CREATE_PIPE_INSTANCE` (https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights, read 2026-11-20). `READ_CONTROL` is what lets the reader read the pipe's owner (section 7).

The `Acceptor` contract, which `check_acceptor` checks:
- `accept` waits until a client connects, the listener fails, or `stop` is called.
- `stop` makes the pending call and every later call return `Stopped`, within the margin. The daemon calls it before the handover of design/11 section 8.
- The Unix acceptor waits with `poll(2)` on the listener and a wake pipe that `stop` writes. The Windows acceptor waits on an overlapped `ConnectNamedPipe` and a stop event.

Callers in slice 0: `open` and `accept` (section 7), the suites, and `grdr-ipc-os`'s implementations.

### 5. Connections (`grdr_wire::local`)
```rust
pub struct ClientConn<L: Link> { /* private */ }
impl<L: Link> ClientConn<L> {
    pub fn endpoint(&self) -> &EndpointIdentity;
    pub fn send<C: Clock>(&mut self, body: &[u8], clock: &C, deadline: Monotonic) -> Result<(), WireError>;
    pub fn recv<C: Clock>(&mut self, clock: &C, deadline: Monotonic) -> Result<Vec<u8>, WireError>;
}
pub struct ServerConn<L: Link> { /* private */ }
impl<L: Link> ServerConn<L> {
    pub fn peer(&self) -> &PeerIdentity;
    pub fn send<C: Clock>(&mut self, body: &[u8], clock: &C, deadline: Monotonic) -> Result<(), WireError>;
    pub fn recv<C: Clock>(&mut self, clock: &C, deadline: Monotonic) -> Result<Vec<u8>, WireError>;
}
#[non_exhaustive]
pub enum WireError {
    FrameTooLarge { declared: u32, cap: FrameCap },
    BodyTooLarge(BodyTooLarge),
    Truncated,
    Broken,
    NoMemory { wanted: usize },
    Link(LinkFault),
}
```
- **Construction.** `ClientConn` comes only from `open` and `ServerConn` only from `PendingPeer::first_frame` (section 7). The two types differ in the identity they carry, so a program reads `endpoint()` or `peer()` with no `Option`.
- **Receiving.** `recv` reads exactly the 4 header bytes and checks the cap with `frame::decode`. A length above the cap is `FrameTooLarge`, returned before any body byte is read. It then reads the body in chunks of the read chunk, growing the buffer with `try_reserve` as bytes arrive. Growth is amortised, so the buffer holds at most twice the bytes received; growing by exact amounts cost about 200 ms per 2 MiB frame in round 2's measurement (m3). So a client that declares 2 MiB and sends nothing holds no memory, and a failed reservation is `NoMemory`, never an abort. The daemon bounds the number of connections (`endpoint.connections-max`), so its memory for frames is at most that bound times what the clients actually sent.
- **States.** A connection is ready or broken; no state accessor exists, because the next call says which.
  - It stays ready after a frame moves, after `BodyTooLarge` (nothing was written), and after `Link(TimedOut)` when no byte of the frame had moved.
  - Every other outcome breaks it and drops the link at once, so the peer sees the close: `FrameTooLarge`, `Truncated` (end of stream inside a frame), `NoMemory`, `Link(Closed)`, a timeout after part of a frame, and any other fault.
  - A broken connection answers every call with `Broken` and does no I/O; dropping it is the exit.
- **Threads and retries.** The calls block and are `Send`. Nothing retries inside `grdr-wire`; a retry is the caller's, through `retry::run` (ARCH-018).
- **Callers.** The shim (#377, #516) opens a new connection for each invocation and never reuses one. Its `open` and its wait for `DecideAck` share the 250 ms acknowledgement window of D-14, which bounds the whole path a developer waits on. The daemon's handlers (#1536, #157) also call these.

### 6. Endpoints (`grdr_wire::peer_auth`)
```rust
#[non_exhaustive]
pub enum Place { Path(PathBuf), UnderRuntimeDir(PathBuf), UnderHome(PathBuf), Pipe(String), PipeForCaller(String) }
#[non_exhaustive]
pub enum OwnerSpec { Root, Caller, Sid(Sid) }
pub struct EndpointSpec { pub place: Place, pub owner: OwnerSpec, pub trusted_groups: Vec<u32>, pub service: Option<String> }
pub struct UserContext { pub runtime_dir: Option<PathBuf>, pub home: Option<PathBuf>, pub sid: Option<Sid> }
pub struct Endpoint { /* private: Address, the expectation */ }
impl Endpoint { pub fn address(&self) -> &Address; }
pub fn resolve(spec: &EndpointSpec, profile: InstallProfile, user: &UserContext) -> Result<Endpoint, ResolveError>;
#[non_exhaustive]
pub enum SpecFault { PathNotAbsolute, PathEscapes, PipeName, OwnerForProfile, OwnerForPlace, Service }
#[non_exhaustive]
pub enum UserPart { RuntimeDir, Home, Sid }
#[non_exhaustive]
pub enum ResolveError { Spec(SpecFault), UserContext(UserPart) }
```
- **One resolver** serves the shim, the CLI, the tray and the daemon (P17).
- **The spec.** `EndpointSpec` is one row of the endpoint table in the configuration schema, keyed by OS, profile and endpoint (`decide`, `local`).
  - The defaults come from the brand manifest's names and the platform path tables (D-66; design/03 section 9), so two vendors' products on one host never share a name. An embedder overrides a row without a code change.
  - Every key of the row is `security`-tagged. In the Protected topology it is read only from layers 1 to 3 (signed server configuration, MDM, the admin-owned install file), never from a user file, the environment or a flag (design/03 section 9).
  - It is organisation-scoped, pushed by the server or an MDM profile, diffable against the default, and audited as a configuration change.
  - The install profile comes from install state, never from the row.
  - `grdr doctor` runs the row's path check as the preflight `endpoint-path` before install, so an MDM profile is checked before any shim depends on it.
- **The user context.** `UserContext` holds the canonical runtime directory, home and caller SID, which the program reads once at start.
- **What `resolve` checks:**
  - `Path` must be absolute by the host's path rules. The relative part of `UnderRuntimeDir` and `UnderHome` must be non-empty and contain only normal components. A missing base is `ResolveError::UserContext`, naming the part that is missing. That error has its own code (`PEER-0011`), and its next step names the one fix. Where `XDG_RUNTIME_DIR` is unset, which WSL, containers and plain `ssh` sessions often leave it, the fix is to log in through a session that sets it or to set it (seat 1).
  - A pipe name is `\\.\pipe\` followed by printable ASCII with no further backslash (`PipeName`). The brand manifest's ASCII names and the SID's ASCII text are its only parts, so no comparison ever needs case folding or Unicode handling.
  - `Root` fits only a socket address and `Sid` only a pipe address (`OwnerForPlace`).
  - Protected takes `Root` or `Sid` and gives `tamper: admin`; User takes `Caller` and gives `tamper: user` (D-48). Anything else is `OwnerForProfile`. This is the only place the grade is set.
  - `service` names the Windows service whose process must serve the pipe. It is required for a Protected pipe, allowed for a User pipe, and refused for a socket address (`Service`).
- **Defaults.** User-profile defaults name the local per-user runtime directory, never the home directory: `$XDG_RUNTIME_DIR` on Linux, and on macOS the directory #1549 settles. A home on a network file system can stall `lstat`, and an inherited or roaming home can carry another account's owner. `UnderHome` stays available as data, with that limit stated.
- **Stale sockets and uninstall.** In the default units the service manager holds the socket, so it outlives a crash of the daemon.
  - Where no manager holds it, the daemon at start runs `check_path`. When every node passes, the socket is its own principal's and nobody listens, it removes the socket and binds again.
  - A stale socket our own service left is owned by the expected principal, so a client sees `SERVICE_NOT_RUNNING`, never `PathForeign`; only another account's socket is `PathForeign`.
  - Uninstall removes the socket and every directory the install or the service created, and restores the rest (design/24, journey 4; the uninstall item, filed on acceptance if none owns it) (seat 2).

### 7. Peer authentication (`grdr_wire::peer_auth`, trust core)
Identity and observation types (the `Copy`, `Eq` and `Debug` derives are omitted here):
```rust
pub struct AuditToken(pub [u32; 8]);
pub struct IntegrityRid(pub u32);
pub struct Sid { /* private: validated bytes */ }
impl Sid {
    pub fn from_bytes(bytes: &[u8]) -> Result<Sid, SidError>;
    pub fn parse(text: &str) -> Result<Sid, SidError>;
    pub fn as_bytes(&self) -> &[u8];
    pub fn to_text(&self) -> String;
}
#[non_exhaustive] pub enum SidError { Length { len: usize }, Revision { found: u8 }, SubAuthorities { count: u8 }, Text { part: usize } }
#[non_exhaustive] pub enum Principal { Uid(u32), Sid(Sid) }
pub struct Caller { pub principal: Principal, pub primary_group: Option<u32> }
pub struct UnixCred { pub pid: u32, pub uid: u32, pub gid: u32 }
#[non_exhaustive] pub enum PidfdSource { Kernel, Opened(OpenedReading) }
#[non_exhaustive] pub enum OpenedReading { Exited, Named { pid: u32, uid: u32 }, Unreadable(ReadFault) }
pub struct MessageIdentity { pub principal: Principal, pub integrity: IntegrityRid }
#[non_exhaustive] pub enum ServiceProcess { Valid(u32), NoValidPid }
#[non_exhaustive] pub enum ClientObservation {
    Linux { cred: UnixCred, pidfd: PidfdSource },
    Macos { token: AuditToken, pid: u32, pid_version: u32, euid: u32, egid: u32 },
    Windows { pid: u32, sid: Sid, integrity: IntegrityRid, created: FileTime, connected: FileTime, exited: bool },
}
#[non_exhaustive] pub enum ServerObservation {
    Unix { uid: u32, gid: u32 },      // the credentials of the process that called listen(2)
    Windows { pid: u32, owner: Sid }, // GetNamedPipeServerProcessId, and the pipe instance's owner
}
pub struct ProcessHold { /* private: pidfd, audit token or process handle */ }
impl ProcessHold {
    #[cfg(target_os = "linux")] pub fn pidfd(fd: OwnedFd) -> ProcessHold;
    #[cfg(target_os = "linux")] pub fn as_pidfd(&self) -> BorrowedFd<'_>;
    #[cfg(target_os = "macos")] pub fn audit_token(token: AuditToken) -> ProcessHold;
    #[cfg(target_os = "macos")] pub fn as_audit_token(&self) -> &AuditToken;
    #[cfg(windows)] pub fn process(handle: OwnedHandle) -> ProcessHold;
    #[cfg(windows)] pub fn as_process(&self) -> BorrowedHandle<'_>;
}
pub struct ClientReading { pub observed: ClientObservation, pub hold: ProcessHold }
#[non_exhaustive] pub enum NodeKind { Directory, Socket, Symlink, Other }
pub struct NodeFacts { pub kind: NodeKind, pub dev: u64, pub ino: u64, pub uid: u32, pub gid: u32, pub mode: u32 }  // mode: st_mode & 0o7777
pub struct PathFacts { pub ancestors: Vec<NodeFacts>, pub socket: NodeFacts }  // ancestors from the root down
pub enum ReadFault { Gone, Unsupported, Denied, Os { code: i32 } }
```
Only `ProcessHold` is per OS. A hold confers nothing by itself; it reaches a program only inside a `PeerIdentity`.

The reader seam:
```rust
pub trait PeerReader: Send + Sync {
    fn caller(&self, call: &ReadCall) -> Result<Caller, ReadFault>;
    fn client(&self, peer: PeerRef<'_>, call: &ReadCall) -> Result<ClientReading, ReadFault>;
    fn message_identity(&self, peer: PeerRef<'_>, call: &ReadCall) -> Result<MessageIdentity, ReadFault>;
    fn server(&self, peer: PeerRef<'_>, call: &ReadCall) -> Result<ServerObservation, ReadFault>;
    fn service_process(&self, service: &str, call: &ReadCall) -> Result<ServiceProcess, ReadFault>;
    fn path(&self, socket: &Path, call: &ReadCall) -> Result<PathFacts, ReadFault>;
}
```
What each method reads in `grdr-peer-os`, and with which rights:
- **`caller`.** The calling process's effective uid and primary gid (Unix), or its token's user SID (Windows).
- **`client`.** Runs on the server, before any frame is read.
  - Linux: `SO_PEERCRED` (effective ids), then `SO_PEERPIDFD`, which gives `Kernel`. Where that option is missing (`ENOPROTOOPT`): `pidfd_open(pid)`, then the pid in the pidfd's `fdinfo` and the effective uid of that process (the second `Uid:` field of its status), then whether the pidfd still names a live process. The reading is one of three:
    - `Opened(Named { pid, uid })` when both reads succeeded and the pidfd was live after them;
    - `Opened(Exited)` when it was not live;
    - `Opened(Unreadable(fault))` when a read failed, for example through an LSM or EDR denial or `hidepid`.
  - macOS: `LOCAL_PEERTOKEN` and the audit-token readers.
  - Windows: `GetNamedPipeClientProcessId`; `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` only, and the handle becomes the hold; the token's SID and integrity level (`TOKEN_QUERY`); the creation time from `GetProcessTimes`; whether the process has exited. `connected` is copied from `PeerRef::PipeServer`; any other peer reference is `Unsupported`.
- **`message_identity`.** Called only for an identity that awaits it (Windows), after the first frame is read: `ImpersonateNamedPipeClient` at identification level, which any caller may do, then the thread token's SID and integrity level, then `RevertToSelf`. Unix readers answer `Unsupported`, and the decision never calls them. Impersonation takes "the security context of the last message read from the pipe" (https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient, read 2026-11-20), so it names the connection's own sender, whatever the pid now names.
- **`server`.** Runs on the client.
  - Unix: the uid and gid that `SO_PEERCRED`, or `LOCAL_PEERCRED` and the token on macOS, report. These are the credentials of the process that called `listen(2)`, which under socket activation is the service manager.
  - Windows: `GetNamedPipeServerProcessId`, and the pipe instance's owner from `GetSecurityInfo(OWNER_SECURITY_INFORMATION)` on the client's own handle. That read needs only `READ_CONTROL` on the handle (https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo, read 2026-11-20). No process handle is opened.
    - The `GetNamedPipeServerProcessId` page says the handle "must be created by the CreateNamedPipe function", which is the server end. On a client handle the call works on Windows 11 in both rounds' probes, so this rests on observation (m1).
    - #555's runner case asserts it on every supported Windows build. A build where it fails is unsupported until an amendment.
- **`service_process`.** Windows: `OpenSCManagerW(SC_MANAGER_CONNECT)`, `OpenServiceW(SERVICE_QUERY_STATUS)` and `QueryServiceStatusEx`. Local authenticated users hold both rights by default (https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights, read 2026-11-20).
    - It returns `Valid(pid)` only in RUNNING, PAUSED, PAUSE_PENDING or CONTINUE_PENDING, and `NoValidPid` otherwise. The pid "may not be valid" in START_PENDING or STOP_PENDING and is never valid when the service is stopped (QueryServiceStatusEx remarks, read by round 2).
    - The daemon reports RUNNING before it serves its pipe (#1724), so a shim meets `NoValidPid` only around a restart.
- **`path`.** `lstat` of every component of the socket path from the root down, and of the socket, never following a link.

Probe on a Windows 11 host, run as a medium-integrity process with Administrators deny-only. For the pipes `wkssvc`, `srvsvc` and `eventlog`:
- `GetNamedPipeServerProcessId` returned 5384, 7564 and 3380.
- The pipe owners read as S-1-5-20, S-1-5-18 and S-1-5-19, each the account of the service that serves the pipe.
- `QueryServiceStatusEx` for LanmanWorkstation, LanmanServer and EventLog returned the same three pids.
- `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` failed with error 5 on all three, as round 1 found.

Every reader call is a non-blocking system call or a local file-system read. A reader closes every descriptor and handle it opened before it returns. A lookup by hold, which #1549 R1 needs for the macOS pid version, and the peer's start time and parent chain, are concrete `grdr-peer-os` functions that take `&ProcessHold` and return facts, returning `Gone` when the hold no longer names the process. They grant nothing, so they are not on this surface.

Opening and accepting:
```rust
pub fn open<R: PeerReader, K: Connector, C: Clock>(reader: &R, connector: &K, endpoint: &Endpoint, clock: &C, deadline: Monotonic, limits: WireLimits)
    -> Result<ClientConn<K::Link>, OpenError>;
pub fn accept<R: PeerReader, A: Acceptor>(reader: &R, acceptor: &A) -> Result<Incoming<A::Link>, LinkFault>;
#[non_exhaustive] pub enum Incoming<L: Link> { Pending(PendingPeer<L>), Refused(Refusal), Stopped }
pub struct PendingPeer<L: Link> { /* private: L, and a state Bound(PeerIdentity) or AwaitsMessage(PeerIdentity) */ }
impl<L: Link> PendingPeer<L> {
    pub fn identity(&self) -> &PeerIdentity;
    pub fn first_frame<R: PeerReader, C: Clock>(self, reader: &R, clock: &C, deadline: Monotonic, limits: WireLimits)
        -> Result<(ServerConn<L>, Vec<u8>), FirstFrameError>;
}
pub fn check_path<R: PeerReader>(reader: &R, endpoint: &Endpoint) -> Result<PathCheck, Refusal>;
#[non_exhaustive] pub enum PathCheck { Passed, NoPath }
#[non_exhaustive] pub enum OpenError { Unreachable(LinkFault), Refused(Refusal) }
#[non_exhaustive] pub enum FirstFrameError { Wire(WireError), Refused(Refusal) }
pub struct EndpointIdentity { /* private */ }
impl EndpointIdentity { pub fn server(&self) -> &Principal; pub fn tamper(&self) -> Tamper; }
pub struct PeerIdentity { /* private */ }
impl PeerIdentity {
    pub fn pid(&self) -> u32;
    pub fn principal(&self) -> &Principal;
    pub fn binding(&self) -> Binding;
    pub fn integrity(&self) -> Option<IntegrityRid>;
    pub fn hold(&self) -> &ProcessHold;
}
#[non_exhaustive] pub enum Binding { Atomic, Confirmed }
```
- **`open`, in order.**
  1. Read the caller, for a `Caller` owner.
  2. On a socket address, read the path and decide rows 2 to 6 below, before connecting. A stale socket another account left is therefore `PathForeign`, not `Unavailable`.
  3. On a Windows endpoint with a service, read the service process.
  4. Connect, with the time left.
  5. On a socket address, read the path again. If any node's device, inode, kind, owner, group or mode differs, the result is `PathChanged`.
  6. Read the server and decide row 7, then read the service process again and decide rows 8 and 9.
- **`accept`.** Waits on the acceptor, reads the client and decides the server table. It sets the pending state from the observation arm: `Bound` for Linux and macOS, `AwaitsMessage` for Windows. `PendingPeer` allows no I/O, and its state is private (f17, f18). The program moves it to a worker, so a client that connects and sends nothing never holds up the accept loop.
- **`first_frame`.** Reads the first frame with its deadline (`ipc.first-frame-ms`). For an identity that awaits it, it then reads `message_identity` and requires its SID and integrity level to equal the pending identity's.
  - No path skips the check: a failed read is `PeerUnverifiable` (Coverage), and a difference is `ClientReplaced` (Transient) (M1).
  - The identity then carries the connection's own integrity level, not only that of the process the pid names (m2).
  - Both protocols are client-first, so a connection that sends nothing is closed at that deadline. No frame reaches the program before every check passes.
- **Callers.** The daemon on every system calls `check_path` at start (#683, #1745). The Windows daemon records `NoPath` in its health report (#684), because a pipe's start check is first-instance creation. `PeerIdentity::integrity` is read by #684 R3 and #157's caller lineage.

**Client decision.** The expected principal is `Uid(0)` for `Root`, the given SID for `Sid`, and the caller's principal for `Caller`. On Unix, uid 0 also fits wherever a uid is expected. A group-writable ancestor is admitted when its gid is in `trusted_groups`, or when the endpoint is the caller's and the ancestor's owner and group are the caller's own uid and primary group (seat 1). The first matching row wins:

| # | Condition | Refusal | Evidence |
|---|---|---|---|
| 1 | A read fails | `PeerGone` for `Gone`, otherwise `ServerUnverifiable(fault)` | Transient, Coverage |
| 2 | Any node on the path is a symlink | `PathUnsafe { at, Symlink }` | Configuration |
| 3 | An ancestor is not a directory, or the socket is not a socket | `PathUnsafe { at, NotDirectory \| NotSocket }` | Configuration |
| 4 | A node's owner is neither uid 0 nor the expected uid | `PathForeign { at }` | Tamper |
| 5 | An ancestor is other-writable (a sticky bit does not admit it), or group-writable and not admitted | `PathUnsafe { at, OtherWritable \| GroupWritable }` | Configuration |
| 6 | Any node differs between the reads before and after connect | `PathChanged` | Transient |
| 7 | The server principal does not fit the expected principal | `ServerForeign(Principal { seen })` | Tamper |
| 8 | Windows with a service: both readings are `Valid(p)` with the same `p`, and `p` is not the pipe's server pid | `ServerForeign(NotTheService)` | Tamper |
| 9 | Windows with a service: the readings differ, or either is `NoValidPid` | `ServiceRestarting` | Transient |
| 10 | Otherwise | `ClientConn` with the server principal and the endpoint's `tamper` | |

Once row 7 passes, only a holder of the service's SID or of `SeRestorePrivilege`, both above the boundary, can own the pipe. A disagreement between the two readings is therefore a restart racing the check, not an attacker, and every upgrade that races a shim call stays Transient (M2).

The socket's own mode is not checked. Connecting needs write permission on the socket inode, so the Protected socket is world-writable by design; who may replace it is decided by its directories, which rows 2 to 5 check up to the root.

What each system guarantees:
- **Unix.** No row checks the server's executable. The kernel names the process that called `listen(2)`, which is the service manager under activation. So the Protected guarantee is "uid 0 listened on a path that only uid 0 can change", and the User guarantee is the same with the caller's uid. On Linux this answers #464, and it removes "the peer executable is the installed daemon" from design/07 for Linux and macOS (section 15).
- **Windows, two factors with no process handle.**
  - The pipe instance's owner is the expected SID. Only a creator holding that SID, or `SeRestorePrivilege`, which is above the boundary, can set that owner, and the daemon's DACL refuses users `FILE_CREATE_PIPE_INSTANCE`.
  - The SCM names the pipe's server pid as the configured service's process, in two equal readings, one before and one after. A restart between the readings is Transient.
  - A squatter's pipe fails the owner factor, whatever its pid. A stale pid fails the service factor.

**Server decision.** This runs on accept, then again on the first frame.

| Observation | Condition, in order | Outcome | Evidence |
|---|---|---|---|
| any | the read fails | `PeerGone` for `Gone`, otherwise `PeerUnverifiable(fault)` | Transient, Coverage |
| Linux `Kernel` | | `Atomic` | |
| Linux `Opened` | `Exited` | `PeerGone` | Transient |
| | `Unreadable(fault)` | `PeerUnverifiable(fault)` | Coverage |
| | `Named` with a pid or uid that differs from `cred`: the pid names another process | `ClientReplaced` | Transient |
| | `Named`, equal | `Confirmed`, `Bound` | |
| macOS | | `Atomic`, `Bound` (the token names one process instance) | |
| Windows | `exited` | `PeerGone` | Transient |
| | `created` is later than `connected`: the pid names a process that started after the stamp | `ClientReplaced` | Transient |
| | otherwise | `Confirmed`, `AwaitsMessage` | |
| first frame, `AwaitsMessage` only | `message_identity` fails | `PeerUnverifiable(fault)`, or `PeerGone` for `Gone` | Coverage, Transient |
| | its SID or integrity level differs from the pending identity's | `ClientReplaced` | Transient |

Every server-side refusal is a client that left, a pid that now names another process, or a read that failed. The client gains nothing from any of them, because its connection is refused, so none is Tamper evidence; repeated `ClientReplaced` shows as a counter. `PIPE_REJECT_REMOTE_CLIENTS` refuses the local-SMB route by which a client pid can be spoofed, so on Windows the first-frame check is defence in depth.

A pass yields the pid, the principal (`Uid` of the effective uid, or `Sid`), the binding, the integrity level on Windows and the hold.

What `Confirmed` does not exclude:
- On Linux before 6.5: a recycled pid with the same uid. That is the same principal (#375's threat model).
- On Windows: a process of the same SID that takes the client's pid between the client's exit and the acceptor's stamp. The first-frame check excludes a process of another SID or integrity level whatever the timing. The stamp-first rule keeps the window to the completion latency. A backward step of the system clock can turn a real client into `ClientReplaced`, which is Transient: no marker, and the shim takes the table path.

### 8. Waits and their exits
| Wait | Where | Exits |
|---|---|---|
| `Connector::connect` | `grdr-ipc-os` | connected; a fault; the rounded `within` elapsed |
| `Link::read`, `Link::write` | `grdr-ipc-os`, `MemLink` | bytes moved; a fault; the rounded `within` elapsed (`TimedOut`); an early `Ok(0)` |
| `Acceptor::accept` | `grdr-ipc-os`, `MemNet` | a connection; a fault; `stop` |
| `send`, `recv`, `open`, `first_frame` | `grdr-wire` | done; a fault; the deadline, after which no seam is called |
| Reader calls | `grdr-peer-os` | return at once. `lstat` on a network file system that stops answering blocks, which is why User-profile defaults avoid home directories (section 6); a stall there ends at the program's watchdog (design/07 section 5) |

No wait in `grdr-wire`, `grdr-wire-testkit` or `grdr-ipc-os` has the end of the process as its only exit.

### 9. Error codes
Areas for `schema/codes/areas.toml`: `WIRE` (IPC framing and local links; design/07, core) and `PEER` (IPC peer authentication; design/02 TM-4, security). Classes and Connect codes are those of design/03 section 10. Every code has a next step. `{cli}` is the CLI name from the brand manifest, an argument of the `fix` token, never a literal (D-66). The `GRDR-` ids belong to the code namespace and stay fixed under a rebrand, so an embedder's support pages can cite them.

| Code | Reason | Class | Connect | Bound by | Evidence | Next step (`code.<code>.fix`) |
|---|---|---|---|---|---|---|
| `GRDR-WIRE-0001` | `FRAME_TOO_LARGE` | input | `resource_exhausted` | `WireError::FrameTooLarge` | | The other end sent a frame above `ipc.frame-max` and was disconnected; run the same release on both ends |
| `GRDR-WIRE-0002` | `BODY_TOO_LARGE` | internal | `invalid_argument` | `BodyTooLarge`, `WireError::BodyTooLarge` | | A defect; report it with the output of `{cli} doctor` |
| `GRDR-WIRE-0003` | `FRAME_TRUNCATED` | retryable | `unavailable` | `WireError::Truncated` | | The other end closed mid-frame; if it repeats, `{cli} doctor` shows whether the service restarted |
| `GRDR-WIRE-0004` | `CONNECTION_BROKEN` | internal | `failed_precondition` | `WireError::Broken` | | A defect in the caller; open a new connection |
| `GRDR-WIRE-0005` | `LINK_TIMED_OUT` | retryable | `deadline_exceeded` | `LinkFault::TimedOut` | | The service did not answer in time; `{cli} doctor` shows its state |
| `GRDR-WIRE-0006` | `PEER_CLOSED` | retryable | `unavailable` | `LinkFault::Closed` | | The other end closed the connection; open a new one |
| `GRDR-WIRE-0007` | `SERVICE_NOT_RUNNING` | retryable | `unavailable` | `LinkFault::Unavailable` | | Protected: the service manager restarts the service. User: `{cli} doctor` names the user unit to start |
| `GRDR-WIRE-0008` | `ENDPOINT_BUSY` | retryable | `resource_exhausted` | `LinkFault::Busy` | | Raise `endpoint.pipe.instances` if it repeats |
| `GRDR-WIRE-0009` | `ENDPOINT_ACCESS_DENIED` | fatal | `permission_denied` | `LinkFault::Denied` | | The endpoint's access list refuses this account; check the endpoint row for this profile |
| `GRDR-WIRE-0010` | `LINK_FAILED` | retryable | `unavailable` | `LinkFault::Os` | | `{cli} doctor` shows the system error |
| `GRDR-WIRE-0011` | `FRAME_BUFFER_UNAVAILABLE` | retryable | `resource_exhausted` | `WireError::NoMemory` | | The process could not reserve memory for a frame and closed the connection |
| `GRDR-PEER-0001` | `PEER_GONE` | retryable | `unavailable` | `Refusal::PeerGone`, `ReadFault::Gone` | Transient | None: the other process exited during the check |
| `GRDR-PEER-0002` | `CLIENT_REPLACED` | retryable | `unavailable` | `Refusal::ClientReplaced` | Transient | None unless it repeats; then check for a system clock step |
| `GRDR-PEER-0003` | `ENDPOINT_CHANGED` | retryable | `unavailable` | `Refusal::PathChanged` | Transient | None: the endpoint was replaced during the connect and is checked again at the next call |
| `GRDR-PEER-0004` | `SERVICE_RESTARTING` | retryable | `unavailable` | `Refusal::ServiceRestarting` | Transient | None: the service restarted during the check, and the call took the table path |
| `GRDR-PEER-0005` | `ENDPOINT_PATH_UNSAFE` | fatal | `failed_precondition` | `Refusal::PathUnsafe` | Configuration | A directory on the endpoint path is a link, not a directory, or writable by others; `{cli} doctor` names it |
| `GRDR-PEER-0006` | `ENDPOINT_PATH_FOREIGN` | policy | `unauthenticated` | `Refusal::PathForeign` | Tamper | Another account owns the endpoint or a directory above it, and the call took the table path; the tamper finding is in `{cli} doctor` and, with a server, the console |
| `GRDR-PEER-0007` | `SERVER_FOREIGN` | policy | `unauthenticated` | `Refusal::ServerForeign` | Tamper | Another account or process serves the endpoint, and the call took the table path; the tamper finding is in `{cli} doctor` and, with a server, the console |
| `GRDR-PEER-0008` | `PEER_UNVERIFIABLE` | fatal | `failed_precondition` | `Refusal::PeerUnverifiable`, `ReadFault::Unsupported`, `ReadFault::Denied`, `ReadFault::Os` | Coverage | The service could not read a client's identity; the runbook lists the reads an endpoint security product must allow |
| `GRDR-PEER-0009` | `SERVER_UNVERIFIABLE` | fatal | `failed_precondition` | `Refusal::ServerUnverifiable` | Coverage | This program could not read the service's identity; the runbook lists the reads and exclusions |
| `GRDR-PEER-0010` | `ENDPOINT_CONFIG_INVALID` | fatal | `failed_precondition` | `ResolveError::Spec`, `SidError` | | Correct the endpoint row; `{cli} doctor` names the key |
| `GRDR-PEER-0011` | `USER_CONTEXT_MISSING` | fatal | `failed_precondition` | `ResolveError::UserContext` | | No per-user runtime directory, home or SID was found; `{cli} doctor` names which, and the one step that sets it |

`WireError::Link`, `OpenError` and `FirstFrameError` take the code of what they carry. A `ReadFault` maps to a `PEER-0001` or `PEER-0008` refusal on the server. On the client the same fault is `PEER-0001` or `PEER-0009`, so each code means one side's failure (F1). Each item registers the codes its area constructs (ARCH-017): #374 registers `WIRE-0002` and `0005` to `0010` and both area rows; #1606 registers `WIRE-0001`, `0003`, `0004` and `0011`; #375 registers the `PEER` codes.

### 10. What reaches people and the server
`Refusal::evidence()` decides what a refusal produces, so a misconfiguration never reads as an attack (seats 3 and 4):
- **Tamper** (`PathForeign`, `ServerForeign`, client side only): the shim takes the table path and writes the tamper marker (#1574).
  - The marker is a typed record: the code, the endpoint (`decide` or `local`), the profile, the structural detail (`PathNode` or `ServerFault`), the verdict the table path returned, and the session reference when the shim has one.
  - It is deduplicated per device on (endpoint, code, detail), with a count and a first and last time.
  - The daemon ingests markers as one tamper finding per key. The finding's stable fields are: the device id, endpoint, profile, code, structural detail, count, first and last time, the latest verdict and session reference, and a reference to the privileged audit-log record that holds the path, uid or SID. The same set is what an export carries (seat 3).
  - The console groups findings across devices by (code, structural detail). A new occurrence after a finding is closed raises a new finding, linked to the closed one.
  - The item that maps a marker to a finding is filed on acceptance, since no open item builds it.
  - The path, uid and SID stay on the device, in the privileged audit log only.
- **Configuration** (`PathUnsafe`): table path, no marker. The daemon raises the health condition `endpoint-unsafe` once per endpoint (degraded, with a runbook) and keeps it raised until `check_path` passes. `grdr doctor` reports it with the failing node.
- **Coverage** (`*Unverifiable`): table path, no marker. The coverage condition `peer-unverifiable` is "could not look", never "nothing found" (P9). It is raised once per endpoint and stays raised until a verification on that endpoint passes, since every decision takes the table path while it lasts. Its runbook names the reads that an incumbent endpoint security product must allow.
- **Transient** (`PeerGone`, `ClientReplaced`, `PathChanged`, `ServiceRestarting`): table path, a counter, nothing else.

In standalone use, a solo developer finds tamper findings in `{cli} doctor` and the desktop's findings list. A server adds the console (seat 1).

The table path is the shim's fail-safe table (design/07 section 5; D-14); this RFC adds no other Mode.

`grdr doctor` derives the failing path from `endpoint.address()` and the node index `at`; a refusal never carries a path (seat 6). It shows the path unless the path lies under another account's home or runtime directory. In that case it says "a directory owned by another account", and the detail stays in the privileged audit log. So every system path, which is every Protected endpoint, is shown to an administrator (seat 2). A shown path is a typed `{path :grdr:path}` argument rendered in a left-to-right isolate (UX6). A name that is not valid UTF-8 (Unix) or that holds an unpaired surrogate (Windows) is shown escaped, with a copy action that returns the exact bytes (seat 9).

The daemon records `Binding` and the endpoint's `tamper` on the session's connection fact (#1536, #25), so a later rule can match a session reached under a weaker binding.

### 11. References, cases and commands
Types used from elsewhere, and who settles them:
- `Monotonic`, `Timestamp` and `Clock { now, monotonic, sleep_until }`: RFC 0002 section 3 (#1688, waiting on the owner).
- `InstallProfile { Protected, User }` and `Tamper { User, Admin, Platform }`: the RFC of #1710.
- `LogSafe`: #284. `Coded`: #280.
- `limits.toml` keys, proposed to #279 with these defaults as data:
  - `ipc.frame-max`, 2 MiB (R7 there);
  - `ipc.call-max-ms`, 1,000;
  - `ipc.read-chunk-bytes`, 65,536;
  - `ipc.first-frame-ms`, 1,800 (the shim's verdict budget);
  - `ipc.link-suite-wait-ms`, 100;
  - `ipc.link-suite-margin-ms`, 250;
  - `endpoint.connections-max`, 256.

`grdr-wire-testkit` holds `MemLink` (`pair(capacity: NonZeroUsize) -> (MemLink, MemLink)`) and `MemNet` (`new(capacity) -> MemNet`, both a `Connector` and an `Acceptor`). A test that needs invented observations writes its own `PeerReader`, which ARCH-028 allows in test targets. `local::conformance` stays in `grdr-wire`, because it must call seam methods and only `grdr-wire` holds the tokens:
```rust
pub struct SuiteLimits { pub wait: Duration, pub margin: Duration }
pub struct CaseFailure { pub case: &'static str, pub detail: String }
pub fn check_links<L: Link, C: Clock>(make_pair: impl FnMut() -> Result<(L, L), LinkFault>, clock: &C, limits: SuiteLimits, os_peer: bool)
    -> Result<(), CaseFailure>;
pub fn check_acceptor<A: Acceptor, K: Connector, C: Clock>(acceptor: &A, connector: &K, address: &Address, clock: &C, limits: SuiteLimits)
    -> Result<(), CaseFailure>;
```
The cases:
- `check_links`:
  - `round_trip`: bytes arrive whole and in order across partial reads.
  - `read_times_out`: a silent peer gives `TimedOut` no earlier than `wait` and no later than `wait + margin`.
  - `one_nanosecond`: a 1 ns `within` returns within `margin`, never "forever".
  - `read_after_close` and `write_after_close`: `Closed`, with no signal and no hang.
  - `peer_kind`.
- `check_acceptor`:
  - `accept_connects`.
  - `accept_stop`: a blocked `accept` returns `Stopped` within `wait + margin` after `stop`.
  - `accept_after_stop`.

Running them on a new link, inside `grdr-ipc-os`'s own test. The test builds the pair with the crate's own constructors, because it cannot call the seams:
```rust
let limits = SuiteLimits { wait: Duration::from_millis(100), margin: Duration::from_millis(250) }; // the two suite keys
let dir = tempdir_for_this_test();                       // the test's own scratch directory
let make_pair = || {
    let path = dir.join("suite.sock");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| fault(&e))?;
    let near = UnixStream::connect(&path).map_err(|e| fault(&e))?;
    let (far, _) = listener.accept().map_err(|e| fault(&e))?;
    Ok((UnixLink::from(near), UnixLink::from(far)))
};
conformance::check_links(make_pair, &clock, limits, true).map_err(|f| format!("{}: {}", f.case, f.detail))?;
```
`os_peer` is `true` when each link's `peer()` must return an OS reference, as every `grdr-ipc-os` link must, and `false` for `MemLink`, whose `peer()` is `Memory`.

Commands:
- `cargo test --locked -p grdr-ipc-os --test links` and `--test acceptors`: the suites on real sockets and pipes.
- `cargo test --locked -p grdr-wire-testkit`: the suites on `MemLink` and `MemNet`.
- `cargo test --locked -p grdr-wire --test conns`: connections over `MemNet`. Golden frames (empty, one byte, at the cap); a header over the cap refused before a counting link is asked for a body byte; `Truncated`; `NoMemory` with a failing allocator; every transition of section 5; #374 AC-1's 1,000,000-stream differential against a splitter written in the test.
- `cargo test --locked -p grdr-wire peer_auth::model::differential`: a reference model in `peer_auth/model/reference.rs`, written from the tables of section 7 and not from the code, run exhaustively over the finite space. The space covers:
  - the owner (0, caller, other) and kind (four) of each of three nodes;
  - the write bits, with a trusted gid, the caller's primary gid and another gid;
  - a before-and-after node change;
  - four server principals;
  - the service pid before and after (equal, different, `None`);
  - every `PidfdSource` and `OpenedReading` arm;
  - every pair of `ServiceProcess` readings;
  - the Windows `exited` and ordering cases;
  - a message identity that is equal, that differs in SID, that differs in integrity, and that cannot be read. An identity that awaits a message is never accepted without one (M1).

  The test asserts that it enumerated as many combinations as the product of the domain sizes.
- `cargo test --locked -p grdr-wire --doc`: a `compile_fail` doctest for each attempt of section 12 that must fail.
- `grdr-peer-os`'s kernel tests (#375 AC-2 to AC-4, #1549 AC-2 and AC-3, #555 AC-2 and AC-3) drive `open` and `accept` with the real reader. They run over a test link and acceptor that each test builds with std sockets or its own pipe calls, which ARCH-028 allows in test targets, so no layer 3 crate depends on another. Each fixture states the refusal it expects from the tables of section 7, read against kernel facts the test reads independently through system tools. No export of the reference model is needed (F8).
- Each reader's suite adds a fixture with a non-ASCII home or runtime path: a Japanese user name, an NFD accent on macOS, an Arabic folder name on Windows (seat 9). None of the decision rows compares paths, since the executable rules are gone.

### 12. Compile sketch
The sketch is on #1757 in three parts:
- Part 1, `grdr_wire.rs`: https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7056002171
- Part 2, `grdr_wire_testkit.rs`, `adapter.rs` and `build.sh`: https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7056002529
- Part 3, `program.rs` and the `forge/` files: https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7056002830

`bash build.sh` uses `rustup run 1.99.1 rustc --edition 2024`, with `#![forbid(unsafe_code)]` in every library crate. From a clean directory on Windows:
- **Library crates.** `grdr_wire`, `grdr_wire_testkit` and `adapter` (the stand-in for `grdr-ipc-os` and `grdr-peer-os`, using public items only) each exit 0 on `x86_64-pc-windows-msvc`. With `--emit=metadata` they also exit 0 on `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`.
- **Program.** `program` builds and runs with exit 0 and prints `program: 39 checks passed`. The checks cover:
  - both suites on `MemLink` and `MemNet`;
  - a verified exchange with a 100,000-byte body read in 4,096-byte chunks;
  - the resolver's service, pipe-name and profile rules;
  - every client row on Windows and Unix, including the caller's private group, a sticky other-writable directory, a socket swapped during connect, a mode 0666 socket that passes, a service restart and a service with no valid pid (both Transient);
  - every server row, including a status read that fails (Coverage), a pid that names another uid (Transient), and the first-frame identity check: a mismatch, a lower integrity level, and a read that fails, which is refused and never skipped;
  - an unset runtime directory (`USER_CONTEXT_MISSING`);
  - a boundary timeout that leaves a connection usable, and `FrameTooLarge` breaking it.
- **Forgery attempts, each its own crate.**

| # | Attempt | Result |
|---|---|---|
| f01 | a `ClientConn` literal | exit 1, E0451 |
| f02 | `LinkCall { _private: () }` | exit 1, E0451 |
| f03 | `ReadCall::new()` | exit 1, E0624 |
| f04 | a `Link` impl storing its token in a `&'static LinkCall` field | exit 1, lifetime may not live long enough |
| f05 | `call.clone()` as a `LinkCall` | exit 1, E0308 |
| f06 | `ServerConn::new(..)` | exit 1, E0624 |
| f07 | an `Endpoint` literal | exit 1, E0451 |
| f08 | a `PeerIdentity` literal | exit 1, E0451 |
| f09 | a `PendingPeer` literal with its private `link` and `state` | exit 1, E0451 |
| f10 | `pending.link` | exit 1, E0616 |
| f11 | `ClientConn::new(..)` | exit 1, E0624 |
| f12 | `Refusal::PeerGone.into()` as a `ServerConn` | exit 1, E0277 |
| f13 | `link.read(.., &LinkCall::new())` from a program | exit 1, E0624 |
| f14 | `connector.connect(.., &ConnectCall { .. })` from a program | exit 1, E0451 |
| f15 | `acceptor.accept(&AcceptCall::new())` from a program | exit 1, E0624 |
| f16 | an `EndpointIdentity` literal | exit 1, E0451 |
| f17 | turning a `PendingPeer` into a `ServerConn` without `first_frame` | exit 1, E0599 |
| f18 | a `PendingPeer` from a `PeerIdentity` | exit 1, E0308 |
| f19 | the round 2 `Opened { named_pid, named_uid, alive_after }` shape | exit 1, E0559 |
| f20 | `OpenedReading::Named` without a uid | exit 1, E0308 |
| f21 | `PeerRef::PipeServer` without a connect time | exit 1, E0308 |
| G2 | a `Link` impl calling the reader with its `&LinkCall` | exit 1, E0308 |
| G2b | a `PeerReader` impl writing to a link with its `&ReadCall` | exit 1, E0308 |
| G2c | an `Acceptor` impl writing to the accepted link with its `&AcceptCall` | exit 1, E0308 |
| G1 | a program-defined `PeerReader` passed to `accept` and `first_frame` | exit 0: open to the types, closed by ARCH-028 |
| G3 | a program-defined `Connector` and `PeerReader` passed to `open` | exit 0: open to the types, closed by ARCH-028 |

### 13. Stability and later change
- **Classes.** Both crates enter `surfaces.toml` as `experimental` (ADR-0020; design/03 section 7), through the protected-change item filed on acceptance.
- **What an embedder may rely on now.** The frame format (a 4-byte little-endian length, then the body) is the local IPC contract of design/03 section 7: restated here, not changed. The shim and the daemon tolerate one release of skew. The seams and proofs are experimental: they change in any release, but only by an amendment that names RFC 0003, listed in the release notes.
- **What needs no RFC.** A change of documentation wording that changes no contract. Everything else is an amendment, including a suite case and a decision row, and one amendment may carry every change that is ready at once.
- **Promotion to `beta`.** By RFC, when the endpoint packages freeze (design/03 section 7). The prerequisites are the three readers and the `grdr-ipc-os` links passing their items on the hosted cells, and questions 1 to 3 settled.
- **Adding a platform** (seat 7). An in-tree change to `grdr-peer-os` and `grdr-ipc-os` for the reader and links, plus an amendment that adds the observation, `PeerRef` and `ProcessHold` arms and their decision rows to `grdr-wire`. That module is trust core, so the change takes the high-tier evaluators (D-63). The reader, the links and the rows may land in one pull request. On an unlisted OS, `grdr-wire` builds, but `ProcessHold` has no constructor and `grdr-peer-os` has no reader. A program that needs a reader therefore does not build there, which is a refusal at build time, not a silent pass.
- **An embedder's own transport** (seat 5).
  - An embedder may ship its own `Link`, `Connector` and `Acceptor` crate, backed by a std descriptor or handle, since those are the only OS arms of `PeerRef`. A link over any other transport needs an amendment.
  - `dist.toml` is the distribution manifest of design/03 (Interfaces). #1593 creates it, and the ARCH-028 item adds its `links` table. The distribution build admits it when `dist.toml` lists it among its `links` and the build runs `check_links` and `check_acceptor` on it with its own fixture, as RFC 0002 does for storage adapters. ARCH-028 reads that list as data, so admitting a link is not a code change in this repository.
  - A `PeerReader` is never admitted from `dist.toml`, because the reader is what a proof rests on. An embedder that authenticates its own way reuses `frame` and its own connections, and does not mint our proofs.
- **Amendments expected, each with its item:**
  - an async driver over the same codec and proofs, once an async runtime is admitted to design/03 section 13;
  - the `Dialer` with the uplink (24 section 3);
  - adopting inherited connections after the handover `exec` of design/11 section 8, as `accept` over an inherited-descriptor acceptor;
  - inherited child channels (#427), with a server row that the peer is the spawned child;
  - an expected-peer row for the `provider` endpoint (07 section 7).

### 14. Mechanisms
| Decision | Mechanism | Built by |
|---|---|---|
| Rule 1 | The edges and an empty third-party allow-list for `grdr-wire` in `architecture.toml`. ARCH-027 fails any raw OS binding in `grdr-wire` | #1751; the entries are a protected change filed on acceptance |
| Rule 2 | ARCH-007 through `cargo public-api` against `surfaces.toml` | The `surfaces.toml` item filed on acceptance |
| Rule 3, calls | Per-seam tokens, held by the type system; `compile_fail` doctests for f02 to f05, f13 to f15, G2, G2b and G2c | #374 |
| Rule 3, implementations | ARCH-028 `wire-seams` over the workspace and the distribution closure, with the crate list in `architecture.toml` and `dist.toml`'s `links` | A lint item filed on acceptance, blocking #377, #516, #683, #684 and #1745; #1593 for the closure run |
| Rule 4 | Private fields and `pub(crate)` constructors; doctests f01, f06 to f12, f16 | #375, #1606 |
| Decision tables | The reference model and the exhaustive differential (section 11) | #375 |
| Rule 5, section 8 | `read_times_out`, `one_nanosecond`, `accept_stop` on every link and acceptor; the connection timeout cases; a connect against a full backlog on Linux and a busy pipe on Windows | #374, #1606, the `grdr-ipc-os` link item |
| Rule 7 | `Coded` with an exhaustive match, the registry, ARCH-017 | #280, #278, #374, #375, #1606 |
| Section 10 | The marker record and its deduplication; the two conditions and their runbooks | #1574; the marker-to-finding item; #375 for the conditions' codes |
| One path rule | `check_path` called by the daemons (#683, #1745) | `eval-architecture`, on each of those pull requests |
| `grdr-wire-testkit` in no layer 4 program's normal closure | The archlint graph rule over the `test-support` list in `architecture.toml`, the rule RFC 0002 Rule 1 gives `grdr-ports-testkit` | #1580 reads the list; the entry is a protected change filed on acceptance |
| One evidence source (Rule 7) | `evidence()` generated from the registry's `evidence` column, and a test over every `Refusal` variant | #375, #278 |
| Stability | The `surfaces.toml` entries, `rfc-required`, `cargo semver-checks` | The protected-change item filed on acceptance |

### 15. Proposed changes to design documents, `architecture.toml` and the ruling on #1743
Each lands through an issue whose write set names its file, after acceptance.
- **design/03 section 2.**
  - The `grdr-wire` row: "IPC and uplink framing, size caps, the local link, connector, acceptor and peer-reader seams, the peer-authentication decision, and the `Dialer`".
  - New rows: `grdr-wire-testkit` (layer 2) and `grdr-ipc-os` (layer 3, endpoint, trust core under IPC peer authentication).
  - The same-layer edges gain `grdr-wire` to `grdr-ports` (unless question 4 removes it) and `grdr-wire-testkit` to `grdr-wire`.
  - ARCH-025 reads: "Outbound network connections are opened only through `grdr-wire`'s `Dialer`; local endpoint connections only through `peer_auth::open` over a `Connector` of `grdr-ipc-os`." The lint fails a socket connect or a pipe open anywhere else. Local IPC is not egress, so `grdr egress` does not list it (F7).
  - A new row adds ARCH-028 `wire-seams`. This table is the one register of lint numbers. Until it is amended, the assignment is recorded on #1688 (https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7056005677): ARCH-027 `os-adapter-only` (#1751), ARCH-028 `wire-seams` (this RFC), ARCH-029 `context-mint` (RFC 0002) (m5).
- **design/03 section 9.** The endpoint table keys are `security`-tagged and organisation-scoped (section 6).
- **design/24 section 3, line 132, and work item 24-10.** "Every outbound connection a product process makes goes through the `Dialer`" becomes "every outbound network connection". The lint sentence and 24-10's criterion ("a socket opened outside the `Dialer` fails archlint") name both routes of the new ARCH-025: network through the `Dialer`, local endpoints through `peer_auth::open` (m6).
- **design/03 section 10.** The `Clock` rule gains its one exception: the Windows pipe connect stamp, compared only with a process creation time (Rule 5).
- **design/07 section 2, "Peer checks, both directions".**
  - The client checks every component of the endpoint path from the root and refuses a symlink anywhere on it. It never checks the socket's mode.
  - On Linux and macOS it checks the principal that listened, not an executable. On Windows it checks the pipe instance's owner and the service's pid, never the server's process.
  - "The peer executable is the installed daemon" goes.
  - "Holds the peer by handle ... so a recycled pid cannot stand in for it" becomes the residual of section 7: a recycled pid of another principal cannot stand in, and one of the same principal can only within the stated window (m6).
  - User-profile endpoints default to the per-user runtime directory.
  - Refusals carry evidence as in section 10.
  - #464 is answered by this text.
- **design/11 section 1, named endpoints.** The client check is RFC 0003's client table. The daemon runs the same path rule at start through `check_path`.
- **design/11 section 14.** A Windows endpoint's DACL grants clients only `FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE`, never `FILE_CREATE_PIPE_INSTANCE` or `FILE_GENERIC_WRITE`. The owner is set to the service's SID. `PIPE_REJECT_REMOTE_CLIENTS` stays on every instance: it refuses the local-SMB route by which a client pid can be spoofed.
- **`architecture.toml`.** The edges, the empty allow-list, the two new crates, and the ARCH-028 list.
- **The decision record of #1743.**
  - `grdr-ipc-os` holds every local link, connector and acceptor.
  - `grdr-os-service` keeps the service seam and hands over listeners and pipe instances as std types.
  - The untrusted programs link `grdr-ipc-os` and `grdr-peer-os`, never `grdr-os-service` (section 2).

### 16. What each item changes
This RFC is normative. Each lead writes these changes back into its item before readying it.
- **#374.** Keeps `frame`, the seams, the tokens, `WireLimits` and `local::conformance`. It registers `WIRE-0002` and `0005` to `0010` and both area rows. Its socket client and server move to `grdr-ipc-os`, and its resolver to #375. R2 loses "decode error". R4's traits become the seams. AC-4 (`SO_PEERCRED`) moves to the Linux reader. AC-5 becomes the token doctests and AC-6 runs on `MemNet`. Blocked by #281 (`Clock`) and the `grdr-wire-testkit` scaffold.
- **#1606.** Re-scoped to the connections of section 5, `WIRE-0001`, `0003`, `0004` and `0011`, and `MemLink` and `MemNet` in `grdr-wire-testkit`. Blocked by #374 and #375. Its macOS and Windows transports move to the `grdr-ipc-os` link item.
- **#375.** The lead splits it in two.
  - (a) `peer_auth` in `grdr-wire`: the types, `PeerReader`, `resolve`, `open`, `accept`, `PendingPeer`, `check_path`, the evidence, the reference model and the differential, and the `PEER` codes in `schema/codes/peer.toml`.
  - (b) The Linux reader in `crates/grdr-peer-os/src/linux/**`: `caller` with the primary gid, `client`, `server` as the listener's ids, and `path` with device and inode.
  - The table changes: `EndpointMode` goes; ancestors are checked to the root; `PeerUid` becomes `ServerForeign`; `CredentialMismatch` goes, since a pid that names another process is `ClientReplaced`; the refusal set is section 7's; uids are effective.
- **#1549.** Moves to `crates/grdr-peer-os/src/macos/**` and implements the reader for macOS. R1's token lookup becomes a concrete `grdr-peer-os` function over `&ProcessHold`. R2's executable check goes. On the macOS runner it records which credentials the client side reads when launchd created the listener, and the owner, group and mode of the per-user runtime directory and of `/private/var/run` (questions 1 and 2).
- **#555.** Moves to `crates/grdr-peer-os/src/windows/**`.
  - `client` per section 7, with `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` only.
  - `message_identity` through identification-level impersonation, with the token's SID and integrity level.
  - `server` as `GetNamedPipeServerProcessId` and the pipe owner, with a runner case asserting that the call works on a client handle on every supported build (m1).
  - `service_process` through the SCM, `Valid` only in the states section 7 lists.
  - R1's re-read of the pid gives way to the creation-time and first-frame rows. R2's image check gives way to the service pid. R4's QoS refusal goes, since no call reads it back; the connector always sets it and `grdr-ipc-os`'s test proves the server gets only an identification-level token.
  - `ServerIdentity` becomes `ServerForeign`. A denied open is `PeerUnverifiable(Denied)`.
- **#683.** R2 calls `check_path`. R3 is `accept` then `first_frame`. The listeners `grdr-os-service` adopts are handed as `UnixListener` to `grdr-ipc-os`'s Unix acceptor, whose `stop` the daemon calls.
- **#684.** R6 creates every pipe instance in `grdr-os-service`, with the flags, DACL rights and owner of sections 2 and 15. The daemon builds `grdr-ipc-os`'s pipe acceptor with an instance source that calls it, and the acceptor stamps `connected_at` first. R3 is `accept` then `first_frame`. The Windows `Connector` is `grdr-ipc-os`'s.
- **#1724.** The service reports RUNNING to the SCM before it serves its pipe (section 7, `service_process`).
- **#372.** No change. `grdr-wire` never decodes the body, so R3's wrapper is decoded by the receiver through `grdr-proto`.
- **#24.** The sub-issue table follows the splits above. AC-3 becomes `cargo run --locked -p grdr-archlint -- check`.
- **#464.** Closed by this RFC's decision (section 15).

Filed on acceptance, each linked as it blocks:
- the `grdr-ipc-os` scaffold, with its `architecture.toml`, `owners.toml` and `trust-core.paths` rows;
- the `grdr-wire-testkit` scaffold;
- the `grdr-ipc-os` link item (endpoint), blocking #377, #516, #683, #684 and #1745;
- the ARCH-028 lint item (core);
- the marker-to-finding item;
- the `surfaces.toml` and `architecture.toml` entries;
- the design amendments of section 15;
- the `limits.toml` keys of section 11, through #279.

Downstream:
- #377 and #516 call `resolve`, `open` and `ClientConn`, and write the marker only for `Evidence::Tamper`; #516 R1's own resolver goes.
- #1745 adopts listeners into the Unix acceptor.
- #1749 R1: `grdr-os-service` hands over std types and holds no links.
- #1710 adds `InstallProfile` and `Tamper`.
- #1536 and #25 record `Binding` and `tamper` on the connection fact.
- #157 reads `integrity`.
- #1636's pages list every variant bound to a code.

## Surfaces changed
- `grdr-wire` (layer 2, public): modules `frame`, `local` (with `local::conformance`) and `peer_auth`. Class `experimental`.
- `grdr-wire-testkit` (layer 2, public): `MemLink` and `MemNet`. Class `experimental`.
- New same-layer edges: `grdr-wire` to `grdr-ports`, and `grdr-wire-testkit` to `grdr-wire`.
- `grdr-model` (layer 1, public): `InstallProfile` and `Tamper`, entering through the RFC of #1710.
- Data and gate files, as proposals: two code areas and 22 codes in `schema/codes`; entries in `surfaces.toml` and `architecture.toml`; `security`-tagged endpoint keys in the configuration schema.
- No spine text, no protobuf package and no frame format changes.

## Alternatives
- **Verifier traits that the security module implements (#374 R4 as written).** Any crate could mint proofs. Rejected for `open` and `accept` over a reader seam.
- **Readers that decide and return neutral facts.** The decision would move into `grdr-peer-os`, against #1757 R3. Rejected.
- **A sealed reader trait, so the types alone close G1.** Rust visibility cannot admit one outside crate and refuse the rest. The reader must live in `grdr-peer-os` (the ruling on #1671), so ARCH-028 carries that route, and Rule 3 says so.
- **One call token for every seam (revision 1).** An implementer of one seam could call the others (G2). Rejected for one token per seam.
- **The shim opens the service's process to read its SID and image (#555 R2).** A standard user is refused (F1; the section 7 probe). Rejected for the pipe owner and the SCM pid.
- **An executable check through peer credentials on Unix (design/07 L67).** The kernel names the process that called `listen(2)`. Under activation that is the service manager, so the check cannot pass. Rejected; the principal that listened is the guarantee.
- **A daemon-signed `Hello` that the shim verifies.** It proves the daemon on every system, but needs a key in the shim's path and cryptography in the decide path. Kept as the amendment if the owner and service factors prove too weak.
- **Local links in `grdr-os-service` (revision 1).** That puts the service seam in every user-session program (F6). Rejected for `grdr-ipc-os`.
- **`Connector` as a `local-ipc` purpose of the `Dialer`.** The `Dialer` exists to list egress and to enforce isolated mode, and neither applies to a local socket. A purpose that bypasses its own checks is two mechanisms under one name. Rejected for ARCH-025 naming both routes (section 15).
- **Programs that hold raw links and call a verifier (revision 1).** A program could check one address and connect to another, or read from a link before verifying. Rejected for `open` and `accept`.
- **The first-frame check folded into `accept`.** A client that connects and sends nothing would hold up the accept loop. Rejected for `PendingPeer`.
- **Tamper for every service-pid disagreement (revision 2, row 8).** A restart racing the check would raise a tamper finding on every upgrade (M2). Rejected for `ServiceRestarting`.
- **`Option` fields for a reader's partial results (revision 2).** A failed status read became a mismatch, and Tamper (M3). Rejected for one enum per outcome.
- **A message check that a reader may answer with `None` (revision 2).** The second factor failed open (M1). Rejected for the `AwaitsMessage` state.
- **Server-side `CredentialMismatch` as Tamper.** Every case it covered is a pid that names another process, from which the client gains nothing. Rejected for `ClientReplaced`, which is Transient.
- **Dropping `trusted_groups` (seat 8).** Seats 1 and 2 show real installs that need it as data, and the caller's own group is admitted without it. Declined. `ExecutableRule` is dropped, as seat 8 asked.
- **One `Conn<L>` for both roles (seat 8).** The identity accessors would become `Option`s. Declined: two types share one internal connection.
- **`MemLink` and the suite in `grdr-wire` (revision 1).** Test support would ship in every host. `MemLink` and `MemNet` move to `grdr-wire-testkit`, following `grdr-ports-testkit`. The suite stays, because it must call seams.
- **An async API over a runtime's stream types.** No runtime is admitted yet (design/03 section 13), and layer 2 has no features, so every host and the 2 MiB shim would link one. Rejected for slice 0.
- **Selecting endpoint rows by OS version range (seat 4).** A build that changes a default ships the default with it, and the daemon reports its resolved address in `Status`, so a rollout can be checked per build. Declined.

## Drawbacks
- Two new crates (`grdr-ipc-os`, `grdr-wire-testkit`) and two same-layer edges.
- Every seam method takes a token its implementer cannot use, which is unusual to read.
- ARCH-028 carries the one remaining forgery route, so the lint must exist, and run on the distribution closure, before any program calls `open` or `accept`.
- The Windows server binding rests on a timestamp and a first-frame check. The window section 7 states remains for a process of the same SID and integrity level.
- No server-side refusal is tamper evidence; a client racing pid reuse shows only as a `ClientReplaced` counter.
- The Windows server-pid read on a client handle rests on observed behaviour that its documentation does not state (m1).
- The ancestor rule can refuse an install whose system directories have unusual modes, until `trusted_groups` data covers it. The cost is a table-path decision and a health condition, not a tamper finding.
- No Unix row proves which executable serves the endpoint; it proves which principal does.

## Unresolved questions
1. **macOS credentials under launchd.** Which credentials the client reads when launchd created the listener. Lean: as on Linux, the listener's creator. Settled by #1549's evidence; it changes no row.
2. **The macOS per-user runtime directory and `/private/var/run` under the ancestor rule.** Settled by #1549's evidence. A group-writable system directory is admitted only through `trusted_groups` data.
3. **`InstallProfile` and `Tamper` in `grdr-model`.** Asked on #1710.
4. **`Clock`.** Lean: RFC 0002 is decided with `Clock` in `grdr-model`, re-exported by `grdr-ports`, which removes Rule 1's edge. Until RFC 0002 is decided, this RFC cannot be accepted, whichever way it goes.
5. **Not checked here:**
   - macOS behaviour; no macOS host.
   - The Windows message check with a real pid race; it was argued from the documented API, not raced.
   - OpenSSH's `safe_path` source, whose page was truncated, so the ancestor walk rests on the rename argument of section 7.
   - Whether a service running as a virtual account can set the pipe owner to its per-service SID, and whether the pipe file system keeps the owner per pipe or per instance. #684's runner case settles both.
   - The Linux `fdinfo` pid across pid namespaces. #375's case runs the reader inside a child pid namespace.

   The round 1 evaluator confirmed the unix(7) and socket(7) facts and the effective-uid fact.

## Review
Round 1, on `55c319f`:
- `eval-architecture`: fail, one blocker (F1), seven majors (F2 to F8), six minors (F9 to F14). https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052455526, addendum https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052460663
- lead-security's requirements: https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7051644082
- Seat 1 (solo developer), one blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052272587
- Seat 2 (IT admin), two blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052247872
- Seat 3 (SOC analyst), one blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052326192
- Seat 4 (MSP operator), one blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052384040
- Seat 5 (OEM partner), one blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052283693
- Seat 6 (privacy), none blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052292754
- Seat 7 (contributor), two blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052259314
- Seat 8 (simplicity), none blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052307738
- Seat 9 (international), none blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7052316586

Round 2, on `f032257`:
- `eval-architecture`: fail, three majors (M1 to M3) and seven minors. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7055922414
- Seat 1, none blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7055773376
- Seat 2, one blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7055763705
- Seat 3, none blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7055783126
- Seat 7, none blocking. https://github.com/416rehman/Guardrails/issues/1757#issuecomment-7055796120

Round 3: pending, on this revision, and the last round. The dispositions are on #1757.

## Decision
Pending.
