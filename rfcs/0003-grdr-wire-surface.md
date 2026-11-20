RFC: 0003
Title: The slice-0 public surface of grdr-wire: frame codec, local links, peer verification and the peer-reader seam
Author: chief-architect
Harness: Claude Code
Model: claude-opus-5-5
State: Draft
Design issue: #1757
Spine: D-14, D-20, D-48, D-61, D-63, D-66, P1, P5, P8, P9, P14, P17 (no spine text changes)
Surfaces: public crate `grdr-wire` (modules `frame`, `local`, `peer_auth`); a new same-layer edge `grdr-wire` to `grdr-ports` (design/03 section 2); the `grdr-model` types `InstallProfile` and `Tamper`, through the RFC of #1710
Decision record: none yet

To comment, write on issue #1757 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

## Summary
Slice 0 adds the first public items to `grdr-wire`: a pure frame codec, three seams that the OS adapter crates implement (`Link` and `Connector` in `grdr-os-service`, `PeerReader` in `grdr-peer-os`), the client and server connection types, endpoint resolution, and the platform-neutral peer-authentication decision with the verified values it mints. `grdr-wire` makes no system call and links no OS binding; it decides, frames and gates. This RFC states every signature, the rules each seam follows, the decision tables, every wait and its exit, and the error codes of two areas, `WIRE` and `PEER`. It enters the crate as `experimental`, changes no spine text, and proposes amendments to design/03, design/07, `architecture.toml` and the ruling on #1743 (section 14).

## Motivation
`grdr-wire` is a public layer 2 crate (design/03 section 2), so its surface changes only by RFC (D-61; design/30 section 3). Seven items build on it without one: #374 (codec, Linux socket, verifier traits), #375, #1549 and #555 (peer authentication on three systems), #1606 (macOS and Windows transport), and #683 and #684 (the daemon's endpoints). The ruling on #1743 and #1671 moved every OS reader to `grdr-peer-os` and every listener to `grdr-os-service`, which leaves a seam between those crates and `grdr-wire` that no item states.

Read together, the items also disagree in places that would become defects:
- #374 R4 makes `PeerVerifier` and `EndpointVerifier` traits that the security module implements. Any crate can then implement a verifier and mint a verified value.
- #374 R3 and #516 R1 each build an endpoint resolver, and the expectation that decides the `tamper` grade has no owner.
- The client checks the endpoint after the program has connected, so nothing ties the checked path to the connected socket.
- #375's table refuses a group- or other-writable socket. `connect(2)` needs write permission on the socket inode on Linux and macOS, so every correct Protected socket, which any local user must reach, is mode 0666 and would be refused.
- #375 checks only the socket's own directory. A principal that can write a higher directory can rename the whole directory.
- #555 R1 re-reads `GetNamedPipeClientProcessId` after `OpenProcess` to catch a reused pid. The call returns the pid the pipe stored at connect, so it cannot see reuse; a process identifier is valid only until the process terminates (https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers, read 2026-11-20, page dated 2025-07-14).
- #555 R4 refuses a handle opened without identification-level QoS, but no call reads a handle's QoS back.
- No item gives connect or accept a deadline. std's `UnixStream` has no connect timeout (https://doc.rust-lang.org/std/os/unix/net/struct.UnixStream.html, read 2026-11-20), and a Windows pipe handle has no read timeout without overlapped I/O, which needs `unsafe`.

If nothing changes, four squads implement against conflicting signatures inside the trust core.

## Design

### 1. Rules
Terms:
- A **seam** is a trait of `grdr-wire` that a layer 3 crate implements: `Link`, `Connector`, `PeerReader`.
- A **proof** is a value that only `grdr-wire` constructs and that grants a capability: `VerifiedEndpoint`, `VerifiedPeer`, and the `Endpoint` that carries an expectation.
- An **observation** is what a reader saw, as plain data. The decision turns observations into a proof or a `Refusal`.
- **ARCH-nnn** is a rule of the architecture lint (design/03 section 2; `cargo run --locked -p grdr-archlint -- check`).

Rule 1. **Dependencies.** `grdr-wire` depends on `grdr-model`, `grdr-ports` (for `Clock` only, a new same-layer edge) and std. It has no third-party dependency, no Cargo feature (design/03 section 8) and `unsafe_code` forbidden. The listed edge to `grdr-crypto` stays, unused in slice 0.

Rule 2. **No OS calls.** `grdr-wire` makes no system call of its own. The only std I/O it uses are the mutex and condition variable inside `MemLink`. Every socket, pipe, file-system read and credential read sits behind a seam. The only OS types on the surface are std's `BorrowedFd`, `OwnedFd`, `BorrowedHandle` and `OwnedHandle` (ARCH-007; #1757 R2). The pure parts (codec, observations, decision, resolver) compile on every target, so the whole decision is tested on any host.

Rule 3. **Seams are called only by `grdr-wire`.** Every seam method takes `call: &WireCall`. `WireCall` has a private field, a `pub(crate)` constructor and no `Clone`, so code outside `grdr-wire` can implement a seam but never call one. It receives a reference whose lifetime is the call, so it cannot keep the token (section 11, f04). A program therefore cannot read or write through a link, connect through a connector, or read peer observations itself. ARCH-028 `wire-seams` holds the implementations to `grdr-os-service`, `grdr-peer-os`, `grdr-wire` (`MemLink`) and test targets, on the workspace and on the distribution build's resolved closure (#1593).

Rule 4. **Proofs are minted only in `grdr-wire`.** `VerifiedEndpoint`, `VerifiedPeer`, `EndpointIdentity`, `PeerIdentity` and `Endpoint` have private fields. None implements `Default`, `Clone`, `Deserialize` or a `From` from another type. A verified value owns the link it verified, so a proof cannot move to another link. The client verifier opens the connection itself, to the address it checks, so a program cannot check one address and connect to another.

Rule 5. **Blocking calls with deadlines.** Every wait has a deadline, a `grdr_model::Monotonic` read through `grdr_ports::Clock` (RFC 0002 section 3). `grdr-wire` gives each seam call the time left as a `Duration`, never zero; when nothing is left it returns `TimedOut` without calling. Section 8 lists every wait and its exits. There is no async API in slice 0 (Alternatives).

Rule 6. **Bytes only.** `grdr-wire` frames bytes. It never decodes a protobuf body; the receiver decodes with `grdr-proto`, which is the IPC frame decoder that ARCH-004 allows.

Rule 7. **Errors.** Each type that can fail has one error enum, and each variant is bound by `Coded` (#280) to one code of `schema/codes/wire.toml` or `schema/codes/peer.toml` (section 9). Errors carry structural values only and implement `LogSafe` (#284). `WireError`, `OpenError` and `ResolveError` are `#[non_exhaustive]` because callers act on the class. `LinkFault`, `ReadFault` and `Refusal` are exhaustive: implementers construct the first two, and `grdr-wire` and the reference model map all three totally.

Rule 8. **Exhaustive data.** `Decoded`, `PeerRef`, `Address`, `ConnState`, `Principal`, `PidfdSource`, `ClientObservation`, `ServerObservation`, `NodeKind`, `Place`, `OwnerSpec`, `ExecutableRule`, `UserPart`, `SpecFault`, `Binding` and `PathCheck` are exhaustive, so a new variant fails every implementer and the reference model until it is handled. Adding one is an amendment with its cases.

Rule 9. **Bounds are parameters.** The frame cap comes from `limits.toml` `ipc.frame-max` (#279 R7). `MemLink` capacity and the conformance wait and margin are arguments. The 4-byte little-endian header of design/07 section 2 is a format constant, not a tunable.

Rule 10. **Nothing without a reference and a case.** Every method and variant has a reference implementation (`MemLink`, the reference model) and a named case (section 10). Each section names its callers in slice 0.

Data classes (P8): pid, uid, gid, SID, audit token, executable path and any path under a home directory are `identifier`; node kind and mode, binding, integrity level, `Refusal`, every fault and every code are `structural`. A frame body carries the classes of the message inside it and is never logged. `grdr-wire` has no logger; its errors are `LogSafe` for the caller's log.

Assurance effect (P1): `tamper` for every decision delivered through a verified endpoint is derived in one place, `resolve` (section 6): `admin` for Protected, `user` for User. No action class changes `visibility`, `control` or `on_failure`.

### 2. What lives where
| Concern | Crate | Squad |
|---|---|---|
| Frame codec, seams, `MemLink`, the link suite, connections | `grdr-wire` `frame`, `local` | core |
| Observations, reader seam, endpoint resolution, decision, verifiers, proofs | `grdr-wire` `peer_auth` (trust core) | security |
| `Connector` and `Link` on Linux and macOS (`socket`, `SO_SNDTIMEO`, `connect`, `read`, `write`), the Unix acceptor with a stop, adopted listeners | `grdr-os-service` | endpoint |
| `Connector` and `Link` on Windows (overlapped pipe client with identification QoS, `WaitNamedPipeW` while busy; pipe instances with the time each connect completed), the pipe acceptor with a stop | `grdr-os-service` | endpoint |
| `PeerReader` on each system | `grdr-peer-os` (trust core) | security |
| `Clock` adapters, accept loops, handlers, the shim's fallback | the programs (and `grdr-os-service` for the clock calls that need `unsafe`) | endpoint, adapters |

This refines the ruling on #1743, under which `grdr-os-service` handed back std or runtime stream types for `grdr-wire` to frame. It now hands back `Link` implementations, for connect and accept on Unix as well. The reason is that std gives Unix connect no deadline and Unix accept no stop, and the Windows deadlines need `unsafe`, so five of the six cells already need that crate. One crate then holds all local stream code (P17). `grdr-hook`, `grdr` and `grdr-tray` link `grdr-os-service`. It holds no content parser (ARCH-004) and keeps its trust-core lane.

### 3. Frame codec (`grdr_wire::frame`)
```rust
pub struct FrameCap { /* private: 1..=u32::MAX */ }
impl FrameCap { pub fn new(bytes: u32) -> Option<FrameCap>; pub fn get(self) -> u32; }
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
- `decode` is pure and stateless. With fewer than 4 bytes it returns `NeedMore { needed: 4 }`. When the declared length is above the cap it returns `TooLarge` as soon as the header is present, whatever follows. Otherwise it returns `NeedMore { needed: 4 + len }` until the body is complete, then `Frame` with the body and the bytes consumed. All arithmetic is checked, and an overflow is `TooLarge`.
- `encode` refuses a body longer than the cap with `BodyTooLarge` and writes nothing.
- Callers: the connections (section 5) and the fuzz and differential targets of #374.

### 4. Seams and the reference link (`grdr_wire::local`)
```rust
pub struct WireCall { /* private; pub(crate) fn new; no Clone */ }
pub struct FileTime(pub u64);              // Windows system time, 100 ns units since 1601 UTC
pub enum PeerRef<'a> {
    #[cfg(unix)] Socket(BorrowedFd<'a>),
    #[cfg(windows)] Pipe { pipe: BorrowedHandle<'a>, connected_at: Option<FileTime> },
    Memory,
}
pub enum Address { Socket(PathBuf), Pipe(String) }
pub enum LinkFault { TimedOut, Closed, Missing, NoListener, Busy, Denied, Os { code: i32 } }

pub trait Link: Send {
    fn read(&mut self, buf: &mut [u8], within: Duration, call: &WireCall) -> Result<usize, LinkFault>;
    fn write(&mut self, buf: &[u8], within: Duration, call: &WireCall) -> Result<usize, LinkFault>;
    fn peer(&self, call: &WireCall) -> PeerRef<'_>;
}
pub trait Connector: Send + Sync {
    type Link: Link;
    fn connect(&self, address: &Address, within: Duration, call: &WireCall) -> Result<Self::Link, LinkFault>;
}

pub struct MemLink { /* private */ }
impl MemLink { pub fn pair(capacity: NonZeroUsize) -> (MemLink, MemLink); }
impl Link for MemLink;
```
The contract every `Link` meets, which the suite of section 10 checks:
- `read` is called with a non-empty `buf` and `within > 0`. It returns `Ok(n)` with `1 <= n <= buf.len()`; `Ok(0)` when it returned early with nothing (a signal, a spurious wake-up), after which `grdr-wire` calls again with the time left; `Err(Closed)` at end of stream, never `Ok(0)`; `Err(TimedOut)` no earlier than `within` and no later than `within` plus the platform's timer granularity; or another fault. It never returns `Interrupted`.
- `write` has the same contract. A write to a closed peer is `Err(Closed)`, never a signal: Rust programs ignore `SIGPIPE`, and the Unix link also sets `MSG_NOSIGNAL` or `SO_NOSIGPIPE`.
- `peer` returns the descriptor or handle the reader inspects. A Windows server link sets `connected_at` to the time its connect completed; a client link sets `None`. `MemLink` returns `Memory`, and every real reader answers `Memory` with `Unsupported`.
- Dropping a link closes it.
- `connect` waits at most `within`. Linux sets `SO_SNDTIMEO` before `connect(2)`; macOS fails at once on a full backlog; Windows retries `ERROR_PIPE_BUSY` through `WaitNamedPipeW` with the time left. It maps a missing path or pipe to `Missing`, no listener to `NoListener`, no free pipe instance at the deadline to `Busy`, and a refused open to `Denied`. The Windows connector always opens with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, which std's `OpenOptionsExt::security_qos_flags` sets (https://doc.rust-lang.org/std/os/windows/fs/trait.OpenOptionsExt.html, read 2026-11-20), so a hostile server can identify the caller but not impersonate it.

`MemLink` is the reference link: two bounded byte queues under a mutex and condition variable, closed on drop. Daemon and handler tests use it with a test reader.

Callers in slice 0: the connections, the verifiers, the suite, and `grdr-os-service`'s links.

### 5. Connections (`grdr_wire::local`)
```rust
pub struct ClientConn<L: Link> { /* private */ }
impl<L: Link> ClientConn<L> {
    pub fn new(verified: VerifiedEndpoint<L>, cap: FrameCap) -> ClientConn<L>;
    pub fn endpoint(&self) -> &EndpointIdentity;
    pub fn state(&self) -> ConnState;
    pub fn send<C: Clock>(&mut self, body: &[u8], clock: &C, deadline: Monotonic) -> Result<(), WireError>;
    pub fn recv<C: Clock>(&mut self, clock: &C, deadline: Monotonic) -> Result<Vec<u8>, WireError>;
}
pub struct ServerConn<L: Link> { /* private */ }
impl<L: Link> ServerConn<L> {
    pub fn new(verified: VerifiedPeer<L>, cap: FrameCap) -> ServerConn<L>;
    pub fn peer(&self) -> &PeerIdentity;
    pub fn state(&self) -> ConnState;
    pub fn send<C: Clock>(&mut self, body: &[u8], clock: &C, deadline: Monotonic) -> Result<(), WireError>;
    pub fn recv<C: Clock>(&mut self, clock: &C, deadline: Monotonic) -> Result<Vec<u8>, WireError>;
}
pub enum ConnState { Ready, Broken }
#[non_exhaustive]
pub enum WireError {
    FrameTooLarge { declared: u32, cap: FrameCap },
    BodyTooLarge(BodyTooLarge),
    Truncated,
    Broken,
    Link(LinkFault),
}
```
- A connection exists only from a proof (section 11, f06 and f12). The proof's direction fixes the type: a client proof cannot make a `ServerConn`.
- `recv` reads exactly the 4 header bytes, checks the cap with `frame::decode`, allocates exactly the declared length and reads the body. A length above the cap is `FrameTooLarge`, returned before any body byte is read or allocated.
- States and transitions. `Ready` stays `Ready` after a frame is sent or received, after `BodyTooLarge` (nothing was written), and after `Link(TimedOut)` when no byte of the frame had moved. Every other outcome moves to `Broken` and drops the link at once, so the peer sees the close: `FrameTooLarge`, `Truncated` (end of stream inside a frame), `Link(Closed)` at a frame boundary, a timeout after part of a frame, and any other fault. `Broken` is terminal: every call returns `Broken` without I/O, and dropping the connection is its exit.
- `send` and `recv` are blocking and `Send`, so a program may move a connection to a worker thread. Nothing retries inside `grdr-wire`; a retry is the caller's, through `retry::run` (ARCH-018).
- Callers: the shim (#377, #516), which waits for `DecideAck` with a deadline of its start plus the acknowledgement window and for `DecideResponse` with its verdict deadline (design/07 section 5), and the daemon's handlers (#1536, #157).

### 6. Endpoints (`grdr_wire::peer_auth`)
```rust
pub enum Place {
    Path(PathBuf),                 // absolute
    UnderRuntimeDir(PathBuf),      // relative, normal components only
    UnderHome(PathBuf),            // relative, normal components only
    Pipe(String),                  // full pipe name
    PipeForCaller(String),         // prefix; the caller's SID text is appended
}
pub enum OwnerSpec { Root, Caller, Sid(Sid) }
pub enum ExecutableRule { Exact(PathBuf), Within(PathBuf) }
pub struct EndpointSpec { pub place: Place, pub owner: OwnerSpec, pub trusted_groups: Vec<u32>, pub executable: Option<ExecutableRule> }
pub struct UserContext { pub runtime_dir: Option<PathBuf>, pub home: Option<PathBuf>, pub sid: Option<Sid> }
pub struct Endpoint { /* private: Address, the expectation */ }
impl Endpoint { pub fn address(&self) -> &Address; }
pub fn resolve(spec: &EndpointSpec, profile: InstallProfile, user: &UserContext) -> Result<Endpoint, ResolveError>;
pub enum UserPart { RuntimeDir, Home, Sid }
pub enum SpecFault { PathNotAbsolute, PathEscapes, OwnerForProfile, OwnerForPlace }
#[non_exhaustive]
pub enum ResolveError { UserContext(UserPart), Spec(SpecFault) }
```
- One resolver serves the shim, the CLI, the tray and the daemon (P17). #374 R3 and #516 R1 both build it today.
- `EndpointSpec` is one row of the per-OS, per-profile endpoint table in the configuration schema. Its defaults come from the brand manifest and the platform path tables (D-66; design/03 section 9), never from literals. `UserContext` holds the canonical runtime directory, home and caller SID, which the program reads once at start.
- `resolve` builds the address, and the expectation the verifier checks against. Rules:
  - `Path` must be absolute (by the host's path rules). The relative part of `UnderRuntimeDir` and `UnderHome` must be non-empty and contain only normal components. A base that is missing is `UserContext`; one that is not absolute is `PathNotAbsolute`.
  - `Root` fits only a socket address and `Sid` only a pipe address (`OwnerForPlace`).
  - Protected takes `Root` or `Sid` and gives `tamper: admin`; User takes `Caller` and gives `tamper: user` (D-48). Anything else is `OwnerForProfile`. This is the only place the grade is set.
- Every component of a configured socket path is a real directory, never a symlink (section 7). The macOS default therefore names the canonical directory under `/private`; #1549 settles the path (question 2).

### 7. Peer authentication (`grdr_wire::peer_auth`, trust core)
Identity and observation types:
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
pub enum SidError { Length { len: usize }, Revision { found: u8 }, SubAuthorities { count: u8 }, Text { index: usize } }
pub enum Principal { Uid(u32), Sid(Sid) }
pub struct UnixCred { pub pid: u32, pub uid: u32, pub gid: u32 }
pub enum PidfdSource { Kernel, Opened { named_pid: Option<u32>, named_uid: Option<u32>, alive_after: bool } }
pub enum ClientObservation {
    Linux { cred: UnixCred, pidfd: PidfdSource },
    Macos { token: AuditToken, pid: u32, pid_version: u32, euid: u32, egid: u32 },
    Windows { pid: u32, sid: Sid, integrity: IntegrityRid, created: FileTime, connected: Option<FileTime>, exited: bool },
}
pub enum ServerObservation {
    Linux { cred: UnixCred, executable: Option<PathBuf> },
    Macos { token: AuditToken, pid: u32, euid: u32, executable: Option<PathBuf> },
    Windows { pid: u32, sid: Sid, executable: Option<PathBuf> },
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
pub enum NodeKind { Directory, Socket, Symlink, Other }
pub struct NodeFacts { pub kind: NodeKind, pub uid: u32, pub gid: u32, pub mode: u32 }   // mode: st_mode & 0o7777
pub struct PathFacts { pub ancestors: Vec<NodeFacts>, pub socket: NodeFacts }            // ancestors from the root down
pub enum ReadFault { Gone, Unsupported, Denied, Os { code: i32 } }
```
Observations are plain data and compile on every target, so the mapping and the decision for all three systems run in one test on one host. Only `ProcessHold` is per OS. A hold confers nothing by itself; it reaches a program only inside a `PeerIdentity`.

The reader seam:
```rust
pub trait PeerReader: Send + Sync {
    fn caller(&self, call: &WireCall) -> Result<Principal, ReadFault>;
    fn client(&self, peer: PeerRef<'_>, call: &WireCall) -> Result<ClientReading, ReadFault>;
    fn server(&self, peer: PeerRef<'_>, call: &WireCall) -> Result<ServerObservation, ReadFault>;
    fn path(&self, socket: &Path, call: &WireCall) -> Result<PathFacts, ReadFault>;
    fn canonical(&self, path: &Path, call: &WireCall) -> Result<PathBuf, ReadFault>;
}
```
What each method reads, in `grdr-peer-os`:
- `caller`: the calling process's effective uid (Unix) or its token's user SID (Windows).
- `client`, on the server side, before any frame is read:
  - Linux: `SO_PEERCRED`, then `SO_PEERPIDFD`, which gives `Kernel`. Where that option is missing (`ENOPROTOOPT`), `pidfd_open(pid)`, then the pid in the pidfd's `fdinfo`, then the effective uid of that process (the second `Uid:` field of its status), then whether the pidfd still names a live process, which gives `Opened`. `SO_PEERCRED` reports the effective uid, so effective is compared with effective.
  - macOS: `LOCAL_PEERTOKEN` and the audit-token readers.
  - Windows: `GetNamedPipeClientProcessId`, then `OpenProcess` (the handle becomes the hold), then the token's SID and integrity level, the creation time from `GetProcessTimes` and whether the process has exited. `connected` is copied from `PeerRef::Pipe`.
- `server`, on the client side: the server's principal from `SO_PEERCRED`, the audit token or `GetNamedPipeServerProcessId`, and its canonical executable path where the system lets an unprivileged caller read it, otherwise `None`.
- `path`: `lstat` of every component of the socket path from the root down, and of the socket, never following a link.
- `canonical`: `std::fs::canonicalize`, so both sides of an executable comparison come from one function on one host.

Every call is a non-blocking system call or a local file-system read. A reader closes every descriptor and handle it opened before it returns an error.

Verifiers and proofs:
```rust
pub struct EndpointVerifier<'r, R> { /* private */ }
impl<'r, R: PeerReader> EndpointVerifier<'r, R> {
    pub fn new(reader: &'r R) -> EndpointVerifier<'r, R>;
    pub fn open<K: Connector, C: Clock>(&self, connector: &K, endpoint: &Endpoint, clock: &C, deadline: Monotonic)
        -> Result<VerifiedEndpoint<K::Link>, OpenError>;
}
pub struct PeerVerifier<'r, R> { /* private */ }
impl<'r, R: PeerReader> PeerVerifier<'r, R> {
    pub fn new(reader: &'r R) -> PeerVerifier<'r, R>;
    pub fn verify<L: Link>(&self, link: L) -> Result<VerifiedPeer<L>, Refusal>;
}
pub fn check_path<R: PeerReader>(reader: &R, endpoint: &Endpoint) -> Result<PathCheck, Refusal>;
pub enum PathCheck { Passed, NoPath }
pub enum OpenError { Unreachable(LinkFault), Refused(Refusal) }
pub struct VerifiedEndpoint<L> { /* private: L, EndpointIdentity */ }
impl<L> VerifiedEndpoint<L> { pub fn identity(&self) -> &EndpointIdentity; }
pub struct VerifiedPeer<L> { /* private: L, PeerIdentity */ }
impl<L> VerifiedPeer<L> { pub fn identity(&self) -> &PeerIdentity; }
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
pub enum Binding { Atomic, Confirmed }
pub enum Refusal {
    PeerGone, CredentialMismatch, Symlink, PathKind, DirectoryOwner, DirectoryMode,
    EndpointOwner, ServerPrincipal, ExecutableMismatch, Unsupported, ReadDenied, ReadFailed { os: i32 },
}
impl From<ReadFault> for Refusal;   // Gone to PeerGone, Unsupported, Denied to ReadDenied, Os to ReadFailed
```
The verifiers are concrete types, not traits (Rule 4). `EndpointVerifier::open` connects through the connector to `endpoint.address()` with the time left, then checks; a connect fault is `Unreachable` and a failed check is `Refused`. The link is dropped (closed) on every refusal. `check_path` runs the same path rule for the daemon at start (#683 R2, #1745), so the shim and the daemon share one rule (P17); on a pipe address it returns `NoPath`, never a silent pass.

**Client decision**, after connect and before any byte is written. The expected principal is `Uid(0)` for `Root`, the given SID for `Sid`, and `caller()` for `Caller`. On Unix the superuser, uid 0, also fits wherever the expected principal is a uid. The first matching row wins:

| # | Condition | Outcome |
|---|---|---|
| 1 | A read fails | `From<ReadFault>` |
| 2 | Socket address, and any ancestor or the socket is a symlink | `Symlink` |
| 3 | An ancestor is not a directory, or the socket is not a socket | `PathKind` |
| 4 | An ancestor's owner is neither uid 0 nor the expected uid | `DirectoryOwner` |
| 5 | An ancestor is other-writable, or group-writable with a gid outside `trusted_groups` | `DirectoryMode` |
| 6 | The socket's owner is neither uid 0 nor the expected uid | `EndpointOwner` |
| 7 | The server principal does not fit the expected principal | `ServerPrincipal` |
| 8 | An executable rule is set, and the server executable is `None`, differs from the canonical `Exact` path, or is not strictly inside the canonical `Within` directory (whole components) | `ExecutableMismatch` |
| 9 | Otherwise | `VerifiedEndpoint` with the server principal and the endpoint's `tamper` |

The socket's own mode is not checked. Connecting needs write permission on the socket inode, so the Protected socket is world-writable by design. Who may replace it is decided by its directory, which rows 4 and 5 check up to the root. `trusted_groups` comes from configuration and defaults to empty. It exists so that a system directory writable by a system group can be admitted as data, with evidence, without a code change (question 2).

**Server decision**, on accept and before any frame is read:

| Observation | Condition, in order | Outcome |
|---|---|---|
| Linux `Kernel` | | `Atomic` |
| Linux `Opened` | not `alive_after`, or `named_pid` is `None` | `PeerGone` |
| | `named_pid` differs from `cred.pid`, or `named_uid` differs from `cred.uid` | `CredentialMismatch` |
| | otherwise | `Confirmed` |
| macOS | | `Atomic` (the token names one process instance) |
| Windows | `exited` | `PeerGone` |
| | `connected` is `None` | `Unsupported` |
| | `created` is later than `connected`, so the pid now names a process that started after the client connected | `PeerGone` |
| | otherwise | `Confirmed` |

A pass yields `VerifiedPeer` with the pid, the principal (`Uid` of the effective uid, or `Sid`), the binding, the integrity level on Windows and the hold. The daemon derives the process key from the hold, never from the pid (#25). What remains open: on Linux before 6.5, a recycled pid with the same uid, which is the same principal (#375's threat model); on Windows, a backward step of the system clock between the client's exit and the reuse of its pid. The same step taken between a client's creation and its connect refuses a real client, which then takes the table path.

### 8. Waits and their exits
| Wait | Where | Exits |
|---|---|---|
| `Connector::connect` | `grdr-os-service` | connected; a fault; `within` elapsed (`SO_SNDTIMEO` on Linux, an immediate refusal on macOS, `WaitNamedPipeW` on Windows) |
| `Link::read`, `Link::write` | `grdr-os-service`, `MemLink` | bytes moved; a fault; `within` elapsed (`TimedOut`); an early `Ok(0)` |
| `send`, `recv`, `open` | `grdr-wire` | done; a fault; the deadline, after which no seam is called |
| Reader calls | `grdr-peer-os` | return at once. A home directory on a network file system that stops answering blocks `lstat`; the program's watchdog ends it (design/07 section 5) |
| Accept | `grdr-os-service` acceptor, outside this surface | a connection; a fault; the acceptor's stop handle, which the handover of design/11 section 8 needs; process end |
| `MemLink` condition wait | `grdr-wire` | data; close; `within` elapsed |

No wait in `grdr-wire` has the end of the process as its only exit.

### 9. Error codes
Areas for `schema/codes/areas.toml`: `WIRE` (IPC framing and local links; design/07, core) and `PEER` (IPC peer authentication; design/02 TM-4, security). Two areas give each squad its own registry file and write set. A refusal of class `policy` is tamper evidence: the shim writes the tamper marker for those only (#516 R3, #1574), and takes the table path without a marker for every other class.

| Code | Reason | Class | Connect | Bound by | Next step (`code.<code>.fix`) |
|---|---|---|---|---|---|
| `GRDR-WIRE-0001` | `FRAME_TOO_LARGE` | input | `resource_exhausted` | `WireError::FrameTooLarge` | |
| `GRDR-WIRE-0002` | `BODY_TOO_LARGE` | internal | `invalid_argument` | `BodyTooLarge`, `WireError::BodyTooLarge` | |
| `GRDR-WIRE-0003` | `FRAME_TRUNCATED` | retryable | `unavailable` | `WireError::Truncated` | |
| `GRDR-WIRE-0004` | `CONNECTION_BROKEN` | internal | `failed_precondition` | `WireError::Broken` | |
| `GRDR-WIRE-0005` | `LINK_TIMED_OUT` | retryable | `deadline_exceeded` | `LinkFault::TimedOut` | |
| `GRDR-WIRE-0006` | `PEER_CLOSED` | retryable | `unavailable` | `LinkFault::Closed` | |
| `GRDR-WIRE-0007` | `ENDPOINT_MISSING` | retryable | `unavailable` | `LinkFault::Missing` | Start the service; `grdr doctor` shows its state |
| `GRDR-WIRE-0008` | `ENDPOINT_NOT_LISTENING` | retryable | `unavailable` | `LinkFault::NoListener` | Restart the service; `grdr doctor` shows its state |
| `GRDR-WIRE-0009` | `ENDPOINT_BUSY` | retryable | `resource_exhausted` | `LinkFault::Busy` | Retried by the caller; raise the pipe instance count if it repeats |
| `GRDR-WIRE-0010` | `ENDPOINT_ACCESS_DENIED` | fatal | `permission_denied` | `LinkFault::Denied` | Check the endpoint's access list for this profile |
| `GRDR-WIRE-0011` | `LINK_FAILED` | retryable | `unavailable` | `LinkFault::Os` | |
| `GRDR-PEER-0001` | `PEER_GONE` | retryable | `unavailable` | `Refusal::PeerGone`, `ReadFault::Gone` | |
| `GRDR-PEER-0002` | `CREDENTIAL_MISMATCH` | policy | `unauthenticated` | `Refusal::CredentialMismatch` | |
| `GRDR-PEER-0003` | `ENDPOINT_SYMLINK` | policy | `unauthenticated` | `Refusal::Symlink` | Remove the link and reinstall; the endpoint path must be real directories |
| `GRDR-PEER-0004` | `ENDPOINT_PATH_KIND` | policy | `unauthenticated` | `Refusal::PathKind` | |
| `GRDR-PEER-0005` | `DIRECTORY_OWNER` | policy | `unauthenticated` | `Refusal::DirectoryOwner` | Another account owns a directory on the endpoint path; `grdr doctor` names it |
| `GRDR-PEER-0006` | `DIRECTORY_MODE` | policy | `unauthenticated` | `Refusal::DirectoryMode` | Remove group and other write from the directory `grdr doctor` names |
| `GRDR-PEER-0007` | `ENDPOINT_OWNER` | policy | `unauthenticated` | `Refusal::EndpointOwner` | |
| `GRDR-PEER-0008` | `SERVER_PRINCIPAL` | policy | `unauthenticated` | `Refusal::ServerPrincipal` | |
| `GRDR-PEER-0009` | `EXECUTABLE_MISMATCH` | policy | `unauthenticated` | `Refusal::ExecutableMismatch` | |
| `GRDR-PEER-0010` | `PEER_AUTH_UNSUPPORTED` | fatal | `failed_precondition` | `Refusal::Unsupported`, `ReadFault::Unsupported` | Run a supported system version (`grdr doctor`) |
| `GRDR-PEER-0011` | `PEER_READ_DENIED` | fatal | `permission_denied` | `Refusal::ReadDenied`, `ReadFault::Denied` | |
| `GRDR-PEER-0012` | `PEER_READ_FAILED` | retryable | `unavailable` | `Refusal::ReadFailed`, `ReadFault::Os` | |
| `GRDR-PEER-0013` | `SID_INVALID` | input | `invalid_argument` | `SidError` | Correct the SID in the endpoint configuration |
| `GRDR-PEER-0014` | `USER_CONTEXT_MISSING` | fatal | `failed_precondition` | `ResolveError::UserContext` | |
| `GRDR-PEER-0015` | `ENDPOINT_SPEC_INVALID` | fatal | `failed_precondition` | `ResolveError::Spec` | Correct the endpoint row of the configuration |

`WireError::Link`, `OpenError::Unreachable` and `OpenError::Refused` take the code of what they carry. A refusal never carries a path or an identifier, so logging one is safe. Each item registers the codes its area constructs (ARCH-017): #374 registers 0002 and 0005 to 0011 and both area rows, #1606 registers 0001, 0003 and 0004, and #375 registers the `PEER` codes. The English in the last column is the source of each `fix` token; the item that registers a code writes the rest.

### 10. References and cases
- `local::conformance` runs on any `Link`:
  ```rust
  pub struct LinkPair<L> { pub near: L, pub far: L }
  pub trait PairSource { type Link: Link; fn pair(&mut self) -> Result<LinkPair<Self::Link>, LinkFault>; }
  pub enum PeerKind { Os, Memory }
  pub struct CaseResult { pub name: &'static str, pub failure: Option<String> }
  pub struct Report { pub results: Vec<CaseResult> }
  impl Report { pub fn passed(&self) -> bool; }
  pub fn run<S: PairSource, C: Clock>(source: &mut S, clock: &C, wait: Duration, margin: Duration, peer: PeerKind) -> Report;
  ```
  Cases: `round_trip` (bytes arrive whole and in order across partial reads), `read_times_out` (a silent peer gives `TimedOut` no earlier than `wait` and no later than `wait + margin`), `read_after_close`, `write_after_close` (`Closed`, no signal, no hang), `peer_kind`. `grdr-wire` runs it on `MemLink`; `grdr-os-service` runs it on each real link in its own tests, with `margin` from `limits.toml`. Test-kit types carry no code (ARCH-017 exemption list).
- Connection cases, on `MemLink`: golden frames (empty, one byte, a body at the cap); an over-cap header refused before a counting link is asked for a body byte; `Truncated`; every transition of section 5; the 1,000,000-stream differential of #374 AC-1 against a splitter written in the test.
- Decision cases: a reference model in `peer_auth/model/reference.rs`, written from the two tables above and not from the code, and an exhaustive differential over the finite space. That space is three kinds of owner (0, caller, other) and four node kinds for each of three nodes; the group and other write bits with a trusted and an untrusted gid; four server principals; executable present, absent, inside and outside; every `PidfdSource` arm; and the Windows `exited`, `connected` and ordering cases. The test asserts that the number of combinations equals the product of the domain sizes.
- Proof cases: a `compile_fail` doctest for each attempt of section 11.

### 11. Compile sketch
The sketch (`grdr_wire.rs` with stand-ins for `Monotonic`, `Clock`, `InstallProfile`, `Tamper` and `LogSafe`; `adapter.rs` standing in for `grdr-os-service` and `grdr-peer-os` and using only public items; `program.rs` composing both sides on the host) was built with `rustup run 1.99.1 rustc --edition 2024`, `#![forbid(unsafe_code)]` in both library crates:
- `grdr_wire.rs` as an rlib for `x86_64-pc-windows-msvc`: exit 0, no warnings. With `--emit=metadata` for `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`: exit 0 each.
- `adapter.rs`: a `Link` and a `Connector` over std `UnixStream` and over a Windows pipe `File` with identification QoS, and `PeerReader` impls that build `PathFacts` from `symlink_metadata` and build Linux, macOS and Windows readings with their holds. Exit 0 on all three targets.
- `program.rs` on Windows: exit 0, 33 checks passed. They cover the codec, the link suite on `MemLink`, the resolver's four refusals and SID text, a verified client and server exchanging frames with `tamper: admin` and `Binding::Confirmed`, `FrameTooLarge` breaking the connection, `ServerPrincipal`, `ExecutableMismatch`, `Unreachable(NoListener)`, the whole Unix path table decided on Windows (symlink, other write, trusted and untrusted group, directory and endpoint owner, path kind, a non-root server in Protected, and a mode 0666 socket that passes), the Linux and Windows server tables, and a boundary timeout that leaves the connection `Ready`. It also asserts `Send` for `ClientConn`, `ServerConn` and `VerifiedPeer`.
- Forgery attempts, each its own crate against the rlib. Each must fail, and each fails with exit 1:

| # | Attempt | Error |
|---|---|---|
| f01 | `VerifiedEndpoint { link, identity }` | E0451 |
| f02 | `WireCall { _private: () }` | E0451 |
| f03 | `WireCall::new()` | E0624 |
| f04 | a `Link` impl storing `call` in a `&'static WireCall` field | lifetime may not live long enough |
| f05 | `call.clone()` as a `WireCall` | E0308 |
| f06 | `ClientConn::new(raw_link, cap)` | E0308 |
| f07 | `Endpoint { address, expect }` | E0451 |
| f08 | a `PeerIdentity` literal | E0451 |
| f09 | `Refusal::PeerGone.into()` as `VerifiedPeer` | E0277 |
| f10 | `verified.link` | E0616 |
| f11 | `verified.into_parts()` | E0624 |
| f12 | `ServerConn::new(verified_endpoint, cap)` | E0308 |
| f13 | `link.read(.., &WireCall::new())` from a program | E0624 |
| f14 | `connector.connect(.., &WireCall { .. })` from a program | E0451 |

One route remains open to the types: a crate implementing `PeerReader` with invented observations. ARCH-028 closes it (Rule 3), as the port-implementation scan does for RFC 0002.

### 12. Stability and later change
- `grdr-wire` enters `surfaces.toml` as `experimental` (ADR-0020; design/03 section 7), through the protected-change item filed on acceptance. Every change still goes by RFC: a signature, a variant, a decision row, a suite case or a code is an amendment that names RFC 0003, and its pull requests name the amendment for `rfc-required`. `cargo public-api` and `cargo semver-checks` run once the entry exists.
- The frame format (4-byte little-endian length, then the body) is the local IPC contract of design/03 section 7. It is restated here, not changed. The shim and the daemon keep one release of skew.
- Amendments expected, each with its item: an async driver over the same codec and proofs, once an async runtime is admitted to design/03 section 13; the `Dialer` (24 section 3) with the uplink; inherited channels (`SOCK_SEQPACKET` pairs and anonymous pipes) as `Link` impls, with a server rule that the peer is the child the daemon spawned (#427); an expected-peer rule for the `provider` endpoint (07 section 7).

### 13. Mechanisms
| Decision | Mechanism | Built by |
|---|---|---|
| Rule 1 | The `grdr-wire` to `grdr-ports` edge and an empty third-party allow-list for `grdr-wire` in `architecture.toml`; ARCH-027 fails any raw OS binding in `grdr-wire` | #1751 for ARCH-027; the entries are a protected change filed on acceptance |
| Rule 2 | ARCH-007 through `cargo public-api` against `surfaces.toml`: no third-party type on the surface | The `surfaces.toml` item filed on acceptance |
| Rule 3, calls | The type system: `WireCall` (f02 to f05, f13, f14) as `compile_fail` doctests | #374 |
| Rule 3, impls | ARCH-028 `wire-seams`: an `impl` of `Link`, `Connector` or `PeerReader` only in the crates `architecture.toml` lists (`grdr-os-service`, `grdr-peer-os`, `grdr-wire`) and in test targets, over the workspace and the distribution closure | A lint item filed on acceptance; #1593 for the closure run |
| Rule 4 | Private fields and `compile_fail` doctests f01, f06 to f12 | #375 (proofs), #1606 (connections) |
| Decision tables | The reference model and the exhaustive differential of section 10 | #375 |
| Rule 5 and section 8 | The `read_times_out` case on `MemLink` and every real link; the connection timeout cases; a connect test against a full backlog on Linux and a busy pipe on Windows | #374, #1606, the `grdr-os-service` link item |
| Rule 7 | `Coded` with an exhaustive match, the registry, ARCH-017 | #280, #278, #374, #375, #1606 |
| One path rule | `check_path` called by the daemon (#683, #1745) | `eval-architecture`, on each of those pull requests |
| Stability | The `surfaces.toml` entry, `rfc-required`, `cargo semver-checks` | The protected-change item filed on acceptance |

### 14. Proposed changes to design documents, `architecture.toml` and the ruling on #1743
Each lands through an issue whose write set names its file, after acceptance.
- **design/03 section 2.** The `grdr-wire` row reads: "IPC and uplink framing, size caps, the local link, connector and peer-reader seams, the peer-authentication decision, and the `Dialer`". The same-layer edges gain `grdr-wire` to `grdr-ports`. A new row adds ARCH-028 `wire-seams`. The `grdr-os-service` row (#1671) adds "local links and connectors for every endpoint program".
- **design/07 section 2, "Peer checks, both directions".** The client checks the endpoint path's every component from the root, never the socket's mode, and refuses a symlink anywhere on it. Refusals are named as in section 7. The Protected macOS path follows #1549.
- **design/11 section 1, named endpoints.** The client-side check is RFC 0003's client table. The daemon runs the same path rule at start through `check_path`.
- **`architecture.toml`.** The edge, the empty allow-list, and the ARCH-028 list. ARCH-028 is the next free number: ARCH-027 is `os-adapter-only` (#1751), and RFC 0002's `context-mint` must take another number when that RFC is decided.
- **The decision record of #1743.** `grdr-os-service` also holds the client connectors and the links of both roles on Unix and Windows, and `grdr-hook`, `grdr` and `grdr-tray` link it (section 2).

### 15. What each item changes
This RFC is normative. Each lead writes these changes back into its item before readying it.
- **#374**: Keeps `frame`, the seams (`WireCall`, `PeerRef`, `Address`, `LinkFault`, `Link`, `Connector`), `MemLink` and `local::conformance`. It registers `WIRE-0002` and `0005` to `0011` and both area rows. R2 loses "decode error" (Rule 6). The socket client and server in R3 move to `grdr-os-service`, and the resolver moves to #375. R4's traits become the seams of section 4, with concrete verifiers in `peer_auth`. AC-4 (`SO_PEERCRED`) moves to the Linux reader. AC-5 becomes the f13 doctest, and AC-6 runs on `MemLink`. Now also blocked by #281 (`Clock`).
- **#1606**: Re-scoped to the connections of section 5 and `WIRE-0001`, `0003` and `0004`. Blocked by #374 and #375. Its macOS and Windows transports, R2's identification QoS included, move to the `grdr-os-service` link item.
- **#375**: The lead splits it in two. (a) `peer_auth` in `grdr-wire`: the types, `PeerReader`, resolution, the verifiers, the proofs, `check_path`, the reference model, the differential and the `PEER` codes in `schema/codes/peer.toml`. (b) The Linux reader in `crates/grdr-peer-os/src/linux/**`. Table changes: the `EndpointMode` row goes; ancestors are checked to the root under rows 4 and 5; `PeerUid` becomes `ServerPrincipal`; `PathKind`, `ReadDenied` and `ReadFailed` are added; uids are effective; the R9 fact space grows to section 10's.
- **#1549**: Moves to `crates/grdr-peer-os/src/macos/**` and implements `PeerReader` for macOS. The decision rows are in (a), so it adds none. On the macOS runner it records two facts. First, which process `LOCAL_PEERTOKEN` names on the client side when launchd created the listener (question 1). Second, the owner, group and mode of `/private/var/run` (question 2).
- **#555**: Moves to `crates/grdr-peer-os/src/windows/**`. R1's re-read of the pid gives way to the creation-time and exit rows of the server table, and the pipe link supplies the connect time. R4's QoS refusal goes: the connector always sets the flag, and `grdr-os-service`'s test proves the server gets only an identification-level token. `ServerIdentity` becomes `ServerPrincipal`. A denied `OpenProcess` is `ReadDenied`, not `CredentialMismatch`.
- **#683**: R2 calls `check_path`. R3 is `PeerVerifier` with the `grdr-peer-os` reader. Accept comes from `grdr-os-service`'s Unix acceptor, which has a stop. R7 changes to match.
- **#684**: R6 returns pipe links that implement `Link` and record the time each connect completed, through a pipe acceptor with a stop. R3 is `PeerVerifier`. The Windows `Connector` joins this item or the `grdr-os-service` link item, as lead-endpoint plans.
- **#372**: No change. `grdr-wire` never decodes the body, so R3's wrapper is decoded by the receiver through `grdr-proto`. The shim derives `deadline_ms` and its `Monotonic` deadlines from one start time.
- **#24**: The sub-issue table follows the splits above. AC-3 becomes `cargo run --locked -p grdr-archlint -- check`.

Downstream: #377 and #516 call `resolve`, `EndpointVerifier::open` and `ClientConn`; #516 R1's own resolver goes, and its R3 writes the tamper marker only for `policy`-class refusals. #1745 adopts listeners through the `grdr-os-service` acceptor. #1749 R1 gains the links, the connectors and an edge to `grdr-wire`. #1710 adds `InstallProfile` and `Tamper` to `grdr-model`. #1636's pages list every variant bound to a code.

## Surfaces changed
- `grdr-wire` (layer 2, public): modules `frame`, `local` (with `local::conformance`) and `peer_auth`. Class `experimental`.
- A new same-layer edge, `grdr-wire` to `grdr-ports`.
- `grdr-model` (layer 1, public): `InstallProfile` and `Tamper`, entering through the RFC of #1710.
- Data and gate files, as proposals: two code areas and their codes in `schema/codes`; entries in `surfaces.toml` and `architecture.toml`.
- No spine text, no protobuf package and no frame format changes.

## Alternatives
- **Verifier traits that the security module implements (#374 R4 as written).** Any crate could implement one and mint proofs. Rejected for concrete verifiers over a reader seam.
- **Readers that decide and return neutral facts.** The decision would move into `grdr-peer-os`, against #1757 R3. Rejected for observations that `grdr-wire` maps and decides.
- **A std Unix link inside `grdr-wire`.** Reads and writes work with std timeouts, but std gives connect no deadline and accept no stop, so the Unix half would be split across two crates. Rejected for one crate of local stream code.
- **An async API over a runtime's stream types (the ruling's "runtime stream types").** No runtime is admitted yet (design/03 section 13). Layer 2 has no Cargo features, so every host and the 2 MiB shim would link one (P5). Rejected for slice 0; an async driver over the same codec and proofs is an amendment.
- **Windows deadlines from a helper thread over a std `File`.** A timed-out read leaves a thread whose only exit is the server. A synchronous pipe handle also serialises its I/O, so a pending read blocks the next write. Rejected for overlapped links in `grdr-os-service`.
- **Links that hand out `BorrowedFd` or `BorrowedHandle` without a token.** A program could clone the handle to an owned one and write before verifying. Rejected.
- **Programs connect, then pass the link to the verifier.** A program could check one address and connect to another. Rejected for `open`, which connects to the address it checks.
- **An expectation the program builds.** A program could claim `tamper: admin` for a User endpoint. Rejected for `resolve`.
- **Checking only the socket's own directory (#375 as written).** A principal that can write a higher directory renames the directory. OpenSSH's `StrictModes` path check is the practice we follow; its source page was not readable here (Unresolved questions). Rejected.
- **One code area for both squads.** It puts security's codes in core's registry file. Rejected for `WIRE` and `PEER`.
- **A `grdr-wire-testkit` crate for `MemLink` and the suite.** A crate and a same-layer edge for two items. Rejected.
- **`Clock` moved into `grdr-model`, as `Entropy` is, to avoid the edge.** It reopens RFC 0002 section 3. Rejected; it is the fallback if RFC 0002 moves `Clock`.

## Drawbacks
- `grdr-os-service`, a privileged trust-core crate, is linked by untrusted programs, and its ordinary I/O code is reviewed in the trust-core lane.
- Blocking calls only. The daemon serves connections on threads until an async driver exists.
- Every seam method takes a token its implementer cannot use, which is unusual to read.
- ARCH-028 carries the one remaining forgery route, so the lint must run on the distribution closure before a contrib reader could ship.
- The ancestor rule can refuse a real install whose system directories have unusual modes, until `trusted_groups` data covers it. The cost is a table-path decision and a tamper finding.
- The Windows pid-reuse row compares wall-clock times (section 7).

## Unresolved questions
1. **The executable expectation per system (#464).** Under socket activation the service manager creates the listener, so it is not yet established which process the client's peer credentials name on Linux and macOS. Lean: no executable rule on Linux (#464's proposal); on macOS, a rule only once #1549 shows that `LOCAL_PEERTOKEN` names the daemon. Either way it is configuration data and the surface does not change.
2. **The macOS Protected path under the ancestor rule.** If `/private/var/run` is group-writable, the choice is a trusted gid as data, when its group is a system group, or a path under `/Library`. Settled by #1549's evidence.
3. **`InstallProfile` and `Tamper` in `grdr-model`.** Lean: they join the RFC of #1710 (comment on #1710).
4. **`Clock`.** This surface uses RFC 0002's `Clock`, and that RFC waits on the owner after its third round. If `Clock` moves, this RFC follows by amendment.
5. **Not checked:** the man pages for `unix(7)` and `SO_PEERCRED` (man7.org is not in the fetch allow-list) and OpenSSH's `safe_path` source (the GitHub page was truncated). The claims that rest on them are that connect needs write permission on the socket, that `SO_PEERCRED` reports the effective uid, that a full Linux backlog makes connect wait, and the ancestor-walk practice. They come from prior knowledge, and each has a case above that would fail if it were wrong.

## Review
Pending: the persona council, one comment per seat, and `eval-architecture`, on #1757.

## Decision
Pending.
