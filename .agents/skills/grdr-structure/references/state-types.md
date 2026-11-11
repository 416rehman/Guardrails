# Replacing an implicit state machine with a state type

Rule 3 of `SKILL.md`. Use this when S4 or A01 reports a finding, or when you are about to add a flag, a status value or an `Option` to a type that already has a lifecycle.

## 1. Write the machine down first

Before touching code, list:

1. **States**: every situation the value can be in, in the spine's vocabulary.
2. **Events**: what moves it (a call, a reply, a timer, a restart, an error).
3. **Transitions**: from, event, to. One row each.
4. **Data per state**: what is known only in that state. A field that is `None` in some states belongs to the states where it is `Some`.
5. **Exits**: for every non-terminal state, the event that leaves it on success, failure, cancel, timeout or restart. A state with no exit is a hang; add the exit before the type.
6. **Combinations the old fields allowed that no transition produces.** These are the bugs the new type removes. Name one in the hand-off.

## 2. Rust: an enum that owns its data

Before: four fields that together encode one lifecycle, with combinations no transition should produce (`written && !probed`, `canary_seen` with `error` set).

```rust
pub struct Install {
    probed: bool,
    written: bool,
    canary_seen: bool,
    status: String,
    journal: Option<Journal>,
    error: Option<InstallError>,
}
```

After: each variant is one state and carries exactly what that state knows.

```rust
pub enum Install {
    Probed { target: Target },
    Written { target: Target, journal: Journal, since: Instant },
    Effective { target: Target, journal: Journal, canary: CanaryProof },
    ConfiguredNotEffective { target: Target, journal: Journal },
    Failed { target: Target, error: InstallError },
}

impl Install {
    pub fn write(self, journal: Journal, now: Instant) -> Result<Self, InstallError> {
        match self {
            Self::Probed { target } => Ok(Self::Written { target, journal, since: now }),
            other => Err(InstallError::out_of_order(other.name(), "write")),
        }
    }

    pub fn canary_fired(self, canary: CanaryProof) -> Self {
        match self {
            Self::Written { target, journal, .. } => Self::Effective { target, journal, canary },
            other => other,
        }
    }

    pub fn canary_deadline(self, now: Instant, limit: Duration) -> Self {
        match self {
            Self::Written { target, journal, since } if now.saturating_duration_since(since) >= limit => {
                Self::ConfiguredNotEffective { target, journal }
            }
            other => other,
        }
    }
}
```

What changed:

- Transitions take `self` and return the next state, so a caller cannot keep using the old one.
- `Written` has two exits: the canary fires, or the deadline passes. The clock is an argument, so layers 0 and 1 stay free of I/O.
- An out-of-order event is an error with a code, not a silent no-op, unless the spec says the event is ignored in that state (then the `other => other` arm is the spec, and a test proves it).
- Code that asked `if written && !canary_seen` now matches `Install::Written { .. }`. The compiler finds every place that must handle a new state.

Add a transition test: one case per row of the table from step 1, plus one per removed illegal combination showing it can no longer be built.

## 3. Typestate, where it is cheap

When the sequence is fixed at compile time and the value is never stored beside values in other states, make the state a type parameter. An illegal call then fails to compile.

```rust
pub struct Grant<S> { digest: ActionDigest, state: S }
pub struct Minted;
pub struct Consumed { at: Instant }

impl Grant<Minted> {
    pub fn consume(self, at: Instant) -> Grant<Consumed> {
        Grant { digest: self.digest, state: Consumed { at } }
    }
}
```

Use the enum instead when states are stored in one collection, persisted, sent over the wire, or reached from many events: typestate there turns into boxing and `Any`. A `trybuild` compile-fail case for the illegal call is a type closure for A01 (`docs/team/04` section 5).

## 4. TypeScript: a discriminated union

```ts
type Install =
  | { kind: "probed"; target: Target }
  | { kind: "written"; target: Target; journal: Journal; since: number }
  | { kind: "effective"; target: Target; journal: Journal; canary: CanaryProof }
  | { kind: "configured-not-effective"; target: Target; journal: Journal }
  | { kind: "failed"; target: Target; error: InstallError };
```

Switch on `kind` and end with an exhaustiveness check (`const unreachable: never = install`), so adding a state fails the typecheck at every switch that misses it.

## 5. Papering over: what never closes a finding

- Another flag, counter or timestamp beside the existing ones.
- An assertion, `debug_assert!` or runtime check that two fields are never both set.
- A comment or a doc listing the legal combinations.
- A test alone. Tests prove the transitions; the type removes the illegal states.
- Renaming `status` to `kind` or `flags` so S4 stops matching.
- A wrapper type that holds the same fields.

## 6. When the type is not yours

If the type lives outside your write set, or changing it is a public-surface or wire change (layers 0 to 2, `proto/`, `schema/`: an RFC under D-61), do not add a local shadow of it. Hand off with the transition table from step 1 as the finding and a proposed issue for the redesign.
