# ADR-0004: Apache-2.0 code, dual-licensed eBPF, dual-licensed docs, no CLA and no sign-off

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-02, D-61
- Requires: nothing
- RFC: not required: restates D-02 as repository mechanism
- Work items: [WI-0004]

## Context
EDR vendors can embed and foundations can accept only a permissive licence (briefs 28, 10, 27; review c6). Kernel programs must be GPL-compatible to load. Owner instruction 7 removed commit signatures and DCO checks with every other human gate.

## Decision
All code, the server included, is Apache-2.0. eBPF kernel programs are `GPL-2.0-only OR BSD-2-Clause` in their own crate outside the workspace. Content is Apache-2.0 with no attribution duty. Docs are `Apache-2.0 OR CC-BY-4.0`. There is one root `LICENSE`, SPDX headers on source files, no contributor licence agreement, and no `Signed-off-by` or DCO check. Copyleft and source-available code is on a do-not-read list.

## Enforced by
The SPDX licence lint; `cargo deny` licence checks per build profile against `supply-chain/licences.toml`; `supply-chain/do-not-read.toml`; gate V24, which refuses any commit message with a trailer.

## Consequences
Anyone may embed, rebuild and resell the product. A dependency under a licence outside the allow-list cannot enter without a protected change to the list.

## Alternatives rejected
- AGPL for the server: embedders and foundations refuse it.
- Open core: P11 forbids withheld features.
- A CLA or DCO: no person certifies a commit, and neither is needed for an inbound Apache-2.0 contribution.

## Revisit when
Never after the first public release. One go or no-go review of the server licence is held before it (D-02).
