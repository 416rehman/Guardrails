# bpf

The kernel programs under `bpf/` are offered under `GPL-2.0-only OR BSD-2-Clause` (ADR-0004). You may use them under either licence. The texts are in `LICENSE-GPL-2.0` and `LICENSE-BSD-2-Clause` in this directory.

## Why two licences

The Linux kernel lets a program call its GPL-only helper functions only when the program's licence string is GPL-compatible. The compiled object therefore declares `Dual BSD/GPL`. BSD-2-Clause is the second licence so that a project that embeds these programs does not take on copyleft terms.

## The rest of this repository

Code outside `bpf/` is under the root `LICENSE` unless `security/supply-chain/licence-headers.toml` or design/30 section 1 gives its path another licence.

## Contributions

A contribution under `bpf/` is offered under both licences. Each source file under `bpf/` starts with an `SPDX-License-Identifier` line naming the expression and an `SPDX-FileCopyrightText` line naming the copyright holder.
