#!/bin/bash -eu
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

cd "${SRC}/guardrails"

NIGHTLY_TOOLCHAIN="$(cd / && env -u RUSTUP_TOOLCHAIN rustup toolchain list | awk '/^nightly/{print $1; exit}')"
if [ -z "${NIGHTLY_TOOLCHAIN}" ]; then
  echo "GRDR-FUZZ-0001: pre-installed nightly Rust toolchain is missing in container" >&2
  exit 1
fi
export RUSTUP_TOOLCHAIN="${NIGHTLY_TOOLCHAIN}"

LOCK_BEFORE="$(sha256sum fuzz/Cargo.lock | awk '{print $1}')"
cargo fetch --manifest-path fuzz/Cargo.toml --locked
export CARGO_NET_OFFLINE=true

if [ -n "${SANITIZER:-}" ]; then
  cargo fuzz build -O --sanitizer "${SANITIZER}"
else
  cargo fuzz build -O
fi

LOCK_AFTER="$(sha256sum fuzz/Cargo.lock | awk '{print $1}')"
if [ "${LOCK_BEFORE}" != "${LOCK_AFTER}" ]; then
  echo "GRDR-FUZZ-0002: fuzz/Cargo.lock modified during fuzz build" >&2
  exit 1
fi

FUZZ_TARGET_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"
if [ ! -d "${FUZZ_TARGET_DIR}" ]; then
  FUZZ_TARGET_DIR="target/x86_64-unknown-linux-gnu/release"
fi

for target in \
  fuzz_normalizers \
  fuzz_hook_codec \
  fuzz_wire_frame \
  fuzz_cedar_compile \
  fuzz_mcp_jsonrpc \
  fuzz_llm_proto \
  fuzz_tuf_dsse \
  fuzz_otlp \
  fuzz_pack_manifest \
  fuzz_fastpath_scan
do
  cp "${FUZZ_TARGET_DIR}/${target}" "${OUT}/${target}"
done
