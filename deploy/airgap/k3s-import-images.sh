#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
set -euo pipefail

# Verified offline k3s container image archive staging (signed manifest, strict allowlist, symlink-safe).
# Usage: k3s-import-images.sh <verified_images_dir> [k3s_images_dir] [trusted_root_or_keyring]

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 <verified_images_dir> [k3s_images_dir] [trusted_root_or_keyring]" >&2
  exit 2
fi

SRC_DIR="$1"
while [ "${#SRC_DIR}" -gt 1 ] && [ "${SRC_DIR%/}" != "$SRC_DIR" ]; do
  SRC_DIR="${SRC_DIR%/}"
done
DEST_DIR="${2:-/var/lib/rancher/k3s/agent/images}"
while [ "${#DEST_DIR}" -gt 1 ] && [ "${DEST_DIR%/}" != "$DEST_DIR" ]; do
  DEST_DIR="${DEST_DIR%/}"
done
TRUST_ARG="${3:-}"
MANIFEST="$SRC_DIR/images.sha256"

if [ ! -d "$SRC_DIR" ] || [ -L "$SRC_DIR" ]; then
  echo "GRDR-K3S-0001: source directory missing or symlink: $SRC_DIR" >&2
  exit 1
fi
if [ ! -f "$MANIFEST" ] || [ -L "$MANIFEST" ]; then
  echo "GRDR-K3S-0002: missing required digest manifest: $MANIFEST" >&2
  exit 1
fi
if [ -L "$DEST_DIR" ]; then
  echo "GRDR-K3S-0003: destination directory cannot be a symlink: $DEST_DIR" >&2
  exit 1
fi
if find "$SRC_DIR" -type l | grep -q .; then
  echo "GRDR-K3S-0004: symlinks forbidden in image staging directory" >&2
  exit 1
fi

TMP_WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_WORK"
}
trap cleanup EXIT

dearmor_to_keyring() {
  local in_key="$1"
  local out_gpg="$2"
  if grep -q 'BEGIN PGP PUBLIC KEY BLOCK' "$in_key"; then
    gpg --batch --yes --dearmor -o "$out_gpg" "$in_key"
  else
    cp -f -- "$in_key" "$out_gpg"
  fi
}

SIGSTORE_BUNDLE="$SRC_DIR/images.sha256.sigstore.json"
GPG_SIG=""
if [ -f "$SRC_DIR/images.sha256.asc" ]; then
  GPG_SIG="$SRC_DIR/images.sha256.asc"
elif [ -f "$SRC_DIR/images.sha256.gpg" ]; then
  GPG_SIG="$SRC_DIR/images.sha256.gpg"
fi

if [ -f "$SIGSTORE_BUNDLE" ]; then
  if [ -L "$SIGSTORE_BUNDLE" ]; then
    echo "GRDR-K3S-0010: symlink forbidden on Sigstore bundle: $SIGSTORE_BUNDLE" >&2
    exit 1
  fi
  TRUST_ROOT="${TRUST_ARG:-${GRDR_TRUSTED_ROOT:-}}"
  if [ -z "$TRUST_ROOT" ] || [ ! -f "$TRUST_ROOT" ] || [ -L "$TRUST_ROOT" ]; then
    echo "GRDR-K3S-0010: missing or symlink Sigstore trusted_root.json (pass arg 3 or GRDR_TRUSTED_ROOT)" >&2
    exit 1
  fi
  "${GRDR_BIN:-grdr}" airgap verify-artefact \
    --artefact "$MANIFEST" \
    --bundle "$SIGSTORE_BUNDLE" \
    --trusted-root "$TRUST_ROOT" >/dev/null
elif [ -n "$GPG_SIG" ]; then
  if [ -L "$GPG_SIG" ]; then
    echo "GRDR-K3S-0011: symlink forbidden on GPG signature: $GPG_SIG" >&2
    exit 1
  fi
  KEYRING_SRC="${TRUST_ARG:-${GRDR_GPG_KEYRING:-}}"
  if [ -z "$KEYRING_SRC" ] || [ ! -f "$KEYRING_SRC" ] || [ -L "$KEYRING_SRC" ]; then
    echo "GRDR-K3S-0011: missing or symlink GPG keyring (pass arg 3 or GRDR_GPG_KEYRING)" >&2
    exit 1
  fi
  dearmor_to_keyring "$KEYRING_SRC" "$TMP_WORK/images-trusted.gpg"
  gpgv --keyring "$TMP_WORK/images-trusted.gpg" "$GPG_SIG" "$MANIFEST"
else
  echo "GRDR-K3S-0008: missing signed attestation (images.sha256.sigstore.json or images.sha256.asc/.gpg)" >&2
  exit 1
fi

declare -A manifest_digests=()
declare -a manifest_files=()

while IFS= read -r raw_line || [ -n "$raw_line" ]; do
  line="${raw_line%$'\r'}"
  if [ -z "$line" ]; then
    continue
  fi
  if [[ ! "$line" =~ ^([0-9a-fA-F]{64})\ [\*[:space:]]([A-Za-z0-9._+-]+)$ ]]; then
    echo "GRDR-K3S-0012: malformed images.sha256 line rejected: $line" >&2
    exit 1
  fi
  expected_digest="${BASH_REMATCH[1],,}"
  entry="${BASH_REMATCH[2]}"
  case "$entry" in
    .|..|*/*|*\\*)
      echo "GRDR-K3S-0012: unsafe filename in images.sha256: $entry" >&2
      exit 1
      ;;
    *.tar|*.tar.gz|*.tgz|*.oci.tar|*.tar.zst)
      ;;
    *)
      echo "GRDR-K3S-0012: unsupported archive extension in images.sha256: $entry" >&2
      exit 1
      ;;
  esac
  if [ -n "${manifest_digests[$entry]+x}" ]; then
    echo "GRDR-K3S-0013: duplicate filename in images.sha256: $entry" >&2
    exit 1
  fi
  archive_path="$SRC_DIR/$entry"
  if [ ! -f "$archive_path" ] || [ -L "$archive_path" ]; then
    echo "GRDR-K3S-0005: missing or symlink manifest image archive: $archive_path" >&2
    exit 1
  fi
  actual_line="$(sha256sum "$archive_path")"
  actual_digest="${actual_line%% *}"
  if [ "${actual_digest,,}" != "$expected_digest" ]; then
    echo "GRDR-K3S-0014: SHA-256 digest mismatch for $entry" >&2
    exit 1
  fi
  manifest_digests["$entry"]="$expected_digest"
  manifest_files+=("$entry")
done < "$MANIFEST"

if [ "${#manifest_files[@]}" -eq 0 ]; then
  echo "GRDR-K3S-0007: zero verified image entries in $MANIFEST" >&2
  exit 1
fi

while IFS= read -r -d '' found_archive; do
  rel="${found_archive#"$SRC_DIR"/}"
  if [[ "$rel" == */* ]] || [ -z "${manifest_digests[$rel]+x}" ]; then
    echo "GRDR-K3S-0009: unmanifested archive file forbidden in $SRC_DIR: $rel" >&2
    exit 1
  fi
done < <(find "$SRC_DIR" \( -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.oci.tar' -o -name '*.tar.zst' \) -print0)

mkdir -p "$DEST_DIR"
staged=0
for entry in "${manifest_files[@]}"; do
  src_file="$SRC_DIR/$entry"
  dst_file="$DEST_DIR/$entry"
  if [ -L "$dst_file" ]; then
    echo "GRDR-K3S-0006: refusing symlink destination: $dst_file" >&2
    exit 1
  fi
  cp -f -- "$src_file" "$dst_file"
  staged=$((staged + 1))
done

if [ "$staged" -eq 0 ]; then
  echo "GRDR-K3S-0007: zero image archives staged into $DEST_DIR" >&2
  exit 1
fi

echo "Verified and staged $staged offline container image archive(s) into $DEST_DIR"
