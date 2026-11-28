#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
set -euo pipefail

# Verified atomic air-gap APT and DNF/RPM site mirror sync (no plain HTTP fallback).
# Usage: sync-apt-dnf-mirror.sh <bundle_extract_dir> <mirror_docroot> <apt_keyring_gpg> [rpm_pubkey]

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 <bundle_extract_dir> <mirror_docroot> <apt_keyring_gpg> [rpm_pubkey]" >&2
  exit 2
fi

SRC_DIR="$1"
while [ "${#SRC_DIR}" -gt 1 ] && [ "${SRC_DIR%/}" != "$SRC_DIR" ]; do
  SRC_DIR="${SRC_DIR%/}"
done
DOCROOT="$2"
while [ "${#DOCROOT}" -gt 1 ] && [ "${DOCROOT%/}" != "$DOCROOT" ]; do
  DOCROOT="${DOCROOT%/}"
done
APT_KEYRING="$3"
RPM_PUBKEY="${4:-}"

if [ ! -d "$SRC_DIR" ] || [ -L "$SRC_DIR" ]; then
  echo "GRDR-MIRROR-0001: source directory missing or symlink: $SRC_DIR" >&2
  exit 1
fi
if [ ! -f "$APT_KEYRING" ] || [ -L "$APT_KEYRING" ]; then
  echo "GRDR-MIRROR-0002: APT trusted keyring missing or symlink: $APT_KEYRING" >&2
  exit 1
fi
if [ -L "$DOCROOT" ] || [ -L "$(dirname "$DOCROOT")" ]; then
  echo "GRDR-MIRROR-0013: mirror docroot or parent cannot be a symlink: $DOCROOT" >&2
  exit 1
fi
if find "$SRC_DIR" -type l | grep -q .; then
  echo "GRDR-MIRROR-0003: symlinks forbidden in extracted bundle source tree" >&2
  exit 1
fi
if [ ! -d "$SRC_DIR/apt" ] && [ ! -d "$SRC_DIR/rpm" ]; then
  echo "GRDR-MIRROR-0010: bundle extract contains neither apt/ nor rpm/ directory" >&2
  exit 1
fi

mkdir -p "$(dirname "$DOCROOT")"
STAGE_DIR="$(mktemp -d "${DOCROOT%/}.stage.XXXXXX")"
TEMP_WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$STAGE_DIR" "$TEMP_WORK"
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

extract_inrelease_body() {
  local inrel="$1"
  local out_body="$2"
  awk '
    BEGIN { in_msg = 0; seen_blank = 0 }
    /^-----BEGIN PGP SIGNED MESSAGE-----/ { in_msg = 1; next }
    in_msg == 1 && seen_blank == 0 && /^\r?$/ { seen_blank = 1; next }
    in_msg == 1 && /^-----BEGIN PGP SIGNATURE-----/ { exit }
    in_msg == 1 && seen_blank == 1 {
      sub(/\r$/, "")
      sub(/^- /, "")
      print
    }
  ' "$inrel" > "$out_body"
}

parse_apt_packages_debs() {
  local logical_name="$1"
  local pkg_file="$2"
  local out_file="$3"
  python3 - "$logical_name" "$pkg_file" "$out_file" <<'PYEOF'
import bz2, gzip, lzma, re, subprocess, sys

logical_name, pkg_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
if logical_name.endswith(".gz"):
    with gzip.open(pkg_path, "rb") as f:
        raw = f.read()
elif logical_name.endswith(".xz"):
    with lzma.open(pkg_path, "rb") as f:
        raw = f.read()
elif logical_name.endswith(".bz2"):
    with bz2.open(pkg_path, "rb") as f:
        raw = f.read()
elif logical_name.endswith(".zst"):
    raw = subprocess.check_output(["zstd", "-dc", pkg_path])
else:
    with open(pkg_path, "rb") as f:
        raw = f.read()

text = raw.decode("utf-8", errors="strict")
rows = []
for stanza in re.split(r"\r?\n\r?\n+", text.strip()):
    if not stanza.strip():
        continue
    fname, sha = None, None
    for line in stanza.splitlines():
        if line.startswith("Filename:"):
            fname = line.split(":", 1)[1].strip()
        elif line.startswith("SHA256:"):
            sha = line.split(":", 1)[1].strip().lower()
    if fname is not None:
        if not sha or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise SystemExit(f"GRDR-MIRROR-0026: Packages entry missing valid SHA256 for {fname}")
        if fname.startswith("/") or "\\" in fname or ".." in fname.split("/"):
            raise SystemExit(f"GRDR-MIRROR-0015: unsafe Filename in Packages: {fname}")
        rows.append((fname, sha))

with open(out_path, "a", encoding="utf-8") as out:
    for fname, sha in rows:
        out.write(f"{fname}\t{sha}\n")
PYEOF
}

verify_apt_suite_indices() {
  local apt_root="$1"
  local suite_dir="$2"
  local body_file="$3"
  local pkg_list_out="$4"
  if ! grep -Eq '^Acquire-By-Hash:[[:space:]]*yes[[:space:]]*$' "$body_file"; then
    echo "GRDR-MIRROR-0006: APT Release missing strict 'Acquire-By-Hash: yes' line in $suite_dir" >&2
    exit 1
  fi

  local entries_file="$TEMP_WORK/apt-sha256-entries.txt"
  awk '
    BEGIN { in_sha = 0 }
    /^SHA256:[[:space:]]*$/ { in_sha = 1; next }
    in_sha == 1 && /^[[:space:]]+[0-9a-fA-F]{64}[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]*$/ {
      sub(/\r$/, "")
      gsub(/^[[:space:]]+/, "")
      split($0, f, /[[:space:]]+/)
      printf "%s\t%s\t%s\n", tolower(f[1]), f[2], f[3]
      next
    }
    in_sha == 1 && /^[^[:space:]]/ { in_sha = 0 }
  ' "$body_file" > "$entries_file"

  if [ ! -s "$entries_file" ]; then
    echo "GRDR-MIRROR-0014: signed APT metadata missing SHA256 section: $suite_dir" >&2
    exit 1
  fi

  declare -A signed_hashes=()
  local verified_packages=0
  while IFS=$'\t' read -r expected_sha expected_size rel_path; do
    case "$rel_path" in
      /*|*..*|*\\*)
        echo "GRDR-MIRROR-0015: unsafe path in APT SHA256 section: $rel_path" >&2
        exit 1
        ;;
    esac
    signed_hashes["$expected_sha"]=1
    local direct_file="$suite_dir/$rel_path"
    local rel_dir
    rel_dir="$(dirname "$rel_path")"
    local by_hash_file="$suite_dir/$rel_dir/by-hash/SHA256/$expected_sha"
    local checked_any=0

    for candidate in "$direct_file" "$by_hash_file"; do
      if [ -f "$candidate" ]; then
        if [ -L "$candidate" ]; then
          echo "GRDR-MIRROR-0003: symlink forbidden on APT index: $candidate" >&2
          exit 1
        fi
        local actual_line actual_sha actual_size
        actual_line="$(sha256sum "$candidate")"
        actual_sha="${actual_line%% *}"
        actual_size="$(wc -c < "$candidate" | tr -d '[:space:]')"
        if [ "${actual_sha,,}" != "$expected_sha" ] || [ "$actual_size" != "$expected_size" ]; then
          echo "GRDR-MIRROR-0016: APT index digest/size mismatch on $candidate" >&2
          exit 1
        fi
        local cand_rel="${candidate#"$apt_root"/}"
        verified_apt_files["$cand_rel"]=1
        checked_any=1
        if [[ "$(basename "$rel_path")" =~ ^Packages(\.(gz|xz|bz2|zst))?$ ]]; then
          printf '%s\t%s\n' "$(basename "$rel_path")" "$candidate" >> "$pkg_list_out"
        fi
      fi
    done

    if [[ "$(basename "$rel_path")" =~ ^Packages(\.(gz|xz|bz2|zst))?$ ]] && [ "$checked_any" -eq 1 ]; then
      verified_packages=$((verified_packages + 1))
    fi
  done < "$entries_file"

  if [ "$verified_packages" -eq 0 ]; then
    echo "GRDR-MIRROR-0017: signed APT metadata verified zero Packages indices in $suite_dir" >&2
    exit 1
  fi

  while IFS= read -r -d '' disk_pkg; do
    local pkg_line pkg_sha
    pkg_line="$(sha256sum "$disk_pkg")"
    pkg_sha="${pkg_line%% *}"
    if [ -z "${signed_hashes[${pkg_sha,,}]+x}" ]; then
      echo "GRDR-MIRROR-0018: unsigned APT Packages index not attested in signed Release: $disk_pkg" >&2
      exit 1
    fi
  done < <(find "$suite_dir" -type f \( -name 'Packages' -o -name 'Packages.*' \) -print0)

  while IFS= read -r -d '' byhash_file; do
    local bh_name bh_line bh_sha
    bh_name="$(basename "$byhash_file")"
    bh_line="$(sha256sum "$byhash_file")"
    bh_sha="${bh_line%% *}"
    if [ "${bh_sha,,}" != "${bh_name,,}" ] || [ -z "${signed_hashes[${bh_sha,,}]+x}" ]; then
      echo "GRDR-MIRROR-0019: unattested or corrupt by-hash file: $byhash_file" >&2
      exit 1
    fi
  done < <(find "$suite_dir" -type f -path '*/by-hash/SHA256/*' -print0)
}

if [ -d "$SRC_DIR/apt" ]; then
  APT_SRC="$SRC_DIR/apt"
  dearmor_to_keyring "$APT_KEYRING" "$TEMP_WORK/apt-trusted.gpg"
  apt_verified_suites=0
  declare -A verified_suite_dirs=()
  declare -A verified_apt_files=()
  VERIFIED_PKG_INDICES="$TEMP_WORK/verified-apt-packages-list.txt"
  : > "$VERIFIED_PKG_INDICES"

  while IFS= read -r -d '' meta_file; do
    meta_name="$(basename "$meta_file")"
    suite_dir="$(dirname "$meta_file")"
    body_out="$TEMP_WORK/apt-release-body.txt"
    if [ "$meta_name" = "InRelease" ]; then
      gpgv --keyring "$TEMP_WORK/apt-trusted.gpg" "$meta_file"
      extract_inrelease_body "$meta_file" "$body_out"
    else
      if [ ! -f "${meta_file}.gpg" ] || [ -L "${meta_file}.gpg" ]; then
        echo "GRDR-MIRROR-0005: missing or symlink ${meta_file}.gpg" >&2
        exit 1
      fi
      gpgv --keyring "$TEMP_WORK/apt-trusted.gpg" "${meta_file}.gpg" "$meta_file"
      cp -f -- "$meta_file" "$body_out"
      verified_apt_files["${meta_file#"$APT_SRC"/}.gpg"]=1
    fi
    verified_apt_files["${meta_file#"$APT_SRC"/}"]=1
    verify_apt_suite_indices "$APT_SRC" "$suite_dir" "$body_out" "$VERIFIED_PKG_INDICES"
    verified_suite_dirs["$suite_dir"]=1
    apt_verified_suites=$((apt_verified_suites + 1))
  done < <(find "$APT_SRC" -type f \( -name 'InRelease' -o -name 'Release' \) -print0)

  if [ "$apt_verified_suites" -eq 0 ]; then
    echo "GRDR-MIRROR-0005: missing signed APT InRelease or Release.gpg in $APT_SRC" >&2
    exit 1
  fi
  if [ -d "$APT_SRC/dists" ]; then
    while IFS= read -r -d '' suite_candidate; do
      if [ -z "${verified_suite_dirs[$suite_candidate]+x}" ]; then
        echo "GRDR-MIRROR-0025: unverified APT suite directory missing signed Release/InRelease: $suite_candidate" >&2
        exit 1
      fi
    done < <(find "$APT_SRC/dists" -mindepth 1 -maxdepth 1 -type d -print0)
  fi

  DEB_ATTESTATIONS="$TEMP_WORK/apt-deb-hashes.txt"
  : > "$DEB_ATTESTATIONS"
  while IFS=$'\t' read -r logical_name pkg_idx; do
    [ -n "$pkg_idx" ] && parse_apt_packages_debs "$logical_name" "$pkg_idx" "$DEB_ATTESTATIONS"
  done < <(sort -u "$VERIFIED_PKG_INDICES")

  declare -A attested_debs=()
  while IFS=$'\t' read -r deb_rel deb_sha; do
    [ -z "$deb_rel" ] && continue
    if [ -n "${attested_debs[$deb_rel]+x}" ] && [ "${attested_debs[$deb_rel]}" != "$deb_sha" ]; then
      echo "GRDR-MIRROR-0026: conflicting SHA256 digests for $deb_rel across Packages indices" >&2
      exit 1
    fi
    attested_debs["$deb_rel"]="$deb_sha"
  done < "$DEB_ATTESTATIONS"

  while IFS= read -r -d '' deb_file; do
    deb_rel="${deb_file#"$APT_SRC"/}"
    if [ -z "${attested_debs[$deb_rel]+x}" ]; then
      echo "GRDR-MIRROR-0026: unverified .deb payload not listed in signed Packages index: $deb_rel" >&2
      exit 1
    fi
    actual_line="$(sha256sum "$deb_file")"
    actual_sha="${actual_line%% *}"
    if [ "${actual_sha,,}" != "${attested_debs[$deb_rel]}" ]; then
      echo "GRDR-MIRROR-0026: .deb SHA-256 mismatch for $deb_rel" >&2
      exit 1
    fi
    verified_apt_files["$deb_rel"]=1
  done < <(find "$APT_SRC" -type f -name '*.deb' -print0)

  if [ -f "$APT_SRC/SHA256SUMS" ]; then
    (cd "$APT_SRC" && sha256sum --strict -c SHA256SUMS)
    verified_apt_files["SHA256SUMS"]=1
  fi

  while IFS= read -r -d '' disk_file; do
    rel="${disk_file#"$APT_SRC"/}"
    if [ -z "${verified_apt_files[$rel]+x}" ]; then
      echo "GRDR-MIRROR-0026: unverified file forbidden in APT mirror tree: $rel" >&2
      exit 1
    fi
    mkdir -p "$STAGE_DIR/apt/$(dirname "$rel")"
    cp -f -- "$disk_file" "$STAGE_DIR/apt/$rel"
  done < <(find "$APT_SRC" -type f -print0)
fi

verify_repomd_data() {
  local rpm_root="$1"
  local repo_root="$2"
  local repomd_xml="$3"
  local items_file="$TEMP_WORK/repomd-items.txt"
  python3 - "$repomd_xml" "$items_file" <<'PYEOF'
import sys, xml.etree.ElementTree as ET

xml_path, out_path = sys.argv[1], sys.argv[2]
tree = ET.parse(xml_path)
root = tree.getroot()
rows = []
for elem in root.iter():
    if elem.tag.split("}")[-1] != "data":
        continue
    ctype, cval, href = "", "", ""
    for child in elem:
        tag = child.tag.split("}")[-1]
        if tag == "checksum":
            ctype = (child.attrib.get("type") or "").strip().lower()
            cval = (child.text or "").strip().lower()
        elif tag == "location":
            href = (child.attrib.get("href") or "").strip()
    if href:
        rows.append((ctype, cval, href))

with open(out_path, "w", encoding="utf-8") as out:
    for ctype, cval, href in rows:
        out.write(f"{ctype}\t{cval}\t{href}\n")
PYEOF

  local verified_data=0
  while IFS=$'\t' read -r ctype cval href; do
    case "$href" in
      /*|*..*|*\\*)
        echo "GRDR-MIRROR-0020: unsafe href in repomd.xml: $href" >&2
        exit 1
        ;;
    esac
    local target="$repo_root/$href"
    if [ ! -f "$target" ] || [ -L "$target" ]; then
      echo "GRDR-MIRROR-0021: missing or symlink repodata file referenced by repomd.xml: $target" >&2
      exit 1
    fi
    local sum_line actual_hex
    case "$ctype" in
      sha256) sum_line="$(sha256sum "$target")" ;;
      sha512) sum_line="$(sha512sum "$target")" ;;
      *)
        echo "GRDR-MIRROR-0022: unsupported repomd checksum algorithm '$ctype' for $href" >&2
        exit 1
        ;;
    esac
    actual_hex="${sum_line%% *}"
    if [ "${actual_hex,,}" != "$cval" ]; then
      echo "GRDR-MIRROR-0023: repodata checksum mismatch for $target" >&2
      exit 1
    fi
    verified_rpm_files["${target#"$rpm_root"/}"]=1
    verified_data=$((verified_data + 1))
  done < "$items_file"

  if [ "$verified_data" -eq 0 ]; then
    echo "GRDR-MIRROR-0024: signed repomd.xml verified zero repodata entries: $repomd_xml" >&2
    exit 1
  fi
}

if [ -d "$SRC_DIR/rpm" ]; then
  RPM_SRC="$SRC_DIR/rpm"
  if [ -z "$RPM_PUBKEY" ] || [ ! -f "$RPM_PUBKEY" ] || [ -L "$RPM_PUBKEY" ]; then
    echo "GRDR-MIRROR-0007: RPM verification requires non-symlink rpm_pubkey argument" >&2
    exit 1
  fi
  dearmor_to_keyring "$RPM_PUBKEY" "$TEMP_WORK/rpm-trusted.gpg"
  mkdir -p "$TEMP_WORK/rpmdb"
  rpm --dbpath "$TEMP_WORK/rpmdb" --import "$RPM_PUBKEY"

  rpm_verified_suites=0
  declare -A verified_repodata_dirs=()
  declare -A verified_rpm_files=()
  while IFS= read -r -d '' repomd_file; do
    if [ ! -f "${repomd_file}.asc" ] || [ -L "${repomd_file}.asc" ]; then
      echo "GRDR-MIRROR-0009: missing or symlink ${repomd_file}.asc" >&2
      exit 1
    fi
    gpgv --keyring "$TEMP_WORK/rpm-trusted.gpg" "${repomd_file}.asc" "$repomd_file"
    repo_root="$(dirname "$(dirname "$repomd_file")")"
    verify_repomd_data "$RPM_SRC" "$repo_root" "$repomd_file"
    verified_repodata_dirs["$(dirname "$repomd_file")"]=1
    verified_rpm_files["${repomd_file#"$RPM_SRC"/}"]=1
    verified_rpm_files["${repomd_file#"$RPM_SRC"/}.asc"]=1
    rpm_verified_suites=$((rpm_verified_suites + 1))
  done < <(find "$RPM_SRC" -type f -name 'repomd.xml' -print0)

  if [ "$rpm_verified_suites" -eq 0 ]; then
    echo "GRDR-MIRROR-0009: missing signed repomd.xml.asc in $RPM_SRC" >&2
    exit 1
  fi
  while IFS= read -r -d '' repodata_dir; do
    if [ -z "${verified_repodata_dirs[$repodata_dir]+x}" ]; then
      echo "GRDR-MIRROR-0027: unverified repodata directory without signed repomd.xml: $repodata_dir" >&2
      exit 1
    fi
  done < <(find "$RPM_SRC" -type d -name 'repodata' -print0)

  while IFS= read -r -d '' rpm_pkg; do
    rpmkeys --dbpath "$TEMP_WORK/rpmdb" --checksig --define "_pkgverify_level all" "$rpm_pkg"
    verified_rpm_files["${rpm_pkg#"$RPM_SRC"/}"]=1
  done < <(find "$RPM_SRC" -name '*.rpm' -type f -print0)
  if [ -f "$RPM_SRC/SHA256SUMS" ]; then
    (cd "$RPM_SRC" && sha256sum --strict -c SHA256SUMS)
    verified_rpm_files["SHA256SUMS"]=1
  fi

  while IFS= read -r -d '' disk_file; do
    rel="${disk_file#"$RPM_SRC"/}"
    if [ -z "${verified_rpm_files[$rel]+x}" ]; then
      echo "GRDR-MIRROR-0028: unverified file forbidden in RPM mirror tree: $rel" >&2
      exit 1
    fi
    mkdir -p "$STAGE_DIR/rpm/$(dirname "$rel")"
    cp -f -- "$disk_file" "$STAGE_DIR/rpm/$rel"
  done < <(find "$RPM_SRC" -type f -print0)
fi

if [ -L "$DOCROOT" ]; then
  echo "GRDR-MIRROR-0013: refusing symlink mirror docroot: $DOCROOT" >&2
  exit 1
fi
mkdir -p "$DOCROOT"
if [ -d "$STAGE_DIR/apt" ]; then
  TARGET_APT="${DOCROOT%/}/apt"
  PREV_APT="${DOCROOT%/}.apt.prev.$$"
  if [ -L "$TARGET_APT" ] || [ -L "$PREV_APT" ]; then
    echo "GRDR-MIRROR-0013: refusing symlink APT target directory: $TARGET_APT" >&2
    exit 1
  fi
  [ -d "$TARGET_APT" ] && mv "$TARGET_APT" "$PREV_APT"
  mv "$STAGE_DIR/apt" "$TARGET_APT"
  rm -rf "$PREV_APT"
fi
if [ -d "$STAGE_DIR/rpm" ]; then
  TARGET_RPM="${DOCROOT%/}/rpm"
  PREV_RPM="${DOCROOT%/}.rpm.prev.$$"
  if [ -L "$TARGET_RPM" ] || [ -L "$PREV_RPM" ]; then
    echo "GRDR-MIRROR-0013: refusing symlink RPM target directory: $TARGET_RPM" >&2
    exit 1
  fi
  [ -d "$TARGET_RPM" ] && mv "$TARGET_RPM" "$PREV_RPM"
  mv "$STAGE_DIR/rpm" "$TARGET_RPM"
  rm -rf "$PREV_RPM"
fi

echo "Verified and atomically synced APT/RPM mirror into $DOCROOT"
