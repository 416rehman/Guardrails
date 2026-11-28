#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
set -euo pipefail

# Offline integration test harness for deploy/airgap/{k3s-import-images.sh,sync-apt-dnf-mirror.sh}.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORK_ROOT="$(mktemp -d)"
trap 'rm -rf "$WORK_ROOT"' EXIT

export GNUPGHOME="$WORK_ROOT/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

cat > "$WORK_ROOT/keygen.batch" <<'EOF'
Key-Type: eddsa
Key-Curve: ed25519
Name-Real: Guardrails Airgap Test
Name-Email: test@guardrails.invalid
Expire-Date: 0
%no-protection
%commit
EOF

gpg --batch --generate-key "$WORK_ROOT/keygen.batch" 2>/dev/null
gpg --batch --yes --export -o "$WORK_ROOT/trusted.gpg" test@guardrails.invalid
gpg --batch --yes --armor --export -o "$WORK_ROOT/trusted.asc" test@guardrails.invalid

# --- 1. k3s-import-images.sh ---
IMG_SRC="$WORK_ROOT/k3s-src"
IMG_DST="$WORK_ROOT/k3s-dst"
mkdir -p "$IMG_SRC"
printf 'tar-payload-1\n' > "$IMG_SRC/grdr-server.tar"
printf 'zst-payload-1\n' > "$IMG_SRC/grdr-sensor.tar.zst"
(cd "$IMG_SRC" && sha256sum grdr-server.tar grdr-sensor.tar.zst > images.sha256)

if bash "$REPO_ROOT/deploy/airgap/k3s-import-images.sh" "$IMG_SRC" "$IMG_DST" "$WORK_ROOT/trusted.asc" 2>/dev/null; then
  echo "FAIL: k3s-import accepted unsigned images.sha256" >&2
  exit 1
fi

gpg --batch --yes --armor --detach-sign -o "$IMG_SRC/images.sha256.asc" "$IMG_SRC/images.sha256"

bash "$REPO_ROOT/deploy/airgap/k3s-import-images.sh" "$IMG_SRC///" "$IMG_DST/" "$WORK_ROOT/trusted.asc" >/dev/null
[ -f "$IMG_DST/grdr-server.tar" ] && [ -f "$IMG_DST/grdr-sensor.tar.zst" ]

printf 'rogue\n' > "$IMG_SRC/evil-smuggled.tar"
if bash "$REPO_ROOT/deploy/airgap/k3s-import-images.sh" "$IMG_SRC" "$IMG_DST" "$WORK_ROOT/trusted.asc" 2>/dev/null; then
  echo "FAIL: k3s-import allowed smuggled evil-smuggled.tar" >&2
  exit 1
fi
rm -f "$IMG_SRC/evil-smuggled.tar"

# --- 2. sync-apt-dnf-mirror.sh (compressed by-hash Packages.gz + .deb verification) ---
MIRROR_SRC="$WORK_ROOT/bundle"
MISSING_PARENT_DOCROOT="$WORK_ROOT/fresh/parent/mirror"
mkdir -p "$MIRROR_SRC/apt/dists/bookworm/main/binary-amd64/by-hash/SHA256"
mkdir -p "$MIRROR_SRC/apt/pool/main/g/grdr"

DEB_FILE="$MIRROR_SRC/apt/pool/main/g/grdr/grdr_0.1.0_amd64.deb"
printf 'fake-deb-ar-bytes\n' > "$DEB_FILE"
DEB_SHA="$(sha256sum "$DEB_FILE" | awk '{print $1}')"

PKG_TMP="$WORK_ROOT/Packages"
cat > "$PKG_TMP" <<EOF
Package: grdr
Version: 0.1.0
Architecture: amd64
Filename: pool/main/g/grdr/grdr_0.1.0_amd64.deb
SHA256: $DEB_SHA

EOF
gzip -c "$PKG_TMP" > "$WORK_ROOT/Packages.gz"
PGZ_SHA="$(sha256sum "$WORK_ROOT/Packages.gz" | awk '{print $1}')"
PGZ_SIZE="$(wc -c < "$WORK_ROOT/Packages.gz" | tr -d '[:space:]')"
cp "$WORK_ROOT/Packages.gz" "$MIRROR_SRC/apt/dists/bookworm/main/binary-amd64/by-hash/SHA256/$PGZ_SHA"

cat > "$MIRROR_SRC/apt/dists/bookworm/Release" <<EOF
Origin: Guardrails
Suite: bookworm
Acquire-By-Hash: yes
SHA256:
 $PGZ_SHA $PGZ_SIZE main/binary-amd64/Packages.gz
EOF
gpg --batch --yes --detach-sign -o "$MIRROR_SRC/apt/dists/bookworm/Release.gpg" "$MIRROR_SRC/apt/dists/bookworm/Release"

bash "$REPO_ROOT/deploy/airgap/sync-apt-dnf-mirror.sh" "$MIRROR_SRC/" "$MISSING_PARENT_DOCROOT/" "$WORK_ROOT/trusted.asc" >/dev/null
[ -f "$MISSING_PARENT_DOCROOT/apt/pool/main/g/grdr/grdr_0.1.0_amd64.deb" ]
[ -f "$MISSING_PARENT_DOCROOT/apt/dists/bookworm/main/binary-amd64/by-hash/SHA256/$PGZ_SHA" ]

# Tampered .deb must fail closed against by-hash Packages.gz SHA256 digest
cp "$DEB_FILE" "$WORK_ROOT/deb.bak"
printf 'tampered-deb-bytes\n' > "$DEB_FILE"
if bash "$REPO_ROOT/deploy/airgap/sync-apt-dnf-mirror.sh" "$MIRROR_SRC" "$MISSING_PARENT_DOCROOT" "$WORK_ROOT/trusted.asc" 2>/dev/null; then
  echo "FAIL: sync-apt-dnf-mirror accepted tampered .deb payload" >&2
  exit 1
fi
mv "$WORK_ROOT/deb.bak" "$DEB_FILE"

# Unattested rogue .deb must fail closed
printf 'rogue-deb\n' > "$MIRROR_SRC/apt/pool/rogue.deb"
if bash "$REPO_ROOT/deploy/airgap/sync-apt-dnf-mirror.sh" "$MIRROR_SRC" "$MISSING_PARENT_DOCROOT" "$WORK_ROOT/trusted.asc" 2>/dev/null; then
  echo "FAIL: sync-apt-dnf-mirror allowed unverified rogue.deb" >&2
  exit 1
fi
rm -f "$MIRROR_SRC/apt/pool/rogue.deb"

# Unverified rogue suite directory must fail closed
mkdir -p "$MIRROR_SRC/apt/dists/rogue-suite"
if bash "$REPO_ROOT/deploy/airgap/sync-apt-dnf-mirror.sh" "$MIRROR_SRC" "$MISSING_PARENT_DOCROOT" "$WORK_ROOT/trusted.asc" 2>/dev/null; then
  echo "FAIL: sync-apt-dnf-mirror allowed unverified dists/rogue-suite" >&2
  exit 1
fi
rmdir "$MIRROR_SRC/apt/dists/rogue-suite"

# Single-line minified repomd.xml XML parse verification
MIN_XML="$WORK_ROOT/repomd.xml"
printf '%s' '<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</checksum><location href="repodata/primary.xml.gz"/></data></repomd>' > "$MIN_XML"
XML_OUT="$(python3 - "$MIN_XML" <<'PYEOF'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
for elem in root.iter():
    if elem.tag.split("}")[-1] == "data":
        c = {k.tag.split("}")[-1]: k for k in elem}
        print(c["checksum"].attrib["type"], c["checksum"].text, c["location"].attrib["href"])
PYEOF
)"
[[ "$XML_OUT" == "sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa repodata/primary.xml.gz" ]]

echo "AIRGAP_QA_HARNESS_OK"
