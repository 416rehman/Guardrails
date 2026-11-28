# Air-Gap Deployment & Site Mirror Assets

This directory contains offline air-gap distribution and site-mirror configurations for Guardrails ADR:

- `zarf.yaml`: Zarf 1.x Apache-2.0 package deploying `grdr-server` via Helm (`values-airgap.yaml`), architecture-filtered `grdr` host binaries (`linux/amd64`, `linux/arm64`), and the `grdr-airgap.tar` bundle (carrying signed TUF metadata, packs, offline docs, CycloneDX SBOM, OpenVEX, and notices). Both `GRDR_SOURCE_IMAGE_DIGEST` (create-time) and `GRDR_SERVER_IMAGE_DIGEST` (deploy-time) fail closed unless set to a valid non-zero `sha256:<64hex>` digest.
- `values-airgap.yaml`: Offline Helm overrides for `deploy/helm/grdr-server` enforcing filesystem object storage, verified TLS database mode, restricted cluster egress, private CA mount, and fail-closed `image.digest: ""` until supplied at deploy time.
- `nginx-repo.conf` & `sync-apt-dnf-mirror.sh`: Hardened TLS site repository mirror configuration and atomic staging script verifying every signed APT `InRelease`/`Release` (`Acquire-By-Hash: yes` + `by-hash/SHA256` immutable caching) and every signed RPM `repomd.xml.asc` + `rpmkeys --checksig` before promotion.
- `zot-config.json`: OCI 1.1 Referrers-capable site container registry configuration enforcing air-gap bundle manifest annotations.
- `distribution-fallback.yml`: TLS-enforced registry configuration for legacy environments without OCI 1.1 Referrers support.
- `k3s-import-images.sh`: Offline `k3s`/`RKE2` containerd archive staging script requiring a signed `images.sha256` manifest (`.sigstore.json` via `grdr airgap verify-artefact` or `.asc`/`.gpg` via `gpgv`), strict filename allowlisting (`.tar`, `.tar.gz`, `.tgz`, `.oci.tar`, `.tar.zst`), zero extra unmanifested archives, and symlink rejection.
- `terraform-mirror.tfrc`: Filesystem provider mirror configuration forbidding outbound registry lookups (`direct { exclude = ["*/*"] }`).

## CLI Workflow Summary

1. Build full or delta bundles (optionally split for FAT32 media): `grdr airgap build ...`
2. Inspect and verify bundle root & terms offline: `grdr airgap verify --bundle ... --print-root` then `grdr airgap verify --accept-terms <manifest_sha256>`
3. Import into site server storage and audit log: `grdr airgap server-import ...`
4. Verify standalone release artefacts offline against pinned `trusted_root.json`: `grdr airgap verify-artefact ...`
5. Synchronize site TUF mirrors, export deltas, or issue deployment freshness vouches: `grdr airgap mirror-sync`, `grdr airgap mirror-export`, `grdr airgap mirror-vouch`, `grdr airgap keys-ceremony`.
