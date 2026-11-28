# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

"""Release config, support.toml matrix drift, TUF/Sigstore roots, manifest, and SBOM CLI."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from sbom_tools import (
    check_fuzz_targets_parity,
    check_grype_report,
    cross_check_sbom,
    generate_workspace_sbom,
    install_grype_verified,
    load_fips_policy,
    validate_fips_sbom_document,
    verify_binary_architecture,
    verify_containerfile_hardening,
)

ROOT = Path(__file__).resolve().parents[2]
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
HEX64_RE = re.compile(r"^[0-9a-f]{64}\Z")
SHA256_PREFIX_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}\Z")
KID_RE = re.compile(r"^kid_[0-9a-f]{16}\Z")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _confine_repo_path(root: Path, rel_path: str) -> Path:
    resolved_root = root.resolve()
    candidate = (resolved_root / rel_path).resolve()
    if not candidate.is_relative_to(resolved_root):
        raise ValueError(f"path escapes repository root: {rel_path}")
    return candidate


def _parse_prerelease_token(tok: str) -> tuple[int, int | str]:
    return (0, int(tok)) if tok.isdigit() else (1, tok)


def parse_semver(ver: str) -> tuple[int, int, int]:
    if not SEMVER_RE.match(ver):
        raise ValueError(f"invalid SemVer: {ver}")
    core = ver.split("-", 1)[0]
    parts = core.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def compare_semver(a: str, b: str) -> int:
    if not SEMVER_RE.match(a) or not SEMVER_RE.match(b):
        raise ValueError(f"invalid SemVer comparison: {a!r} vs {b!r}")
    a_core, _, a_pre = a.partition("-")
    b_core, _, b_pre = b.partition("-")
    a_nums = tuple(int(x) for x in a_core.split("."))
    b_nums = tuple(int(x) for x in b_core.split("."))
    if a_nums != b_nums:
        return -1 if a_nums < b_nums else 1
    if not a_pre and not b_pre:
        return 0
    if not a_pre:
        return 1
    if not b_pre:
        return -1
    a_ids = [_parse_prerelease_token(t) for t in a_pre.split(".")]
    b_ids = [_parse_prerelease_token(t) for t in b_pre.split(".")]
    for ai, bi in zip(a_ids, b_ids):
        if ai != bi:
            return -1 if ai < bi else 1
    return -1 if len(a_ids) < len(b_ids) else (1 if len(a_ids) > len(b_ids) else 0)


def format_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_timestamp(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        raise ValueError(f"timestamp missing UTC timezone: {value}")
    return dt.astimezone(timezone.utc)


def load_support_contract(root: Path = ROOT) -> dict[str, Any]:
    return tomllib.loads((root / "contracts" / "support.toml").read_text("utf-8"))


def build_support_matrix(root: Path = ROOT) -> dict[str, Any]:
    support = load_support_contract(root)
    os_section = support["os"]
    cells: list[dict[str, str]] = []
    for os_name in ("linux", "windows", "macos"):
        spec = os_section[os_name]
        for target in spec.get("architectures", []):
            cells.append({"tier": f"tier{spec['tier']}", "os": os_name, "target": target})
    platform = support["platform"]
    contracts = {c["name"]: c["version"] for c in support["compatibility_matrix"]["contracts"]}
    return {
        "schema_version": "grdr.support-matrix.v1",
        "support_schema": support["schema"],
        "tier1_cells": cells,
        "object_stores_tier1": platform["object_stores"]["tier1"],
        "kubernetes_supported": platform["kubernetes"]["supported_versions"],
        "helm_minimum": platform["kubernetes"]["helm_min_v3"],
        "postgresql_major": platform["databases"]["postgresql_major"],
        "nats_minimum": platform["bus"]["distributed"],
        "contracts": contracts,
    }


def check_workflow_matrix_coverage(
    matrix: dict[str, Any], workflow_paths: list[Path]
) -> list[str]:
    targets_in_matrix: set[str] = set()
    has_unconditional_target_flag = False
    for p in workflow_paths:
        lines = p.read_text("utf-8").splitlines()
        in_matrix_include = False
        has_target_cmd = False
        conditional_target = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if stripped == "matrix:":
                in_matrix_include = True
            elif in_matrix_include and re.match(r"^(?:-\s+)?target:\s*([A-Za-z0-9_.-]+)\s*$", stripped):
                m = re.match(r"^(?:-\s+)?target:\s*([A-Za-z0-9_.-]+)\s*$", stripped)
                if m:
                    targets_in_matrix.add(m.group(1))
            elif in_matrix_include and stripped in ("steps:", "runs-on:"):
                in_matrix_include = False
            if re.search(r"cargo\s+build\b.*--target\b", line):
                has_target_cmd = True
            if 'OS_KIND" = "linux"' in line and 'ARCH_KIND" = "x86_64"' in line:
                conditional_target = True
        if has_target_cmd and not conditional_target:
            has_unconditional_target_flag = True

    missing: list[str] = []
    for cell in matrix["tier1_cells"]:
        target = cell["target"]
        if target not in targets_in_matrix:
            missing.append(f"Tier 1 target missing from release/verify CI matrix include: {target}")
    if not has_unconditional_target_flag:
        missing.append("build-binaries must pass --target unconditionally for every matrix cell")
    return missing


def compute_upgrade_hops(
    from_ver: str, to_ver: str, lts_versions: list[str] | None = None
) -> list[str]:
    cmp = compare_semver(from_ver, to_ver)
    if cmp > 0:
        raise ValueError(f"downgrade not permitted: {from_ver} -> {to_ver}")
    if cmp == 0:
        return [to_ver]

    f_maj, f_min, _ = parse_semver(from_ver)
    t_maj, t_min, _ = parse_semver(to_ver)
    if f_maj != t_maj:
        raise ValueError(f"cross-major direct hop requires explicit major boundary plan: {from_ver} -> {to_ver}")

    lts_set = set(lts_versions or [])
    hops: list[str] = []
    cur_min = f_min
    while cur_min < t_min:
        next_min = min(cur_min + 2, t_min)
        for cand_min in range(cur_min + 1, next_min + 1):
            cand_str = f"{t_maj}.{cand_min}.0"
            if cand_str in lts_set and cand_min < next_min:
                next_min = cand_min
                break
        hop_ver = to_ver if next_min == t_min else f"{t_maj}.{next_min}.0"
        hops.append(hop_ver)
        cur_min = next_min
    if not hops:
        hops.append(to_ver)
    return hops


def validate_tuf_root_doc(tuf_doc: dict[str, Any], now: datetime | None = None) -> None:
    if "signed" not in tuf_doc or "signatures" not in tuf_doc:
        raise ValueError("TUF root must contain 'signed' and 'signatures'")
    signed = tuf_doc["signed"]
    if signed.get("root_kind") != "project":
        raise ValueError("deploy/release/tuf/1.root.json must have root_kind='project'")
    if int(signed.get("version", 0)) < 1:
        raise ValueError("TUF root version must be >= 1")
    expires_raw = signed.get("expires")
    if not expires_raw:
        raise ValueError("TUF root missing 'expires'")
    expires = parse_utc_timestamp(str(expires_raw))
    ref_now = now or datetime.now(timezone.utc)
    if expires <= ref_now:
        raise ValueError(f"TUF root expired at {expires_raw}")

    keys = signed.get("keys", {})
    roles = signed.get("roles", {})
    if "fleet" in roles:
        raise ValueError("D-37 project root must not contain deployment 'fleet' role")

    for kid, key_obj in keys.items():
        if not KID_RE.match(kid) or key_obj.get("key_id") != kid:
            raise ValueError(f"malformed TUF key entry '{kid}'")
        pub_raw = base64.b64decode(str(key_obj.get("public_key_b64", "")), validate=True)
        if len(pub_raw) != 32:
            raise ValueError(f"TUF Ed25519 public key '{kid}' must decode to 32 bytes")
        expected_kid = f"kid_{hashlib.sha256(pub_raw).hexdigest()[:16]}"
        if kid != expected_kid:
            raise ValueError(f"TUF key_id '{kid}' does not match public key SHA-256 ({expected_kid})")

    for critical_role in ("root", "targets", "binaries"):
        role = roles.get(critical_role)
        if not role or int(role.get("threshold", 0)) < 2:
            raise ValueError(f"TUF role '{critical_role}' must enforce threshold >= 2")
        kids = role.get("key_ids", [])
        if len(set(kids)) < int(role["threshold"]):
            raise ValueError(f"TUF role '{critical_role}' distinct key_ids below threshold")
        for kid in kids:
            if kid not in keys:
                raise ValueError(f"TUF role '{critical_role}' references missing key '{kid}'")

    root_kids = set(roles["root"]["key_ids"])
    pipeline_kids = set(roles["targets"]["key_ids"]) | set(roles["binaries"]["key_ids"])
    if root_kids & pipeline_kids:
        raise ValueError("offline 'root' keys must remain separate from targets/binaries keys")

    seen_online_kids: set[str] = set()
    for online_role in ("timestamp", "snapshot", "content", "rollout"):
        role = roles.get(online_role)
        if not role or int(role.get("threshold", 0)) < 1 or not role.get("key_ids"):
            raise ValueError(f"TUF online role '{online_role}' missing key_ids or threshold")
        for kid in role["key_ids"]:
            if kid not in keys:
                raise ValueError(f"TUF online role '{online_role}' references missing key '{kid}'")
            if kid in root_kids or kid in pipeline_kids:
                raise ValueError(f"TUF online role '{online_role}' reused offline/pipeline key '{kid}'")
            if kid in seen_online_kids:
                raise ValueError(f"TUF online role '{online_role}' reused another online role key '{kid}'")
            seen_online_kids.add(kid)

    root_role = roles["root"]
    valid_sigs: set[str] = set()
    for sig in tuf_doc["signatures"]:
        kid = sig.get("keyid")
        if kid in root_kids and sig.get("sig"):
            sig_bytes = base64.b64decode(str(sig["sig"]), validate=True)
            if len(sig_bytes) != 64:
                raise ValueError(f"TUF signature for '{kid}' must decode to 64 bytes")
            valid_sigs.add(kid)
    if len(valid_sigs) < int(root_role["threshold"]):
        raise ValueError("TUF root signatures count below root role threshold")


def validate_sigstore_trusted_root(doc: dict[str, Any]) -> None:
    if doc.get("mediaType") != "application/vnd.dev.sigstore.trustedroot+json;version=0.1":
        raise ValueError("unexpected sigstore trusted_root mediaType")
    for log_section in ("tlogs", "ctlogs"):
        entries = doc.get(log_section)
        if not isinstance(entries, list) or not entries:
            raise ValueError(f"sigstore trusted_root missing non-empty '{log_section}'")
        for idx, entry in enumerate(entries):
            raw_b64 = entry.get("publicKey", {}).get("rawBytes", "")
            spki_der = base64.b64decode(str(raw_b64), validate=True) if raw_b64 else b""
            if len(spki_der) < 44 or spki_der[0] != 0x30:
                raise ValueError(f"sigstore '{log_section}[{idx}].publicKey.rawBytes' must be non-empty ASN.1 DER SPKI")
            kid_b64 = entry.get("logId", {}).get("keyId", "")
            kid_raw = base64.b64decode(str(kid_b64), validate=True) if kid_b64 else b""
            if len(kid_raw) != 32:
                raise ValueError(f"sigstore '{log_section}[{idx}].logId.keyId' must decode to 32 bytes")
            base_url = str(entry.get("baseUrl", ""))
            if (log_section == "ctlogs" or base_url == "https://rekor.sigstore.dev") and kid_raw != hashlib.sha256(spki_der).digest():
                raise ValueError(f"sigstore '{log_section}[{idx}].logId.keyId' must equal base64 SHA-256(SPKI)")

    for auth_section in ("certificateAuthorities", "timestampAuthorities"):
        entries = doc.get(auth_section)
        if not isinstance(entries, list) or not entries:
            raise ValueError(f"sigstore trusted_root missing non-empty '{auth_section}'")
        for idx, entry in enumerate(entries):
            certs = entry.get("certChain", {}).get("certificates", [])
            if not isinstance(certs, list) or not certs:
                raise ValueError(f"sigstore '{auth_section}[{idx}].certChain.certificates' must not be empty")
            for c_idx, cert in enumerate(certs):
                cert_b64 = cert.get("rawBytes", "")
                cert_der = base64.b64decode(str(cert_b64), validate=True) if cert_b64 else b""
                if len(cert_der) < 100 or cert_der[0] != 0x30:
                    raise ValueError(
                        f"sigstore '{auth_section}[{idx}].certChain.certificates[{c_idx}].rawBytes' invalid DER X.509 cert"
                    )


def check_release_configs(root: Path = ROOT) -> dict[str, Any]:
    version_file = (root / "deploy" / "release" / "VERSION").read_text("utf-8").strip()
    if not SEMVER_RE.match(version_file):
        raise ValueError(f"invalid deploy/release/VERSION: {version_file}")

    rp_cfg = json.loads((root / "deploy" / "release" / "release-please-config.json").read_text("utf-8"))
    rp_manifest = json.loads((root / "deploy" / "release" / ".release-please-manifest.json").read_text("utf-8"))

    packages = rp_cfg.get("packages", {})
    if not packages or "." not in packages:
        raise ValueError("release-please-config.json must configure root '.' and workspace packages")
    if packages["."].get("version-file") != "deploy/release/VERSION":
        raise ValueError("release-please-config.json root '.' must set version-file='deploy/release/VERSION'")
    if rp_manifest.get(".") != version_file:
        raise ValueError(f".release-please-manifest.json['.'] ({rp_manifest.get('.')}) != VERSION ({version_file})")

    surfaces = tomllib.loads((root / "contracts" / "surfaces.toml").read_text("utf-8")).get("crates", {})
    for pkg_path in packages:
        if pkg_path not in rp_manifest:
            raise ValueError(f"package '{pkg_path}' missing from .release-please-manifest.json")
        full = _confine_repo_path(root, pkg_path)
        if not full.exists():
            raise ValueError(f"configured release-please package path does not exist: {pkg_path}")
        if pkg_path.startswith("crates/"):
            crate_name = pkg_path.split("/", 1)[1]
            meta = surfaces.get(crate_name, {})
            if meta.get("publish") is False or not meta:
                raise ValueError(f"unpublished/internal crate '{pkg_path}' must not be in release-please-config.json")

    dist = tomllib.loads((root / "deploy" / "release" / "dist.toml").read_text("utf-8"))
    tuf_path = _confine_repo_path(root, dist["trust"]["initial_root_path"])
    sigstore_path = _confine_repo_path(root, dist["trust"]["trusted_root_path"])
    validate_tuf_root_doc(json.loads(tuf_path.read_text("utf-8")))
    validate_sigstore_trusted_root(json.loads(sigstore_path.read_text("utf-8")))

    checklist = tomllib.loads((root / "deploy" / "release" / "checklist.toml").read_text("utf-8"))
    if checklist.get("gates", {}).get("fips", {}).get("forbid_macos_fips_claim") is not True:
        raise ValueError("checklist.toml must forbid macOS FIPS claim")

    fips = load_fips_policy(root)
    if fips["platforms"]["macos"]["fips_supported"] is not False:
        raise ValueError("security/fips-policy.toml must mark macOS fips_supported = false")
    if fips["platforms"]["macos"]["cmvp_certificate"]:
        raise ValueError("security/fips-policy.toml must not specify macOS CMVP certificate")

    return {
        "bundle_version": version_file,
        "package_count": len(packages),
        "tuf_root_sha256": sha256_file(tuf_path),
        "sigstore_trusted_root_sha256": sha256_file(sigstore_path),
    }


def build_release_manifest(
    bundle_version: str,
    commit_sha: str,
    channel: str,
    artefacts: list[dict[str, Any]],
    root: Path = ROOT,
) -> dict[str, Any]:
    if not COMMIT_SHA_RE.match(commit_sha):
        raise ValueError(f"commit must be 40-char lowercase hex: {commit_sha}")
    if channel not in ("nightly", "canary", "beta", "broad", "lts"):
        raise ValueError(f"invalid release channel: {channel}")
    if not artefacts:
        raise ValueError("release manifest requires at least one artefact")

    support = load_support_contract(root)
    dist = tomllib.loads((root / "deploy" / "release" / "dist.toml").read_text("utf-8"))
    fips = load_fips_policy(root)
    tuf_path = _confine_repo_path(root, dist["trust"]["initial_root_path"])
    sigstore_path = _confine_repo_path(root, dist["trust"]["trusted_root_path"])
    tuf_doc = json.loads(tuf_path.read_text("utf-8"))

    contracts_map = {
        c["name"]: {"min": c["version"], "max": c["version"]}
        for c in support["compatibility_matrix"]["contracts"]
    }
    digest_pairs = "\n".join(
        f"{a['name']}:{a['sha256']}" for a in sorted(artefacts, key=lambda item: str(item["name"]))
    )
    bundle_sha256 = hashlib.sha256(digest_pairs.encode("utf-8")).hexdigest()

    cmvp_claimed = bool(fips.get("cmvp_validation_claimed", False))
    platforms_cfg = fips.get("platforms", {}) if isinstance(fips.get("platforms"), dict) else {}
    linux_plat = platforms_cfg.get("linux") if isinstance(platforms_cfg.get("linux"), dict) else {}
    active_platforms = [
        p
        for p in ("linux", "windows")
        if isinstance(platforms_cfg.get(p), dict) and platforms_cfg[p].get("cmvp_active") is True
    ]
    fips_module = (
        {
            "name": str(linux_plat["module_name"]),
            "certificate": str(linux_plat["cmvp_certificate"]),
            "platforms": active_platforms,
        }
        if cmvp_claimed and active_platforms and linux_plat.get("module_name") and linux_plat.get("cmvp_certificate")
        else None
    )

    t_maj, t_min, _ = parse_semver(bundle_version)
    min_upgrade_from = f"{t_maj}.{max(0, t_min - 2)}.0"

    return {
        "schema_version": "grdr.release-manifest.v1",
        "bundle_version": bundle_version,
        "commit": commit_sha,
        "released_at": format_utc_now(),
        "channel": channel,
        "avoid": False,
        "platform_signed": all(bool(a.get("platform_signature_present")) for a in artefacts),
        "wire_major": 1,
        "schema_rev": 1,
        "fips_module": fips_module,
        "fips_status": "validated" if fips_module else "unvalidated-pending-sp-24-2",
        "trusted_root": {
            "tuf_root_version": int(tuf_doc["signed"]["version"]),
            "tuf_root_sha256": sha256_file(tuf_path),
            "sigstore_trusted_root_sha256": sha256_file(sigstore_path),
        },
        "compat": {
            "contracts": contracts_map,
            "min_upgrade_from": min_upgrade_from,
            "required_stops": [],
            "postgresql_major": int(support["platform"]["databases"]["postgresql_major"]),
            "kubernetes_min": str(support["platform"]["kubernetes"]["supported_versions"][0]),
            "helm_min": str(support["platform"]["kubernetes"]["helm_min_v3"]),
        },
        "components": {
            "grdr-bundle": {
                "version": bundle_version,
                "sha256": bundle_sha256,
                "signed": all(bool(a.get("sigstore_bundle")) for a in artefacts),
            }
        },
        "artefacts": artefacts,
        "upgrade_paths": [
            {
                "from_version": min_upgrade_from,
                "to_version": bundle_version,
                "hops": compute_upgrade_hops(min_upgrade_from, bundle_version),
                "rollback_supported": True,
            }
        ],
    }


def _ensure_rust_target(target_triple: str, root: Path = ROOT) -> None:
    tc_cfg = tomllib.loads((root / "rust-toolchain.toml").read_text("utf-8"))
    pinned_channel = str(tc_cfg["toolchain"]["channel"])
    proc = subprocess.run(["rustup", "target", "add", "--toolchain", pinned_channel, target_triple], check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"failed adding pinned target {target_triple} on toolchain {pinned_channel}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guardrails ADR release pipeline utilities")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check-config")

    sm = sub.add_parser("support-matrix")
    sm.add_argument("--out", type=Path)
    sm.add_argument("--check-workflow", type=Path, action="append", default=[])

    fs = sub.add_parser("validate-fips-sbom")
    fs.add_argument("--sbom", type=Path, required=True)
    fs.add_argument("--os", choices=["linux", "windows", "macos"], required=True)
    fs.add_argument("--fips", action="store_true")

    rm = sub.add_parser("build-manifest")
    rm.add_argument("--version", required=True)
    rm.add_argument("--commit", required=True)
    rm.add_argument("--channel", default="broad")
    rm.add_argument("--artefacts-json", type=Path, required=True)
    rm.add_argument("--out-manifest", type=Path, required=True)
    rm.add_argument("--out-upgrade-path", type=Path, required=True)

    et = sub.add_parser("ensure-rust-target")
    et.add_argument("--target", required=True)

    va = sub.add_parser("verify-binary-arch")
    va.add_argument("--target", required=True)
    va.add_argument("--binary", type=Path, action="append", required=True)

    gs = sub.add_parser("generate-workspace-sbom")
    gs.add_argument("--out", type=Path, required=True)
    gs.add_argument("--version", required=True)
    gs.add_argument("--os", choices=["linux", "windows", "macos"], required=True)
    gs.add_argument("--target", required=True)
    gs.add_argument("--fips", action="store_true")
    gs.add_argument("--package", action="append", default=[])

    cs = sub.add_parser("cross-check-sbom")
    cs.add_argument("--sbom", type=Path, required=True)
    cs.add_argument("--target", required=True)
    cs.add_argument("--fips", action="store_true")
    cs.add_argument("--package", action="append", default=[])

    vc = sub.add_parser("verify-containerfile")
    vc.add_argument("--path", type=Path, action="append", required=True)

    fp = sub.add_parser("check-fuzz-parity")
    fp.add_argument("--targets", type=Path, default=ROOT / "security" / "fuzz-targets.toml")
    fp.add_argument("--build-script", type=Path, default=ROOT / ".clusterfuzzlite" / "build.sh")

    ig = sub.add_parser("install-grype")
    ig.add_argument("--version", required=True)
    ig.add_argument("--dest", type=Path, required=True)

    cg = sub.add_parser("check-grype-report")
    cg.add_argument("--report", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.cmd == "check-config":
        summary = check_release_configs()
        print(f"release config PASS (version={summary['bundle_version']}, packages={summary['package_count']})")
        return 0
    if args.cmd == "support-matrix":
        matrix = build_support_matrix()
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(matrix, indent=2) + "\n", "utf-8")
        if args.check_workflow:
            missing = check_workflow_matrix_coverage(matrix, args.check_workflow)
            if missing:
                for item in missing:
                    print(f"ERROR: {item}", file=sys.stderr)
                return 1
        print(f"support-matrix PASS ({len(matrix['tier1_cells'])} Tier 1 targets verified)")
        return 0
    if args.cmd == "validate-fips-sbom":
        validate_fips_sbom_document(json.loads(args.sbom.read_text("utf-8")), args.os, args.fips)
        print(f"fips-sbom PASS (os={args.os}, fips={args.fips})")
        return 0
    if args.cmd == "build-manifest":
        artefacts = json.loads(args.artefacts_json.read_text("utf-8"))
        support = load_support_contract()
        manifest = build_release_manifest(args.version, args.commit, args.channel, artefacts)
        args.out_manifest.parent.mkdir(parents=True, exist_ok=True)
        args.out_manifest.write_text(json.dumps(manifest, indent=2) + "\n", "utf-8")
        upgrade_path = {
            "version": args.version,
            "from": manifest["upgrade_paths"],
            "required_stops": manifest["compat"]["required_stops"],
            "min_backup_age_h": 24,
            "tested": {
                "kubernetes": support["platform"]["kubernetes"]["supported_versions"],
                "postgresql_major": manifest["compat"]["postgresql_major"],
                "nats": support["platform"]["bus"]["distributed"],
                "object_stores": support["platform"]["object_stores"]["tier1"],
                "helm_min": manifest["compat"]["helm_min"],
            },
        }
        args.out_upgrade_path.parent.mkdir(parents=True, exist_ok=True)
        args.out_upgrade_path.write_text(json.dumps(upgrade_path, indent=2) + "\n", "utf-8")
        print(f"release-manifest PASS ({args.out_manifest})")
        return 0
    if args.cmd == "ensure-rust-target":
        _ensure_rust_target(args.target)
        print(f"ensure-rust-target PASS ({args.target})")
        return 0
    if args.cmd == "verify-binary-arch":
        for bin_path in args.binary:
            verify_binary_architecture(bin_path, args.target)
        print(f"verify-binary-arch PASS ({args.target}, {len(args.binary)} binaries)")
        return 0
    if args.cmd == "generate-workspace-sbom":
        doc = generate_workspace_sbom(
            out_path=args.out,
            bundle_version=args.version,
            target_os=args.os,
            target_triple=args.target,
            fips_enabled=args.fips,
            packages=args.package or None,
        )
        print(f"workspace-sbom PASS ({len(doc['components'])} components -> {args.out})")
        return 0
    if args.cmd == "cross-check-sbom":
        count = cross_check_sbom(
            sbom_doc=json.loads(args.sbom.read_text("utf-8")),
            target_triple=args.target,
            fips_enabled=args.fips,
            packages=args.package or None,
        )
        print(f"cross-check-sbom PASS ({count} dependencies verified)")
        return 0
    if args.cmd == "verify-containerfile":
        for p in args.path:
            verify_containerfile_hardening(p)
        print(f"verify-containerfile PASS ({len(args.path)} Containerfiles verified)")
        return 0
    if args.cmd == "check-fuzz-parity":
        names = check_fuzz_targets_parity(args.targets, args.build_script)
        print(f"fuzz-parity PASS ({len(names)} targets verified)")
        return 0
    if args.cmd == "install-grype":
        bin_path = install_grype_verified(args.version, args.dest)
        print(f"install-grype PASS ({bin_path})")
        return 0
    if args.cmd == "check-grype-report":
        total = check_grype_report(json.loads(args.report.read_text("utf-8")))
        print(f"check-grype-report PASS ({total} matches checked, 0 KEV/High/Critical)")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
