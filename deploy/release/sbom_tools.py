# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

"""CycloneDX 1.6 workspace SBOM generation, cross-check, binary arch, and fuzz parity checks."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import tomllib
from typing import Any
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
FUZZ_TARGET_BLOCK_RE = re.compile(r"for\s+target\s+in\s+(?P<body>.*?)\bdo\b", re.S)
GRYPE_PINNED_DIGESTS: dict[tuple[str, str], str] = {
    ("v0.121.3", "linux_amd64"): "e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85",
    ("v0.121.3", "linux_arm64"): "b7815598d48da78bfd16f5b98ef28e1bb09c03d34fc8c3e350f99b6ccb3c7cba",
}


def load_fips_policy(root: Path = ROOT) -> dict[str, Any]:
    return tomllib.loads((root / "security" / "fips-policy.toml").read_text("utf-8"))


def validate_fips_sbom_document(
    sbom_doc: dict[str, Any], target_os: str, fips_enabled: bool, root: Path = ROOT
) -> None:
    fips_policy = load_fips_policy(root)
    prop_mod = fips_policy["sbom"]["component_property"]
    prop_cert = fips_policy["sbom"]["certificate_property"]
    cmvp_claimed = bool(fips_policy.get("cmvp_validation_claimed", False))
    platform_cfg = fips_policy.get("platforms", {}).get(target_os, {})
    platform_cmvp_active = bool(platform_cfg.get("cmvp_active", False))

    props: dict[str, str] = {}
    for prop in sbom_doc.get("metadata", {}).get("component", {}).get("properties", []):
        props[str(prop.get("name", ""))] = str(prop.get("value", ""))

    if target_os == "macos":
        if prop_mod in props or prop_cert in props or "grdr:fips:profile" in props:
            raise ValueError("macOS artefact SBOM must never carry a FIPS module, profile, or CMVP claim")
        return

    if target_os not in ("linux", "windows"):
        raise ValueError(f"unsupported FIPS target_os check: {target_os}")

    has_cmvp_props = bool(props.get(prop_mod) or props.get(prop_cert))
    if not fips_enabled:
        if has_cmvp_props:
            raise ValueError(f"non-FIPS {target_os} SBOM must not carry CMVP claims")
        return

    if cmvp_claimed and platform_cmvp_active:
        if not props.get(prop_mod):
            raise ValueError(f"{target_os} FIPS SBOM missing '{prop_mod}' property")
        if not props.get(prop_cert):
            raise ValueError(f"{target_os} FIPS SBOM missing '{prop_cert}' property")
    else:
        if props.get(prop_cert) or props.get(prop_mod):
            raise ValueError(
                f"{target_os} FIPS SBOM must not claim CMVP module/certificate while cmvp_validation_claimed=false"
            )
        if props.get("grdr:fips:profile") != "fips":
            raise ValueError(f"{target_os} FIPS SBOM missing grdr:fips:profile='fips'")
        if props.get("grdr:fips:cmvp-status") != "unvalidated-pending-sp-24-2":
            raise ValueError(
                f"{target_os} FIPS SBOM must declare grdr:fips:cmvp-status='unvalidated-pending-sp-24-2'"
            )


def _load_cargo_lock_hashes(root: Path) -> dict[tuple[str, str], str]:
    lock_path = root / "Cargo.lock"
    if not lock_path.is_file():
        return {}
    lock_data = tomllib.loads(lock_path.read_text("utf-8"))
    out: dict[tuple[str, str], str] = {}
    for pkg in lock_data.get("package", []):
        name = str(pkg.get("name", ""))
        version = str(pkg.get("version", ""))
        checksum = str(pkg.get("checksum", ""))
        if name and version and checksum:
            out[(name, version)] = checksum
    return out


def load_cargo_metadata(
    root: Path = ROOT, fips_enabled: bool = False, target_triple: str | None = None
) -> dict[str, Any]:
    cmd = ["cargo", "metadata", "--locked", "--format-version", "1"]
    if target_triple:
        cmd.extend(["--filter-platform", target_triple])
    if fips_enabled:
        cmd.extend(["--features", "grdr-crypto/fips"])
    proc = subprocess.run(cmd, cwd=root, capture_output=True, encoding="utf-8", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"cargo metadata failed ({proc.returncode}): {(proc.stderr or '').strip()}")
    return json.loads(proc.stdout)


def generate_workspace_sbom(
    out_path: Path,
    bundle_version: str,
    target_os: str,
    target_triple: str,
    fips_enabled: bool = False,
    packages: list[str] | None = None,
    root: Path = ROOT,
    cargo_metadata_doc: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fips_policy = load_fips_policy(root)
    if target_os == "macos" and fips_enabled:
        raise ValueError("macOS carries no FIPS build or claim")

    meta = cargo_metadata_doc or load_cargo_metadata(
        root=root, fips_enabled=fips_enabled, target_triple=target_triple
    )
    lock_hashes = _load_cargo_lock_hashes(root)

    pkg_by_id = {pkg["id"]: pkg for pkg in meta.get("packages", [])}
    resolve_nodes = {n["id"]: n for n in meta.get("resolve", {}).get("nodes", [])}

    selected_roots: list[str] = []
    if packages:
        wanted = set(packages)
        for pid, pkg in pkg_by_id.items():
            if pkg.get("name") in wanted and pid in set(meta.get("workspace_members", [])):
                selected_roots.append(pid)
        if len(selected_roots) != len(wanted):
            found_names = {pkg_by_id[pid]["name"] for pid in selected_roots}
            missing = sorted(wanted - found_names)
            raise ValueError(f"requested SBOM root packages not found in workspace: {missing}")
    else:
        selected_roots = list(meta.get("workspace_members", []))

    visited: set[str] = set()
    queue = list(selected_roots)
    while queue:
        cur = queue.pop(0)
        if cur in visited or cur not in pkg_by_id:
            continue
        visited.add(cur)
        node = resolve_nodes.get(cur)
        if node:
            for dep in node.get("deps", []):
                dep_id = dep.get("pkg")
                if dep_id and dep_id not in visited:
                    queue.append(dep_id)

    components: list[dict[str, Any]] = []
    bom_refs: dict[str, str] = {}
    for pid in sorted(visited, key=lambda i: (pkg_by_id[i]["name"], pkg_by_id[i]["version"])):
        pkg = pkg_by_id[pid]
        name = pkg["name"]
        ver = pkg["version"]
        purl = f"pkg:cargo/{name}@{ver}"
        bom_refs[pid] = purl
        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": ver,
            "purl": purl,
        }
        lic = pkg.get("license")
        if lic:
            comp["licenses"] = [{"expression": lic}]
        digest = lock_hashes.get((name, ver))
        if digest:
            comp["hashes"] = [{"alg": "SHA-256", "content": digest}]
        components.append(comp)

    dependencies: list[dict[str, Any]] = []
    for pid in sorted(visited, key=lambda i: bom_refs[i]):
        node = resolve_nodes.get(pid, {})
        depends_on = sorted(
            {
                bom_refs[d["pkg"]]
                for d in node.get("deps", [])
                if d.get("pkg") in bom_refs
            }
        )
        dependencies.append({"ref": bom_refs[pid], "dependsOn": depends_on})

    props: list[dict[str, str]] = [
        {"name": "grdr:target-triple", "value": target_triple},
        {"name": "grdr:target-os", "value": target_os},
    ]
    cmvp_claimed = bool(fips_policy.get("cmvp_validation_claimed", False))
    platform_active = bool(fips_policy.get("platforms", {}).get(target_os, {}).get("cmvp_active", False))
    if fips_enabled and target_os in ("linux", "windows"):
        props.append({"name": "grdr:fips:profile", "value": "fips"})
        if cmvp_claimed and platform_active:
            props.append(
                {
                    "name": fips_policy["sbom"]["component_property"],
                    "value": fips_policy["platforms"][target_os]["module_name"],
                }
            )
            props.append(
                {
                    "name": fips_policy["sbom"]["certificate_property"],
                    "value": fips_policy["platforms"][target_os]["cmvp_certificate"],
                }
            )
        else:
            props.append({"name": "grdr:fips:cmvp-status", "value": "unvalidated-pending-sp-24-2"})

    serial_seed = hashlib.sha256(f"{bundle_version}:{target_triple}:{len(components)}".encode("utf-8")).hexdigest()
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial_seed[:8]}-{serial_seed[8:12]}-4{serial_seed[13:16]}-8{serial_seed[17:20]}-{serial_seed[20:32]}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "grdr",
                "version": bundle_version,
                "properties": props,
            }
        },
        "components": components,
        "dependencies": dependencies,
    }
    validate_fips_sbom_document(doc, target_os, fips_enabled, root=root)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2) + "\n", "utf-8")
    return doc


def cross_check_sbom(
    sbom_doc: dict[str, Any],
    target_triple: str,
    fips_enabled: bool = False,
    packages: list[str] | None = None,
    root: Path = ROOT,
    cargo_metadata_doc: dict[str, Any] | None = None,
) -> int:
    if sbom_doc.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM must use bomFormat='CycloneDX'")
    components = sbom_doc.get("components", [])
    if not isinstance(components, list) or not components:
        raise ValueError("CycloneDX SBOM must contain non-empty 'components'")

    meta = cargo_metadata_doc or load_cargo_metadata(
        root=root, fips_enabled=fips_enabled, target_triple=target_triple
    )
    lock_hashes = _load_cargo_lock_hashes(root)
    pkg_by_id = {pkg["id"]: pkg for pkg in meta.get("packages", [])}
    resolve_nodes = {n["id"]: n for n in meta.get("resolve", {}).get("nodes", [])}

    roots = (
        [pid for pid, pkg in pkg_by_id.items() if pkg.get("name") in set(packages)]
        if packages
        else list(meta.get("workspace_members", []))
    )
    expected: set[tuple[str, str]] = set()
    queue = list(roots)
    seen: set[str] = set()
    while queue:
        cur = queue.pop(0)
        if cur in seen or cur not in pkg_by_id:
            continue
        seen.add(cur)
        pkg = pkg_by_id[cur]
        expected.add((pkg["name"], pkg["version"]))
        for dep in resolve_nodes.get(cur, {}).get("deps", []):
            dep_id = dep.get("pkg")
            if dep_id:
                queue.append(dep_id)

    sbom_by_nv: dict[tuple[str, str], dict[str, Any]] = {}
    for comp in components:
        sbom_by_nv[(str(comp.get("name", "")), str(comp.get("version", "")))] = comp

    missing = sorted(expected - set(sbom_by_nv))
    if missing:
        raise ValueError(f"SBOM missing resolved Cargo components: {missing[:10]}")

    for nv in expected:
        expected_hash = lock_hashes.get(nv)
        if not expected_hash:
            continue
        hashes = {h.get("alg"): h.get("content") for h in sbom_by_nv[nv].get("hashes", [])}
        if hashes.get("SHA-256") != expected_hash:
            raise ValueError(f"Cargo.lock SHA-256 mismatch in SBOM for {nv[0]}@{nv[1]}")
    return len(expected)


def verify_binary_architecture(binary_path: Path, target_triple: str) -> str:
    data = binary_path.read_bytes()
    if len(data) < 64:
        raise ValueError(f"{binary_path} is too small to hold an executable header")

    want_arch = "aarch64" if target_triple.startswith("aarch64-") else "x86_64"
    if "linux" in target_triple:
        if data[:4] != b"\x7fELF":
            raise ValueError(f"{binary_path} is not an ELF binary for {target_triple}")
        endian = "<" if data[5] == 1 else ">"
        e_machine = struct.unpack_from(f"{endian}H", data, 18)[0]
        actual = {62: "x86_64", 183: "aarch64"}.get(e_machine, f"elf-0x{e_machine:x}")
    elif "windows" in target_triple:
        if data[:2] != b"MZ":
            raise ValueError(f"{binary_path} is not a PE binary for {target_triple}")
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 6 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
            raise ValueError(f"{binary_path} has malformed PE signature")
        machine = struct.unpack_from("<H", data, pe_off + 4)[0]
        actual = {0x8664: "x86_64", 0xAA64: "aarch64"}.get(machine, f"pe-0x{machine:x}")
    elif "apple-darwin" in target_triple:
        magic = data[:4]
        if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
            fmt = "<I" if magic == b"\xcf\xfa\xed\xfe" else ">I"
            cputype = struct.unpack_from(fmt, data, 4)[0]
            actual = {0x01000007: "x86_64", 0x0100000C: "aarch64"}.get(cputype, f"macho-0x{cputype:x}")
        elif magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            nfat = struct.unpack_from(">I", data, 4)[0]
            stride = 20 if magic == b"\xca\xfe\xba\xbe" else 32
            cputypes = [struct.unpack_from(">I", data, 8 + i * stride)[0] for i in range(nfat)]
            wanted_cpu = 0x0100000C if want_arch == "aarch64" else 0x01000007
            actual = want_arch if wanted_cpu in cputypes else f"fat-{cputypes}"
        else:
            raise ValueError(f"{binary_path} is not a Mach-O binary for {target_triple}")
    else:
        raise ValueError(f"unsupported target triple for binary inspection: {target_triple}")

    if actual != want_arch:
        raise ValueError(f"{binary_path} architecture mismatch: expected {want_arch} for {target_triple}, got {actual}")
    return actual


def verify_containerfile_hardening(path: Path) -> None:
    text = path.read_text("utf-8")
    from_lines = [line.strip() for line in text.splitlines() if line.strip().startswith("ARG ") and "IMAGE=" in line]
    for line in from_lines:
        if "@sha256:" not in line:
            raise ValueError(f"{path} base image pin missing @sha256 digest: {line}")
    if "USER 65532:65532" not in text:
        raise ValueError(f"{path} must drop privileges to USER 65532:65532")
    if "--locked" not in text:
        raise ValueError(f"{path} cargo build must use --locked")
    if "fips" in path.name.lower():
        if "--features fips" not in text:
            raise ValueError(f"{path} FIPS Containerfile must compile with --features fips")
        if "GRDR_FIPS_REQUIRE_VALIDATED_MODULE=1" in text:
            raise ValueError(f"{path} must not hardcode GRDR_FIPS_REQUIRE_VALIDATED_MODULE=1 before SP-24-2 admission")
        if "/src/web/apps/console/dist" in text or "/src/web/dist" not in text:
            raise ValueError(f"{path} must copy Vite console bundle from /src/web/dist")


def install_grype_verified(version: str, dest_dir: Path, arch: str | None = None) -> Path:
    norm_ver = version.strip()
    if not norm_ver.startswith("v"):
        norm_ver = f"v{norm_ver}"
    if arch is None:
        mach = platform.machine().lower()
        arch_key = "linux_arm64" if mach in ("aarch64", "arm64") else "linux_amd64"
    else:
        arch_key = arch
    expected_sha256 = GRYPE_PINNED_DIGESTS.get((norm_ver, arch_key))
    if not expected_sha256:
        raise ValueError(f"no pinned SHA-256 digest configured for grype {norm_ver} ({arch_key})")

    bare_ver = norm_ver.lstrip("v")
    filename = f"grype_{bare_ver}_{arch_key}.tar.gz"
    url = f"https://github.com/anchore/grype/releases/download/{norm_ver}/{filename}"
    raw = urllib.request.urlopen(url, timeout=60).read()
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError(
            f"grype archive SHA-256 mismatch for {filename}: expected {expected_sha256}, got {actual_sha256}"
        )

    dest_dir.mkdir(parents=True, exist_ok=True)
    out_bin = dest_dir / "grype"
    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / filename
        archive_path.write_bytes(raw)
        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf.getmembers():
                member_name = member.name.lstrip("./")
                if member_name == "grype" and member.isfile():
                    src_f = tf.extractfile(member)
                    if src_f is None:
                        raise ValueError("failed extracting grype binary from archive")
                    fd = os.open(out_bin, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o755)
                    with os.fdopen(fd, "wb") as dst_f:
                        shutil.copyfileobj(src_f, dst_f)
                    return out_bin
    raise ValueError(f"grype binary not found inside {filename}")


def check_grype_report(report_doc: dict[str, Any]) -> int:
    matches = report_doc.get("matches", [])
    if not isinstance(matches, list):
        raise ValueError("grype report 'matches' must be a list")

    kev_hits: list[str] = []
    high_crit_hits: list[str] = []
    for match in matches:
        vuln = match.get("vulnerability", {}) if isinstance(match, dict) else {}
        vid = str(vuln.get("id", "unknown"))
        severity = str(vuln.get("severity", "")).lower()

        is_kev = bool(vuln.get("knownExploited") or vuln.get("kev"))
        for rel in match.get("relatedVulnerabilities", []) if isinstance(match, dict) else []:
            if isinstance(rel, dict) and (rel.get("knownExploited") or rel.get("kev")):
                is_kev = True
        if is_kev:
            kev_hits.append(f"{vid} ({severity or 'unknown'})")
        if severity in ("high", "critical"):
            high_crit_hits.append(f"{vid} ({severity})")

    if kev_hits:
        raise ValueError(f"Grype detected CISA KEV vulnerabilities regardless of severity: {kev_hits}")
    if high_crit_hits:
        raise ValueError(f"Grype detected High/Critical vulnerabilities: {high_crit_hits}")
    return len(matches)


def check_fuzz_targets_parity(targets_toml: Path, build_sh: Path) -> list[str]:
    cfg = tomllib.loads(targets_toml.read_text("utf-8"))
    toml_targets = [str(entry["name"]) for entry in cfg.get("target", [])]
    if not toml_targets:
        raise ValueError(f"{targets_toml} declares no [[target]] entries")

    build_text = build_sh.read_text("utf-8")
    m = FUZZ_TARGET_BLOCK_RE.search(build_text)
    if not m:
        raise ValueError(f"{build_sh} missing 'for target in ... do' build loop")
    cleaned = m.group("body").replace("\\\n", " ").replace("\\", " ")
    script_targets = [tok.strip() for tok in cleaned.split() if tok.strip()]

    missing_in_script = sorted(set(toml_targets) - set(script_targets))
    extra_in_script = sorted(set(script_targets) - set(toml_targets))
    if missing_in_script or extra_in_script:
        raise ValueError(
            f"fuzz-targets.toml mismatch with {build_sh}: "
            f"missing_in_script={missing_in_script}, extra_in_script={extra_in_script}"
        )
    return toml_targets
