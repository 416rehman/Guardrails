# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

"""Unit tests for deploy/release/release_tools.py and sbom_tools.py."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_tools as rt
import sbom_tools as st


def _assert_matches_schema(doc: object, schema: dict, path: str = "$") -> None:
    expected_type = schema.get("type")
    if expected_type is not None:
        allowed = expected_type if isinstance(expected_type, list) else [expected_type]
        type_ok = any(
            (t == "null" and doc is None)
            or (t == "boolean" and isinstance(doc, bool))
            or (t == "integer" and isinstance(doc, int) and not isinstance(doc, bool))
            or (t == "string" and isinstance(doc, str))
            or (t == "array" and isinstance(doc, list))
            or (t == "object" and isinstance(doc, dict))
            for t in allowed
        )
        if not type_ok:
            raise AssertionError(f"{path}: expected type {allowed}, got {type(doc).__name__}")
    if doc is None:
        return
    if "const" in schema and doc != schema["const"]:
        raise AssertionError(f"{path}: expected const {schema['const']!r}, got {doc!r}")
    if "enum" in schema and doc not in schema["enum"]:
        raise AssertionError(f"{path}: {doc!r} not in enum {schema['enum']}")
    if isinstance(doc, str) and "pattern" in schema:
        if not re.match(schema["pattern"], doc):
            raise AssertionError(f"{path}: {doc!r} failed pattern {schema['pattern']}")
    if isinstance(doc, int) and not isinstance(doc, bool) and "minimum" in schema:
        if doc < schema["minimum"]:
            raise AssertionError(f"{path}: {doc} < minimum {schema['minimum']}")
    if isinstance(doc, list):
        if "minItems" in schema and len(doc) < schema["minItems"]:
            raise AssertionError(f"{path}: array len {len(doc)} < minItems {schema['minItems']}")
        if "items" in schema:
            for idx, item in enumerate(doc):
                _assert_matches_schema(item, schema["items"], f"{path}[{idx}]")
    if isinstance(doc, dict):
        if "minProperties" in schema and len(doc) < schema["minProperties"]:
            raise AssertionError(f"{path}: object keys {len(doc)} < minProperties {schema['minProperties']}")
        for req in schema.get("required", []):
            if req not in doc:
                raise AssertionError(f"{path}: missing required key {req!r}")
        props = schema.get("properties", {})
        addl = schema.get("additionalProperties", True)
        for key, val in doc.items():
            if key in props:
                _assert_matches_schema(val, props[key], f"{path}.{key}")
            elif addl is False:
                raise AssertionError(f"{path}: unexpected additionalProperty {key!r}")
            elif isinstance(addl, dict):
                _assert_matches_schema(val, addl, f"{path}.{key}")


def _fake_cargo_metadata(root_name: str = "grdr") -> dict:
    return {
        "workspace_members": [f"{root_name} 0.1.0 (path+file:///repo)"],
        "packages": [
            {
                "id": f"{root_name} 0.1.0 (path+file:///repo)",
                "name": root_name,
                "version": "0.1.0",
                "license": "Apache-2.0",
            },
            {
                "id": "grdr-crypto 0.1.0 (path+file:///repo/crates/grdr-crypto)",
                "name": "grdr-crypto",
                "version": "0.1.0",
                "license": "Apache-2.0",
            },
        ],
        "resolve": {
            "nodes": [
                {
                    "id": f"{root_name} 0.1.0 (path+file:///repo)",
                    "deps": [{"pkg": "grdr-crypto 0.1.0 (path+file:///repo/crates/grdr-crypto)"}],
                },
                {
                    "id": "grdr-crypto 0.1.0 (path+file:///repo/crates/grdr-crypto)",
                    "deps": [],
                },
            ]
        },
    }


class ReleaseToolsTests(unittest.TestCase):
    def test_release_configs_and_real_roots_pass(self) -> None:
        summary = rt.check_release_configs()
        self.assertEqual(summary["bundle_version"], "0.1.0")
        self.assertGreaterEqual(summary["package_count"], 20)

    def test_support_matrix_and_semver_prerelease_rules(self) -> None:
        matrix = rt.build_support_matrix()
        targets = {cell["target"] for cell in matrix["tier1_cells"]}
        self.assertIn("x86_64-unknown-linux-musl", targets)
        self.assertIn("aarch64-apple-darwin", targets)
        self.assertIn("x86_64-pc-windows-msvc", targets)
        self.assertEqual(matrix["postgresql_major"], 18)

        hops = rt.compute_upgrade_hops("1.0.0", "1.5.2", lts_versions=["1.3.0"])
        self.assertEqual(hops, ["1.2.0", "1.3.0", "1.5.2"])
        self.assertEqual(rt.compute_upgrade_hops("0.1.0-rc.1", "0.1.0"), ["0.1.0"])
        with self.assertRaises(ValueError):
            rt.compute_upgrade_hops("0.1.0", "0.1.0-rc.1")
        with self.assertRaises(ValueError):
            rt.parse_semver("0.1.0\n")

    def test_support_matrix_drift_checks_yaml_matrix_and_unconditional_target(self) -> None:
        matrix = rt.build_support_matrix()
        self.assertEqual(
            rt.check_workflow_matrix_coverage(matrix, [rt.ROOT / ".github" / "workflows" / "release.yml"]),
            [],
        )
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp) / "partial.yml"
            wf.write_text("  - target: x86_64-unknown-linux-musl\n", "utf-8")
            missing = rt.check_workflow_matrix_coverage(matrix, [wf])
            self.assertTrue(missing)

    def test_fips_sbom_validation_honesty_and_macos_prohibition(self) -> None:
        honest_linux_fips = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "name": "grdr",
                    "properties": [
                        {"name": "grdr:fips:profile", "value": "fips"},
                        {"name": "grdr:fips:cmvp-status", "value": "unvalidated-pending-sp-24-2"},
                    ],
                }
            },
        }
        st.validate_fips_sbom_document(honest_linux_fips, "linux", True)
        st.validate_fips_sbom_document(honest_linux_fips, "windows", True)
        with self.assertRaises(ValueError):
            st.validate_fips_sbom_document(honest_linux_fips, "macos", False)

        fabricated_cmvp = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "name": "grdr-server",
                    "properties": [
                        {"name": "grdr:fips:module", "value": "AWS-LC Cryptographic Module"},
                        {"name": "grdr:fips:cmvp-certificate", "value": "#5314"},
                    ],
                }
            },
        }
        with self.assertRaises(ValueError):
            st.validate_fips_sbom_document(fabricated_cmvp, "linux", True)

    def test_workspace_sbom_generation_and_crosscheck(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = Path(tmp) / "out.cdx.json"
            fake_meta = _fake_cargo_metadata()
            doc = st.generate_workspace_sbom(
                out_path=sbom_path,
                bundle_version="0.1.0",
                target_os="linux",
                target_triple="x86_64-unknown-linux-gnu",
                fips_enabled=True,
                packages=["grdr"],
                cargo_metadata_doc=fake_meta,
            )
            self.assertEqual(len(doc["components"]), 2)
            self.assertEqual(st.cross_check_sbom(doc, "x86_64-unknown-linux-gnu", True, ["grdr"], cargo_metadata_doc=fake_meta), 2)

            tampered = copy.deepcopy(doc)
            tampered["components"] = [c for c in tampered["components"] if c["name"] != "grdr-crypto"]
            with self.assertRaises(ValueError):
                st.cross_check_sbom(tampered, "x86_64-unknown-linux-gnu", True, ["grdr"], cargo_metadata_doc=fake_meta)

    def test_tuf_and_sigstore_root_tampering_rejected(self) -> None:
        real_tuf = json.loads((rt.ROOT / "deploy" / "release" / "tuf" / "1.root.json").read_text("utf-8"))
        rt.validate_tuf_root_doc(real_tuf)

        with_fleet = copy.deepcopy(real_tuf)
        with_fleet["signed"]["roles"]["fleet"] = {"key_ids": ["kid_00df61b945c6e257"], "threshold": 1}
        with self.assertRaises(ValueError):
            rt.validate_tuf_root_doc(with_fleet)

        real_sigstore = json.loads((rt.ROOT / "deploy" / "release" / "sigstore" / "trusted_root.json").read_text("utf-8"))
        rt.validate_sigstore_trusted_root(real_sigstore)

        empty_cert = copy.deepcopy(real_sigstore)
        empty_cert["certificateAuthorities"][0]["certChain"]["certificates"] = []
        with self.assertRaises(ValueError):
            rt.validate_sigstore_trusted_root(empty_cert)

    def test_release_manifest_bundle_aggregation_schema_and_upgrade_k8s(self) -> None:
        schema = json.loads((rt.ROOT / "deploy" / "release" / "release-manifest.schema.json").read_text("utf-8"))
        art_a = {
            "name": "grdr-0.4.0-x86_64-unknown-linux-musl.tar.gz",
            "kind": "binary-tarball",
            "os": "linux",
            "arch": "x86_64",
            "uri": "https://github.com/416rehman/Guardrails/releases/download/grdr-v0.4.0/grdr-0.4.0-x86_64-unknown-linux-musl.tar.gz",
            "sha256": "b" * 64,
            "size_bytes": 1234,
            "platform_signature_present": False,
            "sigstore_bundle": "grdr-0.4.0-x86_64-unknown-linux-musl.tar.gz.sigstore.json",
        }
        art_b = {
            "name": "grdr-0.4.0-x86_64-unknown-linux-musl.cdx.json",
            "kind": "sbom",
            "os": "linux",
            "arch": "x86_64",
            "uri": "https://github.com/416rehman/Guardrails/releases/download/grdr-v0.4.0/grdr-0.4.0-x86_64-unknown-linux-musl.cdx.json",
            "sha256": "a" * 64,
            "size_bytes": 567,
            "platform_signature_present": False,
        }
        manifest = rt.build_release_manifest("0.4.0", "1" * 40, "broad", [art_a, art_b])
        _assert_matches_schema(manifest, schema)
        expected_agg = hashlib.sha256(
            f"{art_b['name']}:{'a' * 64}\n{art_a['name']}:{'b' * 64}".encode("utf-8")
        ).hexdigest()
        self.assertEqual(manifest["components"]["grdr-bundle"]["sha256"], expected_agg)
        self.assertFalse(manifest["components"]["grdr-bundle"]["signed"])
        self.assertIsNone(manifest["fips_module"])
        self.assertEqual(manifest["fips_status"], "unvalidated-pending-sp-24-2")
        self.assertEqual(manifest["compat"]["min_upgrade_from"], "0.2.0")

    def test_grype_report_rejects_kev_and_high_critical(self) -> None:
        st.check_grype_report({"matches": [{"vulnerability": {"id": "CVE-2026-0001", "severity": "Low"}}]})
        with self.assertRaises(ValueError):
            st.check_grype_report(
                {
                    "matches": [
                        {
                            "vulnerability": {
                                "id": "CVE-2026-0002",
                                "severity": "Low",
                                "knownExploited": [{"cve": "CVE-2026-0002"}],
                            }
                        }
                    ]
                }
            )
        with self.assertRaises(ValueError):
            st.check_grype_report({"matches": [{"vulnerability": {"id": "CVE-2026-0003", "severity": "High"}}]})

    def test_binary_arch_inspection_and_fuzz_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            elf = Path(tmp) / "grdr"
            buf = bytearray(64)
            buf[0:4] = b"\x7fELF"
            buf[5] = 1
            struct.pack_into("<H", buf, 18, 62)
            elf.write_bytes(bytes(buf))
            self.assertEqual(st.verify_binary_architecture(elf, "x86_64-unknown-linux-gnu"), "x86_64")
            with self.assertRaises(ValueError):
                st.verify_binary_architecture(elf, "aarch64-unknown-linux-gnu")

        names = st.check_fuzz_targets_parity(
            rt.ROOT / "security" / "fuzz-targets.toml",
            rt.ROOT / ".clusterfuzzlite" / "build.sh",
        )
        self.assertEqual(len(names), 10)
        st.verify_containerfile_hardening(rt.ROOT / "deploy" / "release" / "fips" / "Containerfile.server-fips")

    def test_collect_release_artefacts_and_repo_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            dist = tmp_path / "dist"
            dist.mkdir()
            tarball = dist / "grdr-0.4.0-x86_64-unknown-linux-musl.tar.gz"
            tarball.write_bytes(b"tarball-bytes")
            (dist / "grdr-0.4.0-x86_64-unknown-linux-musl.tar.gz.sigstore.json").write_text("{}", "utf-8")
            (dist / "grdr-0.4.0-x86_64-unknown-linux-musl.cdx.json").write_text("{}", "utf-8")
            (dist / "ignored.tmp").write_text("x", "utf-8")
            out_json = tmp_path / "bundle" / "artefacts.json"
            items = rt.collect_release_artefacts(dist, "0.4.0", "416rehman/Guardrails", out_json)
            self.assertEqual(len(items), 2)
            self.assertTrue(out_json.is_file())
            tar_entry = [i for i in items if i["kind"] == "binary-tarball"][0]
            self.assertEqual(tar_entry["sigstore_bundle"], "grdr-0.4.0-x86_64-unknown-linux-musl.tar.gz.sigstore.json")
            self.assertEqual(
                tar_entry["uri"],
                "https://github.com/416rehman/Guardrails/releases/download/grdr-v0.4.0/grdr-0.4.0-x86_64-unknown-linux-musl.tar.gz",
            )
            with self.assertRaises(ValueError):
                rt.collect_release_artefacts(dist, "0.4.0", "416rehman/Guardrails/extra", out_json)


if __name__ == "__main__":
    unittest.main()
