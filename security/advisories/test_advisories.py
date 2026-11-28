# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

"""Unit tests for PSIRT CSAF 2.0, OpenVEX 0.2.0, OSV 1.6, CRA Art.14, and yank tools."""

from __future__ import annotations

import copy
import sys
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_advisories as ga


SAMPLE_ADVISORY = {
    "schema_version": "grdr.advisory.v1",
    "id": "GRDR-ADV-2026-0001",
    "cve": "CVE-2026-99999",
    "ghsa": "GHSA-aaaa-bbbb-cccc",
    "title": "Test TLS handshake parser bounds check issue",
    "summary": "A crafted frame in a component triggered bounded rejection before allocation.",
    "severity": "high",
    "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N",
    "kev": False,
    "actively_exploited": True,
    "discovered_at": "2026-11-01T00:00:00Z",
    "published_at": "2026-11-02T00:00:00Z",
    "cra_incident_class": "actively_exploited_vulnerability",
    "affected_packages": [
        {
            "ecosystem": "crates.io",
            "name": "grdr-wire",
            "purl": "pkg:cargo/grdr-wire@0.1.0",
            "ranges": [{"introduced": "0.1.0", "fixed": "0.1.1"}],
        }
    ],
    "vex_statements": [
        {
            "product": "pkg:cargo/grdr-server@0.1.0",
            "status": "affected",
            "action_statement": "Upgrade grdr-server bundle to 0.1.1 or later.",
        },
        {
            "product": "pkg:cargo/grdr-hook@0.1.0",
            "status": "not_affected",
            "justification": "vulnerable_code_not_present",
            "impact_statement": "grdr-hook does not compile the affected decoder path.",
        },
    ],
    "yank_versions": [
        {
            "component": "grdr-server",
            "version": "0.1.0",
            "reason": "Superseded by 0.1.1 fix.",
        }
    ],
}


class AdvisoryToolsTests(unittest.TestCase):
    def test_generates_csaf_openvex_osv_deadlines_and_yanks(self) -> None:
        bundle = ga.generate_all_documents(SAMPLE_ADVISORY)

        csaf = bundle["csaf"]
        self.assertEqual(csaf["document"]["category"], "csaf_vex")
        self.assertEqual(csaf["document"]["csaf_version"], "2.0")
        vuln = csaf["vulnerabilities"][0]
        self.assertEqual(vuln["cve"], "CVE-2026-99999")
        self.assertIn({"system_name": "Guardrails Advisory", "text": "GRDR-ADV-2026-0001"}, vuln["ids"])
        self.assertIn("pkg:cargo/grdr-hook@0.1.0", vuln["product_status"]["known_not_affected"])

        tree_pids = {b["product"]["product_id"] for b in csaf["product_tree"]["branches"]}
        for group_pids in vuln["product_status"].values():
            for pid in group_pids:
                self.assertIn(pid, tree_pids)
        for threat in vuln.get("threats", []):
            for pid in threat["product_ids"]:
                self.assertIn(pid, tree_pids)
        for rem in vuln.get("remediations", []):
            self.assertEqual(rem["category"], "vendor_fix")
            for pid in rem["product_ids"]:
                self.assertIn(pid, tree_pids)

        openvex = bundle["openvex"]
        self.assertEqual(openvex["@context"], "https://openvex.dev/ns/v0.2.0")
        self.assertEqual(len(openvex["statements"]), 2)
        self.assertEqual(openvex["statements"][1]["justification"], "vulnerable_code_not_present")

        osv = bundle["osv"]
        self.assertEqual(osv["schema_version"], "1.6.0")
        self.assertEqual(osv["affected"][0]["ranges"][0]["events"][1]["fixed"], "0.1.1")

        deadlines = bundle["deadlines"]
        self.assertTrue(deadlines["cra_applicable"])
        self.assertEqual(deadlines["early_warning_due_utc"], "2026-11-02T00:00:00Z")
        self.assertEqual(deadlines["initial_notification_due_utc"], "2026-11-04T00:00:00Z")
        self.assertEqual(deadlines["final_report_due_utc"], "2026-11-15T00:00:00Z")
        self.assertEqual(deadlines["patch_sla_due_utc"], "2026-11-08T00:00:00Z")

        yanks = bundle["yanks"]
        self.assertEqual(len(yanks), 1)
        self.assertTrue(yanks[0]["avoid"])
        self.assertIn("GRDR-ADV-2026-0001", yanks[0]["avoid_reason"])

    def test_severe_incident_uses_30_day_cra_final_clock(self) -> None:
        severe = copy.deepcopy(SAMPLE_ADVISORY)
        severe["cra_incident_class"] = "severe_incident"
        deadlines = ga.generate_all_documents(severe)["deadlines"]
        self.assertEqual(deadlines["final_report_due_utc"], "2026-12-01T00:00:00Z")

    def test_rejects_not_affected_without_justification(self) -> None:
        bad = copy.deepcopy(SAMPLE_ADVISORY)
        del bad["vex_statements"][1]["justification"]
        with self.assertRaises(ValueError):
            ga.validate_advisory_record(bad)

    def test_rejects_affected_without_action_statement(self) -> None:
        bad = copy.deepcopy(SAMPLE_ADVISORY)
        del bad["vex_statements"][0]["action_statement"]
        with self.assertRaises(ValueError):
            ga.validate_advisory_record(bad)

    def test_missing_cve_uses_ids_only_and_rejects_bad_inputs(self) -> None:
        no_cve = copy.deepcopy(SAMPLE_ADVISORY)
        del no_cve["cve"]
        no_cve["published_at"] = "2026-11-02T01:00:00+01:00"
        bundle = ga.generate_all_documents(no_cve)
        vuln = bundle["csaf"]["vulnerabilities"][0]
        self.assertNotIn("cve", vuln)
        self.assertIn({"system_name": "Guardrails Advisory", "text": "GRDR-ADV-2026-0001"}, vuln["ids"])
        self.assertEqual(bundle["csaf"]["document"]["tracking"]["initial_release_date"], "2026-11-02T00:00:00Z")

        for bad_mut in (
            lambda r: r.__setitem__("id", "GRDR-ADV-2026-0001\n"),
            lambda r: r["vex_statements"][0].__setitem__("product", "  "),
            lambda r: r["affected_packages"][0]["ranges"][0].__setitem__("introduced", ""),
        ):
            bad = copy.deepcopy(SAMPLE_ADVISORY)
            bad_mut(bad)
            with self.assertRaises(ValueError):
                ga.validate_advisory_record(bad)

    def test_records_dir_validation_and_cli_emit(self) -> None:
        records_dir = Path(__file__).resolve().parent / "records"
        count = ga.check_advisory_dir(records_dir)
        self.assertGreaterEqual(count, 0)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "GRDR-ADV-2026-0001.json"
            import json
            src.write_text(json.dumps(SAMPLE_ADVISORY), "utf-8")
            out_dir = tmp_path / "out"
            rc = ga.main(["--emit", str(src), "--out-dir", str(out_dir)])
            self.assertEqual(rc, 0)
            self.assertTrue((out_dir / "GRDR-ADV-2026-0001.csaf.json").is_file())
            self.assertTrue((out_dir / "GRDR-ADV-2026-0001.openvex.json").is_file())
            self.assertTrue((out_dir / "GRDR-ADV-2026-0001.osv.json").is_file())


if __name__ == "__main__":
    unittest.main()
