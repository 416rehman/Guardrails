# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors

"""PSIRT CSAF 2.0, OpenVEX 0.2.0, OSV 1.6, CRA Art.14 clock, and yank tooling."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "none"})
VALID_VEX_STATUSES = frozenset({"not_affected", "affected", "fixed", "under_investigation"})
VALID_VEX_JUSTIFICATIONS = frozenset(
    {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "vulnerable_code_not_in_execute_path",
        "inline_mitigations_already_exist",
    }
)
VALID_CRA_CLASSES = frozenset({"actively_exploited_vulnerability", "severe_incident", "none"})
ADV_ID_RE = re.compile(r"^GRDR-ADV-[0-9]{4}-[0-9]{4}\Z")
CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}\Z")
ROOT = Path(__file__).resolve().parents[2]


def load_policy_context(root: Path = ROOT) -> dict[str, Any]:
    psirt = tomllib.loads((root / "security" / "advisories" / "psirt-policy.toml").read_text("utf-8"))
    brand = tomllib.loads((root / "contracts" / "interface" / "brand" / "brand.toml").read_text("utf-8"))
    support = tomllib.loads((root / "contracts" / "support.toml").read_text("utf-8"))
    dist = tomllib.loads((root / "deploy" / "release" / "dist.toml").read_text("utf-8"))
    return {"psirt": psirt, "brand": brand, "support": support, "dist": dist}


def parse_utc(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        raise ValueError(f"timestamp must include UTC/offset timezone: {value}")
    return dt.astimezone(timezone.utc)


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_advisory_record(record: dict[str, Any]) -> None:
    required = [
        "schema_version",
        "id",
        "title",
        "summary",
        "severity",
        "discovered_at",
        "published_at",
        "cra_incident_class",
        "affected_packages",
        "vex_statements",
    ]
    for field in required:
        if field not in record:
            raise ValueError(f"missing required advisory field: {field}")

    if record["schema_version"] != "grdr.advisory.v1":
        raise ValueError(f"unsupported schema_version: {record['schema_version']}")
    if not ADV_ID_RE.match(str(record["id"])):
        raise ValueError(f"invalid advisory id format: {record['id']}")
    if "cve" in record and record["cve"] and not CVE_ID_RE.match(str(record["cve"])):
        raise ValueError(f"invalid CVE format: {record['cve']}")
    if record["severity"] not in VALID_SEVERITIES:
        raise ValueError(f"invalid severity: {record['severity']}")
    if record["cra_incident_class"] not in VALID_CRA_CLASSES:
        raise ValueError(f"invalid cra_incident_class: {record['cra_incident_class']}")

    discovered = parse_utc(str(record["discovered_at"]))
    published = parse_utc(str(record["published_at"]))
    if published < discovered:
        raise ValueError("published_at cannot precede discovered_at")

    pkgs = record["affected_packages"]
    if not isinstance(pkgs, list) or not pkgs:
        raise ValueError("affected_packages must be a non-empty list")
    for pkg in pkgs:
        for f in ("ecosystem", "name", "purl", "ranges"):
            if not pkg.get(f):
                raise ValueError(f"affected_packages entry missing {f}")
        ranges = pkg["ranges"]
        if not isinstance(ranges, list) or not ranges:
            raise ValueError(f"affected_packages '{pkg.get('name')}' ranges must be a non-empty list")
        for rng in ranges:
            if not isinstance(rng, dict) or not str(rng.get("introduced", "")).strip():
                raise ValueError(f"affected_packages '{pkg.get('name')}' range missing non-empty 'introduced'")

    stmts = record["vex_statements"]
    if not isinstance(stmts, list) or not stmts:
        raise ValueError("vex_statements must be a non-empty list")
    for stmt in stmts:
        pid = stmt.get("product")
        if not isinstance(pid, str) or not pid.strip():
            raise ValueError("vex_statements entry missing non-empty 'product'")
        status = stmt.get("status")
        if status not in VALID_VEX_STATUSES:
            raise ValueError(f"invalid VEX status: {status}")
        if status == "not_affected":
            just = stmt.get("justification")
            if just not in VALID_VEX_JUSTIFICATIONS:
                raise ValueError(
                    f"OpenVEX not_affected statement for '{stmt.get('product')}' requires valid justification"
                )
        if status == "affected" and not stmt.get("action_statement"):
            raise ValueError(
                f"affected VEX statement for '{stmt.get('product')}' requires action_statement"
            )

    for yank in record.get("yank_versions", []):
        for f in ("component", "version", "reason"):
            if not yank.get(f):
                raise ValueError(f"yank_versions entry missing {f}")


def compute_reporting_deadlines(record: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    psirt = policy["psirt"]
    discovered = parse_utc(str(record["discovered_at"]))
    cra = psirt["cra_article_14"]
    sla = psirt["sla"]

    patch_due = discovered + timedelta(days=int(sla["bundled_dependency_patch_days"]))
    incident_class = record["cra_incident_class"]
    if incident_class == "none":
        return {
            "advisory_id": record["id"],
            "cra_applicable": False,
            "patch_sla_due_utc": format_utc(patch_due),
        }

    early_due = discovered + timedelta(hours=int(cra["early_warning_hours"]))
    initial_due = discovered + timedelta(hours=int(cra["initial_notification_hours"]))
    final_days = (
        int(cra["final_report_exploited_vulnerability_days"])
        if incident_class == "actively_exploited_vulnerability"
        else int(cra["final_report_severe_incident_days"])
    )
    final_due = discovered + timedelta(days=final_days)
    return {
        "advisory_id": record["id"],
        "cra_applicable": True,
        "cra_incident_class": incident_class,
        "discovered_at_utc": format_utc(discovered),
        "early_warning_due_utc": format_utc(early_due),
        "initial_notification_due_utc": format_utc(initial_due),
        "final_report_due_utc": format_utc(final_due),
        "patch_sla_due_utc": format_utc(patch_due),
    }


def _infer_product_name(product_id: str) -> str:
    if product_id.startswith("pkg:"):
        body = product_id.split(":", 1)[1]
        name_part = body.rsplit("@", 1)[0]
        return name_part.rsplit("/", 1)[-1]
    return product_id


def render_csaf_vex(record: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    brand = policy["brand"]
    publisher_name = brand["identity"]["publisher"]
    advisories_ns = f"https://{brand['identity']['domain']}/security/advisories"
    published_utc = format_utc(parse_utc(str(record["published_at"])))

    branches = []
    seen_products: set[str] = set()
    for pkg in record["affected_packages"]:
        pid = str(pkg["purl"])
        if pid in seen_products:
            continue
        seen_products.add(pid)
        branches.append(
            {
                "category": "product_version",
                "name": str(pkg["name"]),
                "product": {
                    "name": str(pkg["name"]),
                    "product_id": pid,
                    "product_identification_helper": {"purl": pid},
                },
            }
        )

    for stmt in record["vex_statements"]:
        pid = str(stmt["product"])
        if pid in seen_products:
            continue
        seen_products.add(pid)
        inferred = _infer_product_name(pid)
        product_entry: dict[str, Any] = {
            "name": inferred,
            "product_id": pid,
        }
        if pid.startswith("pkg:"):
            product_entry["product_identification_helper"] = {"purl": pid}
        branches.append(
            {
                "category": "product_version",
                "name": inferred,
                "product": product_entry,
            }
        )

    status_groups: dict[str, list[str]] = {
        "known_affected": [],
        "known_not_affected": [],
        "fixed": [],
        "under_investigation": [],
    }
    threats = []
    remediations = []
    for stmt in record["vex_statements"]:
        pid = str(stmt["product"])
        st = stmt["status"]
        if st == "affected":
            status_groups["known_affected"].append(pid)
            remediations.append(
                {
                    "category": "vendor_fix",
                    "details": str(stmt["action_statement"]),
                    "product_ids": [pid],
                }
            )
        elif st == "not_affected":
            status_groups["known_not_affected"].append(pid)
            threats.append(
                {
                    "category": "impact",
                    "details": stmt.get("impact_statement") or stmt["justification"],
                    "product_ids": [pid],
                }
            )
        elif st == "fixed":
            status_groups["fixed"].append(pid)
        else:
            status_groups["under_investigation"].append(pid)

    product_status = {k: v for k, v in status_groups.items() if v}
    ids = [{"system_name": "Guardrails Advisory", "text": str(record["id"])}]
    if record.get("ghsa"):
        ids.append({"system_name": "GitHub Security Advisory", "text": str(record["ghsa"])})
    vuln: dict[str, Any] = {
        "ids": ids,
        "title": record["title"],
        "notes": [{"category": "summary", "text": record["summary"]}],
        "product_status": product_status,
    }
    if record.get("cve"):
        vuln["cve"] = str(record["cve"])
    if threats:
        vuln["threats"] = threats
    if remediations:
        vuln["remediations"] = remediations

    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": record["title"],
            "publisher": {
                "category": "vendor",
                "name": publisher_name,
                "namespace": advisories_ns,
            },
            "tracking": {
                "id": record["id"],
                "status": "final",
                "version": "1",
                "initial_release_date": published_utc,
                "current_release_date": published_utc,
            },
        },
        "product_tree": {"branches": branches},
        "vulnerabilities": [vuln],
    }


def render_openvex(record: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    brand = policy["brand"]
    psirt = policy["psirt"]
    domain = brand["identity"]["domain"]
    vuln_id = record.get("cve") or record["id"]
    published_utc = format_utc(parse_utc(str(record["published_at"])))
    statements = []
    for stmt in record["vex_statements"]:
        entry: dict[str, Any] = {
            "vulnerability": {"name": vuln_id, "description": record["summary"]},
            "products": [{"@id": stmt["product"]}],
            "status": stmt["status"],
        }
        if stmt.get("justification"):
            entry["justification"] = stmt["justification"]
        if stmt.get("impact_statement"):
            entry["impact_statement"] = stmt["impact_statement"]
        if stmt.get("action_statement"):
            entry["action_statement"] = stmt["action_statement"]
        statements.append(entry)

    return {
        "@context": psirt["formats"]["openvex_context"],
        "@id": f"https://{domain}/security/vex/{record['id']}",
        "author": brand["identity"]["publisher"],
        "role": "vendor",
        "timestamp": published_utc,
        "version": 1,
        "statements": statements,
    }


def render_osv(record: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    psirt = policy["psirt"]
    published_utc = format_utc(parse_utc(str(record["published_at"])))
    aliases = [v for v in (record.get("cve"), record.get("ghsa")) if v]
    affected = []
    for pkg in record["affected_packages"]:
        events = []
        for rng in pkg["ranges"]:
            events.append({"introduced": rng["introduced"]})
            if rng.get("fixed"):
                events.append({"fixed": rng["fixed"]})
        affected.append(
            {
                "package": {
                    "ecosystem": pkg["ecosystem"],
                    "name": pkg["name"],
                    "purl": pkg["purl"],
                },
                "ranges": [{"type": "SEMVER", "events": events}],
            }
        )

    out: dict[str, Any] = {
        "schema_version": psirt["formats"]["osv_schema_version"],
        "id": record["id"],
        "published": published_utc,
        "modified": published_utc,
        "summary": record["title"],
        "details": record["summary"],
        "affected": affected,
        "database_specific": {
            "severity": record["severity"],
            "kev": bool(record.get("kev", False)),
        },
    }
    if aliases:
        out["aliases"] = aliases
    return out


def render_yank_records(record: dict[str, Any]) -> list[dict[str, Any]]:
    published_utc = format_utc(parse_utc(str(record["published_at"])))
    records = []
    for yank in record.get("yank_versions", []):
        records.append(
            {
                "schema_version": "grdr.yank-record.v1",
                "advisory_id": record["id"],
                "component": yank["component"],
                "version": yank["version"],
                "avoid": True,
                "avoid_reason": f"{record['id']}: {yank['reason']}",
                "issued_at": published_utc,
            }
        )
    return records


def generate_all_documents(record: dict[str, Any], root: Path = ROOT) -> dict[str, Any]:
    validate_advisory_record(record)
    policy = load_policy_context(root)
    return {
        "csaf": render_csaf_vex(record, policy),
        "openvex": render_openvex(record, policy),
        "osv": render_osv(record, policy),
        "deadlines": compute_reporting_deadlines(record, policy),
        "yanks": render_yank_records(record),
    }


def check_advisory_dir(records_dir: Path, root: Path = ROOT) -> int:
    index_path = records_dir / "index.json"
    if not index_path.is_file():
        raise FileNotFoundError(f"missing advisories index: {index_path}")
    index_doc = json.loads(index_path.read_text("utf-8"))
    if index_doc.get("schema_version") != "grdr.advisories-index.v1":
        raise ValueError("invalid advisories index schema_version")
    record_files = sorted(
        p for p in records_dir.glob("*.json") if p.name != "index.json"
    )
    listed = set(index_doc.get("advisories", []))
    actual = {p.stem for p in record_files}
    if listed != actual:
        raise ValueError(f"index.json mismatch: listed={sorted(listed)}, files={sorted(actual)}")
    for path in record_files:
        record = json.loads(path.read_text("utf-8"))
        if record.get("id") != path.stem:
            raise ValueError(f"filename {path.name} must match advisory id {record.get('id')}")
        generate_all_documents(record, root=root)
    return len(record_files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guardrails PSIRT advisory generator/validator")
    parser.add_argument("--check-dir", type=Path, help="Validate an advisories records directory")
    parser.add_argument("--emit", type=Path, help="Input advisory JSON file to compile")
    parser.add_argument("--out-dir", type=Path, help="Output directory for generated CSAF/OpenVEX/OSV")
    args = parser.parse_args(argv)

    if args.check_dir is not None:
        count = check_advisory_dir(args.check_dir)
        print(f"advisories check PASS ({count} advisory records verified)")
        return 0

    if args.emit is not None:
        if args.out_dir is None:
            raise SystemExit("--out-dir is required with --emit")
        record = json.loads(args.emit.read_text("utf-8"))
        bundle = generate_all_documents(record)
        args.out_dir.mkdir(parents=True, exist_ok=True)
        adv_id = record["id"]
        (args.out_dir / f"{adv_id}.csaf.json").write_text(
            json.dumps(bundle["csaf"], indent=2) + "\n", "utf-8"
        )
        (args.out_dir / f"{adv_id}.openvex.json").write_text(
            json.dumps(bundle["openvex"], indent=2) + "\n", "utf-8"
        )
        (args.out_dir / f"{adv_id}.osv.json").write_text(
            json.dumps(bundle["osv"], indent=2) + "\n", "utf-8"
        )
        (args.out_dir / f"{adv_id}.deadlines.json").write_text(
            json.dumps(bundle["deadlines"], indent=2) + "\n", "utf-8"
        )
        (args.out_dir / f"{adv_id}.yank.json").write_text(
            json.dumps(bundle["yanks"], indent=2) + "\n", "utf-8"
        )
        print(f"advisory bundle emitted for {adv_id} into {args.out_dir}")
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
