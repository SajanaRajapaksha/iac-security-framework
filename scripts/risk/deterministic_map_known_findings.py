#!/usr/bin/env python3
"""
scripts/risk/deterministic_map_known_findings.py

Map normalized findings to CIS/AWS canonical controls using the
deterministic cis-mapping.yml lookup table.

Usage:
    python scripts/risk/deterministic_map_known_findings.py <SCAN_ID>

Input:
    reports/risk/<SCAN_ID>/normalized-findings.json
    config/risk/cis-mapping.yml

Output:
    reports/risk/<SCAN_ID>/deterministic-mappings.json
    reports/risk/<SCAN_ID>/unmapped-findings.json
"""

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso


def load_cis_mapping(path: Path) -> dict:
    if not path.is_file():
        print(f"[deterministic_map] ERROR: CIS mapping not found: {path}", file=sys.stderr)
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def map_finding(finding: dict, cis: dict) -> dict | None:
    """Attempt deterministic mapping.  Returns mapping dict or None."""
    # Try source_rule_id first
    rule_id = finding.get("source_rule_id", "")
    if rule_id and rule_id in cis:
        return _build_mapping(finding, cis[rule_id], matched_by="source_rule_id")

    # Try policy_id
    policy = finding.get("policy", {})
    policy_id = policy.get("policy_id") if isinstance(policy, dict) else None
    if policy_id and policy_id in cis:
        return _build_mapping(finding, cis[policy_id], matched_by="policy_id")

    return None


def _build_mapping(finding: dict, entry: dict, matched_by: str) -> dict:
    return {
        "finding_id": finding["finding_id"],
        "canonical_control": entry.get("canonical_control", "UNKNOWN_SECURITY_MISCONFIGURATION"),
        "control_domain": entry.get("control_domain", "unknown"),
        "cis_controls_v8": entry.get("cis_controls_v8", []),
        "aws_control_refs": entry.get("aws_control_refs", []),
        "base_control_criticality": entry.get("base_control_criticality", 4),
        "mandatory_block": entry.get("mandatory_block", False),
        "mapping_confidence": "high",
        "requires_review": False,
        "mapping_source": "deterministic",
        "matched_by": matched_by,
        "mapping_reason": entry.get("description", "Deterministic mapping from cis-mapping.yml."),
    }


def main():
    parser = argparse.ArgumentParser(description="Deterministically map known findings to CIS controls.")
    parser.add_argument("scan_id", help="SCAN_ID for this pipeline run")
    args = parser.parse_args()
    scan_id = args.scan_id

    report_dir = ROOT / "reports" / "risk" / scan_id
    report_dir.mkdir(parents=True, exist_ok=True)

    # Load inputs
    norm_path = report_dir / "normalized-findings.json"
    norm_data = safe_read_json(str(norm_path))
    if not isinstance(norm_data, dict):
        print(f"[deterministic_map] ERROR: Cannot read {norm_path}", file=sys.stderr)
        sys.exit(1)

    findings = norm_data.get("findings", [])
    cis = load_cis_mapping(ROOT / "config" / "risk" / "cis-mapping.yml")

    mapped = []
    unmapped = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        mapping = map_finding(finding, cis)
        if mapping:
            mapped.append(mapping)
        else:
            unmapped.append(finding)

    # Write outputs
    safe_write_json(str(report_dir / "deterministic-mappings.json"), {
        "metadata": {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "total_findings": len(findings),
            "mapped_count": len(mapped),
            "unmapped_count": len(unmapped),
        },
        "mappings": mapped,
    })

    safe_write_json(str(report_dir / "unmapped-findings.json"), {
        "metadata": {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "unmapped_count": len(unmapped),
        },
        "findings": unmapped,
    })

    print(f"[deterministic_map] SCAN_ID            = {scan_id}")
    print(f"[deterministic_map] Total findings      = {len(findings)}")
    print(f"[deterministic_map] Deterministic mapped = {len(mapped)}")
    print(f"[deterministic_map] Unmapped            = {len(unmapped)}")


if __name__ == "__main__":
    main()
