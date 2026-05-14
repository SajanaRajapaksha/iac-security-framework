#!/usr/bin/env python3
"""
scripts/risk/normalize_findings.py

Normalizes findings from Checkov and Policy-as-Code into a unified schema for the Finding Enrichment Engine.
Ignores Trivy completely. Generates stable FIND-000001 IDs.

Usage: python scripts/risk/normalize_findings.py <SCAN_ID>
"""

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

def main():
    parser = argparse.ArgumentParser(description="Normalize findings for enrichment.")
    parser.add_argument("scan_id", help="The unique SCAN_ID")
    args = parser.parse_args()
    scan_id = args.scan_id

    static_combined_path = ROOT_DIR / "reports" / "static" / scan_id / "combined" / "static-analysis-evidence.json"
    risk_dir = ROOT_DIR / "reports" / "risk" / scan_id
    risk_dir.mkdir(parents=True, exist_ok=True)

    warnings = []
    checkov_findings_raw = []
    policy_findings_raw = []

    static_data = safe_read_json(str(static_combined_path))
    if isinstance(static_data, dict):
        checkov_findings_raw = static_data.get("checkov_findings", [])
        policy_section = static_data.get("policy_as_code", {})
        policy_findings_raw = policy_section.get("violations", [])
    else:
        warnings.append(f"Could not load static analysis evidence at {static_combined_path}")

    normalized = []
    finding_counter = 1

    # 1. Normalize Checkov findings
    for cf in checkov_findings_raw:
        fid = f"FIND-{finding_counter:06d}"
        finding_counter += 1
        
        orig_sev = cf.get("severity", "UNKNOWN")
        sev = orig_sev if orig_sev and orig_sev != "NONE" else "UNKNOWN"
        
        normalized.append({
            "finding_id": fid,
            "scan_id": scan_id,
            "source_tool": "checkov",
            "source_rule_id": cf.get("check_id", "UNKNOWN"),
            "title": cf.get("check_name", "No Title"),
            "description": cf.get("check_name", ""),
            "resource": cf.get("resource", "Unknown"),
            "resource_type": cf.get("resource", "").split(".")[0] if "." in cf.get("resource", "") else "Unknown",
            "file_path": cf.get("file_path", "Unknown"),
            "line_start": None,
            "line_end": None,
            "scanner_severity": sev,
            "scanner_severity_original": orig_sev,
            "policy": {
                "policy_violation": False,
                "policy_id": None,
                "policy_severity": None,
                "enforcement_level": "none"
            },
            "raw_finding_ref": cf.get("finding_id", ""),
            "normalization_notes": []
        })

    # 2. Normalize Policy-as-Code findings
    for pf in policy_findings_raw:
        fid = f"FIND-{finding_counter:06d}"
        finding_counter += 1
        
        orig_sev = pf.get("severity", "UNKNOWN")
        sev = orig_sev if orig_sev and orig_sev != "NONE" else "UNKNOWN"
        
        normalized.append({
            "finding_id": fid,
            "scan_id": scan_id,
            "source_tool": "policy",
            "source_rule_id": pf.get("policy_id", "UNKNOWN"),
            "title": pf.get("title", pf.get("message", "No Title")),
            "description": pf.get("message", pf.get("reason", "")),
            "resource": pf.get("resource", "Unknown"),
            "resource_type": pf.get("resource_type", "Unknown"),
            "file_path": pf.get("input_file", "Unknown"),
            "line_start": None,
            "line_end": None,
            "scanner_severity": None,
            "scanner_severity_original": None,
            "policy": {
                "policy_violation": True,
                "policy_id": pf.get("policy_id", "UNKNOWN"),
                "policy_severity": sev,
                "enforcement_level": pf.get("enforcement_level", "advisory")
            },
            "raw_finding_ref": "",
            "normalization_notes": []
        })

    output_data = {
        "metadata": {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "tool": "normalize_findings.py",
            "active_static_scanner": "checkov",
            "trivy_used": False,
            "checkov_findings": len(checkov_findings_raw),
            "policy_findings": len(policy_findings_raw),
            "warnings": warnings
        },
        "findings": normalized
    }

    out_path = risk_dir / "normalized-findings.json"
    safe_write_json(str(out_path), output_data)

    print(f"[normalize_findings] SCAN_ID = {scan_id}")
    print(f"[normalize_findings] Normalized {len(checkov_findings_raw)} Checkov findings.")
    print(f"[normalize_findings] Normalized {len(policy_findings_raw)} Policy findings.")
    print(f"[normalize_findings] Ignored Trivy findings.")
    print(f"[normalize_findings] Output = {out_path}")

if __name__ == "__main__":
    main()
