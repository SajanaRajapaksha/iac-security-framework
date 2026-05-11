#!/usr/bin/env python3
"""
scripts/risk/normalize_findings.py

Normalize Checkov, Trivy, and Policy-as-Code findings into a compact
internal schema for risk scoring.

Usage:
    python scripts/risk/normalize_findings.py <SCAN_ID>

Input:
    reports/static/<SCAN_ID>/combined/static-analysis-evidence.json
    (fallback: individual evidence files)
    reports/policy/<SCAN_ID>/policy-evidence.json

Output:
    reports/risk/<SCAN_ID>/normalized-findings.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _counter():
    """Sequential FIND-NNNNNN generator."""
    n = 0
    while True:
        n += 1
        yield f"FIND-{n:06d}"


def _sev(raw) -> str:
    if not raw or not isinstance(raw, str):
        return "UNKNOWN"
    return raw.strip().upper() or "UNKNOWN"


# ---------------------------------------------------------------------------
# Checkov normalizer
# ---------------------------------------------------------------------------

def normalize_checkov(findings: list, scan_id: str, id_gen) -> list[dict]:
    normalized = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = next(id_gen)
        normalized.append({
            "finding_id": fid,
            "scan_id": scan_id,
            "source_tool": "checkov",
            "source_rule_id": f.get("check_id", f.get("rule_id", "UNKNOWN")),
            "source_severity": _sev(f.get("severity", f.get("enriched_severity"))),
            "title": f.get("check_name", f.get("rule_name", "")),
            "description": f.get("check_name", f.get("description", "")),
            "resource": f.get("resource", ""),
            "resource_type": f.get("resource_type", _infer_resource_type(f.get("resource", ""))),
            "file_path": f.get("file_path", ""),
            "line_start": f.get("file_line_range", [None, None])[0] if isinstance(f.get("file_line_range"), list) and len(f.get("file_line_range", [])) >= 1 else f.get("start_line"),
            "line_end": f.get("file_line_range", [None, None])[1] if isinstance(f.get("file_line_range"), list) and len(f.get("file_line_range", [])) >= 2 else f.get("end_line"),
            "raw_finding_ref": f.get("finding_id", f.get("check_id", "")),
            "policy": {
                "policy_violation": False,
                "policy_id": None,
                "enforcement_level": "none",
            },
        })
    return normalized


# ---------------------------------------------------------------------------
# Trivy normalizer
# ---------------------------------------------------------------------------

def normalize_trivy(findings: list, scan_id: str, id_gen) -> list[dict]:
    normalized = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = next(id_gen)
        normalized.append({
            "finding_id": fid,
            "scan_id": scan_id,
            "source_tool": "trivy",
            "source_rule_id": f.get("rule_id", f.get("MisconfID", f.get("ID", "UNKNOWN"))),
            "source_severity": _sev(f.get("severity", f.get("Severity"))),
            "title": f.get("rule_name", f.get("Title", "")),
            "description": f.get("description", f.get("Description", f.get("message", f.get("Message", "")))),
            "resource": f.get("resource", f.get("Target", "")),
            "resource_type": f.get("resource_type", _infer_resource_type(f.get("resource", f.get("Target", "")))),
            "file_path": f.get("file_path", f.get("target_file", "")),
            "line_start": f.get("start_line", f.get("StartLine")),
            "line_end": f.get("end_line", f.get("EndLine")),
            "raw_finding_ref": f.get("finding_id", f.get("rule_id", "")),
            "policy": {
                "policy_violation": False,
                "policy_id": None,
                "enforcement_level": "none",
            },
        })
    return normalized


# ---------------------------------------------------------------------------
# Policy-as-Code normalizer
# ---------------------------------------------------------------------------

def normalize_policy(violations: list, scan_id: str, id_gen) -> list[dict]:
    normalized = []
    for v in violations:
        if not isinstance(v, dict):
            continue
        fid = next(id_gen)
        policy_id = v.get("policy_id", "UNKNOWN")
        enforcement = _infer_enforcement_level(v)
        normalized.append({
            "finding_id": fid,
            "scan_id": scan_id,
            "source_tool": "policy",
            "source_rule_id": policy_id,
            "source_severity": _sev(v.get("severity")),
            "title": v.get("title", v.get("message", "")),
            "description": v.get("reason", v.get("message", "")),
            "resource": v.get("resource", ""),
            "resource_type": v.get("resource_type", _infer_resource_type(v.get("resource", ""))),
            "file_path": v.get("input_file", ""),
            "line_start": None,
            "line_end": None,
            "raw_finding_ref": v.get("policy_id", ""),
            "policy": {
                "policy_violation": True,
                "policy_id": policy_id,
                "enforcement_level": enforcement,
            },
        })
    return normalized


def _infer_enforcement_level(violation: dict) -> str:
    """Infer enforcement level from violation metadata."""
    sev = _sev(violation.get("severity"))
    if sev in ("CRITICAL", "HIGH"):
        return "hard_mandatory"
    if sev == "MEDIUM":
        return "soft_mandatory"
    return "advisory"


def _infer_resource_type(resource: str) -> str:
    """Best-effort resource type from resource string like aws_security_group.foo."""
    if not resource:
        return ""
    parts = resource.split(".")
    return parts[0] if parts else ""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Normalize scanner findings for risk scoring.")
    parser.add_argument("scan_id", help="SCAN_ID for this pipeline run")
    args = parser.parse_args()
    scan_id = args.scan_id

    report_dir = ROOT / "reports" / "risk" / scan_id
    report_dir.mkdir(parents=True, exist_ok=True)

    warnings: list[str] = []
    id_gen = _counter()

    # ---- Load combined evidence ----
    combined_path = ROOT / "reports" / "static" / scan_id / "combined" / "static-analysis-evidence.json"
    combined = safe_read_json(str(combined_path))

    checkov_findings = []
    trivy_findings = []
    policy_violations = []

    if isinstance(combined, dict):
        checkov_findings = combined.get("checkov_findings", [])
        trivy_findings = combined.get("trivy_findings", [])
        pac = combined.get("policy_as_code", {})
        if isinstance(pac, dict):
            policy_violations = pac.get("violations", [])
        print(f"[normalize] Loaded combined evidence from {combined_path}")
    else:
        warnings.append(f"Combined evidence not found at {combined_path}; trying individual files.")
        print(f"[normalize] WARNING: {warnings[-1]}")

        # Fallback: individual Checkov evidence
        ck_path = ROOT / "reports" / "static" / scan_id / "checkov" / "checkov-evidence.json"
        ck = safe_read_json(str(ck_path))
        if isinstance(ck, dict):
            checkov_findings = ck.get("findings", [])
            print(f"[normalize] Loaded {len(checkov_findings)} Checkov findings from {ck_path}")
        else:
            warnings.append(f"Checkov evidence not found at {ck_path}")
            print(f"[normalize] WARNING: {warnings[-1]}")

        # Fallback: individual Trivy evidence
        tr_path = ROOT / "reports" / "static" / scan_id / "trivy" / "trivy-evidence.json"
        tr = safe_read_json(str(tr_path))
        if isinstance(tr, dict):
            trivy_findings = tr.get("findings", [])
            print(f"[normalize] Loaded {len(trivy_findings)} Trivy findings from {tr_path}")
        else:
            warnings.append(f"Trivy evidence not found at {tr_path}")
            print(f"[normalize] WARNING: {warnings[-1]}")

    # Fallback: policy evidence if not in combined
    if not policy_violations:
        pol_path = ROOT / "reports" / "policy" / scan_id / "policy-evidence.json"
        pol = safe_read_json(str(pol_path))
        if isinstance(pol, dict):
            policy_violations = pol.get("violations", [])
            print(f"[normalize] Loaded {len(policy_violations)} policy violations from {pol_path}")
        else:
            warnings.append(f"Policy evidence not found at {pol_path}")
            print(f"[normalize] WARNING: {warnings[-1]}")

    # ---- Normalize ----
    all_findings = []
    all_findings.extend(normalize_checkov(checkov_findings, scan_id, id_gen))
    all_findings.extend(normalize_trivy(trivy_findings, scan_id, id_gen))
    all_findings.extend(normalize_policy(policy_violations, scan_id, id_gen))

    output = {
        "metadata": {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "finding_count": len(all_findings),
            "source_counts": {
                "checkov": len(checkov_findings),
                "trivy": len(trivy_findings),
                "policy": len(policy_violations),
            },
            "warnings": warnings,
        },
        "findings": all_findings,
    }

    out_path = str(report_dir / "normalized-findings.json")
    safe_write_json(out_path, output)

    print(f"[normalize] SCAN_ID         = {scan_id}")
    print(f"[normalize] Checkov         = {len(checkov_findings)}")
    print(f"[normalize] Trivy           = {len(trivy_findings)}")
    print(f"[normalize] Policy          = {len(policy_violations)}")
    print(f"[normalize] Total findings  = {len(all_findings)}")
    print(f"[normalize] Output          = {out_path}")


if __name__ == "__main__":
    main()
