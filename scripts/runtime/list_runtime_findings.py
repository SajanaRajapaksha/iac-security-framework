#!/usr/bin/env python3
"""
scripts/runtime/list_runtime_findings.py

Prints a human-readable console summary of runtime findings for GitHub Actions.

Usage:
    python scripts/runtime/list_runtime_findings.py <SCAN_ID>
"""

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import safe_read_json

def list_findings(scan_id: str) -> None:
    runtime_dir = ROOT_DIR / "reports" / "runtime" / scan_id
    normalized_path = runtime_dir / "normalized" / "normalized-runtime-findings.json"
    summary_path = runtime_dir / "normalized" / "runtime-findings-summary.json"

    summary = safe_read_json(str(summary_path))
    normalized_data = safe_read_json(str(normalized_path))

    if not summary or not normalized_data:
        print("============================================================")
        print("  NORMALIZED RUNTIME SECURITY FINDINGS")
        print("============================================================")
        print(f"  SCAN_ID              : {scan_id}")
        print("  Status               : ERROR (No findings data available)")
        print("============================================================")
        return

    sc = summary.get("severity_counts", {})
    
    print("============================================================")
    print("  NORMALIZED RUNTIME SECURITY FINDINGS")
    print("============================================================")
    print(f"  SCAN_ID              : {scan_id}")
    print(f"  AWS Account          : {summary.get('aws_account_id', 'unknown')}")
    print(f"  Region               : {summary.get('region', 'unknown')}")
    print(f"  Deployed Resources   : {summary.get('deployed_resources', 0)}")
    print(f"  Raw Prowler Failures : {summary.get('raw_prowler_failures', 0)}")
    print(f"  Unique Findings      : {summary.get('unique_findings', 0)}")
    print(f"  Critical             : {sc.get('CRITICAL', 0)}")
    print(f"  High                 : {sc.get('HIGH', 0)}")
    print(f"  Medium               : {sc.get('MEDIUM', 0)}")
    print(f"  Low                  : {sc.get('LOW', 0)}")
    print(f"  Informational        : {sc.get('INFORMATIONAL', 0)}")
    print(f"  Unknown              : {sc.get('UNKNOWN', 0)}")
    print(f"  Unmatched Findings   : {summary.get('unmatched_findings_count', 0)}")
    print("============================================================\n")

    deployment_findings = normalized_data.get("deployment_findings", [])
    
    # Sort findings by severity (Critical -> High -> Medium -> Low -> Informational -> Unknown)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "UNKNOWN": 5}
    deployment_findings.sort(key=lambda x: sev_order.get(x.get("severity", {}).get("normalized", "UNKNOWN"), 5))

    for f in deployment_findings:
        sev = f.get("severity", {})
        norm_sev = sev.get("normalized", "UNKNOWN")
        sev_src = sev.get("source", "UNKNOWN")
        
        fsbp = []
        cis = []
        for s in f.get("standards", []):
            if s.get("name") == "AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES":
                fsbp.append(s.get("control_id", ""))
            elif s.get("name") == "CIS_AWS_FOUNDATIONS_BENCHMARK":
                cis.append(s.get("requirement_id", ""))
        
        fsbp_str = ", ".join(fsbp) if fsbp else "None"
        cis_str = ", ".join(cis) if cis else "None"

        print(f"[ {norm_sev} ] {f.get('title', 'Unknown finding')}")
        print(f"         Check:      {f.get('scanner', {}).get('check_id', 'unknown')}")
        print(f"         Resource:   {f.get('resource', {}).get('resource_id', 'unknown')}")
        print(f"         Terraform:  {f.get('resource', {}).get('terraform_address', 'unknown')}")
        print(f"         AWS FSBP:   {fsbp_str}")
        print(f"         CIS AWS:    {cis_str}")
        print(f"         Severity:   {norm_sev}")
        print(f"         Source:     {sev_src}")
        print()

def main():
    parser = argparse.ArgumentParser(description="List runtime findings.")
    parser.add_argument("scan_id", help="The unique SCAN_ID")
    args = parser.parse_args()
    list_findings(args.scan_id)

if __name__ == "__main__":
    main()
