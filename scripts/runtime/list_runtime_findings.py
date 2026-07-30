#!/usr/bin/env python3
"""
scripts/runtime/list_runtime_findings.py

Prints a human-readable console summary of runtime findings for GitHub Actions,
and emits GH Actions annotations.

Usage:
    python scripts/runtime/list_runtime_findings.py <SCAN_ID>
"""

import argparse
import sys
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import safe_read_json

def escape_annotation(s: str) -> str:
    if not s:
        return ""
    # Only need to escape newlines and basic chars for GH actions title/message
    return str(s).replace("\n", " ").replace("\r", "").replace("%", "%25")

def emit_github_annotation(finding: dict):
    # Determine severity
    sev = finding.get("severity", {}).get("normalized", "UNKNOWN")
    check_id = finding.get("control_id", "unknown")
    resource_id = finding.get("resource", {}).get("id", "unknown")
    title = finding.get("title", "")
    
    # GitHub Action levels
    level = "notice"
    if sev in ("CRITICAL", "HIGH"):
        level = "error"
    elif sev == "MEDIUM":
        level = "warning"
        
    gh_title = escape_annotation(f"Prowler {sev} Finding")
    gh_msg = escape_annotation(f"{check_id} affected {resource_id}. {title}")
    
    print(f"::{level} title={gh_title}::{gh_msg}")

def list_findings(scan_id: str) -> None:
    runtime_dir = ROOT_DIR / "reports" / "runtime" / scan_id
    normalized_path = runtime_dir / "normalized" / "runtime-findings.json"
    summary_path = runtime_dir / "normalized" / "runtime-findings-summary.json"
    exec_path = runtime_dir / "prowler" / "prowler-execution.json"
    tagged_path = runtime_dir / "scope" / "tagged-resources.json"
    op_error_path = runtime_dir / "normalized" / "runtime-operational-error.json"
    
    op_error = safe_read_json(str(op_error_path))
    if op_error:
        print("Prowler runtime assessment was not completed.")
        print("No security conclusion can be made.")
        if op_error.get("code") == "SCAN_SCOPE_EMPTY":
            print(op_error.get("message", ""))
        sys.exit(1)

    normalized_data = safe_read_json(str(normalized_path))
    if not normalized_data:
        print("Prowler runtime assessment was not completed.")
        print("No security conclusion can be made.")
        sys.exit(1)

    summary = normalized_data.get("summary", {})
    exec_data = safe_read_json(str(exec_path)) or {}
    tagged_data = safe_read_json(str(tagged_path)) or {}
    
    tagged_count = len(tagged_data.get("ResourceTagMappingList", []))

    print("============================================================")
    print("  NORMALIZED PROWLER RUNTIME SECURITY FINDINGS")
    print("============================================================")
    print(f"  SCAN_ID                    : {scan_id}")
    aws_identity = exec_data.get("aws_identity", {})
    print(f"  AWS Account                : {aws_identity.get('account_id', 'unknown')}")
    print(f"  Region                     : {exec_data.get('filters', {}).get('region', 'unknown')}")
    print(f"  Prowler Version            : {exec_data.get('version', '5.28.1')}")
    deps = exec_data.get("dependencies", {})
    print(f"  Boto3 Version              : {deps.get('boto3', 'resolved version')}")
    print(f"  Botocore Version           : {deps.get('botocore', 'resolved version')}")
    print(f"  Scan Scope                 : {exec_data.get('scan_scope', 'TAGGED_DEPLOYMENT_RESOURCES_ONLY')}")
    print(f"  Tagged Resources           : {tagged_count}")
    print(f"  Raw Prowler Findings       : {summary.get('raw_findings', 0)}")
    print(f"  Deduplicated Findings      : {summary.get('deduplicated_findings', 0)}")
    print(f"  Merged Duplicate Records   : {summary.get('merged_duplicate_records', 0)}")
    print(f"  Critical                   : {summary.get('critical', 0)}")
    print(f"  High                       : {summary.get('high', 0)}")
    print(f"  Medium                     : {summary.get('medium', 0)}")
    print(f"  Low                        : {summary.get('low', 0)}")
    print(f"  Informational              : {summary.get('informational', 0)}")
    print(f"  Unknown                    : {summary.get('unknown', 0)}")
    print("============================================================")

    deployment_findings = normalized_data.get("findings", [])
    
    if not deployment_findings:
        print("\nNo failed Prowler checks were found for the tagged deployment resources.")
        return

    # Sort findings by severity, service, check_id
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "UNKNOWN": 5}
    def sort_key(f):
        sev = sev_order.get(f.get("severity", {}).get("normalized", "UNKNOWN"), 5)
        service = f.get("resource", {}).get("arn", "").split(":")[2] if ":" in f.get("resource", {}).get("arn", "") else "unknown"
        check_id = f.get("control_id", "")
        r_id = f.get("resource", {}).get("id", "")
        return (sev, service, check_id, r_id)

    deployment_findings.sort(key=sort_key)
    print()

    for idx, f in enumerate(deployment_findings, 1):
        sev = f.get("severity", {})
        norm_sev = sev.get("normalized", "UNKNOWN")
        sev_src = sev.get("source", "UNKNOWN")
        
        resource = f.get("resource", {})
        r_arn = resource.get("arn", "")
        service = r_arn.split(":")[2] if ":" in r_arn else "unknown"

        print("------------------------------------------------------------")
        print(f"[{idx}] {norm_sev} — {f.get('control_id', 'unknown')}")
        print("------------------------------------------------------------")
        print(f"Title          : {f.get('title', '')}")
        print(f"Resource       : {resource.get('id', '')}")
        print(f"Resource ARN   : {r_arn}")
        print(f"Resource Name  : {resource.get('name', '')}")
        print(f"Service        : {service}")
        print(f"Region         : {resource.get('aws_region', '')}")
        print(f"AWS Account    : {resource.get('aws_account_id', '')}")
        print(f"Status         : {f.get('status', '')}")
        print(f"Severity       : {norm_sev}")
        print(f"Severity Source: {sev_src}")
        print(f"SCAN_ID        : {f.get('attribution', {}).get('scan_id', scan_id)}")
        print(f"Attribution    : {f.get('attribution', {}).get('method', 'PROWLER_RESOURCE_TAG_FILTER')}")
        print(f"Description    : {f.get('description', '')}")
        print(f"Risk           : {f.get('risk', '')}")
        print(f"Remediation    : {f.get('remediation', {}).get('text', '')}")
        refs = f.get('remediation', {}).get('references', [])
        print(f"Related URL    : {refs[0] if refs else ''}")
        
        print("Compliance:")
        compliance_list = f.get("compliance", [])
        if compliance_list:
            for c in compliance_list:
                print(f"  - {c.get('framework', '')} {c.get('version', '')} — {c.get('control_id', '')}")
        else:
            print("  - None")
        
        print()
        
        # Emit GitHub Annotation
        if os.environ.get("GITHUB_ACTIONS"):
            emit_github_annotation(f)

def main():
    parser = argparse.ArgumentParser(description="List runtime findings.")
    parser.add_argument("scan_id", help="The unique SCAN_ID")
    args = parser.parse_args()
    list_findings(args.scan_id)

if __name__ == "__main__":
    main()
