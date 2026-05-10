#!/usr/bin/env python3
"""
scripts/list_findings.py

A utility script to list all findings from each component (Checkov, Trivy, and Policy-as-Code)
for a given SCAN_ID.

Usage:
    python scripts/list_findings.py <SCAN_ID>
"""

import json
import os
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/list_findings.py <SCAN_ID>")
        sys.exit(1)

    scan_id = sys.argv[1]
    
    # Path to the combined static analysis evidence
    report_path = os.path.join("reports", "static", scan_id, "combined", "static-analysis-evidence.json")
    
    # Fallback to the old directory structure if needed
    if not os.path.exists(report_path):
        report_path = os.path.join("reports", "static_analysis", scan_id, "combined", "static-analysis-evidence.json")
        
    if not os.path.exists(report_path):
        # Additional fallback just in case
        report_path_alt = os.path.join("reports", "static", scan_id, "static-analysis-evidence.json")
        if os.path.exists(report_path_alt):
            report_path = report_path_alt
        else:
            print(f"Error: Combined evidence report not found for SCAN_ID '{scan_id}'.")
            print(f"Expected path: {report_path}")
            print("Please ensure the static analysis stages have run completely.")
            sys.exit(1)

    with open(report_path, "r") as f:
        data = json.load(f)

    print(f"\n============================================================")
    print(f"  FORENSIC SECURITY FINDINGS FOR: {scan_id}")
    print(f"============================================================\n")

    # 1. Checkov Findings
    checkov_findings = data.get("checkov_findings", [])
    print(f"--- CHECKOV FINDINGS ({len(checkov_findings)}) ---")
    if not checkov_findings:
        print("  No Checkov misconfigurations found.")
    else:
        for i, finding in enumerate(checkov_findings, 1):
            severity = finding.get("severity", "UNKNOWN")
            check_id = finding.get("check_id", "UNKNOWN")
            title = finding.get("check_name", "No Title")
            resource = finding.get("resource", "Unknown Resource")
            file_path = finding.get("file_path", "Unknown File")
            
            print(f"[{severity:^8}] {check_id}: {title}")
            print(f"           Resource: {resource}")
            print(f"           File:     {file_path}\n")

    # 2. Trivy Findings
    trivy_findings = data.get("trivy_findings", [])
    print(f"--- TRIVY FINDINGS ({len(trivy_findings)}) ---")
    if not trivy_findings:
        print("  No Trivy misconfigurations found.\n")
    else:
        for i, finding in enumerate(trivy_findings, 1):
            # Findings in the combined report come from scripts/trivy_scan.py, which
            # normalizes Trivy output into a stable schema.
            severity = finding.get("severity", "UNKNOWN")
            check_id = finding.get("rule_id", finding.get("id", "UNKNOWN"))
            title = finding.get("rule_name", finding.get("title", "No Title"))
            resource = finding.get("resource", "Unknown Resource")
            file_path = finding.get("file_path", finding.get("target_file", "Unknown File"))
            
            print(f"[{severity:^8}] {check_id}: {title}")
            print(f"           Target:   {resource}")
            print(f"           File:     {file_path}\n")

    # 3. Policy-as-Code Findings
    policy_section = data.get("policy_as_code", {})
    policy_violations = policy_section.get("violations", [])
    print(f"--- POLICY-AS-CODE VIOLATIONS ({len(policy_violations)}) ---")
    if not policy_section:
        print("  Policy-as-Code stage data not found (stage may have been skipped).\n")
    elif not policy_violations:
        print("  No Policy-as-Code violations found.\n")
    else:
        for i, violation in enumerate(policy_violations, 1):
            severity = violation.get("severity", "UNKNOWN")
            policy_id = violation.get("policy_id", "UNKNOWN")
            title = violation.get("title", violation.get("reason", violation.get("message", "No Title")))
            resource = violation.get("resource", violation.get("resource_type", "Unknown Resource"))
            file_path = violation.get("input_file", "Unknown File")
            
            print(f"[{severity:^8}] {policy_id}: {title}")
            print(f"           Resource: {resource}")
            print(f"           File:     {file_path}\n")

    print(f"============================================================")
    print("Summary:")
    print(f"  Checkov Misconfigurations: {len(checkov_findings)}")
    print(f"  Trivy Misconfigurations:   {len(trivy_findings)}")
    print(f"  Policy-as-Code Violations: {len(policy_violations)}")
    print(f"============================================================")

if __name__ == "__main__":
    main()
