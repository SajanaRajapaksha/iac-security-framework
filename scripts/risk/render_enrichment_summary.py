#!/usr/bin/env python3
"""
scripts/risk/render_enrichment_summary.py

Renders the finding enrichment summary and advisory decision.
Outputs both JSON and Markdown artifacts, and prints a console report.

Usage: python scripts/risk/render_enrichment_summary.py <SCAN_ID>
"""

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    scan_id = args.scan_id

    risk_dir = ROOT_DIR / "reports" / "risk" / scan_id
    enriched = safe_read_json(str(risk_dir / "enriched-findings.json")) or {"findings": []}
    findings = enriched.get("findings", [])

    total = len(findings)
    checkov_count = 0
    policy_count = 0
    requires_review = 0
    
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0}
    mapping_counts = {}

    highest_order = -2
    highest_sev = "INFO"

    sev_order_map = {"UNKNOWN": -1, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for f in findings:
        if f.get("source_tool") == "checkov":
            checkov_count += 1
        elif f.get("source_tool") == "policy":
            policy_count += 1
            
        if f.get("requires_review"):
            requires_review += 1
            
        sev = f.get("final_severity", "UNKNOWN")
        if sev in sev_counts:
            sev_counts[sev] += 1
            
        mapping = f.get("mapping_type", "UNKNOWN")
        mapping_counts[mapping] = mapping_counts.get(mapping, 0) + 1

        order = f.get("severity_order", sev_order_map.get(sev, -1))
        # Determine highest severity excluding UNKNOWN
        if order > highest_order and order >= 0:
            highest_order = order
            highest_sev = sev

    # Advisory decision logic
    if sev_counts["UNKNOWN"] > 0:
        suggested_decision = "REVIEW_REQUIRED"
    elif sev_counts["CRITICAL"] > 0:
        suggested_decision = "BLOCK_RECOMMENDED"
    elif sev_counts["HIGH"] > 0:
        suggested_decision = "REVIEW_HIGH_RISK"
    elif sev_counts["MEDIUM"] > 0:
        suggested_decision = "REVIEW"
    elif sev_counts["LOW"] > 0:
        suggested_decision = "PASS_WITH_ADVISORY"
    else:
        suggested_decision = "PASS"

    # Outputs
    summary_json = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "total_findings": total,
        "checkov_findings": checkov_count,
        "policy_findings": policy_count,
        "severity_counts": sev_counts,
        "mapping_type_counts": mapping_counts,
        "requires_review_count": requires_review,
        "highest_severity": highest_sev if highest_order >= 0 else "UNKNOWN",
        "suggested_decision": suggested_decision,
        "enforcement_mode": "advisory",
        "should_fail_pipeline": False
    }

    decision_json = {
        "scan_id": scan_id,
        "highest_severity": highest_sev if highest_order >= 0 else "UNKNOWN",
        "suggested_decision": suggested_decision,
        "enforcement_mode": "advisory",
        "should_fail_pipeline": False,
        "top_reasons": []
    }

    safe_write_json(str(risk_dir / "finding-enrichment-summary.json"), summary_json)
    safe_write_json(str(risk_dir / "finding-enrichment-decision.json"), decision_json)

    # Markdown
    md = [
        f"# Finding Enrichment Summary",
        f"",
        f"- **Scan ID:** `{scan_id}`",
        f"- **Total Findings:** {total}",
        f"- **Highest Severity:** {highest_sev if highest_order >= 0 else 'UNKNOWN'}",
        f"- **Suggested Decision:** {suggested_decision}",
        f"",
        f"## Severity Counts",
        f"| Severity | Count |",
        f"|---|---|",
    ]
    for k, v in sev_counts.items():
        md.append(f"| {k} | {v} |")
    
    with open(str(risk_dir / "finding-enrichment-summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    # Console Output
    print(f"\n{'='*60}")
    print(f"  FORENSIC FINDING ENRICHMENT SUMMARY")
    print(f"{'='*60}")
    print(f"SCAN_ID              : {scan_id}")
    print(f"Total Findings       : {total}")
    print(f"Checkov Findings     : {checkov_count}")
    print(f"Policy Findings      : {policy_count}")
    print(f"Highest Severity     : {highest_sev if highest_order >= 0 else 'UNKNOWN'}")
    print(f"Unknown Findings     : {sev_counts['UNKNOWN']}")
    print(f"Requires Review      : {requires_review}")
    print(f"Suggested Decision   : {suggested_decision}")
    print(f"Enforcement Mode     : advisory")
    print(f"Pipeline Will Fail   : false\n")

    print(f"Severity Counts:")
    for k, v in sev_counts.items():
        print(f"  {k:<8} : {v}")

    print(f"\n{'-'*60}")
    print(f"  ENRICHED FINDINGS")
    print(f"{'-'*60}")

    for f in findings:
        sev = f.get("final_severity", "UNKNOWN")
        print(f"[{sev}] {f.get('finding_id')}")
        print(f"  Source Tool        : {f.get('source_tool')}")
        print(f"  Rule / Policy ID   : {f.get('source_rule_id')}")
        print(f"  Resource           : {f.get('resource')}")
        print(f"  File               : {f.get('file_path')}")
        print(f"  Scanner Severity   : {f.get('scanner_severity')}")
        print(f"  Policy Severity    : {f.get('policy_severity')}")
        print(f"  AI Suggested Sev.  : {f.get('ai_suggested_severity')}")
        print(f"  Final Severity     : {f.get('final_severity')}")
        print(f"  Severity Source    : {f.get('severity_source')}")
        
        refs = f.get("standards_references", [])
        if refs:
            print(f"\n  Standards References:")
            for r in refs:
                print(f"    - {r.get('standard')}: {r.get('control_code')} [{r.get('confidence')}]")
        else:
            print(f"\n  Standards References:")
            print(f"    - none")
            
        print(f"\n  Mapping Type       : {f.get('mapping_type')}")
        print(f"  Mapping Confidence : {f.get('mapping_confidence')}")
        print(f"  Requires Review    : {str(f.get('requires_review')).lower()}")
        print(f"  Reason             : {f.get('enrichment_reason')}")
        print(f"")

if __name__ == "__main__":
    main()
