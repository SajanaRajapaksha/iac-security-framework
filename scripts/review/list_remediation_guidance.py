#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.review.review_utils import safe_read_json, sort_findings_by_severity

def print_finding(f: dict, guidance: dict):
    stage = f.get("stage", "")
    print("-" * 60)
    print(f"[{f.get('severity')}] — {f.get('check_id')}")
    print("-" * 60)
    print(f"Stage               : {stage}")
    print(f"Scanner             : {f.get('scanner')}")
    print(f"Finding ID          : {f.get('review_finding_id')}")
    print(f"Check ID            : {f.get('check_id')}")
    print(f"Title               : {f.get('title')}")
    
    if stage == "POST_DEPLOYMENT":
        print(f"Service             : {f.get('service', 'N/A')}")
        print(f"Region              : {f.get('region', 'N/A')}")
    
    print(f"Resource            : {f.get('resource')}")
    print(f"Resource Type       : {f.get('resource_type')}")
    
    print("\nScanner Remediation :")
    print(f"{f.get('existing_remediation', 'N/A')}")
    
    if guidance and guidance.get("source") != "SCANNER_METADATA_ONLY":
        ai = guidance.get("ai_guidance", {})
        print("\nAI Remediation:")
        print(f"  Summary             : {ai.get('summary', 'N/A')}")
        print(f"  Terraform Action    : {ai.get('terraform_action', 'N/A')}")
        print(f"  Runtime Action      : {ai.get('runtime_action', 'N/A')}")
        print(f"  Validation Step     : {ai.get('validation_step', 'N/A')}")
        print(f"  Operational Caution : {ai.get('operational_caution', 'N/A')}")
        print(f"\nGuidance Source      : {guidance.get('source')}")
    else:
        print("\nAI Remediation      : Unavailable")
        print("Guidance Source     : SCANNER_METADATA_ONLY")
    print()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    scan_id = args.scan_id

    review_dir = ROOT_DIR / "reports" / "review" / scan_id
    sec_review_path = review_dir / "security-review.json"
    guidance_path = review_dir / "remediation-guidance.json"
    usage_path = review_dir / "openai-usage.json"
    
    sec_review = safe_read_json(str(sec_review_path)) or {}
    guidance = safe_read_json(str(guidance_path)) or {}
    usage = safe_read_json(str(usage_path)) or {}
    
    g_list = guidance.get("guidance", [])
    
    # Map finding_id -> guidance record
    guidance_map = {}
    for g in g_list:
        for fid in g.get("affected_finding_ids", []):
            guidance_map[fid] = g
            
    pre_findings = sort_findings_by_severity(sec_review.get("pre_deployment_findings", []))
    post_findings = sort_findings_by_severity(sec_review.get("post_deployment_findings", []))
    
    total_findings = len(pre_findings) + len(post_findings)
    ai_guided = sum(1 for g in g_list if g.get("source") == "OPENAI_WITH_SCANNER_CONTEXT")
    cached_guided = sum(1 for g in g_list if g.get("source") == "LOCAL_AI_REMEDIATION_CACHE")
    scanner_only = sum(1 for g in g_list if g.get("source") == "SCANNER_METADATA_ONLY")
    
    print("============================================================")
    print("  SECURITY FINDING REMEDIATION GUIDANCE")
    print("============================================================")
    print(f"SCAN_ID                  : {scan_id}")
    print(f"Total Findings           : {total_findings}")
    print(f"AI-Guided Findings       : {ai_guided}")
    print(f"Cached AI Guidance       : {cached_guided}")
    print(f"Scanner-Only Findings    : {scanner_only}")
    print(f"AI Remediation Status    : {usage.get('status', 'N/A')}")
    print(f"OpenAI Requests          : {usage.get('request_count', 0)}")
    print(f"Input Tokens             : {usage.get('input_tokens', 0)}")
    print(f"Output Tokens            : {usage.get('output_tokens', 0)}")
    print(f"Total Tokens             : {usage.get('total_tokens', 0)}")
    print("============================================================\n")
    
    for f in pre_findings:
        print_finding(f, guidance_map.get(f.get("review_finding_id")))
        
    for f in post_findings:
        print_finding(f, guidance_map.get(f.get("review_finding_id")))

if __name__ == "__main__":
    main()
