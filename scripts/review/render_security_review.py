#!/usr/bin/env python3
import sys
import argparse
import hashlib
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.review.review_utils import safe_read_json, safe_write_json
from scripts.review.remediation_cache import CACHE_PATH
from scripts.utils.evidence import utc_now_iso

def hash_file(path: Path) -> str:
    if not path.is_file():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def render_markdown(review: dict, guidance: dict, usage: dict, review_dir: Path):
    scan_id = review.get("scan_id", "")
    
    # 1. security-review.md
    md_lines = [
        f"# Security Review Report: {scan_id}",
        "",
        "## Executive Summary",
        "This report compares the pre-deployment Infrastructure as Code static analysis score "
        "against the post-deployment runtime Prowler assessment.",
        ""
    ]
    
    score_comp = review.get("score_comparison", {})
    md_lines.extend([
        "### Score Comparison",
        f"- **Pre-Deployment Score**: `{score_comp.get('pre_deployment_score', 'N/A')} / 1000`",
        f"- **Pre-Deployment Risk Band**: **{score_comp.get('pre_deployment_risk_band', 'N/A')}**",
        f"- **Post-Deployment Score**: `{score_comp.get('post_deployment_score', 'N/A')} / 1000`",
        f"- **Post-Deployment Risk Band**: **{score_comp.get('post_deployment_risk_band', 'N/A')}**",
        f"- **Score Delta**: `{'+' if score_comp.get('score_delta_points', 0) > 0 else ''}{score_comp.get('score_delta_points', 0)} points`",
        f"- **Risk-Band Movement**: **{score_comp.get('risk_band_movement', 'N/A')}**",
        ""
    ])
    
    rec = review.get("review_recommendation", {})
    md_lines.extend([
        "### Deterministic Review Recommendation",
        f"- **Recommendation**: **{rec.get('decision', 'N/A')}**",
        f"- **Trigger Rule**: {rec.get('rule', 'N/A')}",
        ""
    ])
    
    md_lines.extend([
        "## Severity Comparison",
        "| Severity | Pre-Deployment | Post-Deployment |",
        "|----------|----------------|-----------------|"
    ])
    sev_comp = review.get("severity_comparison", {})
    pre_sev = sev_comp.get("pre_deployment", {})
    post_sev = sev_comp.get("post_deployment", {})
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]:
        md_lines.append(f"| **{s}** | {pre_sev.get(s, 0)} | {post_sev.get(s, 0)} |")
    md_lines.append("")
    
    md_lines.extend([
        "## Pre-Deployment Findings",
    ])
    
    g_list = guidance.get("guidance", [])
    guidance_map = {}
    for g in g_list:
        for fid in g.get("affected_finding_ids", []):
            guidance_map[fid] = g
            
    def append_finding_guidance(f_id: str):
        g = guidance_map.get(f_id)
        if not g:
            return
        
        sr = g.get("scanner_remediation")
        if sr:
            md_lines.extend([
                "",
                "#### Scanner Remediation",
                f"{sr}"
            ])
            
        ai = g.get("ai_guidance", {})
        if ai and g.get("source") != "SCANNER_METADATA_ONLY":
            md_lines.extend([
                "",
                "#### AI Remediation Guidance",
                f"- **Summary**: {ai.get('summary', 'N/A')}",
                f"- **Terraform Action**: {ai.get('terraform_action', 'N/A')}",
                f"- **Runtime Action**: {ai.get('runtime_action', 'N/A')}",
                f"- **Validation Step**: {ai.get('validation_step', 'N/A')}",
                f"- **Operational Caution**: {ai.get('operational_caution', 'N/A')}",
                f"- **Source**: {g.get('source')}"
            ])
        else:
            md_lines.extend([
                "",
                "#### AI Remediation Guidance",
                "Unavailable.",
                "- **Source**: SCANNER_METADATA_ONLY"
            ])

    if not review.get("pre_deployment_findings"):
        md_lines.append("No pre-deployment findings.\n")
    else:
        for f in review.get("pre_deployment_findings", []):
            md_lines.extend([
                f"### {f.get('severity')} - {f.get('title')}",
                f"- **Scanner**: {f.get('scanner')}",
                f"- **Check ID**: `{f.get('check_id')}`",
                f"- **Resource**: `{f.get('resource')}`",
                f"- **Location**: `{f.get('location')}`",
                f"- **Description**: {f.get('description')}"
            ])
            append_finding_guidance(f.get("review_finding_id"))
            md_lines.append("")
            
    md_lines.extend([
        "## Post-Deployment Findings",
    ])
    if not review.get("post_deployment_findings"):
        md_lines.append("No post-deployment findings.\n")
    else:
        for f in review.get("post_deployment_findings", []):
            md_lines.extend([
                f"### {f.get('severity')} - {f.get('title')}",
                f"- **Scanner**: {f.get('scanner')}",
                f"- **Check ID**: `{f.get('check_id')}`",
                f"- **Service**: {f.get('service')}",
                f"- **Resource**: `{f.get('resource')}`",
                f"- **Region**: {f.get('region')}",
                f"- **Description**: {f.get('description')}"
            ])
            append_finding_guidance(f.get("review_finding_id"))
            md_lines.append("")
            
    md_lines.extend([
        "## OpenAI Usage Summary",
        f"- **Status**: {usage.get('status', 'N/A')}",
        f"- **Model**: {usage.get('model', 'N/A')}",
        f"- **Requests**: {usage.get('request_count', 0)}",
        f"- **Cache Hits**: {usage.get('cache_hits', 0)}",
        f"- **Cache Misses**: {usage.get('cache_misses', 0)}",
        f"- **Total Tokens**: {usage.get('total_tokens', 0)}",
        ""
    ])
    
    md_lines.extend([
        "## Limitations",
    ])
    for l in review.get("limitations", []):
        md_lines.append(f"- {l}")
    md_lines.append("")
    
    with open(review_dir / "security-review.md", "w") as f:
        f.write("\n".join(md_lines))
        
    # 2. remediation-guidance.md
    rem_lines = [
        f"# Remediation Guidance: {scan_id}",
        f"**Status**: {usage.get('status', 'N/A')}",
        ""
    ]
    
    g_list_local = guidance.get("guidance", [])
    
    def render_stage_guidance(stage: str):
        items = [g for g in g_list_local if g.get("stage") == stage]
        # Sort by priority CRITICAL -> UNKNOWN
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "INFO": 4, "UNKNOWN": 5}
        items.sort(key=lambda x: order.get(x.get("priority", "UNKNOWN").upper(), 99))
        
        rem_lines.append(f"## {stage}")
        if not items:
            rem_lines.append(f"No guidance for {stage}.\n")
            return
            
        for idx, item in enumerate(items):
            rem_lines.extend([
                f"### {idx+1}. {item.get('priority')} - {item.get('check_id')}",
                f"- **Scanner**: {item.get('scanner')}",
                f"- **Affected Resources**: {item.get('affected_resource_count')}",
                f"- **Source**: {item.get('source')}"
            ])
            
            ai = item.get("ai_guidance", {})
            if ai and ai.get("summary"):
                rem_lines.extend([
                    "",
                    "#### AI Guidance",
                    f"- **Summary**: {ai.get('summary')}",
                    f"- **Terraform Action**: {ai.get('terraform_action')}",
                    f"- **Runtime Action**: {ai.get('runtime_action')}",
                    f"- **Validation Step**: {ai.get('validation_step')}",
                    f"- **Operational Caution**: {ai.get('operational_caution')}",
                    ""
                ])
                
            sr = item.get("scanner_remediation")
            if sr:
                rem_lines.extend([
                    "#### Scanner Remediation",
                    f"{sr}",
                    ""
                ])
    
    render_stage_guidance("PRE_DEPLOYMENT")
    render_stage_guidance("POST_DEPLOYMENT")
    
    with open(review_dir / "remediation-guidance.md", "w") as f:
        f.write("\n".join(rem_lines))

def print_console(review: dict, usage: dict):
    scan_id = review.get("scan_id", "")
    sc = review.get("score_comparison", {})
    rec = review.get("review_recommendation", {})
    rem = review.get("remediation", {})
    
    delta_str = f"+{sc.get('score_delta_points', 0)}" if sc.get("score_delta_points", 0) > 0 else str(sc.get("score_delta_points", 0))
    
    print("============================================================")
    print("  PRE- VS POST-DEPLOYMENT SECURITY REVIEW")
    print("============================================================")
    print(f"SCAN_ID                    : {scan_id}\n")
    print(f"Pre-Deployment Score       : {sc.get('pre_deployment_score', 'N/A')} / 1000")
    print(f"Pre-Deployment Risk Band   : {sc.get('pre_deployment_risk_band', 'N/A')}")
    print(f"Pre-Deployment Decision    : {sc.get('pre_deployment_decision', 'N/A')}\n")
    print(f"Post-Deployment Score      : {sc.get('post_deployment_score', 'N/A')} / 1000")
    print(f"Post-Deployment Risk Band  : {sc.get('post_deployment_risk_band', 'N/A')}")
    print(f"Post-Deployment Action     : {sc.get('post_deployment_action', 'N/A')}\n")
    print(f"Score Delta                : {delta_str} points")
    print(f"Comparison Result          : {sc.get('comparison_result', 'N/A')}")
    print(f"Risk-Band Movement         : {sc.get('risk_band_movement', 'N/A')}")
    print(f"Review Recommendation      : {rec.get('decision', 'N/A')}")
    print(f"AI Remediation Status      : {usage.get('status', 'N/A')}")
    print(f"OpenAI Requests            : {usage.get('request_count', 0)}")
    print(f"Cache Hits                 : {usage.get('cache_hits', 0)}")
    print(f"Cache Misses               : {usage.get('cache_misses', 0)}")
    print("============================================================")
    print("PRE-DEPLOYMENT FINDINGS")
    print("POST-DEPLOYMENT FINDINGS")
    print("REMEDIATION GUIDANCE")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    scan_id = args.scan_id

    review_dir = ROOT_DIR / "reports" / "review" / scan_id
    sec_review_path = review_dir / "security-review.json"
    guidance_path = review_dir / "remediation-guidance.json"
    usage_path = review_dir / "openai-usage.json"
    manifest_path = review_dir / "review-evidence-manifest.json"
    
    review = safe_read_json(str(sec_review_path)) or {}
    guidance = safe_read_json(str(guidance_path)) or {}
    usage = safe_read_json(str(usage_path)) or {}
    
    render_markdown(review, guidance, usage, review_dir)
    print_console(review, usage)
    
    # Generate manifest
    manifest = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "files": {}
    }
    
    for p in review_dir.glob("*"):
        if p.is_file() and p.name != "review-evidence-manifest.json":
            manifest["files"][p.name] = hash_file(p)
            
    safe_write_json(str(manifest_path), manifest)
    print(f"[render_security_review] Saved manifest with {len(manifest['files'])} hashes.")

if __name__ == "__main__":
    main()
