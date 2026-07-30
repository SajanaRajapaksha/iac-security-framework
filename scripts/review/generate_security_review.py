#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import utc_now_iso
from scripts.review.review_utils import safe_read_json, safe_write_json, get_risk_band_index, sort_findings_by_severity

def extract_pre_deployment_findings(enriched_data: dict) -> list[dict]:
    results = []
    findings = enriched_data.get("findings", [])
    for idx, f in enumerate(findings):
        # We need a stable ID if possible, else generate one.
        fid = f.get("finding_id", f"pre-{idx}")
        sev = (f.get("final_severity") or f.get("severity") or "UNKNOWN").upper()
        
        results.append({
            "review_finding_id": f"pre_{fid}",
            "stage": "PRE_DEPLOYMENT",
            "scanner": f.get("source_tool", "checkov_or_policy"),
            "check_id": f.get("source_rule_id", ""),
            "severity": sev,
            "title": f.get("title", ""),
            "resource": f.get("resource", ""),
            "resource_type": f.get("resource_type", ""),
            "location": f.get("file_path", ""),
            "description": f.get("description", ""),
            "existing_remediation": f.get("policy", {}).get("resolution", "") if f.get("source_tool") == "policy" else "",
            "references": f.get("references", [])
        })
    return sort_findings_by_severity(results)

def extract_post_deployment_findings(runtime_data: dict) -> list[dict]:
    results = []
    findings = runtime_data.get("findings", [])
    for idx, f in enumerate(findings):
        fid = f.get("finding_id", f"post-{idx}")
        sev = (f.get("severity", {}).get("normalized") or "UNKNOWN").upper()
        if sev == "INFORMATIONAL":
            sev = "INFO"
            
        res = f.get("resource", {})
        
        results.append({
            "review_finding_id": f"post_{fid}",
            "stage": "POST_DEPLOYMENT",
            "scanner": f.get("scanner", "prowler"),
            "check_id": f.get("control_id", ""),
            "severity": sev,
            "title": f.get("title", ""),
            "service": res.get("service") or f.get("service") or "",
            "resource": res.get("arn") or res.get("id") or "",
            "resource_type": f.get("resource_type", ""),
            "region": res.get("region", ""),
            "description": f.get("description", ""),
            "risk": f.get("risk", ""),
            "existing_remediation": f.get("remediation", {}).get("recommendation", {}).get("text", ""),
            "references": f.get("compliance", [])
        })
    return sort_findings_by_severity(results)

def determine_recommendation(
    pre_score: dict, 
    post_score: dict, 
    post_findings: list[dict],
    exec_status: str
) -> tuple[str, str, str]:
    
    if not pre_score or not post_score or not post_score.get("score") or post_score.get("status") != "CALCULATED":
        return "REVIEW_INCOMPLETE", "Missing or invalid score/runtime evidence", "1. Missing or invalid score/runtime evidence"
        
    post_band = post_score.get("score", {}).get("risk_band")
    if post_band == "CRITICAL_RISK":
        return "CRITICAL_REMEDIATION", "Post-deployment score is CRITICAL_RISK", "2. Post-deployment score is CRITICAL_RISK"
        
    if any(f.get("severity") == "CRITICAL" for f in post_findings):
        return "URGENT_REVIEW", "Any post-deployment CRITICAL finding", "3. Any post-deployment CRITICAL finding"
        
    pre_num = pre_score.get("score")
    post_num = post_score.get("score", {}).get("post_deployment_risk_score")
    
    if pre_num is not None and post_num is not None and post_num < pre_num:
        return "RUNTIME_RISK_INCREASED", "Post-deployment score is lower than pre-deployment score", "4. Post-deployment score is lower than pre-deployment score"
        
    if pre_num is not None and post_num is not None and post_num > pre_num:
        if any(f.get("severity") in ("CRITICAL", "HIGH") for f in post_findings):
            return "IMPROVED_WITH_REMEDIATION_REQUIRED", "Post score improved but HIGH or CRITICAL runtime findings remain", "5. Post score improved but HIGH or CRITICAL runtime findings remain"

    if exec_status == "SUCCESS_NO_FINDINGS" and post_num == 1000 and len(post_findings) == 0:
        return "RUNTIME_VALIDATION_PASSED", "Successful runtime scan, score 1000 and no runtime findings", "6. Successful runtime scan, score 1000 and no runtime findings"

    return "REVIEW_REQUIRED", "Otherwise", "7. Otherwise"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    args = parser.parse_args()
    scan_id = args.scan_id

    pre_score_path = ROOT_DIR / "reports" / "risk" / scan_id / "predeployment-risk-score.json"
    enriched_path = ROOT_DIR / "reports" / "risk" / scan_id / "enriched-findings.json"
    post_score_path = ROOT_DIR / "reports" / "runtime" / scan_id / "risk" / "postdeployment-risk-score.json"
    runtime_findings_path = ROOT_DIR / "reports" / "runtime" / scan_id / "normalized" / "runtime-findings.json"
    prowler_exec_path = ROOT_DIR / "reports" / "runtime" / scan_id / "prowler" / "prowler-execution.json"
    
    out_dir = ROOT_DIR / "reports" / "review" / scan_id
    out_json = out_dir / "security-review.json"

    pre_score = safe_read_json(str(pre_score_path))
    enriched = safe_read_json(str(enriched_path))
    post_score = safe_read_json(str(post_score_path))
    runtime_findings = safe_read_json(str(runtime_findings_path))
    prowler_exec = safe_read_json(str(prowler_exec_path))

    pre_f = extract_pre_deployment_findings(enriched or {})
    post_f = extract_post_deployment_findings(runtime_findings or {})

    exec_status = prowler_exec.get("execution", {}).get("status") if prowler_exec else ""

    rec_decision, rec_reason, rec_rule = determine_recommendation(pre_score, post_score, post_f, exec_status)
    
    comp_res = "NOT_AVAILABLE"
    band_move = "NOT_AVAILABLE"
    delta = 0
    abs_delta = 0
    pre_num = pre_score.get("score") if pre_score else None
    post_num = post_score.get("score", {}).get("post_deployment_risk_score") if post_score else None

    if pre_num is not None and post_num is not None:
        delta = post_num - pre_num
        abs_delta = abs(delta)
        if delta > 0:
            comp_res = "RUNTIME_POSTURE_BETTER"
        elif delta < 0:
            comp_res = "RUNTIME_POSTURE_WORSE"
        else:
            comp_res = "SCORES_EQUAL"
            
        pre_band_idx = get_risk_band_index(pre_score.get("risk_band", ""))
        post_band_idx = get_risk_band_index(post_score.get("score", {}).get("risk_band", ""))
        
        if pre_band_idx < 99 and post_band_idx < 99:
            # lower index = better band
            if post_band_idx < pre_band_idx:
                band_move = "IMPROVED"
            elif post_band_idx > pre_band_idx:
                band_move = "DEGRADED"
            else:
                band_move = "NO_CHANGE"

    # Aggregations
    pre_res_count = len({f["resource"] for f in pre_f if f.get("resource")})
    post_res_count = len({f["resource"] for f in post_f if f.get("resource")})
    
    pre_unknown = sum(1 for f in pre_f if f["severity"] == "UNKNOWN")
    post_unknown = sum(1 for f in post_f if f["severity"] == "UNKNOWN")
    
    pre_sev = {}
    for f in pre_f: pre_sev[f["severity"]] = pre_sev.get(f["severity"], 0) + 1
    
    post_sev = {}
    for f in post_f: post_sev[f["severity"]] = post_sev.get(f["severity"], 0) + 1

    doc = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "module": "Security Review Module",
        "status": "COMPLETE" if rec_decision != "REVIEW_INCOMPLETE" else "INCOMPLETE",
        "score_comparison": {
            "pre_deployment_score": pre_num,
            "pre_deployment_risk_band": pre_score.get("risk_band") if pre_score else None,
            "pre_deployment_decision": pre_score.get("suggested_decision") if pre_score else None,
            "post_deployment_score": post_num,
            "post_deployment_risk_band": post_score.get("score", {}).get("risk_band") if post_score else None,
            "post_deployment_action": post_score.get("score", {}).get("suggested_action") if post_score else None,
            "score_delta_points": delta,
            "absolute_score_delta_points": abs_delta,
            "comparison_result": comp_res,
            "risk_band_movement": band_move
        },
        "review_recommendation": {
            "decision": rec_decision,
            "reason": rec_reason,
            "rule": rec_rule
        },
        "summary": {
            "pre_deployment_findings": len(pre_f),
            "post_deployment_findings": len(post_f),
            "pre_deployment_resource_count": pre_res_count,
            "post_deployment_resource_count": post_res_count,
            "pre_deployment_unknown_findings": pre_unknown,
            "post_deployment_unknown_findings": post_unknown
        },
        "severity_comparison": {
            "pre_deployment": pre_sev,
            "post_deployment": post_sev
        },
        "pre_deployment_findings": pre_f,
        "post_deployment_findings": post_f,
        "remediation": {
            "status": "PENDING",
            "guidance_path": "",
            "cache_hits": 0,
            "cache_misses": 0
        },
        "limitations": [
            "Pre-deployment and post-deployment findings are not directly correlated.",
            "Scanner coverage differs between static IaC analysis and live AWS assessment."
        ],
        "warnings": []
    }

    safe_write_json(str(out_json), doc)
    print(f"[generate_security_review] Saved deterministic review to {out_json}")

if __name__ == "__main__":
    main()
