#!/usr/bin/env python3
"""
scripts/dashboard/export_dashboard_bundle.py

Gathers all available security evidence, generates dashboard-ready normalized
JSON files (scan-summary.json, findings.json, evidence-manifest.json), and
prepares them for S3 upload.

Usage: python scripts/dashboard/export_dashboard_bundle.py <SCAN_ID>
"""

import argparse
import ast
import hashlib
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, sha256_file, utc_now_iso

# Authoritative raw evidence locations relative to ROOT_DIR
EVIDENCE_PATHS = {
    "metadata": "repositories/metadata/{scan_id}/scan-metadata.json",
    "terraform_validation": "reports/static/{scan_id}/terraform-validation/terraform-validation.json",
    "static_analysis": "reports/static/{scan_id}/combined/static-analysis-evidence.json",
    "policy_results": "reports/policy/{scan_id}/policy-results.json",
    "predeployment_inventory": "reports/risk/{scan_id}/predeployment-resource-inventory.json",
    "enriched_findings": "reports/risk/{scan_id}/enriched-findings.json",
    "enrichment_summary": "reports/risk/{scan_id}/finding-enrichment-summary.json",
    "predeployment_score": "reports/risk/{scan_id}/predeployment-risk-score.json",
    "deployment_contract": "reports/deployment/{scan_id}/deployment-contract-validation.json",
    "deployment_plan": "reports/deployment/{scan_id}/deployment-plan-evidence.json",
    "deployment_auth": "reports/deployment/{scan_id}/deployment-authorization.json",
    "deployment_apply": "reports/deployment/{scan_id}/deployment-apply-evidence.json",
    "tagged_inventory": "reports/deployment/{scan_id}/tagged-aws-resource-inventory.json",
    "state_inventory": "reports/deployment/{scan_id}/terraform-state-resource-inventory.json",
    "deployment_validation": "reports/deployment/{scan_id}/deployment-validation.json",
    "runtime_findings": "reports/runtime/{scan_id}/normalized/runtime-findings.json",
    "postdeployment_score": "reports/runtime/{scan_id}/risk/postdeployment-risk-score.json",
    "prowler_execution": "reports/runtime/{scan_id}/prowler/prowler-execution.json",
    "security_review": "reports/review/{scan_id}/security-review.json",
    "ai_remediation": "reports/review/{scan_id}/remediation-guidance.json",
    "cleanup_evidence": "reports/deployment/{scan_id}/terraform-destroy-evidence.json"
}

def load_evidence(scan_id: str):
    loaded = {}
    for key, path_template in EVIDENCE_PATHS.items():
        path = ROOT_DIR / path_template.format(scan_id=scan_id)
        if path.is_file():
            loaded[key] = {
                "path": str(path.relative_to(ROOT_DIR)),
                "data": safe_read_json(str(path))
            }
    return loaded

def normalize_severity(value) -> str:
    """Extract a safe uppercase string severity from diverse formats."""
    if not value:
        return "UNKNOWN"
        
    if isinstance(value, dict):
        return str(value.get("normalized") or value.get("original") or value.get("ORIGINAL") or "UNKNOWN").upper()
        
    if isinstance(value, str):
        val_str = value.strip()
        # Handle stringified dictionary e.g. "{'ORIGINAL': 'CRITICAL', ...}"
        if val_str.startswith("{") and val_str.endswith("}"):
            try:
                parsed = ast.literal_eval(val_str)
                if isinstance(parsed, dict):
                    return str(parsed.get("normalized") or parsed.get("NORMALIZED") or parsed.get("original") or parsed.get("ORIGINAL") or "UNKNOWN").upper()
            except (ValueError, SyntaxError):
                pass
        return val_str.upper()
        
    return "UNKNOWN"


def generate_scan_summary(scan_id: str, evidence: dict):
    summary = {
        "scan_id": scan_id,
        "workflow_id": os.environ.get("GITHUB_RUN_ID", "UNKNOWN"),
        "scan_status": "COMPLETED",
        "started_timestamp": "NOT_AVAILABLE",
        "completed_timestamp": utc_now_iso(),
        "repository": {
            "url": "NOT_AVAILABLE",
            "name": "NOT_AVAILABLE",
            "branch": "NOT_AVAILABLE",
            "commit_sha": os.environ.get("GITHUB_SHA", "NOT_AVAILABLE")
        },
        "pre_deployment": {
            "risk_score": "NOT_AVAILABLE",
            "risk_band": "NOT_AVAILABLE",
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "unknown_count": 0,
            "checkov_finding_count": 0,
            "policy_finding_count": 0,
            "review_required_finding_count": 0
        },
        "deployment": {
            "status": "NOT_EXECUTED",
            "authorization_decision": "NOT_EXECUTED",
            "aws_region": "NOT_AVAILABLE",
            "planned_resources": "NOT_AVAILABLE",
            "deployed_resources": "NOT_AVAILABLE"
        },
        "runtime": {
            "finding_count": "NOT_EXECUTED",
            "critical_count": "NOT_EXECUTED",
            "high_count": "NOT_EXECUTED",
            "medium_count": "NOT_EXECUTED",
            "low_count": "NOT_EXECUTED",
            "unknown_count": "NOT_EXECUTED",
            "risk_score": "NOT_EXECUTED",
            "risk_band": "NOT_EXECUTED"
        },
        "risk_comparison": {
            "score_delta": "NOT_AVAILABLE",
            "direction": "NOT_AVAILABLE"
        },
        "final_decision": {
            "decision": "NOT_AVAILABLE",
            "reason": "NOT_AVAILABLE",
            "urgent_review_required": False
        },
        "cleanup": {
            "destroy_status": "NOT_EXECUTED",
            "verification_status": "NOT_EXECUTED"
        }
    }

    if "metadata" in evidence:
        md = evidence["metadata"]["data"]
        summary["started_timestamp"] = md.get("generated_at", "NOT_AVAILABLE")
        
        repo_url = md.get("repo_url", "NOT_AVAILABLE")
        summary["repository"]["url"] = repo_url
        if repo_url and repo_url != "NOT_AVAILABLE":
            summary["repository"]["name"] = repo_url.split('/')[-1].replace('.git', '')
            
        summary["repository"]["branch"] = md.get("branch", "NOT_AVAILABLE")

    if "predeployment_score" in evidence:
        score_doc = evidence["predeployment_score"]["data"]
        score_val = score_doc.get("score")
        if isinstance(score_val, dict):
            summary["pre_deployment"]["risk_score"] = score_val.get("pre_deployment_risk_score", "NOT_AVAILABLE")
            summary["pre_deployment"]["risk_band"] = score_val.get("risk_band", "NOT_AVAILABLE")
        else:
            summary["pre_deployment"]["risk_score"] = score_val if score_val is not None else "NOT_AVAILABLE"
            summary["pre_deployment"]["risk_band"] = score_doc.get("risk_band", "NOT_AVAILABLE")

    if "enriched_findings" in evidence:
        findings = evidence["enriched_findings"]["data"].get("findings", [])
        summary["pre_deployment"]["total_findings"] = len(findings)
        
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        checkov = 0
        policy = 0
        review = 0
        for f in findings:
            sev = normalize_severity(f.get("final_severity", f.get("scanner_severity", "UNKNOWN")))
            if sev in counts:
                counts[sev] += 1
            else:
                counts["UNKNOWN"] += 1
                
            if f.get("source_tool") == "checkov":
                checkov += 1
            elif f.get("source_tool") == "policy":
                policy += 1
            if f.get("requires_review"):
                review += 1
                
        summary["pre_deployment"].update({
            "critical_count": counts["CRITICAL"],
            "high_count": counts["HIGH"],
            "medium_count": counts["MEDIUM"],
            "low_count": counts["LOW"],
            "unknown_count": counts["UNKNOWN"],
            "checkov_finding_count": checkov,
            "policy_finding_count": policy,
            "review_required_finding_count": review
        })

    if "deployment_plan" in evidence:
        plan = evidence["deployment_plan"]["data"]
        summary["deployment"]["aws_region"] = plan.get("aws_region", "NOT_AVAILABLE")
        summary["deployment"]["planned_resources"] = plan.get("metrics", {}).get("taggable_checked", "NOT_AVAILABLE")

    if "deployment_auth" in evidence:
        summary["deployment"]["authorization_decision"] = evidence["deployment_auth"]["data"].get("decision", "NOT_AVAILABLE")
        summary["deployment"]["status"] = "AUTHORIZED" if summary["deployment"]["authorization_decision"] == "PROCEED" else "BLOCKED"

    if "tagged_inventory" in evidence:
        summary["deployment"]["deployed_resources"] = evidence["tagged_inventory"]["data"].get("metrics", {}).get("total_tagged", "NOT_AVAILABLE")
        # If resources were deployed, the deployment was clearly successful/active. 
        if summary["deployment"]["status"] != "AUTHORIZED":
             summary["deployment"]["status"] = "EXECUTED"

    if "runtime_findings" in evidence:
        rf = evidence["runtime_findings"]["data"].get("findings", [])
        summary["runtime"]["finding_count"] = len(rf)
        rcounts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for f in rf:
            sev = normalize_severity(f.get("severity", "UNKNOWN"))
            if sev in rcounts:
                rcounts[sev] += 1
            else:
                rcounts["UNKNOWN"] += 1
                
        summary["runtime"].update({
            "critical_count": rcounts["CRITICAL"],
            "high_count": rcounts["HIGH"],
            "medium_count": rcounts["MEDIUM"],
            "low_count": rcounts["LOW"],
            "unknown_count": rcounts["UNKNOWN"]
        })

    if "postdeployment_score" in evidence:
        post_score_doc = evidence["postdeployment_score"]["data"]
        p_val = post_score_doc.get("score")
        if isinstance(p_val, dict):
            summary["runtime"]["risk_score"] = p_val.get("post_deployment_risk_score", "NOT_AVAILABLE")
            summary["runtime"]["risk_band"] = p_val.get("risk_band", "NOT_AVAILABLE")
        else:
            summary["runtime"]["risk_score"] = p_val if p_val is not None else "NOT_AVAILABLE"
            summary["runtime"]["risk_band"] = post_score_doc.get("risk_band", "NOT_AVAILABLE")

    if "security_review" in evidence:
        sr = evidence["security_review"]["data"]
        comp = sr.get("score_comparison", {})
        summary["risk_comparison"]["score_delta"] = comp.get("score_delta_points", "NOT_AVAILABLE")
        summary["risk_comparison"]["direction"] = comp.get("comparison_result", "NOT_AVAILABLE")
        
        rec = sr.get("review_recommendation", {})
        summary["final_decision"]["decision"] = rec.get("decision", "NOT_AVAILABLE")
        summary["final_decision"]["reason"] = rec.get("reason", "NOT_AVAILABLE")
        summary["final_decision"]["urgent_review_required"] = sr.get("urgent_review_required", False)

    if "cleanup_evidence" in evidence:
        clean = evidence["cleanup_evidence"]["data"]
        summary["cleanup"]["destroy_status"] = "SUCCESS" if clean.get("exit_code") == 0 else "FAILED"
        summary["cleanup"]["verification_status"] = "CLEAN" if clean.get("verification_status") == "CLEAN" else "DIRTY"

    return summary


def _get_remediation_doc(remediation_data, finding_key):
    """Extract remediation for a given finding based on AI guidance list."""
    if not remediation_data:
        return {"available": False}
    
    # New AI Remediation format: {"guidance": [ {"finding_key": ..., "ai_guidance": ...}, ... ]}
    guidance_list = remediation_data.get("guidance", [])
    
    for item in guidance_list:
        if item.get("finding_key") == finding_key:
            ai = item.get("ai_guidance", {})
            return {
                "available": True,
                "target": "IAC_SOURCE",
                "summary": ai.get("summary", ""),
                "steps": ai.get("terraform_action", []),
                "terraform_example": ai.get("example", ""),
                "verification": ai.get("runtime_action", []),
                "references": ai.get("references", []),
                "source": "AI_REMEDIATION"
            }
            
    return {"available": False}


def build_finding_record_key(scanner, original_id, phase, resource_identifier):
    """Deterministic hash for finding uniqueness."""
    raw = f"{scanner}|{original_id}|{phase}|{resource_identifier}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def generate_findings(scan_id: str, evidence: dict):
    all_findings = []
    ai_remediation = evidence.get("ai_remediation", {}).get("data", {})

    # 1. Pre-deployment findings
    if "enriched_findings" in evidence:
        for f in evidence["enriched_findings"]["data"].get("findings", []):
            scanner = f.get("source_tool", "checkov")
            original_scanner_id = f.get("source_rule_id", "UNKNOWN")
            resource = f.get("resource", "Unknown")
            
            # Reconstruct the AI engine finding_key logic roughly (source_tool:source_rule_id:resource_type:hash)
            # Actually, the simplest is to match the exact mechanism AI uses if possible.
            # We'll just look up by a known key structure, or if finding_key isn't populated on `f`, we'll build it.
            f_desc = f.get("description", "")[:50]
            f_desc_hash = hashlib.md5(f_desc.encode()).hexdigest()[:8]
            expected_finding_key = f"{scanner}:{original_scanner_id}:{f.get('resource_type')}:{f_desc_hash}"
            
            rem = _get_remediation_doc(ai_remediation, expected_finding_key)
            
            record_key = build_finding_record_key(scanner, original_scanner_id, "PRE_DEPLOYMENT", resource)
            
            all_findings.append({
                "finding_record_key": record_key,
                "finding_id": f.get("finding_id"),
                "original_scanner_id": original_scanner_id,
                "scanner": scanner,
                "phase": "PRE_DEPLOYMENT",
                "severity": normalize_severity(f.get("final_severity", f.get("scanner_severity", "UNKNOWN"))),
                "title": f.get("title", ""),
                "description": f.get("description", ""),
                "security_category": f.get("mapping_type", "UNKNOWN"),
                "affected_resource_type": f.get("resource_type", "Unknown"),
                "resource_name": resource,
                "full_address": resource,
                "file_path": f.get("file_path", "Unknown"),
                "line_start": f.get("line_start"),
                "line_end": f.get("line_end"),
                "aws_service": f.get("resource_type", "").split("_")[1] if "_" in f.get("resource_type", "") else "Unknown",
                "review_required": f.get("requires_review", False),
                "framework_mapping": f.get("mapping_type"),
                "compliance_mappings": f.get("standards_references", []),
                "source_evidence_artifact": evidence["enriched_findings"]["path"],
                "remediation": rem
            })
            
    # 2. Runtime findings
    if "runtime_findings" in evidence:
        for f in evidence["runtime_findings"]["data"].get("findings", []):
            scanner = f.get("scanner", f.get("source_tool", "prowler"))
            original_scanner_id = f.get("control_id", f.get("check_id", "UNKNOWN"))
            
            res_obj = f.get("resource", {})
            r_arn = res_obj.get("arn", "Unknown")
            r_name = res_obj.get("name") or res_obj.get("id") or "Unknown"
            
            expected_finding_key = f"{scanner}:{original_scanner_id}:runtime:n/a" # AI doesn't typically enrich runtime the exact same way natively, but let's safely fall back
            
            rem = _get_remediation_doc(ai_remediation, expected_finding_key)
            
            if not rem["available"] and f.get("remediation"):
                p_text = f.get("remediation", {}).get("text", "")
                p_refs = f.get("remediation", {}).get("references", [])
                if p_text or p_refs:
                    rem = {
                        "available": True,
                        "target": "RUNTIME_AWS",
                        "summary": p_text,
                        "steps": [],
                        "terraform_example": "",
                        "verification": [],
                        "references": p_refs,
                        "source": "PROWLER"
                    }

            record_key = build_finding_record_key(scanner, original_scanner_id, "POST_DEPLOYMENT", r_arn)

            aws_service = "Unknown"
            if "arn:aws:" in r_arn:
                aws_service = r_arn.split(":")[2]
            elif f.get("service"):
                aws_service = f.get("service")
            
            all_findings.append({
                "finding_record_key": record_key,
                "finding_id": f.get("finding_id"),
                "original_scanner_id": original_scanner_id,
                "scanner": scanner,
                "phase": "POST_DEPLOYMENT",
                "severity": normalize_severity(f.get("severity", "UNKNOWN")),
                "title": f.get("title", ""),
                "description": f.get("description", ""),
                "security_category": aws_service.upper() if aws_service != "Unknown" else "UNKNOWN",
                "affected_resource_type": f"aws_{aws_service}" if aws_service != "Unknown" else "Unknown",
                "resource_name": r_name,
                "full_address": r_arn,
                "file_path": "RUNTIME",
                "aws_service": aws_service,
                "review_required": f.get("requires_review", False),
                "framework_mapping": f.get("mapping_type"),
                "compliance_mappings": f.get("compliance", []),
                "source_evidence_artifact": evidence["runtime_findings"]["path"],
                "remediation": rem
            })
            
    return {"scan_id": scan_id, "findings": all_findings}


def _determine_category(path: str) -> str:
    if "metadata" in path: return "METADATA"
    if "static" in path: return "STATIC_ANALYSIS"
    if "policy" in path: return "POLICY_ANALYSIS"
    if "risk" in path: return "RISK_ANALYSIS"
    if "deployment" in path: return "DEPLOYMENT"
    if "runtime" in path: return "RUNTIME_ANALYSIS"
    if "review" in path: return "SECURITY_REVIEW"
    if "cleanup" in path or "destroy" in path: return "CLEANUP"
    return "UNKNOWN"

def generate_evidence_manifest(scan_id: str, evidence: dict):
    manifest = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "artifacts": []
    }
    
    for key, item in evidence.items():
        original_path = item["path"]
        abs_path = ROOT_DIR / original_path
        size = abs_path.stat().st_size if abs_path.is_file() else 0
        sha = sha256_file(str(abs_path)) if abs_path.is_file() else "UNKNOWN"
        category = _determine_category(original_path)
        cat_lower = category.lower().split("_")[0]
        if cat_lower == "policy": cat_lower = "static"
        s3_prefix = f"raw/{scan_id}/{cat_lower}"
        
        manifest["artifacts"].append({
            "name": abs_path.name,
            "original_path": original_path,
            "s3_key": f"{s3_prefix}/{abs_path.name}",
            "type": category,
            "sha256": sha,
            "size_bytes": size,
            "export_timestamp": utc_now_iso()
        })
    return manifest


def validate_dashboard_consistency(summary: dict, findings: list):
    """Verify that finding counts match the explicit totals."""
    pre = summary["pre_deployment"]
    run = summary["runtime"]
    
    pre_calc = pre["critical_count"] + pre["high_count"] + pre["medium_count"] + pre["low_count"] + pre["unknown_count"]
    run_calc = run["critical_count"] + run["high_count"] + run["medium_count"] + run["low_count"] + run["unknown_count"]
    
    if pre["total_findings"] != 0 and pre_calc != pre["total_findings"]:
        print(f"WARNING: Pre-deployment severity counts ({pre_calc}) do not match total ({pre['total_findings']})!", file=sys.stderr)
        
    if run["finding_count"] != "NOT_EXECUTED" and run["finding_count"] != 0 and run_calc != run["finding_count"]:
        print(f"WARNING: Runtime severity counts ({run_calc}) do not match total ({run['finding_count']})!", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    scan_id = args.scan_id

    out_dir = ROOT_DIR / "dashboard-export" / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)

    evidence = load_evidence(scan_id)
    
    print("============================================================")
    print("DASHBOARD EXPORT BUNDLE GENERATION")
    print("============================================================")
    print(f"Scan ID           : {scan_id}")
    print(f"Raw Evidences     : {len(evidence)} loaded")

    summary_doc = generate_scan_summary(scan_id, evidence)
    findings_doc = generate_findings(scan_id, evidence)
    manifest_doc = generate_evidence_manifest(scan_id, evidence)
    
    validate_dashboard_consistency(summary_doc, findings_doc["findings"])
    
    safe_write_json(str(out_dir / "scan-summary.json"), summary_doc)
    safe_write_json(str(out_dir / "findings.json"), findings_doc)
    safe_write_json(str(out_dir / "evidence-manifest.json"), manifest_doc)

    print(f"Findings Exported : {len(findings_doc['findings'])}")
    print(f"Bundle Saved      : dashboard-export/{scan_id}/")
    print("============================================================")


if __name__ == "__main__":
    main()
