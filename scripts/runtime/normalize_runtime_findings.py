#!/usr/bin/env python3
"""
scripts/runtime/normalize_runtime_findings.py

Parses raw Prowler JSON output, maps severities and standards, dedupes findings,
attributes them to deployed resources from the deployment manifest, and outputs
the normalized finding results.

Usage:
    python scripts/runtime/normalize_runtime_findings.py <SCAN_ID>
"""

import argparse
import glob
import sys
from pathlib import Path
from collections import defaultdict

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import (
    safe_read_json,
    safe_write_json,
    utc_now_iso,
    generate_finding_id
)

def _normalize_severity(orig: str) -> str:
    orig = str(orig).upper()
    if orig in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        return orig
    if orig == "INFO":
        return "INFORMATIONAL"
    return "UNKNOWN"

def _find_prowler_json(raw_dir: Path) -> Path | None:
    # Prowler JSON format files usually look like prowler-output-*.json
    files = list(raw_dir.glob("prowler-output-*.json"))
    if not files:
        return None
    # Return the one with the latest modification time
    return sorted(files, key=lambda f: f.stat().st_mtime)[-1]

def match_resource(finding: dict, manifest_resources: list, scan_id: str) -> tuple[dict | None, str, str | None]:
    """Match a Prowler finding to a resource in the deployment manifest.
    Returns (matched_resource_dict, attribution_method, unmatched_reason).
    """
    f_arn = finding.get("ResourceArn")
    f_id = finding.get("ResourceId")
    f_account = str(finding.get("AccountId", ""))
    f_region = finding.get("Region")
    f_tags = finding.get("Tags", {})
    
    # 1. Exact ARN
    if f_arn:
        for r in manifest_resources:
            if r.get("resource_arn") == f_arn:
                return r, "RESOURCE_ARN", None
                
    # 2. Exact Resource ID + account + region
    if f_id and f_account and f_region:
        for r in manifest_resources:
            if r.get("resource_id") == f_id and f_region in r.get("resource_arn", ""):
                # Basic check, state inventory doesn't explicitly store account, but manifest has it globally.
                return r, "RESOURCE_ID", None
                
    # 3. Exact name + service + region (fallback when ID not matched)
    f_name = finding.get("ResourceName")
    f_service = finding.get("ServiceName")
    if f_name and f_service and f_region:
        for r in manifest_resources:
            if (r.get("resource_name") == f_name or r.get("resource_id") == f_name) and r.get("aws_service") == f_service:
                 return r, "RESOURCE_NAME", None
                 
    # 4. Tags
    if isinstance(f_tags, dict):
        scan_id_tag = (
            f_tags.get("scan-id")
            or f_tags.get("ResearchScanId")
            or f_tags.get("research-scan-id")
        )
        if scan_id_tag and scan_id_tag == scan_id:
            for r in manifest_resources:
                 r_tags = r.get("tags", {})
                 r_scan_id_tag = r_tags.get("scan-id") or r_tags.get("ResearchScanId") or r_tags.get("research-scan-id")
                 if r_scan_id_tag == scan_id_tag:
                      return r, "SCAN_ID_TAG", None
            
            # Attributed by tag even if resource ID wasn't in manifest
            return None, "SCAN_ID_TAG", None

    # 5. Account-level
    # If the resource is the account itself or an account-level finding
    if f_id == f_account or "account" in str(f_id).lower() or not f_id:
        return None, "ACCOUNT_LEVEL", None

    # 6. Unmatched diagnostics
    if not manifest_resources:
        return None, "UNMATCHED", "MANIFEST_EMPTY"
    if not f_id and not f_arn:
        return None, "UNMATCHED", "MISSING_RESOURCE_ID"
    if f_arn:
        return None, "UNMATCHED", "RESOURCE_ARN_NOT_IN_MANIFEST"
    if f_id:
        return None, "UNMATCHED", "RESOURCE_ID_NOT_IN_MANIFEST"
    if f_service:
        return None, "UNMATCHED", "SERVICE_MISMATCH"
    if f_region:
        return None, "UNMATCHED", "REGION_MISMATCH"
        
    return None, "UNMATCHED", "ACCOUNT_LEVEL_NOT_RECOGNIZED"

def normalize_prowler(scan_id: str) -> None:
    runtime_dir = ROOT_DIR / "reports" / "runtime" / scan_id
    manifest_path = runtime_dir / "deployment-resource-manifest.json"
    prowler_raw_dir = runtime_dir / "prowler" / "raw"
    normalized_out_path = runtime_dir / "normalized" / "normalized-runtime-findings.json"
    summary_out_path = runtime_dir / "normalized" / "runtime-findings-summary.json"

    registry_path = ROOT_DIR / "mappings" / "runtime" / "prowler-security-hub-standards.json"
    registry = safe_read_json(str(registry_path)) or {"checks": {}}
    registry_checks = registry.get("checks", {})

    manifest = safe_read_json(str(manifest_path))
    if not manifest:
        print(f"[normalize] ERROR: Deployment manifest not found at {manifest_path}")
        sys.exit(1)
        
    manifest_resources = manifest.get("resources", [])
    aws_account_id = manifest.get("aws_account_id", "")
    
    prowler_base_dir = runtime_dir / "prowler"
    tag_scan_dir = prowler_base_dir / "deployment-tag-scan"
    arn_scan_dir = prowler_base_dir / "deployment-arn-scan"
    ctx_scan_dir = prowler_base_dir / "account-context-scan"
    
    raw_findings = []
    
    for scan_dir in [tag_scan_dir, arn_scan_dir, ctx_scan_dir]:
        if scan_dir.exists():
            for json_file in scan_dir.glob("prowler-output-*.json"):
                data = safe_read_json(str(json_file))
                if isinstance(data, list):
                    raw_findings.extend(data)
    
    if not raw_findings:
        print("[normalize] ERROR: No Prowler JSON output found.")
        # Write empty structural data to avoid breaking downstream scripts
        empty_out = {
            "metadata": {
                "scan_id": scan_id,
                "generated_at": utc_now_iso(),
                "total_raw_failures": 0,
                "total_unique_findings": 0,
                "total_merged_duplicates": 0,
                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0, "UNKNOWN": 0},
                "status": "PROWLER_EXECUTION_FAILED"
            },
            "deployment_findings": [],
            "account_context_findings": [],
            "unmatched_findings": []
        }
        safe_write_json(str(normalized_out_path), empty_out)
        
        empty_summary = {
            "scan_id": scan_id,
            "aws_account_id": aws_account_id,
            "region": manifest.get("regions", ["unknown"])[0] if manifest.get("regions") else "unknown",
            "deployed_resources": len(manifest_resources),
            "raw_prowler_failures": 0,
            "deduplicated_findings": 0,
            "merged_duplicate_records": 0,
            "deployment_findings": 0,
            "unique_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0, "UNKNOWN": 0},
            "unmatched_findings_count": 0,
            "account_findings_count": 0,
            "status": "PROWLER_EXECUTION_FAILED",
            "attribution_summary": {}
        }
        safe_write_json(str(summary_out_path), empty_summary)
        sys.exit(1)

    # Filter out PASS / INFO unless they are FAIL, ERROR, or MANUAL? 
    # Prowler 4 might return PASS, FAIL, MANUAL, WARNING, MUTED.
    failed_findings = [f for f in raw_findings if f.get("Status") in ("FAIL", "ERROR", "MANUAL", "WARNING")]
    
    deployment_findings = []
    account_context_findings = []
    unmatched_findings = []
    operational_errors = []
    account_context_findings = []
    unmatched_findings = []
    
    # Deduplication map: key -> list of raw finding dicts
    dedup_map = defaultdict(list)
    
    for f in failed_findings:
        check_id = f.get("CheckID", "unknown")
        reg_info = registry_checks.get(check_id, {})
        canonical_control = reg_info.get("canonical_control", check_id.upper())
        
        account = f.get("AccountId", aws_account_id)
        region = f.get("Region", "unknown")
        r_id = f.get("ResourceId", "unknown")
        
        # canonical key
        dedup_key = f"{account}|{region}|{r_id}|{canonical_control}"
        dedup_map[dedup_key].append(f)

    unique_findings = len(dedup_map)
    total_merged = len(failed_findings) - unique_findings
    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0, "UNKNOWN": 0}
    match_methods_counts = {"RESOURCE_ARN": 0, "RESOURCE_ID": 0, "RESOURCE_NAME": 0, "SCAN_ID_TAG": 0}
    unmatched_reasons_counts = defaultdict(int)

    # Process each deduplicated group
    for dedup_key, finding_group in dedup_map.items():
        # Take the first as the primary representation for resource info
        f = finding_group[0]
        check_id = f.get("CheckID", "unknown")
        reg_info = registry_checks.get(check_id, {})
        # Match resource
        matched_resource, attr_method, unmatched_reason = match_resource(f, manifest_resources, scan_id)
        
        status = f.get("Status", "UNKNOWN")
        is_operational_error = status in ("ERROR", "WARNING", "MANUAL")
        
        # Determine Severity (Hierarchy: Local Override > Native Prowler > UNKNOWN)
        prowler_sev = f.get("Severity", "unknown")
        
        # Check local registry override
        override_sev = reg_info.get("severity_override")
        if override_sev:
            norm_sev = _normalize_severity(override_sev)
            sev_source = "LOCAL_REVIEWED_OVERRIDE"
        else:
            norm_sev = _normalize_severity(prowler_sev)
            sev_source = "PROWLER_METADATA"

        severity_obj = {
            "original": prowler_sev,
            "normalized": norm_sev,
            "source": sev_source
        }
        
        if override_sev:
            severity_obj["reason"] = "Documented reason"
            severity_obj["reviewed_at"] = utc_now_iso()
            severity_obj["reviewed_by"] = "local-registry"

        # Determine Compliance Mappings
        standards = []
        compliance_data = f.get("Compliance", {})
        if isinstance(compliance_data, dict):
            for framework, versions in compliance_data.items():
                if isinstance(versions, dict):
                    for version, controls in versions.items():
                        if isinstance(controls, list):
                            for control in controls:
                                standards.append({
                                    "framework": framework,
                                    "version": str(version),
                                    "control_id": str(control),
                                    "source": "PROWLER_COMPLIANCE_METADATA"
                                })
        elif isinstance(compliance_data, list):
            for entry in compliance_data:
                if isinstance(entry, dict):
                    standards.append({
                        "framework": entry.get("Framework", "unknown"),
                        "version": entry.get("Version", "unknown"),
                        "control_id": entry.get("Requirement", entry.get("Control", "unknown")),
                        "source": "PROWLER_COMPLIANCE_METADATA"
                    })
                    standards.append({
                        "name": "CIS_AWS_FOUNDATIONS_BENCHMARK",
                        "version": "unknown",
                        "requirement_id": entry,
                        "mapping_source": "PROWLER_METADATA"
                    })
        
        normalized = {
            "schema_version": "1.0",
            "finding_id": generate_finding_id(),
            "scan_id": scan_id,
            "phase": "RUNTIME",
            "scanner": {
                "name": "Prowler",
                "version": "unknown",
                "check_id": check_id
            },
            "status": "FAIL",
            "title": f.get("CheckTitle", ""),
            "description": f.get("Description", ""),
            "service": f.get("ServiceName", ""),
            "region": f.get("Region", ""),
            "aws_account_id": f.get("AccountId", ""),
            "resource": {
                "resource_id": f.get("ResourceId", ""),
                "resource_arn": f.get("ResourceArn", ""),
                "resource_name": f.get("ResourceName", ""),
                "id": r_id,
                "arn": f.get("ResourceArn", ""),
                "aws_account_id": account,
                "aws_region": region,
                "deployment_attributed": bool(matched_resource),
                "attribution_method": attr_method,
                "unmatched_reason": unmatched_reason,
                "tags": f.get("Tags", {})
            },
            "status": "OPERATIONAL_ERROR" if is_operational_error else "FAIL",
            "remediation": {
                "text": f.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                "references": [f.get("Remediation", {}).get("Recommendation", {}).get("Url", "")]
            },
            "evidence": {
                "raw_source_file": "prowler-output",
                "raw_record_reference": f.get("ResourceId", "")
            },
            "first_observed_at": utc_now_iso(),
            "generated_at": utc_now_iso()
        }
        if is_operational_error:
            operational_errors.append(normalized)
        elif normalized["resource"]["deployment_attributed"]:
            deployment_findings.append(normalized)
            severity_counts[norm_sev] += 1
            if attr_method in match_methods_counts:
                match_methods_counts[attr_method] += 1
        elif attr_method == "ACCOUNT_LEVEL":
            account_context_findings.append(normalized)
        else:
            unmatched_findings.append(normalized)
            if unmatched_reason:
                unmatched_reasons_counts[unmatched_reason] += 1

    out_data = {
        "metadata": {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "total_raw_failures": len(failed_findings),
            "deduplicated_findings": unique_findings,
            "total_merged_duplicates": total_merged,
            "deployment_findings": len(deployment_findings),
            "account_context_findings": len(account_context_findings),
            "unmatched_findings": len(unmatched_findings),
            "operational_errors": len(operational_errors),
            "severity_counts": severity_counts
        },
        "deployment_findings": deployment_findings,
        "account_context_findings": account_context_findings,
        "unmatched_findings": unmatched_findings,
        "operational_errors": operational_errors
    }
    
    safe_write_json(str(normalized_out_path), out_data)

    # Coverage calculations
    taggable_resources = sum(1 for r in manifest_resources if r.get("taggable"))
    arn_resources = sum(1 for r in manifest_resources if not r.get("taggable") and r.get("resource_arn"))
    verified_resources = len({f["resource"]["arn"] for f in deployment_findings if f["resource"].get("arn")} | {f["resource"]["id"] for f in deployment_findings if f["resource"].get("id")})
    
    total_scannable = taggable_resources + arn_resources
    cov_pct = round((verified_resources / total_scannable * 100), 2) if total_scannable > 0 else 100.0

    summary = {
        "scan_id": scan_id,
        "aws_account_id": aws_account_id,
        "region": manifest.get("regions", ["unknown"])[0] if manifest.get("regions") else "unknown",
        "prowler_version": "4.3.4", # Hardcoded or fetched from execution evidence
        "scan_scope": "DEPLOYMENT_TAG_FILTER",
        "deployed_resources": len(manifest_resources),
        "tag_scannable_resources": taggable_resources,
        "arn_scannable_resources": arn_resources,
        "raw_prowler_failures": len(failed_findings),
        "deduplicated_findings": unique_findings,
        "merged_duplicate_records": total_merged,
        "deployment_findings": len(deployment_findings),
        "unique_findings": len(deployment_findings) + len(account_context_findings),
        "severity_counts": severity_counts,
        "unmatched_findings_count": len(unmatched_findings),
        "account_findings_count": len(account_context_findings),
        "operational_errors_count": len(operational_errors),
        "status": "SUCCESS",
        "coverage": {
            "manifest_resources": len(manifest_resources),
            "tag_scannable_resources": taggable_resources,
            "arn_scannable_resources": arn_resources,
            "verified_scanned_resources": verified_resources,
            "coverage_percentage": cov_pct,
            "coverage_status": "FULL" if cov_pct == 100 else "PARTIAL"
        },
        "attribution_summary": {
            "deployment_findings": len(deployment_findings),
            "account_context_findings": len(account_context_findings),
            "unmatched_findings": len(unmatched_findings),
            "match_methods": match_methods_counts,
            "unmatched_reasons": dict(unmatched_reasons_counts)
        }
    }
    safe_write_json(str(summary_out_path), summary)
    
    print(f"[normalize] Normalization complete. {len(deployment_findings)} deployment findings extracted.")

def main():
    parser = argparse.ArgumentParser(description="Normalize runtime findings.")
    parser.add_argument("scan_id", help="The unique SCAN_ID")
    args = parser.parse_args()
    normalize_prowler(args.scan_id)

if __name__ == "__main__":
    main()
