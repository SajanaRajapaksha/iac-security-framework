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
import csv
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

def _find_prowler_csv(raw_dir: Path) -> Path | None:
    files = list(raw_dir.glob("prowler-output-*.csv"))
    if not files:
        return None
    return sorted(files, key=lambda f: f.stat().st_mtime)[-1]

def _find_prowler_ocsf(raw_dir: Path) -> Path | None:
    files = list(raw_dir.glob("prowler-output-*.ocsf.json"))
    if not files:
        return None
    return sorted(files, key=lambda f: f.stat().st_mtime)[-1]

def match_resource(finding: dict, manifest_resources: list, scan_id: str) -> tuple[dict | None, str]:
    """Match a Prowler finding to a resource in the deployment manifest.
    Returns (matched_resource_dict, attribution_method).
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
                return r, "RESOURCE_ARN"
                
    # 2. Exact Resource ID + account + region
    if f_id and f_account and f_region:
        for r in manifest_resources:
            if r.get("resource_id") == f_id and f_region in r.get("resource_arn", ""):
                return r, "RESOURCE_ID"
                
    # 3. Exact name + service + region (fallback when ID not matched)
    f_name = finding.get("RESOURCE_NAME", finding.get("RESOURCE_DETAILS"))
    f_service = finding.get("SERVICE_NAME")
    if f_name and f_service and f_region:
        for r in manifest_resources:
            if (r.get("resource_name") == f_name or r.get("resource_id") == f_name) and r.get("aws_service") == f_service:
                 return r, "RESOURCE_NAME"
                 
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
                      return r, "SCAN_ID_TAG"
            
            # Attributed by tag even if resource ID wasn't in manifest
            return None, "SCAN_ID_TAG"

    # 5. Account-level
    # If the resource is the account itself
    if f_id == f_account:
        return None, "ACCOUNT_LEVEL"

    return None, "UNMATCHED"

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
    
    prowler_csv_path = _find_prowler_csv(prowler_raw_dir)
    prowler_ocsf_path = _find_prowler_ocsf(prowler_raw_dir)
    
    if not prowler_csv_path:
        print("[normalize] ERROR: No Prowler CSV output found.")
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
            "unique_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0, "UNKNOWN": 0},
            "unmatched_findings_count": 0,
            "account_findings_count": 0,
            "status": "PROWLER_EXECUTION_FAILED"
        }
        safe_write_json(str(summary_out_path), empty_summary)
        sys.exit(1)

    with open(prowler_csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        raw_findings = list(reader)

    # Filter out PASS / INFO unless they are FAIL
    failed_findings = [f for f in raw_findings if f.get("STATUS") == "FAIL"]
    
    deployment_findings = []
    account_context_findings = []
    unmatched_findings = []
    
    # Deduplication map: key -> list of raw finding dicts
    dedup_map = defaultdict(list)
    
    for f in failed_findings:
        check_id = f.get("CHECK_ID", "unknown")
        reg_info = registry_checks.get(check_id, {})
        canonical_control = reg_info.get("canonical_control", check_id.upper())
        
        account = f.get("ACCOUNT_ID", aws_account_id)
        region = f.get("REGION", "unknown")
        r_id = f.get("RESOURCE_ID", "unknown")
        
        # canonical key
        dedup_key = f"{account}|{region}|{r_id}|{canonical_control}"
        dedup_map[dedup_key].append(f)

    total_merged = 0
    unique_findings = 0
    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0, "UNKNOWN": 0}

    # Process each deduplicated group
    for dedup_key, finding_group in dedup_map.items():
        unique_findings += 1
        if len(finding_group) > 1:
            total_merged += (len(finding_group) - 1)
            
        # Take the first as the primary representation for resource info
        f = finding_group[0]
        check_id = f.get("CHECK_ID", "unknown")
        reg_info = registry_checks.get(check_id, {})
        
        # We need to map CSV fields to what match_resource expects
        f_mapped = {
            "ResourceArn": f.get("RESOURCE_ARN"),
            "ResourceId": f.get("RESOURCE_ID"),
            "AccountId": f.get("ACCOUNT_ID"),
            "Region": f.get("REGION"),
            "ResourceName": f.get("RESOURCE_DETAILS"),
            "ServiceName": f.get("SERVICE_NAME"),
            "Tags": {} # CSV has RESOURCE_TAGS as a string (e.g. 'scan-id=SCAN-123|managed-by=...'), we must parse it
        }
        
        tags_raw = f.get("RESOURCE_TAGS", "")
        if tags_raw:
            for pair in str(tags_raw).split("|"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    f_mapped["Tags"][k] = v
                    
        # Match resource
        matched_resource, attr_method = match_resource(f_mapped, manifest_resources, scan_id)
        
        # Determine Severity
        prowler_sev = f.get("SEVERITY", "UNKNOWN")
        norm_sev = "UNKNOWN"
        sev_source = "UNKNOWN"
        
        if reg_info.get("severity"):
            norm_sev = _normalize_severity(reg_info["severity"])
            sev_source = reg_info.get("severity_source", "LOCAL_REGISTRY")
        else:
            norm_sev = _normalize_severity(prowler_sev)
            sev_source = "PROWLER_METADATA"

        # Determine Standards Mappings
        standards = []
        if reg_info.get("mappings"):
            standards = reg_info["mappings"]
        else:
            # Attempt to extract from Prowler native compliance fields in CSV (format: "AWS-Foundational-Security-Best-Practices v1.0.0, CIS-AWS-Foundations-Benchmark v1.4.0")
            compliance_str = f.get("COMPLIANCE", "")
            if "AWS-Foundational" in compliance_str:
                 standards.append({
                     "name": "AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES",
                     "version": "unknown",
                     "control_id": "unknown", # CSV doesn't expose the exact sub-control easily, fallback to unknown
                     "mapping_source": "PROWLER_METADATA"
                 })
            if "CIS" in compliance_str:
                 standards.append({
                     "name": "CIS_AWS_FOUNDATIONS_BENCHMARK",
                     "version": "unknown",
                     "requirement_id": "unknown",
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
            "title": f.get("CHECK_TITLE", ""),
            "description": f.get("CHECK_TITLE", ""),
            "service": f.get("SERVICE_NAME", ""),
            "region": f.get("REGION", ""),
            "aws_account_id": f.get("ACCOUNT_ID", ""),
            "resource": {
                "resource_id": f.get("RESOURCE_ID", ""),
                "resource_arn": f.get("RESOURCE_ARN", ""),
                "resource_name": f.get("RESOURCE_DETAILS", ""),
                "resource_type": matched_resource.get("terraform_type", "unknown") if matched_resource else "unknown",
                "terraform_address": matched_resource.get("terraform_address", "") if matched_resource else "",
                "deployment_attributed": attr_method in ["RESOURCE_ARN", "RESOURCE_ID", "RESOURCE_NAME", "SCAN_ID_TAG"],
                "attribution_method": attr_method
            },
            "severity": {
                "original": prowler_sev,
                "normalized": norm_sev,
                "source": sev_source
            },
            "canonical_control": reg_info.get("canonical_control", check_id.upper()),
            "standards": standards,
            "remediation": {
                "text": f.get("REMEDIATION_RECOMMENDATION_TEXT", ""),
                "references": [f.get("REMEDIATION_RECOMMENDATION_URL", "")]
            },
            "evidence": {
                "raw_source_file": prowler_ocsf_path.name if prowler_ocsf_path else prowler_csv_path.name,
                "raw_record_reference": f.get("RESOURCE_ID", "")
            },
            "first_observed_at": utc_now_iso(),
            "generated_at": utc_now_iso()
        }
        
        if normalized["resource"]["deployment_attributed"]:
            deployment_findings.append(normalized)
            severity_counts[norm_sev] += 1
        elif attr_method == "ACCOUNT_LEVEL":
            account_context_findings.append(normalized)
        else:
            unmatched_findings.append(normalized)

    out_data = {
        "metadata": {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "total_raw_failures": len(failed_findings),
            "total_unique_findings": unique_findings,
            "total_merged_duplicates": total_merged,
            "severity_counts": severity_counts
        },
        "deployment_findings": deployment_findings,
        "account_context_findings": account_context_findings,
        "unmatched_findings": unmatched_findings
    }
    
    safe_write_json(str(normalized_out_path), out_data)
    
    summary = {
        "scan_id": scan_id,
        "aws_account_id": aws_account_id,
        "region": manifest.get("regions", ["unknown"])[0] if manifest.get("regions") else "unknown",
        "deployed_resources": len(manifest_resources),
        "raw_prowler_failures": len(failed_findings),
        "unique_findings": len(deployment_findings),
        "severity_counts": severity_counts,
        "unmatched_findings_count": len(unmatched_findings),
        "account_findings_count": len(account_context_findings)
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
