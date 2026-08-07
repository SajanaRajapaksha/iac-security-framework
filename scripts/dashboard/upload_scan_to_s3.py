#!/usr/bin/env python3
"""
scripts/dashboard/upload_scan_to_s3.py

Uploads raw evidence and dashboard JSON bundles to S3 using boto3.
Uses existing AWS credentials (e.g., from OIDC via AWS_ROLE_ARN).

Usage: python scripts/dashboard/upload_scan_to_s3.py <SCAN_ID>
"""

import argparse
import sys
import boto3
import json
from botocore.exceptions import BotoCoreError, ClientError
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json
from scripts.dashboard.export_dashboard_bundle import EVIDENCE_PATHS

EVIDENCE_BUCKET = "iac-security-framework-evidence-172201861173-us-east-1"

def upload_file_to_s3(s3_client, local_path: Path, bucket: str, s3_key: str) -> bool:
    if not local_path.is_file():
        return False
    try:
        s3_client.upload_file(str(local_path), bucket, s3_key)
        return True
    except (BotoCoreError, ClientError) as e:
        print(f"Error uploading {local_path} to s3://{bucket}/{s3_key}: {e}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    scan_id = args.scan_id

    dashboard_dir = ROOT_DIR / "dashboard-export" / scan_id
    manifest_path = dashboard_dir / "evidence-manifest.json"

    print("============================================================")
    print("DASHBOARD / S3 EVIDENCE EXPORT")
    print("============================================================")
    print(f"SCAN_ID              : {scan_id}")
    print(f"Evidence Bucket      : {EVIDENCE_BUCKET}")
    print("")

    if not manifest_path.is_file():
        print(f"Manifest not found: {manifest_path}. Aborting export.", file=sys.stderr)
        sys.exit(1)

    manifest = safe_read_json(str(manifest_path))
    if not isinstance(manifest, dict) or "artifacts" not in manifest:
        print("Invalid manifest format. Aborting export.", file=sys.stderr)
        sys.exit(1)

    try:
        s3_client = boto3.client('s3')
    except Exception as e:
        print(f"Failed to initialize Boto3 S3 client: {e}", file=sys.stderr)
        sys.exit(1)

    # 1. Upload Raw Evidence
    raw_artifacts = manifest["artifacts"]
    raw_uploaded = 0
    raw_missing = 0
    
    # Check all configured sources and print diagnostics
    print("Evidence Source Diagnostics:")
    found_keys = set()
    for artifact in raw_artifacts:
        # Match original_path to keys
        # We know if it is in manifest it was FOUND
        pass
        
    for key, path_tpl in EVIDENCE_PATHS.items():
        expected_path = ROOT_DIR / path_tpl.format(scan_id=scan_id)
        if expected_path.is_file():
            print(f"[FOUND]   {key}")
            found_keys.add(key)
        else:
            # Check if we should classify as SKIPPED
            # If deployment never happened, deployment files are genuinely missing/skipped
            print(f"[MISSING] {key} (Not generated or unavailable)")
    print("")

    for artifact in raw_artifacts:
        orig_path = ROOT_DIR / artifact["original_path"]
        s3_key = artifact["s3_key"]
        
        if upload_file_to_s3(s3_client, orig_path, EVIDENCE_BUCKET, s3_key):
            raw_uploaded += 1
        else:
            raw_missing += 1

    # 2. Upload Dashboard Files
    dashboard_files = ["scan-summary.json", "findings.json", "evidence-manifest.json"]
    dashboard_uploaded = 0
    
    for d_file in dashboard_files:
        local_path = dashboard_dir / d_file
        s3_key = f"dashboard/{scan_id}/{d_file}"
        if upload_file_to_s3(s3_client, local_path, EVIDENCE_BUCKET, s3_key):
            dashboard_uploaded += 1

    # Print Summary
    # Read findings to count remediation
    findings_data = safe_read_json(str(dashboard_dir / "findings.json"))
    findings = findings_data.get("findings", []) if isinstance(findings_data, dict) else []
    
    ai_remediation_count = 0
    prowler_remediation_count = 0
    no_remediation_count = 0
    
    pre_deployment_count = 0
    post_deployment_count = 0

    for f in findings:
        if f.get("phase") == "PRE_DEPLOYMENT":
            pre_deployment_count += 1
        elif f.get("phase") == "POST_DEPLOYMENT":
            post_deployment_count += 1
            
        rem = f.get("remediation", {})
        if rem.get("available", False):
            if rem.get("source") == "AI_REMEDIATION":
                ai_remediation_count += 1
            elif rem.get("source") == "PROWLER":
                prowler_remediation_count += 1
            else:
                ai_remediation_count += 1 # Default
        else:
            no_remediation_count += 1

    print(f"Raw Artifacts Found  : {len(raw_artifacts)}")
    print(f"Raw Uploaded         : {raw_uploaded}")
    print(f"Raw Failed Uploads   : {raw_missing}")
    print("")
    print(f"Findings Exported    : {len(findings)}")
    print(f"Pre-Deployment       : {pre_deployment_count}")
    print(f"Post-Deployment      : {post_deployment_count}")
    print("")
    print(f"AI Remediation       : {ai_remediation_count}")
    print(f"Prowler Remediation  : {prowler_remediation_count}")
    print(f"No Remediation       : {no_remediation_count}")
    print("")
    print("Dashboard Files:")
    for f in dashboard_files:
        print(f"  {f}")
    print("")
    print("Raw Prefix:")
    print(f"s3://{EVIDENCE_BUCKET}/raw/{scan_id}/")
    print("")
    print("Dashboard Prefix:")
    print(f"s3://{EVIDENCE_BUCKET}/dashboard/{scan_id}/")
    print("")
    
    success = (raw_uploaded > 0) and (dashboard_uploaded == len(dashboard_files))
    print("Export Status:")
    if success:
        print("SUCCESS")
    else:
        print("FAILED (partial or complete failure)")
        sys.exit(1)
    print("============================================================")

if __name__ == "__main__":
    main()
