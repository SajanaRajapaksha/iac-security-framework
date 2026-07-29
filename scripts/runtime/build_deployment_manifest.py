#!/usr/bin/env python3
"""
scripts/runtime/build_deployment_manifest.py

Stage 37 — Creates the authoritative deployment resource manifest for runtime scanning.
It uses the sanitized Terraform state inventory generated during deployment to define
the exact scope of resources that belong to this SCAN_ID.

Usage:
    python scripts/runtime/build_deployment_manifest.py <SCAN_ID>

Output:
    reports/runtime/<SCAN_ID>/deployment-resource-manifest.json
"""

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import (
    safe_read_json,
    safe_write_json,
    utc_now_iso,
    collect_github_metadata,
)

def build_manifest(scan_id: str) -> None:
    deployment_inventory_path = ROOT_DIR / "reports" / "deployment" / scan_id / "terraform-state-resource-inventory.json"
    runtime_dir = ROOT_DIR / "reports" / "runtime" / scan_id
    manifest_out_path = runtime_dir / "deployment-resource-manifest.json"

    print(f"Building deployment manifest for {scan_id}...")

    # Load the sanitized Terraform state inventory
    inventory = safe_read_json(str(deployment_inventory_path))
    if not inventory:
        print(f"[build_deployment_manifest] ERROR: Deployment inventory not found at {deployment_inventory_path}")
        sys.exit(1)

    state_resources = inventory.get("resources", [])
    
    # Extract unique regions from the deployed resources
    regions = set()
    for res in state_resources:
        if res.get("resource_arn") and "arn:aws:" in res["resource_arn"]:
            parts = res["resource_arn"].split(":")
            if len(parts) > 3 and parts[3]:
                regions.add(parts[3])
    
    # We might not have regions explicitly in ARNs for all services (e.g., S3, IAM are global)
    # If empty, we can try to fall back to AWS_REGION env var, but for now just use what's in ARNs.
    import os
    env_region = os.environ.get("AWS_REGION")
    if env_region:
        regions.add(env_region)

    github_meta = collect_github_metadata()
    
    manifest = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "aws_account_id": inventory.get("aws_account_id", ""),
        "regions": sorted(list(regions)),
        "repository": {
            "url": github_meta.get("repository_url", ""),
            "branch": github_meta.get("branch", ""),
            "commit_sha": github_meta.get("commit_sha", "")
        },
        "github": {
            "run_id": github_meta.get("workflow_run_id", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "actor": github_meta.get("actor", "")
        },
        "terraform": {
            "workspace": os.environ.get("TF_WORKSPACE", "default"),
            "state_source": inventory.get("state_key", "unknown"),
            "resource_count": len(state_resources)
        },
        "resources": state_resources
    }

    if safe_write_json(str(manifest_out_path), manifest):
        print(f"Deployment manifest saved to: {manifest_out_path}")
    else:
        print(f"[build_deployment_manifest] ERROR: Failed to save manifest.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Build deployment resource manifest.")
    parser.add_argument("scan_id", help="The unique SCAN_ID")
    args = parser.parse_args()
    build_manifest(args.scan_id)

if __name__ == "__main__":
    main()
