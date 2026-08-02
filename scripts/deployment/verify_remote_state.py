#!/usr/bin/env python3
"""
scripts/deployment/verify_remote_state.py

Runs after successful `terraform apply` to verify that the S3 state object exists
and that Terraform can read it.
"""

import argparse
import json
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import safe_write_json, utc_now_iso

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    parser.add_argument("deployment_root", help="Path to the deployment root")
    args = parser.parse_args()
    
    scan_id = args.scan_id
    deployment_root = Path(args.deployment_root).resolve()
    
    out_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "terraform-remote-state-verification.json"
    
    bucket = os.environ.get("TF_STATE_BUCKET", "unknown")
    expected_key = f"research/{scan_id}/terraform.tfstate"
    
    status = "PASS"
    object_exists = False
    object_size = 0
    last_modified = None
    state_pull_success = False
    resource_count = 0
    
    # 1. AWS CLI verification
    try:
        aws_cmd = [
            "aws", "s3api", "head-object",
            "--bucket", bucket,
            "--key", expected_key,
            "--output", "json"
        ]
        result = subprocess.run(aws_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            object_exists = True
            head_data = json.loads(result.stdout)
            object_size = head_data.get("ContentLength", 0)
            last_modified = head_data.get("LastModified")
        else:
            status = "REMOTE_STATE_MISSING"
    except Exception:
        status = "REMOTE_STATE_MISSING"
        
    # 2. Terraform state pull verification
    if object_exists:
        try:
            tf_cmd = ["terraform", "state", "pull"]
            tf_result = subprocess.run(tf_cmd, cwd=deployment_root, capture_output=True, text=True)
            if tf_result.returncode == 0:
                state_pull_success = True
                state_data = json.loads(tf_result.stdout)
                
                # Count resources
                resources = state_data.get("resources", [])
                resource_count = len(resources)
            else:
                status = "REMOTE_STATE_UNREADABLE"
        except Exception:
            status = "REMOTE_STATE_UNREADABLE"

    evidence = {
        "scan_id": scan_id,
        "bucket": bucket,
        "state_key": expected_key,
        "object_exists": object_exists,
        "object_size": object_size,
        "last_modified": last_modified,
        "state_pull_success": state_pull_success,
        "resource_count": resource_count,
        "verification_status": status
    }
    
    safe_write_json(str(out_file), evidence)
    
    print("============================================================")
    print("  TERRAFORM REMOTE STATE VERIFICATION")
    print("============================================================")
    print(f"SCAN_ID       : {scan_id}")
    print(f"State Bucket  : {bucket}")
    print(f"State Key     : {expected_key}")
    print(f"Exists        : {object_exists}")
    print(f"Size          : {object_size} bytes")
    print(f"Pull Success  : {state_pull_success}")
    print(f"Resources     : {resource_count}")
    print(f"Status        : {status}")
    print("============================================================")
    
    if status != "PASS":
        sys.exit(1)

if __name__ == "__main__":
    main()
