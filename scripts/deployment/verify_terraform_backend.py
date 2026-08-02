#!/usr/bin/env python3
"""
scripts/deployment/verify_terraform_backend.py

Runs after `terraform init` to ensure the configured backend is actually `s3`
and that it points to the correct bucket and scan-specific key.
"""

import argparse
import json
import sys
import os
from pathlib import Path

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
    out_file = out_dir / "terraform-backend-verification.json"
    
    expected_bucket = os.environ.get("TF_STATE_BUCKET")
    expected_region = os.environ.get("AWS_REGION")
    expected_key = f"research/{scan_id}/terraform.tfstate"
    
    tfstate_path = deployment_root / ".terraform" / "terraform.tfstate"
    
    actual_type = None
    actual_bucket = None
    actual_key = None
    actual_region = None
    status = "PASS"
    
    if not expected_bucket:
        status = "EXPECTED_BUCKET_NOT_CONFIGURED"
    elif not expected_region:
        status = "EXPECTED_REGION_NOT_CONFIGURED"
    elif not tfstate_path.is_file():
        status = "MISSING_TERRAFORM_TFSTATE"
    else:
        try:
            data = json.loads(tfstate_path.read_text(encoding="utf-8"))
            backend_block = data.get("backend", {})
            actual_type = backend_block.get("type")
            
            if actual_type == "s3":
                config = backend_block.get("config", {})
                actual_bucket = config.get("bucket")
                actual_key = config.get("key")
                actual_region = config.get("region")
                
                if actual_bucket != expected_bucket:
                    status = "BACKEND_BUCKET_MISMATCH"
                elif actual_key != expected_key:
                    status = "BACKEND_KEY_MISMATCH"
                elif actual_region and actual_region != expected_region:
                    # some TF versions might not enforce region locally in the same way, but if present it should match
                    status = "BACKEND_REGION_MISMATCH"
            else:
                status = "INVALID_BACKEND_TYPE"
                
        except Exception:
            status = "MALFORMED_TFSTATE"

    evidence = {
        "scan_id": scan_id,
        "deployment_root": str(deployment_root),
        "expected_backend": "s3",
        "actual_backend": actual_type,
        "expected_bucket": expected_bucket,
        "actual_bucket": actual_bucket,
        "expected_key": expected_key,
        "actual_key": actual_key,
        "expected_region": expected_region,
        "actual_region": actual_region,
        "timestamp": utc_now_iso(),
        "status": status
    }
    
    safe_write_json(str(out_file), evidence)
    
    print("============================================================")
    print("  TERRAFORM BACKEND VERIFICATION")
    print("============================================================")
    print(f"SCAN_ID       : {scan_id}")
    print(f"Backend Type  : {actual_type if actual_type else 'N/A'}")
    print(f"State Bucket  : {actual_bucket if actual_bucket else 'N/A'}")
    print(f"State Key     : {actual_key if actual_key else 'N/A'}")
    print(f"Status        : {status}")
    print("============================================================")
    
    if status != "PASS":
        sys.exit(1)

if __name__ == "__main__":
    main()
