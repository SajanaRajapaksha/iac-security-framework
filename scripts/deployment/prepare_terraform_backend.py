#!/usr/bin/env python3
"""
scripts/deployment/prepare_terraform_backend.py

Inspects the resolved Terraform deployment root for existing backend configurations.
If no backend is defined, generates a framework-specific `iac_framework_backend.tf`
to enforce the S3 backend. If a non-S3 backend exists, it fails.
"""

import argparse
import json
import re
import sys
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import safe_write_json, utc_now_iso

BACKEND_PATTERN = re.compile(r'backend\s+"([^"]+)"')

def detect_backend(deployment_root: Path) -> tuple[str | None, str | None]:
    for p in deployment_root.rglob("*"):
        if not p.is_file():
            continue
            
        if p.name == "iac_framework_backend.tf":
            continue
            
        if p.suffix == ".tf":
            try:
                content = p.read_text(encoding="utf-8")
                # Look for terraform { backend "..."
                match = BACKEND_PATTERN.search(content)
                if match:
                    return match.group(1), p.name
            except Exception:
                pass
                
        elif p.name.endswith(".tf.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                tf_block = data.get("terraform", {})
                if isinstance(tf_block, list) and tf_block:
                    tf_block = tf_block[0]
                
                backend_block = tf_block.get("backend", {}) if isinstance(tf_block, dict) else {}
                if isinstance(backend_block, list) and backend_block:
                    backend_block = backend_block[0]
                
                if isinstance(backend_block, dict) and backend_block:
                    return list(backend_block.keys())[0], p.name
            except Exception:
                pass
                
    return None, None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    parser.add_argument("deployment_root", help="Path to the deployment root")
    args = parser.parse_args()
    
    scan_id = args.scan_id
    deployment_root = Path(args.deployment_root).resolve()
    
    if not deployment_root.is_dir():
        print(f"ERROR: Deployment root not found: {deployment_root}", file=sys.stderr)
        sys.exit(1)
        
    out_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "terraform-backend-preparation.json"
    
    bucket = os.environ.get("TF_STATE_BUCKET", "unknown-bucket")
    region = os.environ.get("AWS_REGION", "unknown-region")
    expected_key = f"research/{scan_id}/terraform.tfstate"
    
    existing_backend, source_file = detect_backend(deployment_root)
    
    status = "PASS"
    generated_file = None
    
    if existing_backend is None:
        generated_file = "iac_framework_backend.tf"
        backend_path = deployment_root / generated_file
        backend_path.write_text("terraform {\n  backend \"s3\" {}\n}\n")
        print("No backend block found. Generated iac_framework_backend.tf with s3 backend.")
    elif existing_backend == "s3":
        print(f"Existing S3 backend detected in {source_file}. Allowing Terraform initialization.")
    else:
        status = "UNSUPPORTED_EXISTING_BACKEND"
        print(f"ERROR: Unsupported existing backend '{existing_backend}' detected in {source_file}. Expected 's3' or none.", file=sys.stderr)
        
    evidence = {
        "scan_id": scan_id,
        "deployment_root": str(deployment_root),
        "expected_backend": "s3",
        "existing_backend_detected": existing_backend is not None,
        "existing_backend_type": existing_backend,
        "framework_backend_file_created": generated_file is not None,
        "framework_backend_filename": generated_file,
        "state_bucket": bucket,
        "state_key": expected_key,
        "region": region,
        "timestamp": utc_now_iso(),
        "status": status
    }
    
    safe_write_json(str(out_file), evidence)
    
    if status != "PASS":
        sys.exit(1)

if __name__ == "__main__":
    main()
