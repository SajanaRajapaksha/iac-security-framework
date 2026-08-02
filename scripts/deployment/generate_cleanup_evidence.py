#!/usr/bin/env python3
"""
scripts/deployment/generate_cleanup_evidence.py

Compiles cleanup evidence into `terraform-destroy-evidence.json` and generates a SHA-256 hash.
Evaluates final cleanup status.
"""

import argparse
import json
import sys
import os
import hashlib
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

def hash_file(filepath: Path) -> str:
    if not filepath.is_file():
        return ""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def count_lines(filepath: Path) -> int:
    if not filepath.is_file():
        return 0
    count = 0
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    parser.add_argument("--destroy-exit-code", type=int, default=-1)
    parser.add_argument("--destroy-start-time", default="")
    parser.add_argument("--destroy-finish-time", default="")
    args = parser.parse_args()

    scan_id = args.scan_id
    destroy_exit_code = args.destroy_exit_code
    start_time = args.destroy_start_time
    finish_time = args.destroy_finish_time

    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    out_evidence = deploy_dir / "terraform-destroy-evidence.json"
    out_sha256 = deploy_dir / "terraform-destroy-evidence.sha256"

    # Inputs
    pre_destroy_txt = deploy_dir / "pre-destroy-state-addresses.txt"
    post_destroy_txt = deploy_dir / "post-destroy-state-addresses.txt"
    post_tagged_json = deploy_dir / "post-destroy-tagged-resources.json"
    backend_verify_json = deploy_dir / "terraform-backend-verification.json"
    destroy_txt = deploy_dir / "terraform-destroy.txt"

    backend_data = safe_read_json(str(backend_verify_json)) or {}
    tagged_data = safe_read_json(str(post_tagged_json)) or {}
    
    backend_status = backend_data.get("status", "UNKNOWN")
    backend_type = backend_data.get("actual_backend", "unknown")
    state_bucket = backend_data.get("actual_bucket", "unknown")
    state_key = backend_data.get("actual_key", "unknown")
    
    pre_count = count_lines(pre_destroy_txt)
    post_count = count_lines(post_destroy_txt)
    tagged_count = tagged_data.get("resource_count", len(tagged_data.get("resources", []))) if post_tagged_json.is_file() else -1

    # Calculate duration
    duration = 0
    try:
        if start_time and finish_time:
            t1 = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%SZ")
            t2 = datetime.strptime(finish_time, "%Y-%m-%dT%H:%M:%SZ")
            duration = int((t2 - t1).total_seconds())
    except Exception:
        pass

    # Determine status
    if backend_status != "PASS":
        status = "BACKEND_VERIFICATION_FAILED"
    elif pre_count == 0 and tagged_count == 0:
        status = "NOTHING_TO_DESTROY"
    elif destroy_exit_code != 0:
        status = "DESTROY_FAILED"
    elif post_count > 0:
        status = "STATE_NOT_EMPTY"
    elif tagged_count > 0:
        status = "TAGGED_RESOURCES_REMAIN"
    elif tagged_count == -1:
        status = "VERIFICATION_INCOMPLETE"
    else:
        status = "VERIFIED_DESTROYED"

    evidence = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "AWS": {
            "account_id": os.environ.get("AWS_ACCOUNT_ID", "unknown"),
            "region": os.environ.get("AWS_REGION", "unknown"),
        },
        "Terraform backend": {
            "backend_type": backend_type,
            "state_bucket": state_bucket,
            "state_key": state_key
        },
        "Destroy": {
            "destroy_start_time": start_time,
            "destroy_finish_time": finish_time,
            "destroy_duration_seconds": duration,
            "destroy_exit_code": destroy_exit_code
        },
        "Resources": {
            "resources_before_destroy": pre_count,
            "state_resources_after_destroy": post_count,
            "tagged_resources_after_destroy": tagged_count if tagged_count != -1 else 0
        },
        "Verification": {
            "backend_verified": backend_status == "PASS",
            "terraform_state_empty": post_count == 0,
            "tagged_resource_check_completed": tagged_count != -1
        },
        "cleanup_status": status,
        "GitHub": {
            "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
            "workflow": os.environ.get("GITHUB_WORKFLOW", "unknown"),
            "run_id": os.environ.get("GITHUB_RUN_ID", "unknown"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "unknown"),
            "actor": os.environ.get("GITHUB_ACTOR", "unknown"),
            "commit_sha": os.environ.get("GITHUB_SHA", "unknown")
        }
    }

    safe_write_json(str(out_evidence), evidence)
    
    # Hash all evidence files
    hash_manifest = {}
    files_to_hash = [
        "pre-destroy-state-addresses.txt",
        "terraform-destroy.txt",
        "post-destroy-state-addresses.txt",
        "post-destroy-tagged-resources.json",
        "terraform-destroy-evidence.json"
    ]
    
    for f in files_to_hash:
        p = deploy_dir / f
        if p.is_file():
            hash_manifest[f] = hash_file(p)
            
    out_sha256.write_text(json.dumps(hash_manifest, indent=2) + "\n", encoding="utf-8")
    
    print("============================================================")
    print("  CONTROLLED INFRASTRUCTURE CLEANUP")
    print("============================================================")
    print(f"SCAN_ID                    : {scan_id}")
    print(f"AWS Region                 : {evidence['AWS']['region']}")
    print(f"State Bucket               : {state_bucket}")
    print(f"State Key                  : {state_key}")
    print(f"Resources Before Destroy   : {pre_count}")
    print(f"Terraform Destroy Exit     : {destroy_exit_code}")
    print(f"Resources Remaining State  : {post_count}")
    print(f"Tagged Resources Remaining : {tagged_count if tagged_count != -1 else 'N/A'}")
    print(f"Cleanup Status             : {status}")
    print(f"Duration                   : {duration} seconds")
    print("============================================================")

    if status not in ("VERIFIED_DESTROYED", "NOTHING_TO_DESTROY"):
        sys.exit(1)

if __name__ == "__main__":
    main()
