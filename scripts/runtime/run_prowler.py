#!/usr/bin/env python3
"""
scripts/runtime/run_prowler.py

Wraps the Prowler CLI execution.
Ensures it runs only against the authorized account, captures stdout/stderr,
and preserves exact command metadata.

Usage:
    python scripts/runtime/run_prowler.py <SCAN_ID>
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

def get_prowler_version() -> str:
    try:
        result = subprocess.run(["prowler", "-v"], capture_output=True, text=True, check=True)
        # prowler -v usually outputs "Prowler 4.x.x ..."
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "UNKNOWN"

def run_prowler_command(name: str, command: list[str], output_dir: Path, prowler_env: dict) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / "stdout.log"
    stderr_path = output_dir / "stderr.log"
    
    start_time = time.time()
    start_iso = utc_now_iso()
    
    print(f"[run_prowler] Executing {name} scan: {' '.join(command)}")
    try:
        with open(stdout_path, "w") as out, open(stderr_path, "w") as err:
            process = subprocess.run(command, stdout=out, stderr=err, env=prowler_env)
            return_code = process.returncode
    except FileNotFoundError:
        print("[run_prowler] ERROR: Prowler executable not found.")
        sys.exit(1)
        
    end_time = time.time()
    duration_secs = round(end_time - start_time, 2)
    
    if return_code == 0:
        status = "SUCCESS_NO_FINDINGS"
    elif return_code == 3:
        status = "SUCCESS_WITH_FINDINGS"
    else:
        status = "EXECUTION_ERROR"
        print(f"[run_prowler] WARNING: {name} scan returned non-zero code {return_code}.")
        
    return {
        "start_time": start_iso,
        "end_time": utc_now_iso(),
        "duration_seconds": duration_secs,
        "return_code": return_code,
        "status": status,
        "command": command
    }

def run_prowler(scan_id: str) -> None:
    runtime_dir = ROOT_DIR / "reports" / "runtime" / scan_id
    manifest_path = runtime_dir / "deployment-resource-manifest.json"
    prowler_base_dir = runtime_dir / "prowler"
    execution_evidence_path = prowler_base_dir / "prowler-execution.json"

    prowler_base_dir.mkdir(parents=True, exist_ok=True)

    print(f"[run_prowler] Starting Prowler scan for SCAN_ID: {scan_id}")

    manifest = safe_read_json(str(manifest_path))
    if not manifest:
        print(f"[run_prowler] ERROR: Deployment manifest not found at {manifest_path}")
        sys.exit(1)

    expected_account_id = manifest.get("aws_account_id")
    aws_region = os.environ.get("AWS_REGION", "us-east-1")

    # Verify AWS Identity
    try:
        sts = boto3.client("sts")
        caller_identity = sts.get_caller_identity()
        actual_account_id = caller_identity.get("Account")
        caller_arn = caller_identity.get("Arn")
    except ClientError as e:
        print(f"[run_prowler] ERROR: AWS Authentication failed: {e}")
        sys.exit(1)

    if expected_account_id and actual_account_id != expected_account_id:
        print(f"[run_prowler] ERROR: Account mismatch! Manifest says {expected_account_id}, but caller is {actual_account_id}")
        sys.exit(1)

    prowler_version = get_prowler_version()
    
    # Save help and list-compliance output for evidence
    help_out = subprocess.run(["prowler", "aws", "--help"], capture_output=True, text=True).stdout
    compliance_out = subprocess.run(["prowler", "aws", "--list-compliance"], capture_output=True, text=True).stdout
    (prowler_base_dir / "prowler-help.txt").write_text(help_out)
    (prowler_base_dir / "prowler-compliance.txt").write_text(compliance_out)

    prowler_env = os.environ.copy()
    prowler_env.pop("AWS_ROLE_ARN", None)
    prowler_env.pop("AWS_WEB_IDENTITY_TOKEN_FILE", None)

    # 1. Primary Scan (Tag Filtered)
    tag_scan_dir = prowler_base_dir / "deployment-tag-scan"
    tag_cmd = [
        "prowler", "aws",
        "--filter-region", aws_region,
        "--resource-tags", f"scan-id={scan_id}", "managed-by=iac-security-framework",
        "--output-modes", "json",
        "--output-directory", str(tag_scan_dir),
        "--no-banner"
    ]
    tag_exec = run_prowler_command("Tag-Filtered", tag_cmd, tag_scan_dir, prowler_env)
    
    # 2. Secondary Scan (ARN Fallback for unsupported tag resources)
    arn_scan_dir = prowler_base_dir / "deployment-arn-scan"
    arn_exec = None
    arn_list = []
    
    for r in manifest.get("resources", []):
        # In a real environment, we'd check if the resource is taggable and was actually tagged
        # For safety, we can collect ARNs of resources that couldn't be tagged.
        if not r.get("taggable", True) and r.get("resource_arn"):
            arn_list.append(r["resource_arn"])
            
    if arn_list:
        arn_cmd = [
            "prowler", "aws",
            "--filter-region", aws_region,
            "--resource-arn", *arn_list,
            "--output-modes", "json",
            "--output-directory", str(arn_scan_dir),
            "--no-banner"
        ]
        # Check command limits if ARN list is huge, but we'll assume it fits for now.
        arn_exec = run_prowler_command("ARN-Fallback", arn_cmd, arn_scan_dir, prowler_env)

    # 3. Account Context Scan
    ctx_scan_dir = prowler_base_dir / "account-context-scan"
    ctx_exec = None
    if os.environ.get("PROWLER_ACCOUNT_CONTEXT_SCAN") == "true":
        ctx_cmd = [
            "prowler", "aws",
            "--filter-region", aws_region,
            "--output-modes", "json",
            "--output-directory", str(ctx_scan_dir),
            "--no-banner"
        ]
        ctx_exec = run_prowler_command("Account-Context", ctx_cmd, ctx_scan_dir, prowler_env)

    evidence = {
        "schema_version": "2.0",
        "scan_id": scan_id,
        "scanner": "prowler",
        "version": prowler_version,
        "scope": "DEPLOYMENT_TAG_FILTER",
        "filters": {
            "region": aws_region,
            "resource_tags": {
                "scan-id": scan_id,
                "managed-by": "iac-security-framework"
            }
        },
        "aws_identity": {
            "account_id": actual_account_id,
            "caller_arn": caller_arn
        },
        "scans": {
            "deployment_tag_scan": tag_exec,
            "deployment_arn_scan": arn_exec,
            "account_context_scan": ctx_exec
        }
    }

    safe_write_json(str(execution_evidence_path), evidence)
    print(f"[run_prowler] Scans completed. Evidence saved to {execution_evidence_path}")

def main():
    parser = argparse.ArgumentParser(description="Run Prowler and capture execution evidence.")
    parser.add_argument("scan_id", help="The unique SCAN_ID")
    args = parser.parse_args()
    run_prowler(args.scan_id)

if __name__ == "__main__":
    main()
