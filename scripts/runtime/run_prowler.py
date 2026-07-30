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

def run_prowler(scan_id: str) -> None:
    runtime_dir = ROOT_DIR / "reports" / "runtime" / scan_id
    manifest_path = runtime_dir / "deployment-resource-manifest.json"
    prowler_raw_dir = runtime_dir / "prowler" / "raw"
    execution_evidence_path = runtime_dir / "prowler" / "prowler-execution.json"

    prowler_raw_dir.mkdir(parents=True, exist_ok=True)

    print(f"[run_prowler] Starting Prowler scan for SCAN_ID: {scan_id}")

    manifest = safe_read_json(str(manifest_path))
    if not manifest:
        print(f"[run_prowler] ERROR: Deployment manifest not found at {manifest_path}")
        sys.exit(1)

    expected_account_id = manifest.get("aws_account_id")
    if not expected_account_id:
        print("[run_prowler] ERROR: No AWS account ID found in deployment manifest.")
        sys.exit(1)

    # Verify AWS Identity
    try:
        sts = boto3.client("sts")
        caller_identity = sts.get_caller_identity()
        actual_account_id = caller_identity.get("Account")
    except ClientError as e:
        print(f"[run_prowler] ERROR: AWS Authentication failed: {e}")
        sys.exit(1)

    if actual_account_id != expected_account_id:
        print(f"[run_prowler] ERROR: Account mismatch! Manifest says {expected_account_id}, but caller is {actual_account_id}")
        sys.exit(1)

    aws_region = os.environ.get("AWS_REGION", "us-east-1") # Fallback to eu-west-1 if not set

    # Command construction
    # We use json for finding output to easily access compliance mappings
    command = [
        "prowler",
        "aws",
        "-f", aws_region,
        "-M", "csv", "json-ocsf",
        "-O", str(prowler_raw_dir)
    ]

    prowler_version = get_prowler_version()
    start_time = time.time()
    start_iso = utc_now_iso()

    print(f"[run_prowler] Executing: {' '.join(command)}")

    # Run Prowler
    stdout_path = prowler_raw_dir / "stdout.log"
    stderr_path = prowler_raw_dir / "stderr.log"

    # Clean the environment for Prowler to prevent it from manually parsing OIDC variables and crashing
    prowler_env = os.environ.copy()
    prowler_env.pop("AWS_ROLE_ARN", None)
    prowler_env.pop("AWS_WEB_IDENTITY_TOKEN_FILE", None)

    try:
        with open(stdout_path, "w") as out, open(stderr_path, "w") as err:
            process = subprocess.run(command, stdout=out, stderr=err, env=prowler_env)
            return_code = process.returncode
    except FileNotFoundError:
        print("[run_prowler] ERROR: Prowler executable not found. Ensure it is installed in the path.")
        sys.exit(1)

    end_time = time.time()
    end_iso = utc_now_iso()
    duration_secs = round(end_time - start_time, 2)

    # Determine execution status
    # Prowler usually returns 3 if findings are found, 0 if successful with no findings, >0 for errors.
    if return_code == 0:
        status = "SUCCESS_NO_FINDINGS"
    elif return_code == 3:
        status = "SUCCESS_WITH_FINDINGS"
    else:
        status = "EXECUTION_ERROR"
        print(f"[run_prowler] WARNING: Prowler returned non-zero code {return_code}.")
        if stderr_path.exists():
            print(f"[run_prowler] Prowler stderr output:\n{stderr_path.read_text()}")

    evidence = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "scanner": "prowler",
        "version": prowler_version,
        "command": command,
        "execution": {
            "start_time": start_iso,
            "end_time": end_iso,
            "duration_seconds": duration_secs,
            "return_code": return_code,
            "status": status
        }
    }

    safe_write_json(str(execution_evidence_path), evidence)
    print(f"[run_prowler] Scan completed in {duration_secs}s. Status: {status}")
    print(f"[run_prowler] Execution evidence saved to: {execution_evidence_path}")

    # We do NOT exit(1) on SUCCESS_WITH_FINDINGS or EXECUTION_ERROR here because we still want the pipeline 
    # to proceed to normalize what it can, and preserve the evidence.
    # An actual failure that blocks the pipeline is an operational failure like missing credentials.

def main():
    parser = argparse.ArgumentParser(description="Run Prowler and capture execution evidence.")
    parser.add_argument("scan_id", help="The unique SCAN_ID")
    args = parser.parse_args()
    run_prowler(args.scan_id)

if __name__ == "__main__":
    main()
