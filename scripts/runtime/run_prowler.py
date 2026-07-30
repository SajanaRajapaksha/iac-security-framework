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

def run_prowler(scan_id: str) -> None:
    runtime_dir = ROOT_DIR / "reports" / "runtime" / scan_id
    scope_dir = runtime_dir / "scope"
    prowler_dir = runtime_dir / "prowler"
    prowler_raw_dir = prowler_dir / "raw"
    
    scope_dir.mkdir(parents=True, exist_ok=True)
    prowler_dir.mkdir(parents=True, exist_ok=True)
    prowler_raw_dir.mkdir(parents=True, exist_ok=True)

    print(f"[run_prowler] Starting Prowler scan for SCAN_ID: {scan_id}")

    aws_region = os.environ.get("AWS_REGION", "us-east-1")

    # 1. Verify AWS Identity
    try:
        sts = boto3.client("sts", region_name=aws_region)
        caller_identity = sts.get_caller_identity()
        actual_account_id = caller_identity.get("Account")
        caller_arn = caller_identity.get("Arn")
    except ClientError as e:
        print(f"[run_prowler] ERROR: AWS Authentication failed: {e}")
        sys.exit(1)

    # 2. Verify tagged resources exist before scanning
    print("[run_prowler] Discovering tagged resources via AWS Resource Groups Tagging API...")
    try:
        tag_client = boto3.client("resourcegroupstaggingapi", region_name=aws_region)
        response = tag_client.get_resources(
            TagFilters=[
                {"Key": "scan-id", "Values": [scan_id]},
                {"Key": "managed-by", "Values": ["iac-security-framework"]}
            ]
        )
        resources = response.get("ResourceTagMappingList", [])
    except ClientError as e:
        print(f"[run_prowler] ERROR: Failed to fetch tagged resources: {e}")
        sys.exit(1)

    tagged_resources_path = scope_dir / "tagged-resources.json"
    safe_write_json(str(tagged_resources_path), response)
    
    resource_count = len(resources)
    print(f"Tagged resources discovered for SCAN_ID: {resource_count}")

    if resource_count == 0:
        print(f"[run_prowler] SCAN_SCOPE_EMPTY:\nNo live AWS resources were discovered with:\nscan-id={scan_id}\nmanaged-by=iac-security-framework")
        # Write operational evidence
        normalized_dir = runtime_dir / "normalized"
        normalized_dir.mkdir(parents=True, exist_ok=True)
        op_error = {
            "scan_id": scan_id,
            "classification": "OPERATIONAL_ERROR",
            "code": "SCAN_SCOPE_EMPTY",
            "message": f"No live AWS resources were discovered with scan-id={scan_id}",
            "security_conclusion_available": False
        }
        safe_write_json(str(normalized_dir / "runtime-operational-error.json"), op_error)
        sys.exit(1)

    # 3. Build Prowler command
    command = [
        "prowler", "aws",
        "--filter-region", aws_region,
        "--resource-tags", f"scan-id={scan_id}", "managed-by=iac-security-framework",
        "--output-modes", "json-ocsf",
        "--output-directory", str(prowler_raw_dir),
        "--no-banner"
    ]

    print(f"[run_prowler] Executing: {' '.join(command)}")

    start_time = time.time()
    start_iso = utc_now_iso()

    stdout_path = prowler_dir / "stdout.log"
    stderr_path = prowler_dir / "stderr.log"

    prowler_env = os.environ.copy()
    prowler_env.pop("AWS_ROLE_ARN", None)
    prowler_env.pop("AWS_WEB_IDENTITY_TOKEN_FILE", None)

    # 4. Capture Prowler execution
    try:
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=prowler_env)
        return_code = process.returncode
        stdout_path.write_text(process.stdout or "")
        stderr_path.write_text(process.stderr or "")
    except FileNotFoundError:
        print("[run_prowler] ERROR: Prowler executable not found.")
        sys.exit(1)

    end_time = time.time()
    duration_secs = round(end_time - start_time, 2)

    # 5. Handle Exit Codes
    if return_code == 0:
        status = "SUCCESS_NO_FINDINGS"
    elif return_code == 3:
        status = "SUCCESS_WITH_FINDINGS"
    else:
        status = "EXECUTION_ERROR"

    if status == "EXECUTION_ERROR":
        print(f"[run_prowler] ERROR: Prowler returned exit code {return_code}")
        if process.stderr:
            print("[run_prowler] Prowler stderr:")
            print(process.stderr)

    import botocore
    
    # 6. Create Execution Evidence
    evidence = {
        "schema_version": "2.0",
        "scan_id": scan_id,
        "scanner": "prowler",
        "version": "5.28.1",
        "scan_scope": "TAGGED_DEPLOYMENT_RESOURCES_ONLY",
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
        "dependencies": {
            "python": sys.version.split(" ")[0],
            "boto3": boto3.__version__,
            "botocore": botocore.__version__
        },
        "execution": {
            "started_at_utc": start_iso,
            "completed_at_utc": utc_now_iso(),
            "duration_seconds": duration_secs,
            "return_code": return_code,
            "status": status
        },
        "command": command,
        "output_files": [],
        "stdout_sha256": "",
        "stderr_sha256": "",
        "scope_limitations": {
            "account_level_controls_included": False,
            "untaggable_resources_included": False
        }
    }

    evidence_path = prowler_dir / "prowler-execution.json"
    safe_write_json(str(evidence_path), evidence)
    print(f"[run_prowler] Execution evidence saved to {evidence_path}")

    if status == "EXECUTION_ERROR":
        normalized_dir = runtime_dir / "normalized"
        normalized_dir.mkdir(parents=True, exist_ok=True)
        op_error = {
            "scan_id": scan_id,
            "classification": "OPERATIONAL_ERROR",
            "code": "PROWLER_EXECUTION_FAILED",
            "return_code": return_code,
            "message": "Prowler rejected one or more command-line arguments or crashed.",
            "security_conclusion_available": False
        }
        safe_write_json(str(normalized_dir / "runtime-operational-error.json"), op_error)
        raise SystemExit(return_code or 1)

def main():
    parser = argparse.ArgumentParser(description="Run Prowler and capture execution evidence.")
    parser.add_argument("scan_id", help="The unique SCAN_ID")
    args = parser.parse_args()
    run_prowler(args.scan_id)

if __name__ == "__main__":
    main()
