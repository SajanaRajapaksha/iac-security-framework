"""
scripts/terraform_validate.py

Run terraform fmt -check, terraform init, and terraform validate
against every discovered Terraform directory.

Environment variables:
    SCAN_ID — Unique scan identifier

Input:
    repositories/metadata/<SCAN_ID>/terraform-directories.json

Output:
    reports/static/<SCAN_ID>/terraform-validation/terraform-validation.json
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_command(cmd: list[str], cwd: str) -> dict:
    """Run a command and capture its result as a metadata dict."""
    started_at = utcnow_iso()
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    completed_at = utcnow_iso()
    status = "PASS" if result.returncode == 0 else "FAIL"
    return {
        "command": " ".join(cmd),
        "status": status,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "started_at": started_at,
        "completed_at": completed_at,
    }


def validate_directory(dir_path: str) -> dict:
    """Run fmt, init, validate on a single Terraform directory."""
    fmt_result = run_command(["terraform", "fmt", "-check", "-recursive"], cwd=dir_path)
    init_result = run_command(["terraform", "init", "-backend=false"], cwd=dir_path)
    validate_result = run_command(["terraform", "validate"], cwd=dir_path)
    return {
        "fmt": fmt_result,
        "init": init_result,
        "validate": validate_result,
    }


def main():
    scan_id = os.environ.get("SCAN_ID", "")
    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)

    discovery_file = os.path.join("repositories", "metadata", scan_id, "terraform-directories.json")
    report_dir = os.path.join("reports", "static", scan_id, "terraform-validation")
    report_file = os.path.join(report_dir, "terraform-validation.json")

    os.makedirs(report_dir, exist_ok=True)

    # --- handle missing discovery file ---
    if not os.path.isfile(discovery_file):
        print(f"ERROR: Discovery file not found: {discovery_file}", file=sys.stderr)
        report = {
            "scan_id": scan_id,
            "generated_at": utcnow_iso(),
            "total_directories": 0,
            "overall_status": "FAIL",
            "message": f"Discovery file not found: {discovery_file}",
            "validation_summary": {"passed_directories": 0, "failed_directories": 0},
            "directories": [],
        }
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        sys.exit(1)

    with open(discovery_file, "r") as f:
        discovery = json.load(f)

    tf_dirs = discovery.get("terraform_directories", [])

    # --- handle no Terraform directories ---
    if len(tf_dirs) == 0:
        print("[terraform_validate] No Terraform directories found.", file=sys.stderr)
        report = {
            "scan_id": scan_id,
            "generated_at": utcnow_iso(),
            "total_directories": 0,
            "overall_status": "FAIL",
            "message": "No Terraform directories found",
            "validation_summary": {"passed_directories": 0, "failed_directories": 0},
            "directories": [],
        }
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        sys.exit(1)

    print(f"[terraform_validate] SCAN_ID      = {scan_id}")
    print(f"[terraform_validate] Directories  = {len(tf_dirs)}")

    # --- validate each directory ---
    passed = 0
    failed = 0
    dir_results = []

    for entry in tf_dirs:
        dir_path = entry["path"]
        rel_path = entry["relative_path"]
        print(f"\n[terraform_validate] Validating: {rel_path}")

        results = validate_directory(dir_path)

        # determine directory-level pass/fail
        dir_passed = all(
            results[step]["status"] == "PASS" for step in ("fmt", "init", "validate")
        )

        if dir_passed:
            passed += 1
            print(f"  ✓ {rel_path} — PASS")
        else:
            failed += 1
            for step in ("fmt", "init", "validate"):
                if results[step]["status"] == "FAIL":
                    print(f"  ✗ {rel_path} — {step} FAIL (exit {results[step]['exit_code']})")

        dir_results.append({
            "path": dir_path,
            "relative_path": rel_path,
            **results,
        })

    overall_status = "PASS" if failed == 0 else "FAIL"

    report = {
        "scan_id": scan_id,
        "generated_at": utcnow_iso(),
        "total_directories": len(tf_dirs),
        "overall_status": overall_status,
        "validation_summary": {
            "passed_directories": passed,
            "failed_directories": failed,
        },
        "directories": dir_results,
    }

    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[terraform_validate] Overall   = {overall_status}")
    print(f"[terraform_validate] Passed    = {passed}/{len(tf_dirs)}")
    print(f"[terraform_validate] Failed    = {failed}/{len(tf_dirs)}")
    print(f"[terraform_validate] Report    = {report_file}")

    if overall_status == "FAIL":
        sys.exit(1)


if __name__ == "__main__":
    main()
