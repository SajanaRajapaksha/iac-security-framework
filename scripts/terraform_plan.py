"""
scripts/terraform_plan.py

Generate Terraform plan JSON safely without deploying infrastructure.

Pipeline behaviour:
    1. Locate the cloned Terraform repository under repositories/cloned/<SCAN_ID>/
    2. Run: terraform init -backend=false -input=false -no-color
    3. Run: terraform plan -refresh=false -input=false -no-color -out=tfplan
    4. Run: terraform show -json tfplan
    5. Save the JSON plan to reports/policy/<SCAN_ID>/terraform-plan.json
    6. Save command metadata to reports/policy/<SCAN_ID>/terraform-plan-metadata.json

Static-scan friendly:
    -backend=false  avoids connecting to remote backends (S3, etc.)
    -refresh=false  avoids refreshing real cloud infrastructure state

NEVER runs terraform apply.  NEVER deploys cloud resources.

Environment variables:
    SCAN_ID — required
    REPO_URL / BRANCH / GITHUB_SHA / GITHUB_RUN_ID — optional context
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.utils.evidence import (
    utc_now_iso,
    sha256_file,
    safe_write_json,
    collect_github_metadata,
)


# ---------------------------------------------------------------------------
# Command runner with forensic capture
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str], cwd: str, timeout: int = 300) -> dict:
    """Execute a command and return a forensic metadata dict."""
    started_at = utc_now_iso()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout,
        )
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired:
        exit_code = -1
        stdout = ""
        stderr = f"Command timed out after {timeout}s"
    except FileNotFoundError:
        exit_code = -2
        stdout = ""
        stderr = f"Binary not found: {cmd[0]}"
    except Exception as exc:
        exit_code = -3
        stdout = ""
        stderr = str(exc)
    completed_at = utc_now_iso()

    return {
        "command": " ".join(cmd),
        "working_directory": cwd,
        "started_at": started_at,
        "completed_at": completed_at,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    }


def get_terraform_version() -> str:
    """Capture the Terraform version string."""
    try:
        r = subprocess.run(
            ["terraform", "version", "-json"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            data = json.loads(r.stdout)
            return data.get("terraform_version", r.stdout.strip())
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["terraform", "version"],
            capture_output=True, text=True, timeout=30,
        )
        return r.stdout.strip().split("\n")[0]
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_plan(scan_id: str) -> tuple[bool, str]:
    """Generate Terraform plan JSON.

    Returns (success: bool, plan_json_path: str).
    Also writes terraform-plan-metadata.json regardless of success.
    """
    clone_dir = os.path.join("repositories", "cloned", scan_id)
    report_dir = os.path.join("reports", "policy", scan_id)
    plan_json_path = os.path.join(report_dir, "terraform-plan.json")
    metadata_path = os.path.join(report_dir, "terraform-plan-metadata.json")

    os.makedirs(report_dir, exist_ok=True)

    github_meta = collect_github_metadata()
    tf_version = get_terraform_version()
    commands_executed = []
    overall_started = utc_now_iso()
    status = "PASS"
    error_message = None

    print(f"[terraform_plan] SCAN_ID    = {scan_id}")
    print(f"[terraform_plan] Clone dir  = {clone_dir}")
    print(f"[terraform_plan] TF version = {tf_version}")

    # Check clone dir exists
    if not os.path.isdir(clone_dir):
        status = "FAIL"
        error_message = f"Cloned repository directory not found: {clone_dir}"
        print(f"[terraform_plan] ERROR: {error_message}")
        _write_metadata(metadata_path, scan_id, clone_dir, plan_json_path,
                        commands_executed, status, error_message,
                        github_meta, tf_version, overall_started)
        return False, plan_json_path

    # Step 1: terraform init -backend=false (no remote state connection)
    print("[terraform_plan] Running: terraform init -backend=false -input=false -no-color")
    init_cmd = run_cmd(
        ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
        cwd=clone_dir,
    )
    commands_executed.append(init_cmd)
    if init_cmd["exit_code"] != 0:
        status = "FAIL"
        error_message = f"terraform init failed (exit {init_cmd['exit_code']})"
        print(f"[terraform_plan] ERROR: {error_message}")
        print(f"[terraform_plan] stderr: {init_cmd['stderr'][-2000:]}")
        _write_metadata(metadata_path, scan_id, clone_dir, plan_json_path,
                        commands_executed, status, error_message,
                        github_meta, tf_version, overall_started)
        return False, plan_json_path

    # Step 2: terraform plan -refresh=false (no cloud state refresh)
    print("[terraform_plan] Running: terraform plan -refresh=false -input=false -no-color -out=tfplan")
    plan_cmd = run_cmd(
        ["terraform", "plan", "-refresh=false", "-input=false", "-no-color", "-out=tfplan"],
        cwd=clone_dir,
    )
    commands_executed.append(plan_cmd)
    if plan_cmd["exit_code"] != 0:
        status = "FAIL"
        error_message = f"terraform plan failed (exit {plan_cmd['exit_code']})"
        print(f"[terraform_plan] ERROR: {error_message}")
        print(f"[terraform_plan] stderr: {plan_cmd['stderr'][-2000:]}")
        _write_metadata(metadata_path, scan_id, clone_dir, plan_json_path,
                        commands_executed, status, error_message,
                        github_meta, tf_version, overall_started)
        return False, plan_json_path

    # Step 3: terraform show -json
    print("[terraform_plan] Running: terraform show -json tfplan")
    show_cmd = run_cmd(
        ["terraform", "show", "-json", "tfplan"],
        cwd=clone_dir,
    )
    commands_executed.append(show_cmd)
    if show_cmd["exit_code"] != 0:
        status = "FAIL"
        error_message = f"terraform show -json failed (exit {show_cmd['exit_code']})"
        print(f"[terraform_plan] ERROR: {error_message}")
        print(f"[terraform_plan] stderr: {show_cmd['stderr'][-2000:]}")
        _write_metadata(metadata_path, scan_id, clone_dir, plan_json_path,
                        commands_executed, status, error_message,
                        github_meta, tf_version, overall_started)
        return False, plan_json_path

    # Write plan JSON
    try:
        with open(plan_json_path, "w") as f:
            f.write(show_cmd["stdout"])
        # Validate it is actual JSON
        json.loads(show_cmd["stdout"])
        print(f"[terraform_plan] Plan JSON  = {plan_json_path}")
    except (json.JSONDecodeError, OSError) as exc:
        status = "FAIL"
        error_message = f"Failed to write/parse plan JSON: {exc}"
        print(f"[terraform_plan] ERROR: {error_message}")
        _write_metadata(metadata_path, scan_id, clone_dir, plan_json_path,
                        commands_executed, status, error_message,
                        github_meta, tf_version, overall_started)
        return False, plan_json_path

    # Success
    _write_metadata(metadata_path, scan_id, clone_dir, plan_json_path,
                    commands_executed, status, error_message,
                    github_meta, tf_version, overall_started)
    return True, plan_json_path


def _write_metadata(
    metadata_path: str,
    scan_id: str,
    clone_dir: str,
    plan_json_path: str,
    commands: list,
    status: str,
    error_message: str | None,
    github_meta: dict,
    tf_version: str,
    started_at: str,
):
    """Always write terraform-plan-metadata.json — even on failure."""
    plan_hash = sha256_file(plan_json_path)

    metadata = {
        "scan_id": scan_id,
        "stage": "terraform_plan_generation",
        "started_at": started_at,
        "completed_at": utc_now_iso(),
        "status": status,
        "cloned_repository_path": clone_dir,
        "output_plan_json_path": plan_json_path,
        "terraform_plan_sha256": plan_hash,
        "terraform_version": tf_version,
        "commands_executed": commands,
        "github_metadata": {
            "repo_url": github_meta.get("repository_url"),
            "branch": github_meta.get("branch"),
            "commit_sha": github_meta.get("commit_sha"),
            "github_run_id": github_meta.get("workflow_run_id"),
        },
        "error_message": error_message,
        "forensic_note": (
            "Terraform plan was generated with -backend=false (no remote state) "
            "and -refresh=false (no cloud infrastructure refresh) to support "
            "static/pre-deployment scanning without requiring live cloud access."
        ),
    }

    safe_write_json(metadata_path, metadata)
    print(f"[terraform_plan] Metadata   = {metadata_path}")
    print(f"[terraform_plan] Status     = {status}")


def main():
    scan_id = os.environ.get("SCAN_ID", "")
    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)

    success, _ = generate_plan(scan_id)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
