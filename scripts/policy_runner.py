"""
scripts/policy_runner.py

Run the full Policy-as-Code enforcement stage.

Pipeline behaviour:
    1. Read SCAN_ID, POLICY_ENFORCEMENT_MODE, and POLICY_INPUT_MODE.
    2. Input Mode = SOURCE (Default):
       a. Discover Terraform source files recursively.
       b. Load policy metadata, select enabled policies.
       c. Snapshot enabled policy files.
       d. Run Conftest sequentially against each Terraform file using --parser hcl2.
       e. Normalize and combine policy findings.
    3. Input Mode = PLAN:
       a. Generate Terraform plan JSON (calls terraform_plan.generate_plan).
       b. Load, select, and snapshot policies.
       c. Run Conftest against the plan JSON.
    4. Write forensic-ready policy-evidence.json.
    5. Exit code depends on POLICY_ENFORCEMENT_MODE.

Distinguishes between:
    - Policy violations (Conftest returns findings) → status=FAIL, decision=DENY
    - Tool errors (Conftest cannot run)             → status=ERROR, decision=ERROR
    - Clean pass (no violations)                    → status=PASS, decision=ALLOW

Enforcement modes (POLICY_ENFORCEMENT_MODE env var):
    - advisory  (default) — violations recorded as findings, exit 0
    - blocking            — violations block pipeline, exit 1

Input modes (POLICY_INPUT_MODE env var):
    - source (default) — direct evaluation of .tf files (no AWS credentials required)
    - plan             — evaluation of terraform-plan.json

Environment variables:
    SCAN_ID                  — required
    POLICY_ENFORCEMENT_MODE  — optional (default: advisory)
    POLICY_INPUT_MODE        — optional (default: source)
    REPO_URL / BRANCH / GITHUB_SHA / GITHUB_RUN_ID — optional context
"""

import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.utils.evidence import (
    utc_now_iso,
    sha256_file,
    safe_read_json,
    safe_write_json,
    collect_github_metadata,
)
from scripts.terraform_plan import generate_plan

# ---------------------------------------------------------------------------
# Terraform plan failure diagnostics
# ---------------------------------------------------------------------------

def print_plan_failure_diagnostics(scan_id: str, plan_metadata_path: str):
    """Read plan metadata and print stderr for debugging in CI logs."""
    print(f"[policy_runner] Terraform plan generation failed.")
    print(f"[policy_runner] Check details in: {plan_metadata_path}")

    plan_meta = safe_read_json(plan_metadata_path)
    if not isinstance(plan_meta, dict):
        print(f"[policy_runner] Could not read plan metadata.")
        return

    commands = plan_meta.get("commands_executed", [])
    for cmd in commands:
        if not isinstance(cmd, dict):
            continue
        if cmd.get("exit_code", 0) != 0:
            cmd_str = cmd.get("command", "unknown command")
            stderr = cmd.get("stderr", "")
            print(f"[policy_runner] Failed command: {cmd_str}")
            print(f"[policy_runner] terraform stderr (last 2000 chars):")
            print(stderr[-2000:])
            break
    else:
        # No failed command found — show the error message
        err = plan_meta.get("error_message", "")
        if err:
            print(f"[policy_runner] Error: {err}")


# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str], cwd: str = ".", timeout: int = 300) -> dict:
    """Execute a command and return forensic metadata."""
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


# ---------------------------------------------------------------------------
# Conftest version
# ---------------------------------------------------------------------------

def get_conftest_version() -> str:
    """Capture the Conftest version string."""
    try:
        r = subprocess.run(
            ["conftest", "--version"],
            capture_output=True, text=True, timeout=30,
        )
        return r.stdout.strip() or r.stderr.strip() or "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def discover_terraform_source_files(clone_dir: str) -> list[str]:
    """Recursively find .tf and .tf.json files, ignoring hidden/internal dirs."""
    discovered = []
    ignore_dirs = {".terraform", ".git", "reports"}
    
    for root, dirs, files in os.walk(clone_dir):
        # Modify dirs in-place to skip ignored directories
        dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith(".")]
        
        for file in files:
            if file.endswith(".tf") or file.endswith(".tf.json"):
                discovered.append(os.path.join(root, file))
                
    return sorted(discovered)


# ---------------------------------------------------------------------------
# Policy helpers
# ---------------------------------------------------------------------------

def load_policy_metadata(path: str) -> list[dict]:
    """Load policy-metadata.json."""
    data = safe_read_json(path)
    if isinstance(data, list):
        return data
    return []


def get_enabled_policies(metadata: list[dict]) -> list[dict]:
    """Return only enabled policies."""
    return [p for p in metadata if p.get("enabled", False)]


def snapshot_policies(
    enabled_policies: list[dict],
    source_dir: str,
    runtime_dir: str,
) -> list[dict]:
    """Copy enabled policy files to the runtime snapshot directory."""
    os.makedirs(runtime_dir, exist_ok=True)
    snapshot = []
    copied_files = set()

    for policy in enabled_policies:
        filename = policy.get("file", "")
        source_path = os.path.join(source_dir, filename)
        runtime_path = os.path.join(runtime_dir, filename)

        if filename not in copied_files and os.path.isfile(source_path):
            shutil.copy2(source_path, runtime_path)
            copied_files.add(filename)

        file_hash = sha256_file(runtime_path)

        snapshot.append({
            "policy_id": policy.get("policy_id", ""),
            "name": policy.get("name", ""),
            "version": policy.get("version", 0),
            "severity": policy.get("severity", "UNKNOWN"),
            "action": policy.get("action", "DENY"),
            "enabled": True,
            "source_file": source_path,
            "runtime_file": runtime_path,
            "sha256": file_hash,
            "compliance": policy.get("compliance", []),
        })

    return snapshot


# ---------------------------------------------------------------------------
# Conftest execution
# ---------------------------------------------------------------------------

def run_conftest_plan(plan_json_path: str, policy_dir: str) -> tuple[dict, list]:
    """Run Conftest in plan mode and return (cmd_record, parsed_results)."""
    cmd = [
        "conftest", "test",
        plan_json_path,
        "--policy", policy_dir,
        "--output", "json",
    ]

    cmd_record = run_cmd(cmd)
    cmd_record["input_file"] = plan_json_path
    
    parsed_results = []
    stdout = cmd_record["stdout"]
    if stdout.strip():
        try:
            parsed_results = json.loads(stdout)
        except json.JSONDecodeError:
            pass

    return cmd_record, parsed_results


def run_conftest_source(source_files: list[str], policy_dir: str) -> tuple[list[dict], list]:
    """Run Conftest sequentially per source file.
    
    Returns (list_of_cmd_records, combined_parsed_results).
    """
    cmd_records = []
    combined_results = []
    
    for file_path in source_files:
        cmd = [
            "conftest", "test",
            file_path,
            "--policy", policy_dir,
            "--parser", "hcl2",
            "--output", "json",
        ]
        
        cmd_record = run_cmd(cmd)
        cmd_record["input_file"] = file_path
        cmd_records.append(cmd_record)
        
        stdout = cmd_record["stdout"]
        if stdout.strip():
            try:
                parsed = json.loads(stdout)
                # Conftest usually returns a list of results per test run.
                # Inject the input file into each result block to track origin.
                if isinstance(parsed, list):
                    for block in parsed:
                        if isinstance(block, dict):
                            block["_source_file"] = file_path
                    combined_results.extend(parsed)
            except json.JSONDecodeError:
                pass
                
    return cmd_records, combined_results


# ---------------------------------------------------------------------------
# Results normalisation
# ---------------------------------------------------------------------------

def extract_violations(conftest_results: list, is_source_mode: bool) -> list[dict]:
    """Extract violation entries from Conftest JSON output."""
    violations = []
    if not isinstance(conftest_results, list):
        return violations

    for result_block in conftest_results:
        if not isinstance(result_block, dict):
            continue
            
        source_file = result_block.get("_source_file", "")
        
        failures = result_block.get("failures", [])
        if not isinstance(failures, list):
            continue

        for failure in failures:
            if not isinstance(failure, dict):
                continue

            msg = failure.get("msg", "")
            metadata = failure.get("metadata", {})

            # msg might be a JSON string (structured deny result)
            violation = {}
            if isinstance(msg, str) and msg.strip().startswith("{"):
                try:
                    violation = json.loads(msg)
                except json.JSONDecodeError:
                    violation = {"reason": msg}
            elif isinstance(msg, dict):
                violation = msg
            elif isinstance(metadata, dict) and metadata:
                violation = metadata
                if "reason" not in violation and isinstance(msg, str):
                    violation["reason"] = msg
            else:
                violation = {"reason": str(msg)}
                
            # Inject source tracking for source mode
            if is_source_mode:
                violation["input_file"] = source_file
                if "input_type" not in violation:
                    violation["input_type"] = "terraform_source_hcl"

            violations.append(violation)

    return violations


def build_severity_counts(violations: list[dict]) -> dict:
    """Count violations by severity."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in violations:
        sev = v.get("severity", "").upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts.setdefault("UNKNOWN", 0)
            counts["UNKNOWN"] += 1
    return counts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    scan_id = os.environ.get("SCAN_ID", "")
    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)

    # Enforcement mode
    enforcement_mode_raw = os.environ.get("POLICY_ENFORCEMENT_MODE", "advisory").strip().lower()
    if enforcement_mode_raw not in ("advisory", "blocking"):
        enforcement_mode_raw = "advisory"
    enforcement_mode = enforcement_mode_raw.upper()
    is_blocking = enforcement_mode == "BLOCKING"
    
    # Input mode
    input_mode_raw = os.environ.get("POLICY_INPUT_MODE", "source").strip().lower()
    if input_mode_raw not in ("source", "plan"):
        input_mode_raw = "source"
    input_mode = input_mode_raw.upper()
    is_source_mode = input_mode == "SOURCE"

    overall_started = utc_now_iso()
    clone_dir = os.path.join("repositories", "cloned", scan_id)
    report_dir = os.path.join("reports", "policy", scan_id)
    runtime_policy_dir = os.path.join(report_dir, "runtime-policies")
    conftest_results_path = os.path.join(report_dir, "conftest-results.json")
    evidence_path = os.path.join(report_dir, "policy-evidence.json")
    policy_metadata_source = os.path.join("policies", "terraform", "policy-metadata.json")
    policy_source_dir = os.path.join("policies", "terraform")

    os.makedirs(report_dir, exist_ok=True)

    github_meta = collect_github_metadata()
    commands_executed = []

    print(f"[policy_runner] SCAN_ID             = {scan_id}")
    print(f"[policy_runner] Enforcement mode    = {enforcement_mode}")
    print(f"[policy_runner] Input mode          = {input_mode}")

    # Variables tracking execution context
    plan_json_path = None
    plan_metadata_path = None
    plan_sha256 = None
    source_files_meta = []
    
    # ---- Step 1: Input preparation ----
    if is_source_mode:
        print("[policy_runner] Discovering Terraform source files...")
        if not os.path.isdir(clone_dir):
            print(f"[policy_runner] WARNING: Cloned repo not found: {clone_dir}")
            discovered_files = []
        else:
            discovered_files = discover_terraform_source_files(clone_dir)
            
        print(f"[policy_runner] Discovered files    = {len(discovered_files)}")
        
        for f in discovered_files:
            source_files_meta.append({
                "path": f,
                "sha256": sha256_file(f)
            })
            
        if len(discovered_files) == 0:
            error_msg = "No Terraform source files found to evaluate."
            _write_evidence(
                evidence_path, scan_id, overall_started,
                input_mode=input_mode,
                status="ERROR", decision="ERROR",
                error_message=error_msg,
                github_meta=github_meta,
                policy_metadata_source=policy_metadata_source,
                runtime_policy_dir=runtime_policy_dir,
                policy_snapshot=[], violations=[], commands_executed=[],
                conftest_results_path=conftest_results_path,
                enforcement_mode=enforcement_mode,
                pipeline_blocked=is_blocking,
                actual_exit_code=1 if is_blocking else 0,
                enforcement_reason=error_msg,
                clone_dir=clone_dir,
                source_files_meta=source_files_meta,
            )
            print(f"[policy_runner] ERROR: {error_msg}")
            sys.exit(1 if is_blocking else 0)
            
    else:
        # Plan mode
        print("[policy_runner] Generating Terraform plan JSON...")
        plan_json_path = os.path.join(report_dir, "terraform-plan.json")
        plan_metadata_path = os.path.join(report_dir, "terraform-plan-metadata.json")
        plan_success, _ = generate_plan(scan_id)

        if not plan_success:
            print_plan_failure_diagnostics(scan_id, plan_metadata_path)
            error_msg = "Terraform plan generation failed. See terraform-plan-metadata.json."
            _write_evidence(
                evidence_path, scan_id, overall_started,
                input_mode=input_mode,
                status="ERROR", decision="ERROR",
                error_message=error_msg,
                github_meta=github_meta,
                plan_json_path=plan_json_path, plan_metadata_path=plan_metadata_path,
                policy_metadata_source=policy_metadata_source,
                runtime_policy_dir=runtime_policy_dir,
                policy_snapshot=[], violations=[], commands_executed=[],
                conftest_results_path=conftest_results_path,
                enforcement_mode=enforcement_mode,
                pipeline_blocked=is_blocking,
                actual_exit_code=1 if is_blocking else 0,
                enforcement_reason=error_msg,
                clone_dir=clone_dir,
            )
            print(f"[policy_runner] ERROR: {error_msg}")
            sys.exit(1 if is_blocking else 0)
            
        plan_sha256 = sha256_file(plan_json_path)


    # ---- Step 2: Load and snapshot policies ----
    print("[policy_runner] Loading policy metadata...")
    all_policies = load_policy_metadata(policy_metadata_source)
    enabled = get_enabled_policies(all_policies)
    print(f"[policy_runner] Total policies      = {len(all_policies)}")
    print(f"[policy_runner] Enabled             = {len(enabled)}")

    if len(enabled) == 0:
        print("[policy_runner] WARNING: No enabled policies found.")

    print("[policy_runner] Creating policy snapshot...")
    policy_snapshot = snapshot_policies(enabled, policy_source_dir, runtime_policy_dir)
    metadata_sha256 = sha256_file(policy_metadata_source)


    # ---- Step 3: Run Conftest ----
    conftest_version = get_conftest_version()
    print(f"[policy_runner] Conftest version    = {conftest_version}")
    print("[policy_runner] Running Conftest...")

    if is_source_mode:
        cmds, conftest_results = run_conftest_source(discovered_files, runtime_policy_dir)
        commands_executed.extend(cmds)
        # Check if any command was a tool error (exit code < 0 or > 1)
        is_tool_error = any(c["exit_code"] < 0 or c["exit_code"] > 1 for c in cmds)
        error_stderr = next((c["stderr"] for c in cmds if c["exit_code"] < 0 or c["exit_code"] > 1), "")
    else:
        cmd, conftest_results = run_conftest_plan(plan_json_path, runtime_policy_dir)
        commands_executed.append(cmd)
        is_tool_error = cmd["exit_code"] < 0 or cmd["exit_code"] > 1
        error_stderr = cmd["stderr"]

    # Save raw Conftest results
    safe_write_json(
        conftest_results_path,
        {
            "input_mode": input_mode,
            "results": conftest_results
        }
    )

    # ---- Step 4: Determine status ----
    violations = []
    if not is_tool_error:
        violations = extract_violations(conftest_results, is_source_mode)

    severity_counts = build_severity_counts(violations)

    if is_tool_error:
        status = "ERROR"
        decision = "ERROR"
        error_message = f"Conftest execution error: {error_stderr[:500]}"
    elif len(violations) > 0:
        status = "FAIL"
        decision = "DENY"
        error_message = None
    else:
        status = "PASS"
        decision = "ALLOW"
        error_message = None

    # ---- Step 5: Determine enforcement outcome ----
    if status == "PASS":
        pipeline_blocked = False
        exit_code = 0
        enforcement_reason = "All policies passed. No violations detected."
    elif status == "ERROR":
        pipeline_blocked = is_blocking
        exit_code = 1 if is_blocking else 0
        enforcement_reason = f"Tool error occurred. Pipeline {'blocked' if pipeline_blocked else 'continues (advisory mode)'}."
    else:
        pipeline_blocked = is_blocking
        exit_code = 1 if is_blocking else 0
        if is_blocking:
            enforcement_reason = f"Policy violations detected. Pipeline blocked ({len(violations)} violation(s))."
        else:
            enforcement_reason = f"Policy findings recorded as advisory findings ({len(violations)} violation(s)). Pipeline continues."

    print(f"[policy_runner] Status              = {status}")
    print(f"[policy_runner] Decision            = {decision}")
    print(f"[policy_runner] Violations          = {len(violations)}")
    print(f"[policy_runner] Severity counts     = {severity_counts}")
    print(f"[policy_runner] Pipeline blocked     = {pipeline_blocked}")

    # ---- Step 6: Write evidence ----
    _write_evidence(
        evidence_path, scan_id, overall_started,
        input_mode=input_mode,
        status=status, decision=decision,
        error_message=error_message,
        github_meta=github_meta,
        policy_metadata_source=policy_metadata_source,
        metadata_sha256=metadata_sha256,
        runtime_policy_dir=runtime_policy_dir,
        policy_snapshot=policy_snapshot,
        violations=violations,
        severity_counts=severity_counts,
        commands_executed=commands_executed,
        conftest_results_path=conftest_results_path,
        conftest_version=conftest_version,
        enforcement_mode=enforcement_mode,
        pipeline_blocked=pipeline_blocked,
        actual_exit_code=exit_code,
        enforcement_reason=enforcement_reason,
        clone_dir=clone_dir,
        source_files_meta=source_files_meta,
        plan_json_path=plan_json_path,
        plan_sha256=plan_sha256,
        plan_metadata_path=plan_metadata_path,
    )

    print(f"[policy_runner] Evidence            = {evidence_path}")

    # ---- Step 7: Console output ----
    if status == "FAIL":
        if is_blocking:
            print(f"\n{'='*60}")
            print(f"  POLICY-AS-CODE BLOCKED PIPELINE")
            print(f"  Enforcement mode : {enforcement_mode}")
            print(f"  Decision         : {decision}")
            print(f"  Pipeline blocked : true")
            print(f"  Violations       : {len(violations)}")
            print(f"{'='*60}\n")
        else:
            print(f"\n{'='*60}")
            print(f"  POLICY-AS-CODE FINDINGS RECORDED")
            print(f"  Enforcement mode : {enforcement_mode}")
            print(f"  Decision         : {decision}")
            print(f"  Pipeline blocked : false")
            print(f"  Violations       : {len(violations)}")
            print(f"  Evidence         : {evidence_path}")
            print(f"{'='*60}\n")
    elif status == "ERROR":
        print(f"\n{'='*60}")
        print(f"  POLICY-AS-CODE: ERROR")
        print(f"  Enforcement mode : {enforcement_mode}")
        print(f"  Pipeline blocked : {pipeline_blocked}")
        print(f"  Evidence         : {evidence_path}")
        print(f"{'='*60}\n")
    else:
        print(f"[policy_runner] All policies passed.")
        print(f"[policy_runner] Enforcement mode    = {enforcement_mode}")
        print(f"[policy_runner] Pipeline blocked     = false")

    sys.exit(exit_code)


def _write_evidence(
    evidence_path: str,
    scan_id: str,
    started_at: str,
    *,
    input_mode: str,
    status: str,
    decision: str,
    error_message: str | None,
    github_meta: dict,
    policy_metadata_source: str,
    runtime_policy_dir: str,
    policy_snapshot: list,
    violations: list,
    commands_executed: list,
    conftest_results_path: str,
    clone_dir: str,
    metadata_sha256: str | None = None,
    severity_counts: dict | None = None,
    conftest_version: str = "unknown",
    enforcement_mode: str = "ADVISORY",
    pipeline_blocked: bool = False,
    actual_exit_code: int = 0,
    enforcement_reason: str = "",
    source_files_meta: list | None = None,
    plan_json_path: str | None = None,
    plan_sha256: str | None = None,
    plan_metadata_path: str | None = None,
):
    """Write the policy-evidence.json file."""
    if severity_counts is None:
        severity_counts = build_severity_counts(violations)
        
    is_source = input_mode == "SOURCE"

    evidence = {
        "scan_id": scan_id,
        "stage": "policy_as_code",
        "input_mode": input_mode,
        "toolchain": {
            "policy_engine": "Open Policy Agent",
            "policy_language": "Rego",
            "runner": "Conftest",
            "conftest_version": conftest_version,
        },
        "execution_context": {
            "live_cloud_access_required": False if is_source else True,
            "terraform_plan_required": False if is_source else True,
            "terraform_backend_access_required": False if is_source else True,
            "aws_credentials_required": False if is_source else True,
        },
        "enforcement": {
            "mode": enforcement_mode,
            "pipeline_blocked": pipeline_blocked,
            "exit_code": actual_exit_code,
            "reason": enforcement_reason,
        },
        "started_at": started_at,
        "completed_at": utc_now_iso(),
        "status": status,
        "decision": decision,
        "github_metadata": {
            "repo_url": github_meta.get("repository_url"),
            "branch": github_meta.get("branch"),
            "commit_sha": github_meta.get("commit_sha"),
            "github_run_id": github_meta.get("workflow_run_id"),
        },
        "inputs": {
            "cloned_repository_path": clone_dir,
            "policy_metadata": policy_metadata_source,
            "policy_metadata_sha256": metadata_sha256,
            "runtime_policy_directory": runtime_policy_dir,
        },
        "policy_snapshot": policy_snapshot,
        "summary": {
            "total_violations": len(violations),
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
        },
        "violations": violations,
        "commands_executed": commands_executed,
        "artifacts": {
            "conftest_results": conftest_results_path,
            "policy_evidence": evidence_path,
        },
        "error_message": error_message,
    }
    
    if is_source:
        evidence["inputs"]["terraform_source_files"] = source_files_meta or []
        evidence["inputs"]["terraform_source_file_count"] = len(source_files_meta or [])
        evidence["forensic_note"] = "Source-based Policy-as-Code validation evaluates Terraform source files directly using Conftest HCL2 parsing. It does not run terraform plan and does not require AWS credentials or live cloud access."
    else:
        evidence["inputs"]["terraform_plan_json"] = plan_json_path
        evidence["inputs"]["terraform_plan_sha256"] = plan_sha256
        evidence["artifacts"]["terraform_plan_metadata"] = plan_metadata_path

    safe_write_json(evidence_path, evidence)


if __name__ == "__main__":
    main()
