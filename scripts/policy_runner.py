"""
scripts/policy_runner.py

Run the full Policy-as-Code enforcement stage.

Pipeline behaviour:
    1. Read SCAN_ID and POLICY_ENFORCEMENT_MODE.
    2. Generate Terraform plan JSON (calls terraform_plan.generate_plan).
    3. Load policy metadata, select enabled policies.
    4. Snapshot enabled policy files into reports/policy/<SCAN_ID>/runtime-policies/.
    5. Hash all inputs (plan JSON, policy files, metadata).
    6. Run Conftest against the plan JSON using the runtime policies.
    7. Save raw Conftest output to conftest-results.json.
    8. Normalise into policy-evidence.json.
    9. Exit code depends on POLICY_ENFORCEMENT_MODE.

Distinguishes between:
    - Policy violations (Conftest returns findings) → status=FAIL, decision=DENY
    - Tool errors (Conftest cannot run)             → status=ERROR, decision=ERROR
    - Clean pass (no violations)                    → status=PASS, decision=ALLOW

Enforcement modes (POLICY_ENFORCEMENT_MODE env var):
    - advisory  (default) — violations recorded as findings, exit 0
    - blocking            — violations block pipeline, exit 1

Environment variables:
    SCAN_ID                  — required
    POLICY_ENFORCEMENT_MODE  — optional (default: advisory)
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
    """Copy enabled policy files to the runtime snapshot directory.

    Returns a list of snapshot records with hashes.
    """
    os.makedirs(runtime_dir, exist_ok=True)
    snapshot = []
    # Track which files we've already copied
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

def run_conftest(plan_json_path: str, policy_dir: str) -> tuple[dict, list]:
    """Run Conftest and return (cmd_record, parsed_results).

    Conftest exit code 1 means violations found (not a crash).
    Exit code 2+ or negative means tool error.
    """
    cmd = [
        "conftest", "test",
        plan_json_path,
        "--policy", policy_dir,
        "--output", "json",
    ]

    cmd_record = run_cmd(cmd)
    parsed_results = []

    if cmd_record["exit_code"] == -2:
        # Conftest binary not found
        return cmd_record, []

    # Try to parse stdout as JSON
    stdout = cmd_record["stdout"]
    if stdout.strip():
        try:
            parsed_results = json.loads(stdout)
        except json.JSONDecodeError:
            pass

    return cmd_record, parsed_results


# ---------------------------------------------------------------------------
# Results normalisation
# ---------------------------------------------------------------------------

def extract_violations(conftest_results: list) -> list[dict]:
    """Extract violation entries from Conftest JSON output.

    Conftest output structure:
    [
      {
        "filename": "...",
        "successes": 0,
        "failures": [ { "msg": "...", "metadata": {...} } ],
        "warnings": [...],
        "exceptions": [...]
      }
    ]
    """
    violations = []
    if not isinstance(conftest_results, list):
        return violations

    for result_block in conftest_results:
        if not isinstance(result_block, dict):
            continue
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
        print(f"[policy_runner] WARNING: Unknown POLICY_ENFORCEMENT_MODE='{enforcement_mode_raw}', defaulting to 'advisory'.")
        enforcement_mode_raw = "advisory"
    enforcement_mode = enforcement_mode_raw.upper()  # ADVISORY or BLOCKING
    is_blocking = enforcement_mode == "BLOCKING"

    overall_started = utc_now_iso()
    report_dir = os.path.join("reports", "policy", scan_id)
    runtime_policy_dir = os.path.join(report_dir, "runtime-policies")
    conftest_results_path = os.path.join(report_dir, "conftest-results.json")
    evidence_path = os.path.join(report_dir, "policy-evidence.json")
    plan_json_path = os.path.join(report_dir, "terraform-plan.json")
    plan_metadata_path = os.path.join(report_dir, "terraform-plan-metadata.json")
    policy_metadata_source = os.path.join("policies", "terraform", "policy-metadata.json")
    policy_source_dir = os.path.join("policies", "terraform")

    os.makedirs(report_dir, exist_ok=True)

    github_meta = collect_github_metadata()
    commands_executed = []

    print(f"[policy_runner] SCAN_ID             = {scan_id}")
    print(f"[policy_runner] Enforcement mode    = {enforcement_mode}")

    # ---- Step 1: Generate Terraform plan JSON ----
    print("[policy_runner] Generating Terraform plan JSON...")
    plan_success, plan_path = generate_plan(scan_id)

    if not plan_success:
        print_plan_failure_diagnostics(scan_id, plan_metadata_path)

        pipeline_blocked = is_blocking
        exit_code = 1 if is_blocking else 0

        _write_evidence(
            evidence_path, scan_id, overall_started,
            status="ERROR", decision="ERROR",
            error_message="Terraform plan generation failed. See terraform-plan-metadata.json.",
            github_meta=github_meta,
            plan_json_path=plan_json_path,
            policy_metadata_source=policy_metadata_source,
            runtime_policy_dir=runtime_policy_dir,
            policy_snapshot=[],
            violations=[],
            commands_executed=commands_executed,
            plan_metadata_path=plan_metadata_path,
            conftest_results_path=conftest_results_path,
            enforcement_mode=enforcement_mode,
            pipeline_blocked=pipeline_blocked,
            actual_exit_code=exit_code,
        )

        print(f"\n{'='*60}")
        print(f"  POLICY-AS-CODE: ERROR")
        print(f"  Enforcement mode : {enforcement_mode}")
        print(f"  Pipeline blocked : {pipeline_blocked}")
        print(f"  Evidence         : {evidence_path}")
        print(f"{'='*60}\n")
        sys.exit(exit_code)

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

    # ---- Step 3: Hash inputs ----
    plan_sha256 = sha256_file(plan_json_path)
    metadata_sha256 = sha256_file(policy_metadata_source)

    # ---- Step 4: Run Conftest ----
    conftest_version = get_conftest_version()
    print(f"[policy_runner] Conftest version    = {conftest_version}")
    print("[policy_runner] Running Conftest...")

    conftest_cmd, conftest_results = run_conftest(plan_json_path, runtime_policy_dir)
    commands_executed.append(conftest_cmd)

    # Save raw Conftest results
    safe_write_json(
        conftest_results_path,
        conftest_results if conftest_results else {
            "raw_stdout": conftest_cmd["stdout"],
            "raw_stderr": conftest_cmd["stderr"],
        },
    )

    # ---- Step 5: Determine status ----
    is_tool_error = False
    if conftest_cmd["exit_code"] == -2:
        is_tool_error = True
    elif conftest_cmd["exit_code"] < 0:
        is_tool_error = True
    elif conftest_cmd["exit_code"] > 1:
        # Conftest returns 2 for syntax errors etc.
        is_tool_error = True

    violations = []
    if not is_tool_error:
        violations = extract_violations(conftest_results)

    severity_counts = build_severity_counts(violations)

    if is_tool_error:
        status = "ERROR"
        decision = "ERROR"
        error_message = f"Conftest execution error (exit {conftest_cmd['exit_code']}): {conftest_cmd['stderr'][:500]}"
    elif len(violations) > 0:
        status = "FAIL"
        decision = "DENY"
        error_message = None
    else:
        status = "PASS"
        decision = "ALLOW"
        error_message = None

    # ---- Step 6: Determine enforcement outcome ----
    if status == "PASS":
        pipeline_blocked = False
        exit_code = 0
    elif status == "ERROR":
        pipeline_blocked = is_blocking
        exit_code = 1 if is_blocking else 0
    else:
        # FAIL / DENY
        pipeline_blocked = is_blocking
        exit_code = 1 if is_blocking else 0

    # Build enforcement reason
    if status == "PASS":
        enforcement_reason = "All policies passed. No violations detected."
    elif status == "ERROR":
        enforcement_reason = f"Tool error occurred. Pipeline {'blocked' if pipeline_blocked else 'continues (advisory mode)'}."
    elif is_blocking:
        enforcement_reason = f"Policy violations detected. Pipeline blocked ({len(violations)} violation(s))."
    else:
        enforcement_reason = f"Policy findings recorded as advisory findings ({len(violations)} violation(s)). Pipeline continues."

    print(f"[policy_runner] Status              = {status}")
    print(f"[policy_runner] Decision            = {decision}")
    print(f"[policy_runner] Violations          = {len(violations)}")
    print(f"[policy_runner] Severity counts     = {severity_counts}")
    print(f"[policy_runner] Pipeline blocked     = {pipeline_blocked}")

    # ---- Step 7: Write evidence ----
    _write_evidence(
        evidence_path, scan_id, overall_started,
        status=status, decision=decision,
        error_message=error_message,
        github_meta=github_meta,
        plan_json_path=plan_json_path,
        plan_sha256=plan_sha256,
        policy_metadata_source=policy_metadata_source,
        metadata_sha256=metadata_sha256,
        runtime_policy_dir=runtime_policy_dir,
        policy_snapshot=policy_snapshot,
        violations=violations,
        severity_counts=severity_counts,
        commands_executed=commands_executed,
        plan_metadata_path=plan_metadata_path,
        conftest_results_path=conftest_results_path,
        conftest_version=conftest_version,
        enforcement_mode=enforcement_mode,
        pipeline_blocked=pipeline_blocked,
        actual_exit_code=exit_code,
        enforcement_reason=enforcement_reason,
    )

    print(f"[policy_runner] Evidence            = {evidence_path}")

    # ---- Step 8: Console output ----
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
    status: str,
    decision: str,
    error_message: str | None,
    github_meta: dict,
    plan_json_path: str,
    policy_metadata_source: str,
    runtime_policy_dir: str,
    policy_snapshot: list,
    violations: list,
    commands_executed: list,
    plan_metadata_path: str,
    conftest_results_path: str,
    plan_sha256: str | None = None,
    metadata_sha256: str | None = None,
    severity_counts: dict | None = None,
    conftest_version: str = "unknown",
    enforcement_mode: str = "ADVISORY",
    pipeline_blocked: bool = False,
    actual_exit_code: int = 0,
    enforcement_reason: str = "",
):
    """Write the policy-evidence.json file — always, even on error."""
    if severity_counts is None:
        severity_counts = build_severity_counts(violations)

    evidence = {
        "scan_id": scan_id,
        "stage": "policy_as_code",
        "toolchain": {
            "policy_engine": "Open Policy Agent",
            "policy_language": "Rego",
            "runner": "Conftest",
            "conftest_version": conftest_version,
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
            "terraform_plan_json": plan_json_path,
            "terraform_plan_sha256": plan_sha256,
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
            "terraform_plan_metadata": plan_metadata_path,
            "conftest_results": conftest_results_path,
            "policy_evidence": evidence_path,
        },
        "error_message": error_message,
    }

    safe_write_json(evidence_path, evidence)


if __name__ == "__main__":
    main()
