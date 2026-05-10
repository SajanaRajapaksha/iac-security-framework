"""
scripts/trivy_scan.py

Run Trivy in config-scanning mode against the cloned Terraform repository
and normalise results into a forensic-ready evidence report.

Pipeline behaviour:
    1. Execute ``trivy config --format json`` and capture exit code.
    2. Save raw output to reports/static/<SCAN_ID>/trivy/trivy-results.json
    3. Parse raw results and extract misconfiguration findings.
    4. For each finding compute / attach:
       - SHA-256 of affected Terraform file
       - Unique finding_id (UUID)
       - Full forensic metadata
    5. Save evidence to reports/static/<SCAN_ID>/trivy/trivy-evidence.json
    6. Exit 0 — enforcement is handled by enforce_static_policy.py.

Environment variables:
    SCAN_ID  — required
    REPO_URL / BRANCH / GITHUB_SHA / GITHUB_RUN_ID — optional

Uses only the Python standard library plus the shared utils module.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.utils.evidence import (
    utc_now_iso,
    sha256_file,
    safe_read_json,
    safe_write_json,
    generate_finding_id,
    collect_github_metadata,
    normalize_path,
)

# ---------------------------------------------------------------------------
# Trivy execution
# ---------------------------------------------------------------------------

def run_trivy(target_dir: str, output_path: str) -> tuple[int, str]:
    """Execute ``trivy config`` and return (exit_code, version)."""
    # Capture version
    version = "unknown"
    try:
        ver = subprocess.run(["trivy", "--version"], capture_output=True, text=True, timeout=30)
        # Trivy prints "Version: x.y.z" or just the semver
        for line in (ver.stdout + ver.stderr).splitlines():
            if "version" in line.lower() or line.strip():
                version = line.strip()
                break
    except Exception:
        pass

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    cmd = [
        "trivy", "config",
        "--format", "json",
        "--output", output_path,
        target_dir,
    ]
    cmd_str = " ".join(cmd)
    print(f"[trivy_scan] Command: {cmd_str}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        exit_code = result.returncode
        if result.stderr:
            print(f"[trivy_scan] stderr: {result.stderr[:500]}")
    except subprocess.TimeoutExpired:
        print("[trivy_scan] WARNING: Trivy timed out after 600 seconds.")
        exit_code = -1
    except FileNotFoundError:
        print("[trivy_scan] ERROR: Trivy binary not found. Is it installed?")
        exit_code = -2
        safe_write_json(output_path, {"error": "Trivy not installed", "exit_code": exit_code})

    return exit_code, version

# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def normalise_trivy_finding(
    misconfig: dict,
    target_file: str,
    scan_id: str,
    clone_dir: str,
    github_meta: dict,
) -> dict:
    """Transform a single Trivy misconfiguration into a forensic finding."""
    rule_id = misconfig.get("ID", misconfig.get("id", "UNKNOWN"))
    title = misconfig.get("Title", misconfig.get("title", ""))
    description = misconfig.get("Description", misconfig.get("description", ""))
    message = misconfig.get("Message", misconfig.get("message", ""))
    severity = misconfig.get("Severity", misconfig.get("severity", "UNKNOWN"))
    if isinstance(severity, str):
        severity = severity.strip().upper()
    resolution = misconfig.get("Resolution", misconfig.get("resolution", ""))
    primary_url = misconfig.get("PrimaryURL", misconfig.get("primaryURL", ""))
    status = misconfig.get("Status", misconfig.get("status", "FAIL"))

    # Location info
    cause_metadata = misconfig.get("CauseMetadata", misconfig.get("causeMetadata", {}))
    resource = cause_metadata.get("Resource", cause_metadata.get("resource", ""))
    start_line = cause_metadata.get("StartLine", cause_metadata.get("startLine"))
    end_line = cause_metadata.get("EndLine", cause_metadata.get("endLine"))

    # File hash
    file_path = normalize_path(target_file)
    abs_file = os.path.join(clone_dir, file_path)
    file_hash = sha256_file(abs_file)
    evidence_warning = None
    if file_hash is None:
        evidence_warning = f"Could not compute hash for {file_path}"

    finding = {
        "scan_id": scan_id,
        "finding_id": generate_finding_id(),
        "rule_id": rule_id,
        "rule_name": title,
        "severity": severity,
        "category": "misconfiguration",
        "description": description,
        "message": message,
        "resolution": resolution,
        "guideline": primary_url,
        "file_path": file_path,
        "resource": resource,
        "start_line": start_line,
        "end_line": end_line,
        "finding_status": status,
        "terraform_file_sha256": file_hash,
        "finding_generated_at": utc_now_iso(),
        "repository_url": github_meta.get("repository_url"),
        "branch": github_meta.get("branch"),
        "commit_sha": github_meta.get("commit_sha"),
    }
    if evidence_warning:
        finding["evidence_warning"] = evidence_warning
    return finding


def parse_trivy_results(raw, scan_id: str, clone_dir: str, github_meta: dict) -> list[dict]:
    """Parse the top-level Trivy JSON structure and extract findings."""
    findings = []
    if not raw:
        return findings

    # Trivy wraps results in a "Results" array
    results_list = []
    if isinstance(raw, dict):
        results_list = raw.get("Results", raw.get("results", []))
    elif isinstance(raw, list):
        results_list = raw

    for result_block in results_list:
        if not isinstance(result_block, dict):
            continue
        target = result_block.get("Target", result_block.get("target", ""))
        misconfigs = result_block.get("Misconfigurations", result_block.get("misconfigurations", []))
        if not isinstance(misconfigs, list):
            continue
        for mc in misconfigs:
            if not isinstance(mc, dict):
                continue
            findings.append(
                normalise_trivy_finding(mc, target, scan_id, clone_dir, github_meta)
            )
    return findings


def build_severity_summary(findings: list[dict]) -> dict:
    """Count findings per severity."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        if sev in summary:
            summary[sev] += 1
        else:
            summary["UNKNOWN"] += 1
    return summary

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    scan_id = os.environ.get("SCAN_ID", "")
    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)

    clone_dir = os.path.join("repositories", "cloned", scan_id)
    raw_output_dir = os.path.join("reports", "static", scan_id, "trivy")
    raw_report_path = os.path.join(raw_output_dir, "trivy-results.json")
    evidence_path = os.path.join(raw_output_dir, "trivy-evidence.json")

    os.makedirs(raw_output_dir, exist_ok=True)

    github_meta = collect_github_metadata()

    print(f"[trivy_scan] SCAN_ID   = {scan_id}")
    print(f"[trivy_scan] Clone dir = {clone_dir}")

    # ---- Step 1: Run Trivy ----
    exit_code, trivy_version = run_trivy(clone_dir, raw_report_path)
    print(f"[trivy_scan] Trivy version = {trivy_version}")
    print(f"[trivy_scan] Exit code     = {exit_code}")

    # ---- Step 2: Parse results ----
    raw = safe_read_json(raw_report_path)
    findings = parse_trivy_results(raw, scan_id, clone_dir, github_meta)
    severity_summary = build_severity_summary(findings)

    print(f"[trivy_scan] Findings = {len(findings)}")
    print(f"[trivy_scan] Severity = {severity_summary}")

    # ---- Step 3: Write evidence ----
    evidence = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "evidence_generated_at": utc_now_iso(),
        "scanner": "trivy",
        "scanner_version": trivy_version,
        "scanned_directory": clone_dir,
        "command_executed": f"trivy config --format json --output {raw_report_path} {clone_dir}",
        "exit_code": exit_code,
        "repository_url": github_meta.get("repository_url"),
        "branch": github_meta.get("branch"),
        "commit_sha": github_meta.get("commit_sha"),
        "workflow_run_id": github_meta.get("workflow_run_id"),
        "severity_summary": severity_summary,
        "total_findings": len(findings),
        "findings": findings,
    }

    safe_write_json(evidence_path, evidence)
    print(f"[trivy_scan] Evidence = {evidence_path}")

    # Always exit 0 — enforcement happens later
    sys.exit(0)


if __name__ == "__main__":
    main()
