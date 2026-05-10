"""
scripts/checkov_scan.py

Run Checkov against the cloned Terraform repository, then normalise the raw
findings into a forensic-ready evidence report.

Pipeline behaviour:
    1. Execute ``checkov -d <clone_dir> -o json`` and capture exit code.
    2. Save raw output to reports/static/<SCAN_ID>/checkov/checkov-results.json
    3. Parse raw results, extract failed checks, enrich each finding with:
       - Local severity mapping (config/severity_mapping.json)
       - SHA-256 hash of the affected Terraform file
       - Unique finding_id (UUID)
       - Full forensic metadata (SCAN_ID, timestamps, GitHub context)
    4. Save evidence to reports/static/<SCAN_ID>/checkov/checkov-evidence.json
    5. Exit 0 regardless of Checkov findings — enforcement is done later.

Environment variables:
    SCAN_ID                    — required
    REPO_URL / BRANCH / GITHUB_SHA / GITHUB_RUN_ID — optional context

Uses only the Python standard library plus the shared utils module.
"""

import json
import os
import subprocess
import sys

# Allow imports from the project root so 'scripts.utils' resolves
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
# Constants
# ---------------------------------------------------------------------------

SEVERITY_MAPPING_PATH = os.path.join("config", "severity_mapping.json")
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def load_severity_mapping(path: str = SEVERITY_MAPPING_PATH) -> dict:
    """Load the local severity-mapping file.

    Returns an empty dict on any error so the script never crashes.
    """
    data = safe_read_json(path)
    if isinstance(data, dict):
        # Strip metadata keys that start with '_'
        return {k: v for k, v in data.items() if not k.startswith("_")}
    return {}


def resolve_severity(native_severity, check_id: str, mapping: dict) -> str:
    """Determine the final severity for a finding.

    Priority:
        1. Native Checkov severity (if present and valid)
        2. Local severity_mapping.json
        3. UNKNOWN
    """
    if native_severity and isinstance(native_severity, str):
        upper = native_severity.strip().upper()
        if upper in VALID_SEVERITIES:
            return upper

    entry = mapping.get(check_id, {})
    mapped = entry.get("severity", "")
    if mapped and isinstance(mapped, str) and mapped.strip().upper() in VALID_SEVERITIES | {"UNKNOWN"}:
        return mapped.strip().upper()

    return "UNKNOWN"

# ---------------------------------------------------------------------------
# File hash helper
# ---------------------------------------------------------------------------

def build_file_hash_map(metadata_path: str) -> dict:
    """Return a mapping of relative_path → SHA-256 from scan-metadata.json."""
    data = safe_read_json(metadata_path)
    if not isinstance(data, dict):
        return {}
    tf_files = data.get("terraform_files", [])
    return {e.get("relative_path", ""): e.get("sha256", "") for e in tf_files if isinstance(e, dict)}


def resolve_file_hash(file_path: str, hash_map: dict, clone_dir: str) -> tuple[str | None, str | None]:
    """Resolve SHA-256 for a Terraform file.

    Tries the pre-computed hash map first, then falls back to computing on
    the fly from the cloned repo.  Returns (hash, warning).
    """
    clean = normalize_path(file_path)

    # Try hash map (various path normalisations)
    for candidate in [clean, file_path]:
        if candidate in hash_map:
            return hash_map[candidate], None
    for rel, sha in hash_map.items():
        if rel.endswith(clean) or clean.endswith(rel):
            return sha, None

    # Fallback — compute from disk
    abs_path = os.path.join(clone_dir, clean)
    computed = sha256_file(abs_path)
    if computed:
        return computed, None

    return None, f"Could not resolve hash for {file_path}"


# ---------------------------------------------------------------------------
# Checkov execution
# ---------------------------------------------------------------------------

def run_checkov(clone_dir: str, output_path: str) -> tuple[int, str]:
    """Execute Checkov and return (exit_code, version_string)."""
    # Capture Checkov version
    version = "unknown"
    try:
        ver_result = subprocess.run(
            ["checkov", "--version"], capture_output=True, text=True, timeout=30,
        )
        version = ver_result.stdout.strip() or ver_result.stderr.strip() or "unknown"
    except Exception:
        pass

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    cmd = [
        "checkov",
        "-d", clone_dir,
        "-o", "json",
        "--output-file-path", os.path.dirname(output_path),
    ]
    cmd_str = " ".join(cmd)
    print(f"[checkov_scan] Command: {cmd_str}")

    started_at = utc_now_iso()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        exit_code = result.returncode
    except subprocess.TimeoutExpired:
        print("[checkov_scan] WARNING: Checkov timed out after 600 seconds.")
        exit_code = -1
    except FileNotFoundError:
        print("[checkov_scan] ERROR: Checkov binary not found. Is it installed?")
        exit_code = -2
    completed_at = utc_now_iso()

    # Checkov writes results_json.json — rename to our expected name
    default_output = os.path.join(os.path.dirname(output_path), "results_json.json")
    if os.path.isfile(default_output):
        os.rename(default_output, output_path)
        print(f"[checkov_scan] Raw report written: {output_path}")
    else:
        print(f"[checkov_scan] WARNING: Expected output not found at {default_output}")
        # Checkov may also write to stdout in some versions — try saving that
        if result and result.stdout:
            try:
                json.loads(result.stdout)
                with open(output_path, "w") as f:
                    f.write(result.stdout)
                print(f"[checkov_scan] Saved stdout output to {output_path}")
            except (json.JSONDecodeError, UnboundLocalError):
                safe_write_json(output_path, {"error": "Checkov produced no parseable output", "exit_code": exit_code})

    return exit_code, version

# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def extract_framework_results(raw) -> list[dict]:
    """Normalise raw Checkov JSON into a list of framework result dicts."""
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    return []


def extract_summary(framework_results: list[dict]) -> dict:
    """Build an aggregate passed/failed/skipped/parsing summary."""
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    parsing_errors = 0
    for fr in framework_results:
        summary = fr.get("summary", {})
        if isinstance(summary, dict):
            total_passed += summary.get("passed", 0)
            total_failed += summary.get("failed", 0)
            total_skipped += summary.get("skipped", 0)
            parsing_errors += summary.get("parsing_errors", 0)
    return {
        "total_passed": total_passed,
        "total_failed": total_failed,
        "total_skipped": total_skipped,
        "parsing_errors": parsing_errors,
    }


def extract_failed_checks(framework_results: list[dict]) -> list[dict]:
    """Collect all failed check entries from framework results."""
    failed = []
    for fr in framework_results:
        results_block = fr.get("results", {})
        if isinstance(results_block, dict):
            checks = results_block.get("failed_checks", [])
            if isinstance(checks, list):
                failed.extend(checks)
    return failed


def normalise_finding(
    raw: dict,
    scan_id: str,
    mapping: dict,
    hash_map: dict,
    clone_dir: str,
    github_meta: dict,
) -> dict:
    """Transform a single raw Checkov failed check into a forensic finding."""
    check_id = raw.get("check_id", "UNKNOWN")
    # Use check name from the raw finding first
    check_name = raw.get("check_name") or raw.get("check") or raw.get("name", "UNKNOWN")
    native_severity = raw.get("severity")
    file_path = raw.get("file_path", raw.get("repo_file_path", ""))
    resource = raw.get("resource", "UNKNOWN")
    guideline = raw.get("guideline", raw.get("guide", ""))

    check_result = raw.get("check_result", {})
    if isinstance(check_result, dict):
        check_result = check_result.get("result", "FAILED")

    # Severity resolution: native > mapping > UNKNOWN
    severity = resolve_severity(native_severity, check_id, mapping)

    # Mapping enrichment
    map_entry = mapping.get(check_id, {})
    category = map_entry.get("category", "general")
    reason = map_entry.get("reason", "")
    enforcement = map_entry.get("enforcement", "")

    # File hash
    file_hash, evidence_warning = resolve_file_hash(file_path, hash_map, clone_dir)

    finding = {
        "scan_id": scan_id,
        "finding_id": generate_finding_id(),
        "check_id": check_id,
        "check_name": check_name,
        "severity": severity,
        "native_checkov_severity": native_severity,
        "severity_source": "checkov" if (native_severity and native_severity.strip().upper() in VALID_SEVERITIES) else ("mapping" if severity != "UNKNOWN" else "none"),
        "category": category,
        "reason": reason,
        "enforcement": enforcement,
        "file_path": file_path,
        "resource": resource,
        "guideline": guideline,
        "check_result": check_result,
        "terraform_file_sha256": file_hash,
        "finding_generated_at": utc_now_iso(),
        "repository_url": github_meta.get("repository_url"),
        "branch": github_meta.get("branch"),
        "commit_sha": github_meta.get("commit_sha"),
    }
    if evidence_warning:
        finding["evidence_warning"] = evidence_warning
    return finding


def build_severity_summary(findings: list[dict]) -> dict:
    """Count findings per severity level."""
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
    metadata_path = os.path.join("repositories", "metadata", scan_id, "scan-metadata.json")
    raw_output_dir = os.path.join("reports", "static", scan_id, "checkov")
    raw_report_path = os.path.join(raw_output_dir, "checkov-results.json")
    evidence_path = os.path.join(raw_output_dir, "checkov-evidence.json")

    os.makedirs(raw_output_dir, exist_ok=True)

    github_meta = collect_github_metadata()

    print(f"[checkov_scan] SCAN_ID    = {scan_id}")
    print(f"[checkov_scan] Clone dir  = {clone_dir}")

    # ---- Step 1: Run Checkov ----
    exit_code, checkov_version = run_checkov(clone_dir, raw_report_path)
    print(f"[checkov_scan] Checkov version = {checkov_version}")
    print(f"[checkov_scan] Exit code       = {exit_code}")

    # ---- Step 2: Load raw results ----
    raw = safe_read_json(raw_report_path)
    framework_results = extract_framework_results(raw) if raw else []
    scan_summary = extract_summary(framework_results)
    failed_checks = extract_failed_checks(framework_results)

    print(f"[checkov_scan] Passed  = {scan_summary['total_passed']}")
    print(f"[checkov_scan] Failed  = {scan_summary['total_failed']}")
    print(f"[checkov_scan] Skipped = {scan_summary['total_skipped']}")

    # ---- Step 3: Load enrichment data ----
    mapping = load_severity_mapping()
    hash_map = build_file_hash_map(metadata_path)
    print(f"[checkov_scan] Severity mappings loaded = {len(mapping)}")
    print(f"[checkov_scan] File hash entries         = {len(hash_map)}")

    # ---- Step 4: Normalise findings ----
    findings = [
        normalise_finding(raw_check, scan_id, mapping, hash_map, clone_dir, github_meta)
        for raw_check in failed_checks
    ]
    severity_summary = build_severity_summary(findings)

    # ---- Step 5: Write evidence report ----
    evidence = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "evidence_generated_at": utc_now_iso(),
        "scanner": "checkov",
        "scanner_version": checkov_version,
        "scanned_directory": clone_dir,
        "command_executed": f"checkov -d {clone_dir} -o json --output-file-path {raw_output_dir}",
        "exit_code": exit_code,
        "repository_url": github_meta.get("repository_url"),
        "branch": github_meta.get("branch"),
        "commit_sha": github_meta.get("commit_sha"),
        "workflow_run_id": github_meta.get("workflow_run_id"),
        "scan_summary": scan_summary,
        "severity_summary": severity_summary,
        "total_failed_checks": len(findings),
        "findings": findings,
    }

    safe_write_json(evidence_path, evidence)

    print(f"[checkov_scan] Evidence = {evidence_path}")
    print(f"[checkov_scan] Severity = {severity_summary}")

    # Always exit 0 — enforcement is handled by enforce_static_policy.py
    sys.exit(0)


if __name__ == "__main__":
    main()
