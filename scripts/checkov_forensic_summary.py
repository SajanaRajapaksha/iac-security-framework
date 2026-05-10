"""
scripts/checkov_forensic_summary.py

Generate a forensic summary of the Checkov scan execution.

Reads normalized findings, Terraform validation results, and scan metadata
to produce a comprehensive forensic summary that links all evidence artifacts
through the SCAN_ID.

Environment variables:
    SCAN_ID   — Unique scan identifier
    REPO_URL  — Repository URL (for metadata record)

Input:
    reports/static/<SCAN_ID>/normalized-checkov-findings.json
    reports/static/<SCAN_ID>/terraform-validation.json
    repositories/metadata/<SCAN_ID>/scan-metadata.json

Output:
    reports/static/<SCAN_ID>/checkov-forensic-summary.json
"""

import json
import os
import sys
from datetime import datetime, timezone


def utcnow_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def safe_load_json(path: str, label: str) -> dict:
    """Load a JSON file safely, returning an empty dict on failure."""
    if not os.path.isfile(path):
        print(f"[checkov_forensic_summary] WARNING: {label} not found: {path}")
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        print(f"[checkov_forensic_summary] WARNING: {label} is not a JSON object.")
        return {}
    except json.JSONDecodeError as exc:
        print(f"[checkov_forensic_summary] WARNING: Invalid JSON in {label}: {exc}")
        return {}


def main():
    scan_id = os.environ.get("SCAN_ID", "")
    repo_url = os.environ.get("REPO_URL", "")

    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)

    report_dir = os.path.join("reports", "static", scan_id)
    os.makedirs(report_dir, exist_ok=True)

    # Input paths
    findings_path = os.path.join(report_dir, "normalized-checkov-findings.json")
    validation_path = os.path.join(report_dir, "terraform-validation.json")
    metadata_path = os.path.join("repositories", "metadata", scan_id, "scan-metadata.json")
    output_path = os.path.join(report_dir, "checkov-forensic-summary.json")

    print(f"[checkov_forensic_summary] SCAN_ID = {scan_id}")

    # ---- Load input data ----
    findings_data = safe_load_json(findings_path, "normalized-checkov-findings.json")
    validation_data = safe_load_json(validation_path, "terraform-validation.json")
    metadata_data = safe_load_json(metadata_path, "scan-metadata.json")

    # ---- Extract key metrics ----

    # Normalized findings
    total_findings = findings_data.get("total_failed_checks", 0)
    severity_summary = findings_data.get("severity_summary", {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
    })

    # Scan metadata
    total_terraform_files = metadata_data.get("total_terraform_files", 0)
    repository_integrity_hash = metadata_data.get("repository_integrity_hash", "")
    repo_url_from_meta = metadata_data.get("repo_url", repo_url)
    if not repo_url:
        repo_url = repo_url_from_meta

    # Terraform validation — extract scanned directories
    validation_dirs = validation_data.get("directories", [])
    total_terraform_directories = validation_data.get("total_directories", len(validation_dirs))
    scanned_directories = []
    for d in validation_dirs:
        scanned_directories.append({
            "relative_path": d.get("relative_path", ""),
            "validation_status": "PASS" if all(
                d.get(step, {}).get("status") == "PASS"
                for step in ("fmt", "init", "validate")
            ) else "FAIL",
        })

    # ---- Timestamps for Checkov execution metadata ----
    # We derive execution timing from the normalized findings generation
    # and the forensic summary generation as bracket timestamps.
    started_at = findings_data.get("generated_at", utcnow_iso())
    completed_at = utcnow_iso()

    # Calculate approximate execution duration
    try:
        start_dt = datetime.fromisoformat(started_at)
        end_dt = datetime.fromisoformat(completed_at)
        duration_seconds = round((end_dt - start_dt).total_seconds(), 2)
    except (ValueError, TypeError):
        duration_seconds = 0.0

    # ---- Build forensic summary ----
    summary = {
        "scan_id": scan_id,
        "generated_at": completed_at,
        "repository_url": repo_url,
        "total_terraform_files": total_terraform_files,
        "total_terraform_directories": total_terraform_directories,
        "total_checkov_findings": total_findings,
        "severity_summary": severity_summary,
        "scanned_directories": scanned_directories,
        "repository_integrity_hash": repository_integrity_hash,
        "evidence_note": (
            "This forensic summary links all Checkov static analysis evidence "
            "for the scan identified by SCAN_ID. All Terraform files were hashed "
            "at clone time using SHA256 to preserve evidence integrity. Checkov "
            "findings have been normalized and correlated with file hashes to "
            "enable tamper detection. The repository_integrity_hash provides a "
            "single composite fingerprint for the entire scanned codebase. All "
            "reports generated during this scan can be linked and verified using "
            "the SCAN_ID as the primary evidence chain key."
        ),
        "checkov_execution_metadata": {
            "started_at": started_at,
            "completed_at": completed_at,
            "execution_duration_seconds": duration_seconds,
        },
        "forensic_chain_summary": {
            "scan_id_linkage": (
                f"SCAN_ID '{scan_id}' is the unique identifier that links all "
                "evidence artifacts across the entire pipeline — from repository "
                "cloning through Terraform validation to Checkov security scanning. "
                "Every report, finding, and metadata record is tagged with this "
                "SCAN_ID, enabling full end-to-end traceability."
            ),
            "terraform_hash_integrity": (
                "Every Terraform (.tf) file was hashed using SHA256 immediately "
                "after repository cloning. These hashes serve as forensic evidence "
                "of the exact file content at scan time. Any modification to a file "
                "after scanning would produce a different hash, enabling tamper "
                "detection during forensic investigation."
            ),
            "findings_as_evidence": (
                "Each Checkov finding has been normalized into a structured format "
                "that includes the check ID, severity, affected resource, file path, "
                "and the SHA256 hash of the associated Terraform file. These "
                "findings constitute security evidence documenting IaC "
                "misconfigurations detected at scan time."
            ),
            "report_auditability": (
                "All reports generated during this scan — including raw Checkov "
                "output, normalized findings, Terraform validation results, and "
                "this forensic summary — are stored as structured JSON with UTC "
                "timestamps. They support forensic investigation, compliance "
                "auditing, and security incident response by providing a complete, "
                "timestamped record of the security assessment."
            ),
        },
    }

    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[checkov_forensic_summary] Total findings     = {total_findings}")
    print(f"[checkov_forensic_summary] Total TF files     = {total_terraform_files}")
    print(f"[checkov_forensic_summary] Total TF dirs      = {total_terraform_directories}")
    print(f"[checkov_forensic_summary] Integrity hash     = {repository_integrity_hash[:16]}..." if repository_integrity_hash else "[checkov_forensic_summary] Integrity hash     = (none)")
    print(f"[checkov_forensic_summary] Output             = {output_path}")


if __name__ == "__main__":
    main()
