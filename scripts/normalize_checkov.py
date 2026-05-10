"""
scripts/normalize_checkov.py

Normalize raw Checkov findings into forensic-ready structured findings.

Reads the raw Checkov JSON report, extracts failed checks, normalizes each
finding into a standard format, and correlates findings with Terraform file
SHA256 hashes from scan metadata.

Environment variables:
    SCAN_ID — Unique scan identifier

Input:
    reports/static/<SCAN_ID>/checkov-report.json
    repositories/metadata/<SCAN_ID>/scan-metadata.json

Output:
    reports/static/<SCAN_ID>/normalized-checkov-findings.json
"""

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone


def utcnow_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Severity handling
# ---------------------------------------------------------------------------

# Checkov may include severity in check results.  When missing, fall back to
# UNKNOWN.  This mapping is intentionally pass-through — we preserve whatever
# Checkov reports, normalised to upper-case.
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def normalise_severity(raw_severity) -> str:
    """Normalise a severity string from Checkov output.

    Checkov may omit severity entirely or use varying casing.
    Returns one of CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN.
    """
    if not raw_severity or not isinstance(raw_severity, str):
        return "UNKNOWN"
    upper = raw_severity.strip().upper()
    return upper if upper in VALID_SEVERITIES else "UNKNOWN"


# ---------------------------------------------------------------------------
# Category inference
# ---------------------------------------------------------------------------

# Checkov check IDs follow the pattern CKV_<provider>_<number>.  We attempt
# to infer a high-level category from the check name / guideline text.
CATEGORY_KEYWORDS = {
    "encryption":  ["encrypt", "kms", "sse", "ssl", "tls"],
    "networking":  ["security group", "ingress", "egress", "vpc", "subnet",
                    "network", "firewall", "port", "cidr"],
    "iam":         ["iam", "policy", "role", "privilege", "permission",
                    "mfa", "password", "access key"],
    "logging":     ["log", "cloudtrail", "flow log", "audit", "monitor",
                    "guardduty", "cloudwatch"],
    "storage":     ["s3", "bucket", "versioning", "public access", "block"],
    "compute":     ["ec2", "instance", "ami", "launch"],
    "database":    ["rds", "dynamodb", "redshift", "aurora", "database"],
    "general":     [],
}


def infer_category(check_name: str, guideline: str, check_id: str) -> str:
    """Attempt to infer a high-level category from Checkov metadata.

    Returns one of the predefined category strings, or 'general'.
    """
    combined = f"{check_name} {guideline} {check_id}".lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if category == "general":
            continue
        for keyword in keywords:
            if keyword in combined:
                return category
    return "general"


# ---------------------------------------------------------------------------
# File-hash correlation
# ---------------------------------------------------------------------------

def load_file_hash_map(metadata_path: str) -> dict:
    """Load scan metadata and return a mapping of relative_path -> sha256.

    Returns an empty dict if the file cannot be read or parsed.
    """
    if not os.path.isfile(metadata_path):
        print(f"[normalize_checkov] WARNING: Scan metadata not found: {metadata_path}")
        return {}
    try:
        with open(metadata_path, "r") as f:
            data = json.load(f)
        tf_files = data.get("terraform_files", [])
        # Build a lookup keyed on the relative path (as recorded by
        # generate_scan_metadata.py) so we can correlate findings.
        return {entry["relative_path"]: entry["sha256"] for entry in tf_files}
    except (json.JSONDecodeError, KeyError) as exc:
        print(f"[normalize_checkov] WARNING: Failed to parse scan metadata: {exc}")
        return {}


def resolve_file_hash(file_path: str, hash_map: dict) -> str:
    """Resolve the SHA256 hash of a Terraform file from the hash map.

    Checkov reports file paths relative to the scan directory, sometimes
    prefixed with '/'.  We try several normalisation strategies before
    falling back to UNKNOWN.
    """
    if not file_path:
        return "UNKNOWN"

    # Normalise the path from Checkov (strip leading '/' or './')
    clean = file_path.lstrip("/").lstrip("./")

    # Direct match
    if clean in hash_map:
        return hash_map[clean]

    # Try matching just the filename portion (last component)
    basename = os.path.basename(clean)
    for rel_path, sha in hash_map.items():
        if os.path.basename(rel_path) == basename and rel_path.endswith(clean):
            return sha

    # Substring match (e.g. Checkov reports 'modules/network/main.tf'
    # while metadata has 'modules/network/main.tf')
    for rel_path, sha in hash_map.items():
        if rel_path.endswith(clean) or clean.endswith(rel_path):
            return sha

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Main normalisation logic
# ---------------------------------------------------------------------------

def load_checkov_report(report_path: str) -> list:
    """Load and parse the raw Checkov JSON report.

    Checkov can produce either a single dict (one framework) or a list of
    dicts (multiple frameworks).  This function always returns a list.
    """
    if not os.path.isfile(report_path):
        print(f"[normalize_checkov] WARNING: Report file not found: {report_path}")
        return []

    file_size = os.path.getsize(report_path)
    if file_size == 0:
        print("[normalize_checkov] WARNING: Report file is empty.")
        return []

    try:
        with open(report_path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"[normalize_checkov] WARNING: Invalid JSON in report: {exc}")
        return []

    # Checkov may output a single dict or a list of framework result dicts
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data

    print("[normalize_checkov] WARNING: Unexpected report structure.")
    return []


def extract_failed_checks(framework_results: list) -> list:
    """Extract all failed check entries from Checkov framework results."""
    failed = []
    for result in framework_results:
        if not isinstance(result, dict):
            continue
        # Checkov nests results under "results" -> "failed_checks"
        results_block = result.get("results", {})
        if isinstance(results_block, dict):
            checks = results_block.get("failed_checks", [])
            if isinstance(checks, list):
                failed.extend(checks)
    return failed


def normalize_finding(raw: dict, scan_id: str, hash_map: dict) -> dict:
    """Normalize a single Checkov failed check into the framework format."""
    check_id = raw.get("check_id", "UNKNOWN")
    check_name = raw.get("check", raw.get("name", "UNKNOWN"))
    guideline = raw.get("guideline", raw.get("guide", ""))
    file_path = raw.get("file_path", raw.get("repo_file_path", ""))
    resource = raw.get("resource", "UNKNOWN")
    severity = normalise_severity(raw.get("severity"))
    check_result = raw.get("check_result", {})

    # If check_result is a dict, extract the result string
    if isinstance(check_result, dict):
        check_result = check_result.get("result", "FAILED")

    category = infer_category(check_name, guideline, check_id)
    file_hash = resolve_file_hash(file_path, hash_map)

    return {
        "scan_id": scan_id,
        "finding_id": str(uuid.uuid4()),
        "check_id": check_id,
        "check_name": check_name,
        "severity": severity,
        "file_path": file_path,
        "resource": resource,
        "guideline": guideline,
        "category": category,
        "check_result": check_result,
        "terraform_file_sha256": file_hash,
        "finding_generated_at": utcnow_iso(),
    }


def build_severity_summary(findings: list) -> dict:
    """Build a severity summary from normalized findings."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for finding in findings:
        sev = finding.get("severity", "UNKNOWN")
        if sev in summary:
            summary[sev] += 1
        else:
            summary["UNKNOWN"] += 1
    return summary


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    scan_id = os.environ.get("SCAN_ID", "")
    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)

    report_dir = os.path.join("reports", "static", scan_id)
    report_path = os.path.join(report_dir, "checkov-report.json")
    output_path = os.path.join(report_dir, "normalized-checkov-findings.json")
    metadata_path = os.path.join("repositories", "metadata", scan_id, "scan-metadata.json")

    os.makedirs(report_dir, exist_ok=True)

    print(f"[normalize_checkov] SCAN_ID      = {scan_id}")
    print(f"[normalize_checkov] Report       = {report_path}")
    print(f"[normalize_checkov] Metadata     = {metadata_path}")

    # Load Terraform file hash map for correlation
    hash_map = load_file_hash_map(metadata_path)
    print(f"[normalize_checkov] Hash entries = {len(hash_map)}")

    # Load and parse raw Checkov report
    framework_results = load_checkov_report(report_path)
    failed_checks = extract_failed_checks(framework_results)

    print(f"[normalize_checkov] Failed checks found = {len(failed_checks)}")

    # Normalize each failed check
    findings = [normalize_finding(raw, scan_id, hash_map) for raw in failed_checks]

    severity_summary = build_severity_summary(findings)

    output = {
        "scan_id": scan_id,
        "generated_at": utcnow_iso(),
        "source_tool": "checkov",
        "total_failed_checks": len(findings),
        "severity_summary": severity_summary,
        "findings": findings,
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[normalize_checkov] Normalized   = {len(findings)} findings")
    print(f"[normalize_checkov] Severity     = {severity_summary}")
    print(f"[normalize_checkov] Output       = {output_path}")

    # Print a brief per-severity breakdown
    for sev, count in severity_summary.items():
        if count > 0:
            print(f"  {sev}: {count}")


if __name__ == "__main__":
    main()
