"""
scripts/static_analysis_report.py

Generate a combined forensic-ready static analysis report that aggregates
evidence from:
    - Terraform validation
    - Checkov (primary scanner)
    - Trivy config (secondary scanner)
    - Policy-as-Code evidence (if available)

Output:
    reports/static/<SCAN_ID>/combined/static-analysis-evidence.json

Environment variables:
    SCAN_ID  — required
    REPO_URL / BRANCH / GITHUB_SHA / GITHUB_RUN_ID — optional
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.utils.evidence import (
    utc_now_iso,
    safe_read_json,
    safe_write_json,
    collect_github_metadata,
)


def load_or_empty(path: str, label: str) -> dict:
    """Load a JSON file or return a placeholder with a warning."""
    data = safe_read_json(path)
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        return {"results": data}
    print(f"[static_analysis_report] WARNING: {label} not found or invalid: {path}")
    return {"warning": f"{label} not available", "path": path}


def merge_severity(checkov_sev: dict, trivy_sev: dict) -> dict:
    """Merge severity summaries from both scanners."""
    merged = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for sev in merged:
        merged[sev] = checkov_sev.get(sev, 0) + trivy_sev.get(sev, 0)
    return merged


def build_policy_section(scan_id: str) -> dict | None:
    """Load policy evidence and build the policy_as_code report section.

    Returns None if policy evidence does not exist (stage not yet run).
    """
    policy_evidence_path = os.path.join("reports", "policy", scan_id, "policy-evidence.json")
    evidence = safe_read_json(policy_evidence_path)
    if not isinstance(evidence, dict):
        return None

    summary = evidence.get("summary", {})
    return {
        "status": evidence.get("status", "UNKNOWN"),
        "decision": evidence.get("decision", "UNKNOWN"),
        "total_violations": summary.get("total_violations", 0),
        "severity_counts": {
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
        },
        "evidence_path": policy_evidence_path,
        "input_plan_path": os.path.join("reports", "policy", scan_id, "terraform-plan.json"),
        "runner": "Conftest",
        "policy_language": "Rego",
        "policy_engine": "Open Policy Agent",
    }


def main():
    scan_id = os.environ.get("SCAN_ID", "")
    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)

    base_dir = os.path.join("reports", "static", scan_id)
    combined_dir = os.path.join(base_dir, "combined")
    os.makedirs(combined_dir, exist_ok=True)

    github_meta = collect_github_metadata()

    # ---- Load inputs ----
    tf_validation_path = os.path.join(base_dir, "terraform-validation", "terraform-validation.json")
    checkov_evidence_path = os.path.join(base_dir, "checkov", "checkov-evidence.json")
    trivy_evidence_path = os.path.join(base_dir, "trivy", "trivy-evidence.json")

    tf_validation = load_or_empty(tf_validation_path, "terraform-validation.json")
    checkov_evidence = load_or_empty(checkov_evidence_path, "checkov-evidence.json")
    trivy_evidence = load_or_empty(trivy_evidence_path, "trivy-evidence.json")

    # ---- Summaries ----
    checkov_sev = checkov_evidence.get("severity_summary", {})
    trivy_sev = trivy_evidence.get("severity_summary", {})
    combined_severity = merge_severity(checkov_sev, trivy_sev)

    checkov_findings = checkov_evidence.get("findings", [])
    trivy_findings = trivy_evidence.get("findings", [])
    total_findings = len(checkov_findings) + len(trivy_findings)

    # Scanner summary
    scanner_summary = {
        "checkov": {
            "scanner": "checkov",
            "version": checkov_evidence.get("scanner_version", "unknown"),
            "exit_code": checkov_evidence.get("exit_code"),
            "total_findings": len(checkov_findings),
            "severity_summary": checkov_sev,
            "scan_summary": checkov_evidence.get("scan_summary", {}),
        },
        "trivy": {
            "scanner": "trivy",
            "version": trivy_evidence.get("scanner_version", "unknown"),
            "exit_code": trivy_evidence.get("exit_code"),
            "total_findings": len(trivy_findings),
            "severity_summary": trivy_sev,
        },
    }

    # Terraform validation summary
    tf_summary = {
        "overall_status": tf_validation.get("overall_status", "UNKNOWN"),
        "total_directories": tf_validation.get("total_directories", 0),
        "validation_summary": tf_validation.get("validation_summary", {}),
    }

    # ---- Build combined report ----
    report = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "evidence_generated_at": utc_now_iso(),
        "repository_url": github_meta.get("repository_url"),
        "branch": github_meta.get("branch"),
        "commit_sha": github_meta.get("commit_sha"),
        "workflow_run_id": github_meta.get("workflow_run_id"),
        "terraform_validation": tf_summary,
        "total_static_findings": total_findings,
        "combined_severity_summary": combined_severity,
        "scanner_summary": scanner_summary,
        "checkov_findings": checkov_findings,
        "trivy_findings": trivy_findings,
        "evidence_note": (
            "This combined static analysis evidence report aggregates findings "
            "from Checkov (primary IaC scanner) and Trivy config (secondary "
            "scanner). All findings are linked to SCAN_ID for end-to-end "
            "traceability. Each finding includes the SHA-256 hash of the "
            "affected Terraform file, preserving forensic integrity. Severity "
            "enrichment for Checkov uses a local severity mapping file "
            "(config/severity_mapping.json) when native Checkov severity is "
            "unavailable."
        ),
    }

    # ---- Policy-as-Code section (if available) ----
    policy_section = build_policy_section(scan_id)
    if policy_section:
        report["policy_as_code"] = policy_section
        print(f"[static_analysis_report] Policy section   = included (status={policy_section['status']})")
    else:
        print(f"[static_analysis_report] Policy section   = not available (stage not run)")

    output_path = os.path.join(combined_dir, "static-analysis-evidence.json")
    safe_write_json(output_path, report)

    print(f"[static_analysis_report] SCAN_ID           = {scan_id}")
    print(f"[static_analysis_report] Checkov findings  = {len(checkov_findings)}")
    print(f"[static_analysis_report] Trivy findings    = {len(trivy_findings)}")
    print(f"[static_analysis_report] Total findings    = {total_findings}")
    print(f"[static_analysis_report] Combined severity = {combined_severity}")
    print(f"[static_analysis_report] Output            = {output_path}")


if __name__ == "__main__":
    main()

