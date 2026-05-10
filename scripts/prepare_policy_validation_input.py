"""
scripts/prepare_policy_validation_input.py

Read the combined static analysis evidence and generate two forensic-ready
handoff files for the future policy validation model:

    1. policy-validation-input.json  — clean input for the policy engine
    2. static-analysis-handoff.json  — audit record of the stage transition

This script NEVER exits 1 because of security findings.  Static analysis is
an evidence-collection and risk-classification stage, not an enforcement gate.
The final enforcement decision will happen in the policy validation model
(not yet implemented).

Exit codes:
    0 — success (including when HIGH/CRITICAL findings exist)
    1 — only for true execution errors (missing SCAN_ID, unwritable output)

Environment variables:
    SCAN_ID  — required
    REPO_URL / BRANCH / GITHUB_SHA / GITHUB_RUN_ID — optional context
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

# ---------------------------------------------------------------------------
# Finding normalisation for policy input
# ---------------------------------------------------------------------------

def normalise_finding_for_policy(finding: dict, source_tool: str) -> dict:
    """Reshape a Checkov or Trivy finding into the policy-validation schema."""
    # Start/end line handling — Checkov may not have these, Trivy usually does
    start_line = finding.get("start_line")
    end_line = finding.get("end_line")
    line_range = []
    if start_line is not None and end_line is not None:
        line_range = [start_line, end_line]
    elif start_line is not None:
        line_range = [start_line]

    return {
        "finding_id": finding.get("finding_id", ""),
        "source_tool": source_tool,
        "rule_id": finding.get("check_id", finding.get("rule_id", "")),
        "rule_name": finding.get("check_name", finding.get("rule_name", "")),
        "severity": finding.get("severity", "UNKNOWN"),
        "category": finding.get("category", "general"),
        "resource": finding.get("resource", ""),
        "file_path": finding.get("file_path", ""),
        "line_range": line_range,
        "check_result": finding.get("check_result", finding.get("finding_status", "FAILED")),
        "guideline": finding.get("guideline", ""),
        "terraform_file_sha256": finding.get("terraform_file_sha256"),
        "reason": finding.get("reason", ""),
        "evidence_generated_at": finding.get(
            "finding_generated_at",
            finding.get("evidence_generated_at", ""),
        ),
        "policy_validation_status": "PENDING",
    }

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    scan_id = os.environ.get("SCAN_ID", "")
    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)

    combined_dir = os.path.join("reports", "static", scan_id, "combined")
    evidence_path = os.path.join(combined_dir, "static-analysis-evidence.json")
    policy_input_path = os.path.join(combined_dir, "policy-validation-input.json")
    handoff_path = os.path.join(combined_dir, "static-analysis-handoff.json")

    os.makedirs(combined_dir, exist_ok=True)
    github_meta = collect_github_metadata()

    print(f"[prepare_policy_input] SCAN_ID = {scan_id}")

    # ---- Load combined evidence ----
    evidence = safe_read_json(evidence_path)
    evidence_available = isinstance(evidence, dict)

    if not evidence_available:
        print(f"[prepare_policy_input] WARNING: Evidence file missing or invalid: {evidence_path}")
        evidence = {}

    severity_summary = evidence.get("combined_severity_summary", {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0,
    })
    total_findings = evidence.get("total_static_findings", 0)

    # ---- Risk classification ----
    high_risk = (severity_summary.get("CRITICAL", 0) + severity_summary.get("HIGH", 0)) > 0
    static_risk_status = (
        "HIGH_RISK_FINDINGS_DETECTED" if high_risk else "NO_HIGH_RISK_FINDINGS"
    )
    static_analysis_status = "COMPLETED" if evidence_available else "EVIDENCE_MISSING"

    print(f"[prepare_policy_input] Static analysis  = {static_analysis_status}")
    print(f"[prepare_policy_input] Risk status       = {static_risk_status}")
    print(f"[prepare_policy_input] Total findings    = {total_findings}")
    print(f"[prepare_policy_input] Severity          = {severity_summary}")

    # ---- Normalise findings for policy input ----
    policy_findings = []

    for f in evidence.get("checkov_findings", []):
        policy_findings.append(normalise_finding_for_policy(f, "checkov"))

    for f in evidence.get("trivy_findings", []):
        policy_findings.append(normalise_finding_for_policy(f, "trivy"))

    # ---- Build policy-validation-input.json ----
    policy_input = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "stage": "static_analysis_to_policy_validation",
        "repository_url": github_meta.get("repository_url"),
        "branch": github_meta.get("branch"),
        "commit_sha": github_meta.get("commit_sha"),
        "workflow_run_id": github_meta.get("workflow_run_id"),
        "source_tools": ["checkov", "trivy"],
        "input_source": evidence_path,
        "static_analysis_status": static_analysis_status,
        "static_risk_status": static_risk_status,
        "pipeline_action": "CONTINUE_TO_POLICY_VALIDATION",
        "severity_summary": severity_summary,
        "total_static_findings": total_findings,
        "policy_validation_status": "PENDING",
        "policy_validation_input_ready": evidence_available,
        "findings": policy_findings,
        "forensic_note": (
            "Static analysis findings are preserved and forwarded to the "
            "policy validation model. The pipeline is not blocked at this "
            "stage. HIGH and CRITICAL findings are classified for risk "
            "awareness but do not cause pipeline failure. The final "
            "enforcement decision will be made by the policy validation model."
        ),
    }

    ok1 = safe_write_json(policy_input_path, policy_input)
    print(f"[prepare_policy_input] Policy input      = {policy_input_path} ({'OK' if ok1 else 'FAILED'})")

    # ---- Build static-analysis-handoff.json ----
    handoff = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "handoff_from": "static_analysis",
        "handoff_to": "policy_validation_model",
        "handoff_status": "READY" if evidence_available else "EVIDENCE_MISSING",
        "pipeline_action": "CONTINUE",
        "policy_validation_implemented": False,
        "input_file": policy_input_path,
        "source_evidence_file": evidence_path,
        "total_static_findings": total_findings,
        "severity_summary": severity_summary,
        "high_risk_findings_present": high_risk,
        "repository_url": github_meta.get("repository_url"),
        "branch": github_meta.get("branch"),
        "commit_sha": github_meta.get("commit_sha"),
        "workflow_run_id": github_meta.get("workflow_run_id"),
        "forensic_note": (
            "This handoff record proves that static analysis findings were "
            "preserved before moving to the next pipeline stage. The policy "
            "validation model has not been implemented yet. When implemented, "
            "it will consume the policy-validation-input.json file generated "
            "alongside this handoff record."
        ),
    }

    ok2 = safe_write_json(handoff_path, handoff)
    print(f"[prepare_policy_input] Handoff           = {handoff_path} ({'OK' if ok2 else 'FAILED'})")

    # ---- Summary ----
    print(f"\n{'='*60}")
    print(f"  STATIC ANALYSIS COMPLETE — NON-BLOCKING")
    print(f"  SCAN_ID              = {scan_id}")
    print(f"  Risk status          = {static_risk_status}")
    print(f"  HIGH/CRITICAL        = {severity_summary.get('HIGH', 0) + severity_summary.get('CRITICAL', 0)}")
    print(f"  Total findings       = {total_findings}")
    print(f"  Pipeline action      = CONTINUE_TO_POLICY_VALIDATION")
    print(f"  Policy validation    = PENDING (not yet implemented)")
    print(f"{'='*60}")

    # NEVER exit 1 for security findings — only for write failures
    if not ok1 or not ok2:
        print("[prepare_policy_input] ERROR: Failed to write one or more output files.", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
