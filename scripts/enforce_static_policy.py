"""
scripts/enforce_static_policy.py

Read the combined static analysis evidence and make an enforcement decision.

Logic:
    - Always generate the enforcement-decision.json before exiting.
    - Fail the pipeline (exit 1) if any finding has severity HIGH or CRITICAL.
    - MEDIUM / LOW / UNKNOWN are recorded but do not fail by default.
    - The threshold is configurable via SECURITY_FAIL_ON_SEVERITIES env var.

Output:
    reports/static/<SCAN_ID>/combined/enforcement-decision.json

Environment variables:
    SCAN_ID                      — required
    SECURITY_FAIL_ON_SEVERITIES  — comma-separated severities that trigger
                                   failure (default: HIGH,CRITICAL)
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
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_FAIL_SEVERITIES = "HIGH,CRITICAL"


def get_fail_severities() -> set[str]:
    """Read the set of severities that should trigger pipeline failure."""
    raw = os.environ.get("SECURITY_FAIL_ON_SEVERITIES", DEFAULT_FAIL_SEVERITIES)
    return {s.strip().upper() for s in raw.split(",") if s.strip()}


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
    decision_path = os.path.join(combined_dir, "enforcement-decision.json")

    os.makedirs(combined_dir, exist_ok=True)
    github_meta = collect_github_metadata()
    fail_severities = get_fail_severities()

    print(f"[enforce] SCAN_ID            = {scan_id}")
    print(f"[enforce] Fail on severities = {fail_severities}")

    # ---- Load evidence ----
    evidence = safe_read_json(evidence_path)
    if not isinstance(evidence, dict):
        print(f"[enforce] WARNING: Combined evidence not found: {evidence_path}")
        evidence = {}

    combined_severity = evidence.get("combined_severity_summary", {})
    total_findings = evidence.get("total_static_findings", 0)

    # ---- Evaluate ----
    blocking_count = 0
    blocking_detail = {}
    for sev in fail_severities:
        count = combined_severity.get(sev, 0)
        if count > 0:
            blocking_count += count
            blocking_detail[sev] = count

    decision = "FAIL" if blocking_count > 0 else "PASS"

    decision_report = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "evidence_generated_at": utc_now_iso(),
        "repository_url": github_meta.get("repository_url"),
        "branch": github_meta.get("branch"),
        "commit_sha": github_meta.get("commit_sha"),
        "workflow_run_id": github_meta.get("workflow_run_id"),
        "enforcement_decision": decision,
        "fail_on_severities": sorted(fail_severities),
        "combined_severity_summary": combined_severity,
        "total_static_findings": total_findings,
        "blocking_findings": blocking_count,
        "blocking_detail": blocking_detail,
        "reason": (
            f"Pipeline blocked: {blocking_count} finding(s) at severity "
            f"{', '.join(sorted(blocking_detail.keys()))} exceed the threshold."
            if decision == "FAIL"
            else "No findings exceed the configured severity threshold."
        ),
        "evidence_note": (
            "This enforcement decision is based on the combined static analysis "
            "evidence from Checkov and Trivy.  The decision is always generated "
            "before the pipeline is allowed to fail, ensuring that all forensic "
            "evidence is preserved regardless of the outcome."
        ),
    }

    safe_write_json(decision_path, decision_report)

    print(f"[enforce] Decision           = {decision}")
    print(f"[enforce] Blocking findings  = {blocking_count}")
    print(f"[enforce] Output             = {decision_path}")

    if decision == "FAIL":
        print(f"\n{'='*60}")
        print(f"  ENFORCEMENT FAILURE")
        print(f"  {blocking_count} finding(s) at severity {sorted(blocking_detail.keys())}")
        print(f"  Reports saved — see {combined_dir}/")
        print(f"{'='*60}\n")
        sys.exit(1)
    else:
        print(f"[enforce] All findings within acceptable thresholds.")
        sys.exit(0)


if __name__ == "__main__":
    main()
