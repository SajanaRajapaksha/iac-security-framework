#!/usr/bin/env python3
"""
scripts/deployment/validate_apply_authorization.py

Stage 27 — Generates a deployment-authorization record by inspecting:
    - Plan artifact verification result
    - Deployment-plan evidence
    - Pre-deployment risk-score report
    - GitHub context
    - Current SCAN_ID
    - Research-exception inputs (when passed)

Authorization types:
    STANDARD_APPROVAL   — Normal path, risk score permits deployment
    RESEARCH_EXCEPTION  — Intentionally insecure IaC deployed for research

Output:
    reports/deployment/<SCAN_ID>/deployment-authorization.json

Usage:
    python scripts/deployment/validate_apply_authorization.py <SCAN_ID> \\
        [--authorization-type STANDARD_APPROVAL|RESEARCH_EXCEPTION] \\
        [--research-exception-reason "..."] \\
        [--github-actor "..."] \\
        [--github-run-id "..."] \\
        [--github-run-attempt "..."]
"""

import argparse
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deployment authorization record.")
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    parser.add_argument(
        "--authorization-type",
        choices=["STANDARD_APPROVAL", "RESEARCH_EXCEPTION"],
        default="STANDARD_APPROVAL",
    )
    parser.add_argument("--research-exception-reason", default="")
    parser.add_argument("--github-actor", default="")
    parser.add_argument("--github-run-id", default="")
    parser.add_argument("--github-run-attempt", default="")
    args = parser.parse_args()

    scan_id: str = args.scan_id
    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)
    out_path = deploy_dir / "deployment-authorization.json"

    errors: list[str] = []
    warnings: list[str] = []

    # ------------------------------------------------------------------ #
    # Validate RESEARCH_EXCEPTION requirements                            #
    # ------------------------------------------------------------------ #
    auth_type = args.authorization_type
    research_exception = auth_type == "RESEARCH_EXCEPTION"

    if research_exception:
        reason = args.research_exception_reason.strip()
        if not reason:
            errors.append(
                "RESEARCH_EXCEPTION requires a non-empty --research-exception-reason."
            )
        warnings.append(
            "RESEARCH_EXCEPTION: Intentionally insecure IaC is being deployed "
            "for controlled research. This must be in an isolated AWS account."
        )
    else:
        reason = None

    # ------------------------------------------------------------------ #
    # Load plan-artifact verification status                              #
    # ------------------------------------------------------------------ #
    artifact_verification = safe_read_json(
        str(deploy_dir / "plan-artifact-verification.json")
    )
    artifact_status = "UNKNOWN"
    if isinstance(artifact_verification, dict):
        artifact_status = artifact_verification.get("status", "UNKNOWN")
    if artifact_status != "PASS":
        errors.append(
            f"Plan artifact verification did not PASS: {artifact_status}. "
            "Deployment is not authorized."
        )

    # ------------------------------------------------------------------ #
    # Load pre-deployment risk decision                                   #
    # ------------------------------------------------------------------ #
    risk_report = safe_read_json(
        str(ROOT_DIR / "reports" / "risk" / scan_id / "predeployment-risk-score.json")
    )
    risk_decision = "UNKNOWN"
    risk_score = None
    if isinstance(risk_report, dict):
        risk_decision = risk_report.get("risk_decision", "UNKNOWN")
        risk_score = risk_report.get("normalized_score")

    # ------------------------------------------------------------------ #
    # GitHub context                                                      #
    # ------------------------------------------------------------------ #
    github_actor = args.github_actor or os.environ.get("GITHUB_ACTOR", "")
    github_run_id = args.github_run_id or os.environ.get("GITHUB_RUN_ID", "")
    github_run_attempt = args.github_run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT", "")
    github_env = os.environ.get("GITHUB_ENVIRONMENT", "research-aws-deployment")

    # ------------------------------------------------------------------ #
    # Final authorization decision                                        #
    # ------------------------------------------------------------------ #
    authorized = len(errors) == 0
    status = "AUTHORIZED" if authorized else "DENIED"

    record = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "status": status,
        "authorization_type": auth_type,
        "artifact_verification_status": artifact_status,
        "risk_decision": risk_decision,
        "risk_score": risk_score,
        "research_exception": research_exception,
        "reason": reason,
        "github_actor": github_actor,
        "github_run_id": github_run_id,
        "github_run_attempt": github_run_attempt,
        "github_environment": github_env,
        "authorized_at_utc": utc_now_iso(),
        "errors": errors,
        "warnings": warnings,
    }
    safe_write_json(str(out_path), record)

    print(f"\n{'='*60}")
    print(f"  DEPLOYMENT AUTHORIZATION — {status}")
    print(f"{'='*60}")
    print(f"  SCAN_ID              : {scan_id}")
    print(f"  Authorization Type   : {auth_type}")
    print(f"  Artifact Verified    : {artifact_status}")
    print(f"  Risk Decision        : {risk_decision}")
    print(f"  Research Exception   : {research_exception}")
    if reason:
        print(f"  Reason               : {reason}")
    print(f"  GitHub Actor         : {github_actor}")
    print(f"  GitHub Run ID        : {github_run_id}")
    print(f"  GitHub Environment   : {github_env}")
    if warnings:
        print(f"\n  WARNINGS:")
        for w in warnings:
            print(f"    - {w}")
    if errors:
        print(f"\n  ERRORS:")
        for e in errors:
            print(f"    - {e}")
    print(f"{'='*60}\n")

    if not authorized:
        sys.exit(1)


if __name__ == "__main__":
    main()
