#!/usr/bin/env python3
"""
scripts/deployment/generate_apply_evidence.py

Stage 29 — Generates forensic-ready deployment apply evidence.

Parses Terraform apply output to extract resource summary counts.
Records timing, AWS identity, and full deployment context.

Usage:
    python scripts/deployment/generate_apply_evidence.py <SCAN_ID> \\
        --apply-exit-code <N> \\
        --plan-sha256 <HASH> \\
        --terraform-version <VER> \\
        --aws-provider-version <VER> \\
        --aws-identity-json '<JSON>' \\
        --state-bucket <BUCKET> \\
        --state-key <KEY> \\
        --deployment-root <PATH> \\
        --apply-start-time <ISO8601> \\
        --apply-finish-time <ISO8601> \\
        --authorization-type STANDARD_APPROVAL \\
        [--apply-output-path <PATH>]

Output:
    reports/deployment/<SCAN_ID>/deployment-apply-evidence.json
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import collect_github_metadata, safe_write_json, utc_now_iso

# ---------------------------------------------------------------------------
# Terraform apply output parser
# ---------------------------------------------------------------------------

# e.g. "Apply complete! Resources: 3 added, 0 changed, 0 destroyed."
RE_APPLY_SUMMARY = re.compile(
    r"Apply complete!\s+Resources:\s*(\d+)\s+added,\s*(\d+)\s+changed,\s*(\d+)\s+destroyed"
)

# Error summary: "Error: ..."
RE_APPLY_ERROR = re.compile(r"Error: (.+)")


def parse_apply_output(text: str) -> dict:
    """
    Extract resource summary from `terraform apply` output.

    Returns a dict with added/changed/destroyed counts and any detected errors.
    """
    summary = {"added": None, "changed": None, "destroyed": None}
    apply_errors: list[str] = []

    m = RE_APPLY_SUMMARY.search(text)
    if m:
        summary["added"] = int(m.group(1))
        summary["changed"] = int(m.group(2))
        summary["destroyed"] = int(m.group(3))

    for m in RE_APPLY_ERROR.finditer(text):
        apply_errors.append(m.group(1).strip())

    return {"resource_summary": summary, "apply_errors": apply_errors}


def _duration_seconds(start: str, finish: str) -> float | None:
    """Return elapsed seconds between two ISO-8601 timestamps."""
    fmt = "%Y-%m-%dT%H:%M:%S%z"
    try:
        t0 = datetime.fromisoformat(start)
        t1 = datetime.fromisoformat(finish)
        return round((t1 - t0).total_seconds(), 1)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Terraform apply forensic evidence.")
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    parser.add_argument("--apply-exit-code", type=int, required=True)
    parser.add_argument("--plan-sha256", default="")
    parser.add_argument("--terraform-version", default="unknown")
    parser.add_argument("--aws-provider-version", default="unknown")
    parser.add_argument("--aws-identity-json", default="{}")
    parser.add_argument("--state-bucket", default="")
    parser.add_argument("--state-key", default="")
    parser.add_argument("--deployment-root", default="")
    parser.add_argument("--apply-start-time", default="")
    parser.add_argument("--apply-finish-time", default="")
    parser.add_argument("--authorization-type", default="STANDARD_APPROVAL")
    parser.add_argument("--apply-output-path", default="")
    args = parser.parse_args()

    scan_id: str = args.scan_id
    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)

    apply_success = args.apply_exit_code == 0
    deployment_status = "APPLY_SUCCESS" if apply_success else "APPLY_FAILED"

    # ------------------------------------------------------------------ #
    # Parse apply output                                                  #
    # ------------------------------------------------------------------ #
    parsed = {"resource_summary": {"added": None, "changed": None, "destroyed": None},
              "apply_errors": []}
    if args.apply_output_path:
        try:
            output_text = Path(args.apply_output_path).read_text(errors="replace")
            parsed = parse_apply_output(output_text)
        except OSError:
            pass

    resource_summary = parsed["resource_summary"]
    apply_errors = parsed["apply_errors"]

    if None in resource_summary.values():
        resource_summary = {k: "unknown" for k in resource_summary}
        warnings = ["Could not parse resource summary from Terraform output."]
    else:
        warnings = []

    # ------------------------------------------------------------------ #
    # AWS identity                                                        #
    # ------------------------------------------------------------------ #
    try:
        aws_identity = json.loads(args.aws_identity_json)
    except (json.JSONDecodeError, TypeError):
        aws_identity = {}

    aws_section = {
        "account_id": aws_identity.get("Account", ""),
        "region": os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "")),
        "role_arn": aws_identity.get("Arn", ""),
        "state_bucket": args.state_bucket,
        "state_key": args.state_key or f"research/{scan_id}/terraform.tfstate",
    }

    # ------------------------------------------------------------------ #
    # GitHub metadata                                                     #
    # ------------------------------------------------------------------ #
    gh = collect_github_metadata()

    # ------------------------------------------------------------------ #
    # Timing                                                              #
    # ------------------------------------------------------------------ #
    finish_time = args.apply_finish_time or utc_now_iso()
    duration = _duration_seconds(args.apply_start_time, finish_time)

    # ------------------------------------------------------------------ #
    # Load authorization record                                           #
    # ------------------------------------------------------------------ #
    auth_record_path = deploy_dir / "deployment-authorization.json"
    auth_record_data = {}
    if auth_record_path.is_file():
        import json as _json
        try:
            auth_record_data = _json.loads(auth_record_path.read_text())
        except Exception:
            pass

    evidence = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "deployment_status": deployment_status,
        "deployment_authorization": {
            "status": auth_record_data.get("status", "UNKNOWN"),
            "type": args.authorization_type,
            "github_environment": auth_record_data.get("github_environment",
                                                        "research-aws-deployment"),
        },
        "repository": {
            "url": gh.get("repository_url"),
            "branch": gh.get("branch"),
            "commit_sha": gh.get("commit_sha"),
        },
        "github": {
            "run_id": gh.get("workflow_run_id"),
            "run_number": gh.get("workflow_run_number"),
            "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
            "actor": gh.get("actor"),
        },
        "terraform": {
            "version": args.terraform_version,
            "aws_provider_version": args.aws_provider_version,
            "deployment_root": args.deployment_root,
            "plan_sha256": args.plan_sha256,
            "apply_exit_code": args.apply_exit_code,
        },
        "aws": aws_section,
        "timing": {
            "started_at_utc": args.apply_start_time or "",
            "completed_at_utc": finish_time,
            "duration_seconds": duration,
        },
        "resource_summary": resource_summary,
        "tagging": {
            "scan_id": scan_id,
            "managed_by": "iac-security-framework",
            "injection_mode": "aws_provider_environment_variables",
        },
        "errors": apply_errors,
        "warnings": warnings,
    }

    out_path = deploy_dir / "deployment-apply-evidence.json"
    safe_write_json(str(out_path), evidence)

    print(f"\n{'='*60}")
    print(f"  DEPLOYMENT APPLY EVIDENCE")
    print(f"{'='*60}")
    print(f"  SCAN_ID          : {scan_id}")
    print(f"  Status           : {deployment_status}")
    print(f"  Apply Exit Code  : {args.apply_exit_code}")
    print(f"  AWS Account      : {aws_section['account_id']}")
    print(f"  Region           : {aws_section['region']}")
    rs = resource_summary
    print(f"  Added            : {rs.get('added', 'unknown')}")
    print(f"  Changed          : {rs.get('changed', 'unknown')}")
    print(f"  Destroyed        : {rs.get('destroyed', 'unknown')}")
    if duration is not None:
        print(f"  Duration         : {duration}s")
    print(f"  Evidence         : {out_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
