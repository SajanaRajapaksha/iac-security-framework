#!/usr/bin/env python3
"""
scripts/deployment/generate_deployment_evidence.py

Collects all deployment metadata into a single forensic-ready evidence file:
    reports/deployment/<SCAN_ID>/deployment-plan-evidence.json

Usage:
    python scripts/deployment/generate_deployment_evidence.py <SCAN_ID> \\
        --deployment-root <PATH> \\
        --plan-exit-code <N> \\
        --plan-sha256 <HASH> \\
        --tag-validation-status <PASS|FAIL> \\
        [--aws-identity-json <JSON_STRING>] \\
        [--terraform-version <VERSION>] \\
        [--state-bucket <BUCKET>] \\
        [--state-key <KEY>]

Output:
    reports/deployment/<SCAN_ID>/deployment-plan-evidence.json
"""

import argparse
import json
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import (
    collect_github_metadata,
    safe_write_json,
    utc_now_iso,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate forensic deployment plan evidence."
    )
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    parser.add_argument("--deployment-root", required=True, help="Terraform deployment root path")
    parser.add_argument("--plan-exit-code", type=int, default=0, help="Terraform plan exit code")
    parser.add_argument("--plan-sha256", default="", help="SHA256 of tfplan binary")
    parser.add_argument("--tag-validation-status", default="UNKNOWN", help="PASS or FAIL")
    parser.add_argument("--aws-identity-json", default="{}", help="JSON from aws sts get-caller-identity")
    parser.add_argument("--terraform-version", default="unknown", help="Terraform CLI version")
    parser.add_argument("--state-bucket", default="", help="S3 state bucket name")
    parser.add_argument("--state-key", default="", help="S3 state key path")
    args = parser.parse_args()

    scan_id: str = args.scan_id
    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Parse AWS identity                                                  #
    # ------------------------------------------------------------------ #
    try:
        aws_identity = json.loads(args.aws_identity_json)
    except (json.JSONDecodeError, TypeError):
        aws_identity = {}

    # Strip secrets — only keep safe identity fields
    aws_section = {
        "account_id": aws_identity.get("Account", ""),
        "region": os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "")),
        "assumed_role_arn": aws_identity.get("Arn", ""),
    }

    # ------------------------------------------------------------------ #
    # GitHub metadata                                                     #
    # ------------------------------------------------------------------ #
    gh = collect_github_metadata()

    # ------------------------------------------------------------------ #
    # Terraform section                                                   #
    # ------------------------------------------------------------------ #
    plan_status = "SUCCESS" if args.plan_exit_code == 0 else "FAILED"

    terraform_section = {
        "version": args.terraform_version,
        "deployment_root": args.deployment_root,
        "backend": "s3",
        "state_bucket": args.state_bucket,
        "state_key": args.state_key or f"research/{scan_id}/terraform.tfstate",
        "plan_exit_code": args.plan_exit_code,
        "plan_status": plan_status,
        "plan_sha256": args.plan_sha256,
    }

    # ------------------------------------------------------------------ #
    # Build evidence                                                      #
    # ------------------------------------------------------------------ #
    evidence = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "stage": "terraform_plan",
        "timestamp_utc": utc_now_iso(),
        "repository": gh.get("repository_url"),
        "branch": gh.get("branch"),
        "source_commit_sha": gh.get("commit_sha"),
        "github": {
            "run_id": gh.get("workflow_run_id"),
            "run_number": gh.get("workflow_run_number"),
            "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
            "actor": gh.get("actor"),
        },
        "aws": aws_section,
        "terraform": terraform_section,
        "tagging": {
            "required": {
                "scan-id": scan_id,
                "managed-by": "iac-security-framework",
            },
            "validation_status": args.tag_validation_status,
        },
        "deployment_status": "NOT_APPLIED",
    }

    out_path = deploy_dir / "deployment-plan-evidence.json"
    safe_write_json(str(out_path), evidence)

    # ------------------------------------------------------------------ #
    # Console output                                                      #
    # ------------------------------------------------------------------ #
    print(f"\n{'='*60}")
    print(f"  TERRAFORM DEPLOYMENT PLAN")
    print(f"{'='*60}")
    print(f"  SCAN_ID              : {scan_id}")
    print(f"  AWS Account          : {aws_section['account_id']}")
    print(f"  AWS Region           : {aws_section['region']}")
    print(f"  State Key            : {terraform_section['state_key']}")
    print(f"  Plan Status          : {plan_status}")
    print(f"  Tag Validation       : {args.tag_validation_status}")
    print(f"  Deployment Status    : NOT_APPLIED")
    print(f"  Evidence             : {out_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
