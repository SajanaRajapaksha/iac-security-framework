#!/usr/bin/env python3
"""
scripts/deployment/render_deployment_summary.py

Stage 34 — Prints a concise, human-readable deployment summary to the console.
Does NOT print secrets, tokens, state data, or sensitive values.

Usage:
    python scripts/deployment/render_deployment_summary.py <SCAN_ID>
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: render_deployment_summary.py <SCAN_ID>", file=sys.stderr)
        sys.exit(1)

    scan_id = sys.argv[1]
    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id

    def _load(name: str) -> dict:
        data = safe_read_json(str(deploy_dir / name))
        return data if isinstance(data, dict) else {}

    auth = _load("deployment-authorization.json")
    apply_ev = _load("deployment-apply-evidence.json")
    verification = _load("deployed-resource-verification.json")
    reconciliation = _load("deployment-resource-reconciliation.json")
    validation = _load("deployment-validation.json")

    aws = apply_ev.get("aws", {})
    timing = apply_ev.get("timing", {})
    res_summary = apply_ev.get("resource_summary", {})
    verif_summary = verification.get("summary", {})
    rval = validation.get("resource_validation", {})

    tag_failures = rval.get("tag_failures", 0)
    recon_status = reconciliation.get("status", "UNKNOWN")
    final_decision = validation.get("status", "UNKNOWN")

    print(f"\n{'='*60}")
    print(f"  CONTROLLED DEPLOYMENT AND VALIDATION SUMMARY")
    print(f"{'='*60}")
    print(f"  SCAN_ID                  : {scan_id}")
    print(f"  Authorization            : {auth.get('authorization_type', 'UNKNOWN')}")
    print(f"  GitHub Actor             : {auth.get('github_actor', 'N/A')}")
    print(f"  AWS Account              : {aws.get('account_id', 'N/A')}")
    print(f"  AWS Region               : {aws.get('region', 'N/A')}")
    print(f"  State Key                : {aws.get('state_key', 'N/A')}")
    apply_status = apply_ev.get("deployment_status", "UNKNOWN")
    print(f"  Terraform Apply          : {apply_status}")
    if timing.get("duration_seconds") is not None:
        print(f"  Apply Duration           : {timing['duration_seconds']}s")
    print(f"  Resources Added          : {res_summary.get('added', 'N/A')}")
    print(f"  Resources Changed        : {res_summary.get('changed', 'N/A')}")
    print(f"  Resources Destroyed      : {res_summary.get('destroyed', 'N/A')}")
    print(f"  Expected State Resources : {rval.get('expected', 0)}")
    print(f"  Verified Resources       : {rval.get('verified', 0)}")
    print(f"  Verified w/ Warnings     : {rval.get('verified_with_warning', 0)}")
    print(f"  Not Found                : {rval.get('not_found', 0)}")
    print(f"  Unsupported Resources    : {rval.get('unsupported', 0)}")
    print(f"  Tag Validation Failures  : {tag_failures}")
    print(f"  Reconciliation           : {recon_status}")
    print(f"  Final Decision           : {final_decision}")
    print(f"  Next Stage               : RUNTIME_VALIDATION")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
