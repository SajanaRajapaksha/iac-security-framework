#!/usr/bin/env python3
"""
scripts/risk/hash_enrichment_evidence.py

Hashes all enrichment artifacts and generates a forensic manifest.

Usage: python scripts/risk/hash_enrichment_evidence.py <SCAN_ID>
"""

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import sha256_file, safe_read_json, safe_write_json, utc_now_iso, collect_github_metadata

ARTIFACTS = [
    "normalized-findings.json",
    "ai-enrichment-request.json",
    "ai-enrichment-response.json",
    "enriched-findings.json",
    "finding-enrichment-summary.json",
    "finding-enrichment-summary.md",
    "finding-enrichment-decision.json",
    "ai-model-metadata.json",
    "predeployment-risk-score.json",
    "predeployment-risk-score.md",
    "predeployment-resource-inventory.json",
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    scan_id = args.scan_id

    risk_dir = ROOT_DIR / "reports" / "risk" / scan_id

    hashes = {}
    for name in ARTIFACTS:
        p = risk_dir / name
        h = sha256_file(str(p))
        hashes[name] = h if h else "FILE_NOT_FOUND"

    safe_write_json(str(risk_dir / "evidence-hashes.json"), {
        "scan_id": scan_id, "generated_at": utc_now_iso(), "hashes": hashes,
    })

    # Model metadata
    ai_meta = safe_read_json(str(risk_dir / "ai-model-metadata.json")) or {}

    gh = collect_github_metadata()
    manifest = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "repository": gh.get("repository_url"),
        "branch": gh.get("branch"),
        "commit_sha": gh.get("commit_sha"),
        "github_run_id": gh.get("workflow_run_id"),
        "active_static_scanner": "checkov",
        "trivy_used": False,
        "ai_used": ai_meta.get("api_calls", 0) > 0,
        "ai_metadata": ai_meta,
        "input_artifacts": [
            f"reports/static/{scan_id}/combined/static-analysis-evidence.json"
        ],
        "output_artifacts": [f"reports/risk/{scan_id}/{n}" for n in ARTIFACTS + ["evidence-hashes.json", "evidence-manifest.json"]],
        "artifact_hashes": hashes,
        "forensic_statement": (
            "AI was used for standards reference enrichment and to fill missing severities only. "
            "Existing Checkov and policy severities were preserved. "
            "The pre-deployment risk score was calculated deterministically from enriched finding "
            "severities and Terraform resource count. The score is normalized to a 0-1000 scale "
            "using exponential decay, where higher values indicate better pre-deployment security "
            "posture."
        )
    }
    
    safe_write_json(str(risk_dir / "evidence-manifest.json"), manifest)
    print(f"[hash_evidence] SCAN_ID = {scan_id}")
    print(f"[hash_evidence] Hashed {sum(1 for v in hashes.values() if v != 'FILE_NOT_FOUND')} artifacts")

if __name__ == "__main__":
    main()
