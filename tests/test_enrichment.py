#!/usr/bin/env python3
"""
tests/test_enrichment.py

Unit tests for the Finding Enrichment Engine.
Run:  python -m pytest tests/test_enrichment.py -v
"""
import json, os, shutil, subprocess, sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SAMPLE_SCAN = "SCAN-TEST-ENRICH"

@pytest.fixture(autouse=True)
def setup_dirs(tmp_path, monkeypatch):
    """Create sample evidence files mimicking pipeline output."""
    monkeypatch.chdir(ROOT)

    risk_dir = ROOT / "reports" / "risk" / SAMPLE_SCAN
    risk_dir.mkdir(parents=True, exist_ok=True)

    static_dir = ROOT / "reports" / "static" / SAMPLE_SCAN / "combined"
    static_dir.mkdir(parents=True, exist_ok=True)

    # 1. Checkov finding with existing severity
    # 2. Checkov finding missing severity
    # 3. Policy finding with existing severity
    # 4. Policy finding missing severity
    # 5. Trivy finding (should be ignored)

    combined = {
        "checkov_findings": [
            {
                "check_id": "CKV_AWS_24",
                "check_name": "Checkov Existing Severity",
                "severity": "HIGH",
                "resource": "aws_sg.valid",
                "finding_id": "ckv-001",
            },
            {
                "check_id": "CKV_AWS_UNKNOWN",
                "check_name": "Checkov Missing Severity",
                "severity": "UNKNOWN",
                "resource": "aws_sg.unknown",
                "finding_id": "ckv-002",
            }
        ],
        "trivy_findings": [
            {
                "rule_id": "AVD-AWS-0107",
                "severity": "HIGH",
                "finding_id": "trivy-001",
            }
        ],
        "policy_as_code": {
            "violations": [
                {
                    "policy_id": "CUSTOM_AWS_001",
                    "title": "Policy Existing Severity",
                    "severity": "LOW",
                    "resource": "aws_s3.valid",
                },
                {
                    "policy_id": "CUSTOM_AWS_002",
                    "title": "Policy Missing Severity",
                    "severity": "UNKNOWN",
                    "resource": "aws_s3.unknown",
                }
            ]
        },
    }

    with open(str(static_dir / "static-analysis-evidence.json"), "w") as f:
        json.dump(combined, f, indent=2)

    yield

    shutil.rmtree(str(ROOT / "reports" / "risk" / SAMPLE_SCAN), ignore_errors=True)
    shutil.rmtree(str(ROOT / "reports" / "static" / SAMPLE_SCAN), ignore_errors=True)


def _run(script, scan_id=SAMPLE_SCAN, env_extra=None):
    env = os.environ.copy()
    env.pop("OPENAI_API_KEY", None)
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "risk" / script), scan_id],
        capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    return result.returncode, result.stdout + result.stderr


class TestEnrichmentEngine:
    def test_normalization_ignores_trivy(self):
        _run("normalize_findings.py")
        norm_path = ROOT / "reports" / "risk" / SAMPLE_SCAN / "normalized-findings.json"
        with open(norm_path) as f:
            data = json.load(f)
        
        findings = data.get("findings", [])
        assert len(findings) == 4 # 2 Checkov, 2 Policy
        
        tools = set(f["source_tool"] for f in findings)
        assert "trivy" not in tools

    def test_ai_unavailable_fallback(self):
        # Without API key, the AI enrichment should fallback gracefully
        _run("normalize_findings.py")
        _run("ai_enrich_findings.py")
        _run("validate_enriched_findings.py")
        
        enrich_path = ROOT / "reports" / "risk" / SAMPLE_SCAN / "enriched-findings.json"
        with open(enrich_path) as f:
            data = json.load(f)
            
        findings = {f["source_rule_id"]: f for f in data["findings"]}
        
        # 1. Checkov existing severity
        assert findings["CKV_AWS_24"]["final_severity"] == "HIGH"
        assert findings["CKV_AWS_24"]["severity_source"] == "checkov_scanner_severity"
        assert findings["CKV_AWS_24"]["requires_review"] is False
        
        # 2. Checkov missing severity
        assert findings["CKV_AWS_UNKNOWN"]["final_severity"] == "UNKNOWN"
        assert findings["CKV_AWS_UNKNOWN"]["severity_source"] == "ai_unavailable"
        assert findings["CKV_AWS_UNKNOWN"]["requires_review"] is True
        
        # 3. Policy existing severity
        assert findings["CUSTOM_AWS_001"]["final_severity"] == "LOW"
        assert findings["CUSTOM_AWS_001"]["severity_source"] == "policy_defined_severity"
        assert findings["CUSTOM_AWS_001"]["requires_review"] is False
        
        # 4. Policy missing severity
        assert findings["CUSTOM_AWS_002"]["final_severity"] == "UNKNOWN"
        assert findings["CUSTOM_AWS_002"]["severity_source"] == "ai_unavailable"
        assert findings["CUSTOM_AWS_002"]["requires_review"] is True

    def test_advisory_gate(self):
        _run("normalize_findings.py")
        _run("ai_enrich_findings.py")
        _run("validate_enriched_findings.py")
        _run("render_enrichment_summary.py")
        
        # Advisory default
        rc, out = _run("advisory_enrichment_gate.py")
        assert rc == 0
        
        # Enforce true -> REVIEW_REQUIRED (due to UNKNOWN findings) -> exit 1
        rc, out = _run("advisory_enrichment_gate.py", env_extra={"ENFORCE_RISK_GATE": "true"})
        assert rc == 1

    def test_evidence_generation(self):
        for script in [
            "normalize_findings.py", "ai_enrich_findings.py",
            "validate_enriched_findings.py", "render_enrichment_summary.py",
            "hash_enrichment_evidence.py"
        ]:
            rc, out = _run(script)
            assert rc == 0, f"{script} failed: {out}"
            
        rd = ROOT / "reports" / "risk" / SAMPLE_SCAN
        expected = [
            "normalized-findings.json", "ai-enrichment-request.json",
            "ai-enrichment-response.json", "enriched-findings.json",
            "finding-enrichment-summary.json", "finding-enrichment-summary.md",
            "finding-enrichment-decision.json", "ai-model-metadata.json",
            "evidence-hashes.json", "evidence-manifest.json"
        ]
        for name in expected:
            assert (rd / name).is_file(), f"Missing: {name}"
