#!/usr/bin/env python3
"""
tests/test_risk_scoring.py

Unit tests for the CIS-driven AI-assisted risk scoring engine.
Run:  python -m pytest tests/test_risk_scoring.py -v
"""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_SCAN = "SCAN-TEST-RISK"

@pytest.fixture(autouse=True)
def setup_dirs(tmp_path, monkeypatch):
    """Create sample evidence files mimicking pipeline output."""
    monkeypatch.chdir(ROOT)

    risk_dir = ROOT / "reports" / "risk" / SAMPLE_SCAN
    risk_dir.mkdir(parents=True, exist_ok=True)

    static_dir = ROOT / "reports" / "static" / SAMPLE_SCAN / "combined"
    static_dir.mkdir(parents=True, exist_ok=True)

    policy_dir = ROOT / "reports" / "policy" / SAMPLE_SCAN
    policy_dir.mkdir(parents=True, exist_ok=True)

    # Checkov finding for CKV_AWS_24 (public SSH)
    combined = {
        "checkov_findings": [
            {
                "check_id": "CKV_AWS_24",
                "check_name": "Ensure no security group allows ingress from 0.0.0.0/0 to port 22",
                "severity": "HIGH",
                "resource": "aws_security_group.public_ssh",
                "resource_type": "aws_security_group",
                "file_path": "main.tf",
                "file_line_range": [1, 15],
                "finding_id": "ckv-001",
            }
        ],
        "trivy_findings": [
            {
                "rule_id": "AVD-AWS-0107",
                "rule_name": "Security group allows ingress from 0.0.0.0/0 to SSH",
                "severity": "HIGH",
                "resource": "aws_security_group.public_ssh",
                "file_path": "main.tf",
                "start_line": 1,
                "end_line": 15,
                "description": "Security groups must not allow unrestricted SSH ingress from 0.0.0.0/0 port 22",
                "finding_id": "trivy-001",
            }
        ],
        "policy_as_code": {
            "violations": [
                {
                    "policy_id": "CUSTOM_AWS_001",
                    "title": "Block public SSH ingress",
                    "severity": "HIGH",
                    "resource": "aws_security_group.public_ssh",
                    "resource_type": "aws_security_group",
                    "input_file": "main.tf",
                    "message": "Public SSH from 0.0.0.0/0 to port 22",
                    "reason": "Public SSH from 0.0.0.0/0 to port 22",
                }
            ]
        },
    }

    with open(str(static_dir / "static-analysis-evidence.json"), "w") as f:
        json.dump(combined, f, indent=2)

    yield

    # Cleanup
    shutil.rmtree(str(ROOT / "reports" / "risk" / SAMPLE_SCAN), ignore_errors=True)
    shutil.rmtree(str(ROOT / "reports" / "static" / SAMPLE_SCAN), ignore_errors=True)
    shutil.rmtree(str(ROOT / "reports" / "policy" / SAMPLE_SCAN), ignore_errors=True)


def _run(script, scan_id=SAMPLE_SCAN, env_extra=None):
    """Run a risk script and return (exit_code, stdout)."""
    env = os.environ.copy()
    env.pop("OPENAI_API_KEY", None)
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "risk" / script), scan_id],
        capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    return result.returncode, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Test 1: CKV_AWS_24 public SSH → BLOCK_RECOMMENDED, score >= 90
# ---------------------------------------------------------------------------

class TestPublicSSH:
    def test_full_pipeline_produces_block_recommended(self):
        """CKV_AWS_24 must result in CRITICAL / BLOCK_RECOMMENDED / score >= 90."""
        # Run full pipeline
        for script in [
            "normalize_findings.py",
            "deterministic_map_known_findings.py",
            "ai_map_unmapped_findings.py",
            "validate_cis_mapping.py",
            "merge_mappings.py",
            "calculate_risk_score.py",
        ]:
            rc, out = _run(script)
            assert rc == 0, f"{script} failed: {out}"

        # Check risk-decision.json
        dec_path = ROOT / "reports" / "risk" / SAMPLE_SCAN / "risk-decision.json"
        assert dec_path.is_file()
        with open(dec_path) as f:
            dec = json.load(f)

        assert dec["overall_score"] >= 90, f"Score {dec['overall_score']} < 90"
        assert dec["risk_level"] == "CRITICAL"
        assert dec["suggested_decision"] == "BLOCK_RECOMMENDED"
        assert dec["should_fail_pipeline"] is False  # advisory by default
        assert len(dec["mandatory_blocks_triggered"]) > 0

    def test_deterministic_mapping(self):
        """CKV_AWS_24 must be deterministically mapped to PUBLIC_ADMIN_ACCESS."""
        _run("normalize_findings.py")
        _run("deterministic_map_known_findings.py")

        det_path = ROOT / "reports" / "risk" / SAMPLE_SCAN / "deterministic-mappings.json"
        with open(det_path) as f:
            data = json.load(f)

        mappings = data["mappings"]
        ckv24 = [m for m in mappings if "CKV_AWS_24" in str(m)]
        assert len(ckv24) > 0
        assert ckv24[0]["canonical_control"] == "PUBLIC_ADMIN_ACCESS"
        assert ckv24[0]["mandatory_block"] is True
        assert ckv24[0]["mapping_confidence"] == "high"


# ---------------------------------------------------------------------------
# Test 2: Missing OPENAI_API_KEY → fallback mapping
# ---------------------------------------------------------------------------

class TestMissingAPIKey:
    def test_no_api_key_uses_fallback(self):
        """Without OPENAI_API_KEY, unmapped findings get UNKNOWN fallback."""
        _run("normalize_findings.py")
        _run("deterministic_map_known_findings.py")

        # Check unmapped count (should be 0 for our known rules, but
        # let's verify the AI mapper handles gracefully)
        rc, out = _run("ai_map_unmapped_findings.py")
        assert rc == 0

        ai_path = ROOT / "reports" / "risk" / SAMPLE_SCAN / "ai-cis-mapping.json"
        with open(ai_path) as f:
            data = json.load(f)
        meta = data.get("metadata", {})
        assert meta.get("api_calls", 0) == 0  # no API calls without key


# ---------------------------------------------------------------------------
# Test 3: ENFORCE_RISK_GATE=true + BLOCK_RECOMMENDED → exit 1
# ---------------------------------------------------------------------------

class TestRiskGateEnforcement:
    def _run_full_pipeline(self):
        for s in ["normalize_findings.py", "deterministic_map_known_findings.py",
                   "ai_map_unmapped_findings.py", "validate_cis_mapping.py",
                   "merge_mappings.py", "calculate_risk_score.py"]:
            _run(s)

    def test_enforce_true_exits_1(self):
        """ENFORCE_RISK_GATE=true + BLOCK_RECOMMENDED → exit 1."""
        self._run_full_pipeline()
        rc, out = _run("enforce_risk_gate.py", env_extra={"ENFORCE_RISK_GATE": "true"})
        assert rc == 1, f"Expected exit 1, got {rc}. Output: {out}"

    def test_enforce_false_exits_0(self):
        """ENFORCE_RISK_GATE=false + BLOCK_RECOMMENDED → exit 0."""
        self._run_full_pipeline()
        rc, out = _run("enforce_risk_gate.py", env_extra={"ENFORCE_RISK_GATE": "false"})
        assert rc == 0, f"Expected exit 0, got {rc}. Output: {out}"

    def test_advisory_default_exits_0(self):
        """Default (no ENFORCE_RISK_GATE) + BLOCK_RECOMMENDED → exit 0."""
        self._run_full_pipeline()
        rc, out = _run("enforce_risk_gate.py")
        assert rc == 0


# ---------------------------------------------------------------------------
# Test 4: Evidence files are generated
# ---------------------------------------------------------------------------

class TestEvidenceGeneration:
    def test_all_evidence_files_created(self):
        """Full pipeline must generate all required evidence files."""
        for s in ["normalize_findings.py", "deterministic_map_known_findings.py",
                   "ai_map_unmapped_findings.py", "validate_cis_mapping.py",
                   "merge_mappings.py", "calculate_risk_score.py",
                   "render_risk_summary.py", "hash_risk_evidence.py"]:
            rc, out = _run(s)
            assert rc == 0, f"{s} failed: {out}"

        rd = ROOT / "reports" / "risk" / SAMPLE_SCAN
        expected = [
            "normalized-findings.json", "deterministic-mappings.json",
            "unmapped-findings.json", "ai-cis-mapping.json",
            "validated-cis-mapping.json", "merged-cis-mapping.json",
            "finding-risk-scores.json", "resource-risk-scores.json",
            "domain-risk-scores.json", "risk-score.json",
            "risk-decision.json", "risk-summary.md",
            "evidence-hashes.json", "evidence-manifest.json",
        ]
        for name in expected:
            assert (rd / name).is_file(), f"Missing: {name}"
