#!/usr/bin/env python3
"""
tests/test_predeployment_risk_score.py

Unit tests for the Pre-Deployment Risk Scoring Engine.

Run:  python -m pytest tests/test_predeployment_risk_score.py -v
"""

import json
import math
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Import the pure scoring function directly for unit tests
from scripts.risk.calculate_predeployment_risk_score import (
    ALPHA,
    BETA,
    RESOURCE_PENALTY_CAP,
    SEVERITY_WEIGHTS,
    _assign_band,
    calculate_score,
)

SAMPLE_SCAN = "SCAN-TEST-RISKSC"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_dirs(monkeypatch):
    """Ensure the risk dir exists and clean up after each test."""
    monkeypatch.chdir(ROOT)
    risk_dir = ROOT / "reports" / "risk" / SAMPLE_SCAN
    risk_dir.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(str(ROOT / "reports" / "risk" / SAMPLE_SCAN), ignore_errors=True)


def _write_enriched(findings: list[dict]) -> None:
    """Write an enriched-findings.json fixture into the test scan dir."""
    risk_dir = ROOT / "reports" / "risk" / SAMPLE_SCAN
    payload = {
        "scan_id": SAMPLE_SCAN,
        "findings": findings,
    }
    with open(str(risk_dir / "enriched-findings.json"), "w") as fh:
        json.dump(payload, fh, indent=2)


def _run_script(scan_id: str = SAMPLE_SCAN) -> tuple[int, str]:
    """Invoke the scoring script as a subprocess; returns (returncode, combined_output)."""
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "risk" / "calculate_predeployment_risk_score.py"),
            scan_id,
        ],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    return result.returncode, result.stdout + result.stderr


def _read_score_json(scan_id: str = SAMPLE_SCAN) -> dict:
    path = ROOT / "reports" / "risk" / scan_id / "predeployment-risk-score.json"
    with open(str(path)) as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Unit tests: pure scoring function
# ---------------------------------------------------------------------------

class TestCalculateScorePure:
    """Tests against the pure calculate_score() function (no I/O)."""

    def test_no_findings_yields_max_score(self):
        """No findings => D=0, U=0 => score = 1000."""
        result = calculate_score([], resource_count=1)
        assert result["score"] == 1000
        assert result["risk_band"] == "VERY_LOW_RISK"
        assert result["suggested_decision"] == "PASS"
        assert result["review_required"] is False
        assert result["unknown_findings_present"] is False

    def test_high_and_medium_findings_reduce_score(self):
        """HIGH + MEDIUM findings should produce a score below 1000."""
        findings = [
            {"final_severity": "HIGH", "resource": "aws_sg.a"},
            {"final_severity": "HIGH", "resource": "aws_sg.b"},
            {"final_severity": "MEDIUM", "resource": "aws_sg.c"},
        ]
        result = calculate_score(findings, resource_count=3)
        assert result["score"] < 1000
        assert result["sev_counts"]["HIGH"] == 2
        assert result["sev_counts"]["MEDIUM"] == 1
        # D = (0.80 + 0.80 + 0.50) / 3, U = 0
        expected_D = (0.80 + 0.80 + 0.50) / 3
        expected_score = round(1000 * math.exp(-(ALPHA * expected_D)))
        assert result["score"] == expected_score

    def test_unknown_findings_set_review_required(self):
        """UNKNOWN findings must set review_required=True without zeroing the score."""
        findings = [
            {"final_severity": "UNKNOWN", "resource": "aws_s3.x"},
        ]
        result = calculate_score(findings, resource_count=1)
        assert result["review_required"] is True
        assert result["unknown_findings_present"] is True
        assert result["score"] > 0, "Score must not be forced to zero by UNKNOWN findings"
        assert result["unknown_count"] == 1
        assert result["confirmed_count"] == 0

    def test_resource_penalty_cap_applied(self):
        """Many findings on one resource must be capped at resource_penalty_cap."""
        # Stack 10 HIGH findings on a single resource -> uncapped = 10 * 0.80 = 8.0
        findings = [
            {"final_severity": "HIGH", "resource": "aws_sg.overloaded"} for _ in range(10)
        ]
        result = calculate_score(findings, resource_count=1)

        rp = result["resource_penalties"][0]
        assert rp["applied_cap"] is True
        assert rp["uncapped_confirmed_penalty"] == pytest.approx(10 * 0.80, abs=1e-5)
        assert rp["capped_confirmed_penalty"] == pytest.approx(RESOURCE_PENALTY_CAP, abs=1e-5)

        # D should equal cap / 1 = RESOURCE_PENALTY_CAP
        assert result["D"] == pytest.approx(RESOURCE_PENALTY_CAP, abs=1e-5)

    def test_mixed_confirmed_and_unknown_on_same_resource(self):
        """UNKNOWN findings on the same resource as confirmed ones are tracked separately."""
        findings = [
            {"final_severity": "MEDIUM", "resource": "aws_s3.bucket"},
            {"final_severity": "UNKNOWN", "resource": "aws_s3.bucket"},
        ]
        result = calculate_score(findings, resource_count=1)
        rp = next(r for r in result["resource_penalties"] if r["resource"] == "aws_s3.bucket")
        assert rp["confirmed_finding_count"] == 1
        assert rp["unknown_finding_count"] == 1
        assert result["review_required"] is True

    def test_score_clamped_within_0_to_1000(self):
        """Score must always be within [0, 1000]."""
        # Large numbers of findings should not push below 0
        findings = [
            {"final_severity": "CRITICAL", "resource": f"res_{i}"} for i in range(100)
        ]
        result = calculate_score(findings, resource_count=1)
        assert 0 <= result["score"] <= 1000

    def test_severity_weights_applied_correctly(self):
        """Each severity weight should match the defined constants."""
        for sev, weight in SEVERITY_WEIGHTS.items():
            findings = [{"final_severity": sev, "resource": "aws_res.test"}]
            result = calculate_score(findings, resource_count=1)
            expected_D = min(weight, RESOURCE_PENALTY_CAP)
            expected_score = round(1000 * math.exp(-(ALPHA * expected_D)))
            assert result["score"] == expected_score, f"Weight mismatch for {sev}"


class TestRiskBandAssignment:
    def test_band_boundaries(self):
        assert _assign_band(1000) == ("VERY_LOW_RISK", "PASS")
        assert _assign_band(900)  == ("VERY_LOW_RISK", "PASS")
        assert _assign_band(899)  == ("LOW_RISK", "PASS_WITH_ADVISORY")
        assert _assign_band(750)  == ("LOW_RISK", "PASS_WITH_ADVISORY")
        assert _assign_band(749)  == ("MODERATE_RISK", "REVIEW")
        assert _assign_band(500)  == ("MODERATE_RISK", "REVIEW")
        assert _assign_band(499)  == ("HIGH_RISK", "REVIEW_HIGH_RISK")
        assert _assign_band(250)  == ("HIGH_RISK", "REVIEW_HIGH_RISK")
        assert _assign_band(249)  == ("CRITICAL_RISK", "BLOCK_RECOMMENDED")
        assert _assign_band(0)    == ("CRITICAL_RISK", "BLOCK_RECOMMENDED")


# ---------------------------------------------------------------------------
# Integration tests: subprocess + filesystem
# ---------------------------------------------------------------------------

class TestScoringScriptIntegration:
    def test_no_findings_integration(self):
        """Script produces score=1000 when no findings exist."""
        _write_enriched([])
        rc, out = _run_script()
        assert rc == 0, f"Script failed: {out}"

        data = _read_score_json()
        assert data["score"]["pre_deployment_risk_score"] == 1000
        assert data["score"]["risk_band"] == "VERY_LOW_RISK"
        assert data["score"]["suggested_decision"] == "PASS"
        assert data["inputs"]["total_findings"] == 0

    def test_high_medium_findings_integration(self):
        """Script produces a score < 1000 with HIGH and MEDIUM findings."""
        findings = [
            {"final_severity": "HIGH", "resource": "aws_sg.a", "source_rule_id": "R1"},
            {"final_severity": "MEDIUM", "resource": "aws_sg.b", "source_rule_id": "R2"},
        ]
        _write_enriched(findings)
        rc, out = _run_script()
        assert rc == 0, f"Script failed: {out}"

        data = _read_score_json()
        score = data["score"]["pre_deployment_risk_score"]
        assert score < 1000
        assert data["severity_counts"]["HIGH"] == 1
        assert data["severity_counts"]["MEDIUM"] == 1

    def test_unknown_findings_integration(self):
        """UNKNOWN findings set review_required=True and U>0, score not zero."""
        findings = [
            {"final_severity": "UNKNOWN", "resource": "aws_s3.x", "source_rule_id": "U1"},
        ]
        _write_enriched(findings)
        rc, out = _run_script()
        assert rc == 0, f"Script failed: {out}"

        data = _read_score_json()
        assert data["score"]["review_required"] is True
        assert data["score"]["unknown_findings_present"] is True
        assert data["density_values"]["unknown_density_U"] > 0
        assert data["score"]["pre_deployment_risk_score"] > 0, \
            "Score must not be forced to zero by UNKNOWN findings"

    def test_resource_penalty_cap_integration(self):
        """Multiple findings on one resource should trigger cap."""
        findings = [
            {"final_severity": "HIGH", "resource": "aws_sg.crowded", "source_rule_id": f"R{i}"}
            for i in range(10)
        ]
        _write_enriched(findings)
        rc, out = _run_script()
        assert rc == 0, f"Script failed: {out}"

        data = _read_score_json()
        rp = next(r for r in data["resource_penalties"] if r["resource"] == "aws_sg.crowded")
        assert rp["applied_cap"] is True
        assert rp["capped_confirmed_penalty"] == pytest.approx(RESOURCE_PENALTY_CAP, abs=1e-4)

    def test_missing_resource_count_defaults_to_1(self):
        """When resource field is absent from findings, defaults to 1 with warning."""
        # Findings with no resource field or Unknown resource
        findings = [
            {"final_severity": "LOW", "source_rule_id": "R1"},  # no resource key
        ]
        _write_enriched(findings)
        rc, out = _run_script()
        assert rc == 0, f"Script failed: {out}"

        data = _read_score_json()
        assert data["inputs"]["resource_count"] == 1
        assert data["inputs"]["resource_count_source"] == "defaulted"
        assert "resource_count_missing_defaulted_to_1" in data["warnings"]

    def test_missing_enriched_findings_exits_1(self):
        """Script must exit with code 1 and a clear error when input file is absent."""
        # Do NOT write enriched-findings.json
        rc, out = _run_script()
        assert rc == 1
        assert "not found" in out.lower() or "error" in out.lower()

    def test_output_files_created(self):
        """Both JSON and Markdown output files must be produced."""
        _write_enriched([
            {"final_severity": "MEDIUM", "resource": "aws_s3.test", "source_rule_id": "X1"},
        ])
        rc, _ = _run_script()
        assert rc == 0

        rd = ROOT / "reports" / "risk" / SAMPLE_SCAN
        assert (rd / "predeployment-risk-score.json").is_file()
        assert (rd / "predeployment-risk-score.md").is_file()

    def test_json_schema_structure(self):
        """Output JSON must contain all required top-level keys."""
        _write_enriched([])
        _run_script()
        data = _read_score_json()

        required_keys = [
            "scan_id", "generated_at", "module", "score_type", "score_scale",
            "formula", "parameters", "inputs", "severity_counts", "density_values",
            "score", "resource_penalties", "warnings",
        ]
        for key in required_keys:
            assert key in data, f"Missing key: {key}"

        score_keys = [
            "raw_score", "pre_deployment_risk_score", "risk_band",
            "suggested_decision", "review_required", "unknown_findings_present",
        ]
        for key in score_keys:
            assert key in data["score"], f"Missing score key: {key}"

    def test_markdown_file_contains_expected_sections(self):
        """Markdown output must contain key headings and data."""
        _write_enriched([
            {"final_severity": "HIGH", "resource": "aws_sg.x", "source_rule_id": "H1"},
        ])
        _run_script()

        md_path = ROOT / "reports" / "risk" / SAMPLE_SCAN / "predeployment-risk-score.md"
        content = md_path.read_text(encoding="utf-8")

        assert "# Pre-Deployment Risk Score" in content
        assert "## Summary" in content
        assert "## Severity Counts" in content
        assert "## Scoring Formula" in content
        assert "## Resource Penalty Table" in content
        assert SAMPLE_SCAN in content
