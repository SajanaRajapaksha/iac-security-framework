import pytest
import json
import math
from pathlib import Path
from unittest.mock import patch, MagicMock

from scripts.risk.calculate_postdeployment_risk_score import (
    calculate_score,
    _assign_band,
    _normalize_severity,
    _write_not_calculated,
    main,
    ALPHA,
    BETA,
    RESOURCE_PENALTY_CAP,
    SEVERITY_WEIGHTS
)

def test_assign_band_boundaries():
    assert _assign_band(1000) == ("VERY_LOW_RISK", "PASS")
    assert _assign_band(900) == ("VERY_LOW_RISK", "PASS")
    assert _assign_band(899) == ("LOW_RISK", "MONITOR")
    assert _assign_band(750) == ("LOW_RISK", "MONITOR")
    assert _assign_band(749) == ("MODERATE_RISK", "REMEDIATION_REQUIRED")
    assert _assign_band(500) == ("MODERATE_RISK", "REMEDIATION_REQUIRED")
    assert _assign_band(499) == ("HIGH_RISK", "URGENT_REMEDIATION")
    assert _assign_band(250) == ("HIGH_RISK", "URGENT_REMEDIATION")
    assert _assign_band(249) == ("CRITICAL_RISK", "CRITICAL_REMEDIATION")
    assert _assign_band(0) == ("CRITICAL_RISK", "CRITICAL_REMEDIATION")

def test_normalize_severity():
    assert _normalize_severity("INFORMATIONAL") == "INFO"
    assert _normalize_severity("CRITICAL") == "CRITICAL"
    assert _normalize_severity("HIGH") == "HIGH"
    assert _normalize_severity("UNKNOWN_SEV") == "UNKNOWN"
    assert _normalize_severity("") == "UNKNOWN"

def test_zero_findings_with_valid_resources():
    res = calculate_score([], resource_count=5)
    assert res["score"] == 1000
    assert res["D"] == 0.0
    assert res["U"] == 0.0
    assert res["risk_band"] == "VERY_LOW_RISK"

def test_one_critical_finding():
    findings = [{"resource": {"arn": "arn:1"}, "severity": {"normalized": "CRITICAL"}}]
    res = calculate_score(findings, resource_count=1)
    # uncapped = 1.0, capped = 1.0. D = 1.0. U = 0
    # score = 1000 * exp(-0.6 * 1.0) = 548.8 -> 549
    assert res["score"] == 549
    assert res["risk_band"] == "MODERATE_RISK"

def test_one_high_finding():
    findings = [{"resource": {"arn": "arn:1"}, "severity": {"normalized": "HIGH"}}]
    res = calculate_score(findings, resource_count=1)
    # D = 0.8. score = 1000 * exp(-0.6 * 0.8) = 618.78 -> 619
    assert res["score"] == 619

def test_multiple_severities_one_resource():
    findings = [
        {"resource": {"arn": "arn:1"}, "severity": {"normalized": "HIGH"}},
        {"resource": {"arn": "arn:1"}, "severity": {"normalized": "MEDIUM"}},
    ]
    res = calculate_score(findings, resource_count=1)
    # uncapped = 0.8 + 0.5 = 1.3
    # D = 1.3
    assert res["resource_penalties"][0]["raw_confirmed_penalty"] == 1.3
    assert res["resource_penalties"][0]["cap_applied"] == False
    assert res["D"] == 1.3

def test_resource_penalty_cap_applied():
    findings = [
        {"resource": {"arn": "arn:1"}, "severity": {"normalized": "CRITICAL"}},
        {"resource": {"arn": "arn:1"}, "severity": {"normalized": "CRITICAL"}},
    ]
    res = calculate_score(findings, resource_count=1)
    # uncapped = 2.0, capped = 1.5
    assert res["resource_penalties"][0]["raw_confirmed_penalty"] == 2.0
    assert res["resource_penalties"][0]["capped_confirmed_penalty"] == 1.5
    assert res["resource_penalties"][0]["cap_applied"] == True

def test_resource_penalty_exactly_equal_to_cap():
    findings = [
        {"resource": {"arn": "arn:1"}, "severity": {"normalized": "CRITICAL"}},
        {"resource": {"arn": "arn:1"}, "severity": {"normalized": "MEDIUM"}},
    ]
    res = calculate_score(findings, resource_count=1)
    # uncapped = 1.5, capped = 1.5
    assert res["resource_penalties"][0]["raw_confirmed_penalty"] == 1.5
    assert res["resource_penalties"][0]["capped_confirmed_penalty"] == 1.5
    assert res["resource_penalties"][0]["cap_applied"] == False

def test_findings_distributed_across_several_resources():
    findings = [
        {"resource": {"arn": "arn:1"}, "severity": {"normalized": "HIGH"}},
        {"resource": {"arn": "arn:2"}, "severity": {"normalized": "HIGH"}},
    ]
    res = calculate_score(findings, resource_count=2)
    assert len(res["resource_penalties"]) == 2
    assert res["D"] == 0.8

def test_unknown_severity_calculation_triggers_review():
    findings = [{"resource": {"arn": "arn:1"}, "severity": {"normalized": "WEIRD"}}]
    res = calculate_score(findings, resource_count=1)
    assert res["unknown_count"] == 1
    assert res["U"] == 1.0
    assert res["D"] == 0.0
    assert res["review_required"] == True
    assert res["unknown_findings_present"] == True

def test_resource_arn_grouping():
    findings = [
        {"resource": {"arn": "arn:aws:s3:::b1"}, "severity": {"normalized": "HIGH"}},
        {"resource": {"arn": "arn:aws:s3:::b1", "id": "b1"}, "severity": {"normalized": "LOW"}},
    ]
    res = calculate_score(findings, resource_count=1)
    assert len(res["resource_penalties"]) == 1
    assert res["resource_penalties"][0]["resource_key"] == "arn:aws:s3:::b1"

def test_resource_id_fallback():
    findings = [{"resource": {"id": "b1"}, "severity": {"normalized": "HIGH"}}]
    res = calculate_score(findings, resource_count=1)
    assert res["resource_penalties"][0]["resource_key"] == "b1"

def test_resource_name_fallback():
    findings = [{"resource": {"name": "b1"}, "severity": {"normalized": "HIGH"}}]
    res = calculate_score(findings, resource_count=1)
    assert res["resource_penalties"][0]["resource_key"] == "b1"

def test_score_clamping():
    # If D was huge or something weird, it should clamp.
    # Actually exponential is always <= 1.0, so max score is 1000.
    # We can fake a very negative D if we want >1000, or huge D for <0.
    res = calculate_score([], resource_count=1, alpha=-100.0, beta=0.0)
    assert res["score"] == 1000 # Clamped 1000

@patch("scripts.risk.calculate_postdeployment_risk_score.sys.exit")
@patch("scripts.risk.calculate_postdeployment_risk_score.safe_write_json")
def test_write_not_calculated(mock_write, mock_exit, tmp_path):
    _write_not_calculated(tmp_path, "SCAN-123", "REASON")
    mock_exit.assert_called_once_with(1)
    mock_write.assert_called_once()
    args = mock_write.call_args[0]
    assert args[1]["status"] == "NOT_CALCULATED"

@patch("scripts.risk.calculate_postdeployment_risk_score.sys.exit")
def test_main_missing_execution(mock_exit, tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.risk.calculate_postdeployment_risk_score.ROOT_DIR", tmp_path)
    monkeypatch.setattr("sys.argv", ["script", "SCAN-123"])
    
    mock_exit.side_effect = SystemExit
    
    with pytest.raises(SystemExit):
        main()

@patch("scripts.risk.calculate_postdeployment_risk_score.sys.exit")
def test_main_execution_error(mock_exit, tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.risk.calculate_postdeployment_risk_score.ROOT_DIR", tmp_path)
    monkeypatch.setattr("sys.argv", ["script", "SCAN-123"])
    
    scan_dir = tmp_path / "reports" / "runtime" / "SCAN-123"
    scan_dir.joinpath("prowler").mkdir(parents=True, exist_ok=True)
    scan_dir.joinpath("prowler", "prowler-execution.json").write_text(json.dumps({
        "execution": {"status": "EXECUTION_ERROR"}
    }))
    
    mock_exit.side_effect = SystemExit
    with pytest.raises(SystemExit):
        main()

@patch("scripts.risk.calculate_postdeployment_risk_score._print_console")
def test_main_success_no_findings(mock_print, tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.risk.calculate_postdeployment_risk_score.ROOT_DIR", tmp_path)
    monkeypatch.setattr("sys.argv", ["script", "SCAN-123"])
    
    scan_dir = tmp_path / "reports" / "runtime" / "SCAN-123"
    scan_dir.joinpath("prowler").mkdir(parents=True, exist_ok=True)
    scan_dir.joinpath("scope").mkdir(parents=True, exist_ok=True)
    scan_dir.joinpath("normalized").mkdir(parents=True, exist_ok=True)
    
    scan_dir.joinpath("prowler", "prowler-execution.json").write_text(json.dumps({
        "execution": {"status": "SUCCESS_NO_FINDINGS"}
    }))
    scan_dir.joinpath("scope", "tagged-resources.json").write_text(json.dumps({
        "ResourceTagMappingList": [{"ResourceARN": "arn:1"}, {"ResourceARN": "arn:2"}]
    }))
    scan_dir.joinpath("normalized", "runtime-findings.json").write_text(json.dumps({
        "findings": []
    }))
    
    main()
    
    risk_dir = scan_dir / "risk"
    out_json = risk_dir / "postdeployment-risk-score.json"
    assert out_json.exists()
    
    data = json.loads(out_json.read_text())
    assert data["status"] == "CALCULATED"
    assert data["score"]["post_deployment_risk_score"] == 1000
    assert data["inputs"]["resource_count"] == 2
    assert data["inputs"]["resource_count_source"] == "tagged_resources_discovered"

    out_md = risk_dir / "postdeployment-risk-score.md"
    assert out_md.exists()
    assert "Score: `1000 / 1000`" in out_md.read_text()
    assert "Risk Band: **VERY_LOW_RISK**" in out_md.read_text()

@patch("scripts.risk.calculate_postdeployment_risk_score._print_console")
def test_main_success_with_findings(mock_print, tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.risk.calculate_postdeployment_risk_score.ROOT_DIR", tmp_path)
    monkeypatch.setattr("sys.argv", ["script", "SCAN-123"])
    
    scan_dir = tmp_path / "reports" / "runtime" / "SCAN-123"
    scan_dir.joinpath("prowler").mkdir(parents=True, exist_ok=True)
    scan_dir.joinpath("scope").mkdir(parents=True, exist_ok=True)
    scan_dir.joinpath("normalized").mkdir(parents=True, exist_ok=True)
    
    scan_dir.joinpath("prowler", "prowler-execution.json").write_text(json.dumps({
        "execution": {"status": "SUCCESS_WITH_FINDINGS"}
    }))
    # Note: No tagged resources file, fallback to unique resources from findings
    scan_dir.joinpath("normalized", "runtime-findings.json").write_text(json.dumps({
        "findings": [
            {"resource": {"id": "res1"}, "severity": {"normalized": "HIGH"}}
        ]
    }))
    
    main()
    
    risk_dir = scan_dir / "risk"
    out_json = risk_dir / "postdeployment-risk-score.json"
    assert out_json.exists()
    
    data = json.loads(out_json.read_text())
    assert data["inputs"]["resource_count"] == 1
    assert data["inputs"]["resource_count_source"] == "unique_normalized_finding_resources"
    assert data["score"]["post_deployment_risk_score"] == 619
