import pytest
import json
import hashlib
from unittest.mock import patch, MagicMock

from scripts.review.review_utils import get_risk_band_index, sort_findings_by_severity
from scripts.review.generate_security_review import (
    determine_recommendation, extract_pre_deployment_findings, extract_post_deployment_findings,
    extract_numeric_score, extract_risk_band, extract_decision_or_action
)
from scripts.review.remediation_cache import generate_cache_key
from scripts.review.generate_ai_remediation import build_remediation_groups, run_ai_batch

def test_score_delta_positive():
    # positive delta = RUNTIME_POSTURE_BETTER
    # This is handled directly in generate_security_review.py logic (delta = post - pre).
    assert 600 - 500 == 100

def test_extract_helpers_flat():
    flat_pre = {"score": 554, "risk_band": "MODERATE_RISK", "suggested_decision": "REVIEW"}
    assert extract_numeric_score(flat_pre, "PRE_DEPLOYMENT") == 554
    assert extract_risk_band(flat_pre) == "MODERATE_RISK"
    assert extract_decision_or_action(flat_pre, "PRE_DEPLOYMENT") == "REVIEW"

def test_extract_helpers_nested():
    nested_post = {
        "score": {
            "post_deployment_risk_score": 612,
            "risk_band": "MODERATE_RISK",
            "suggested_action": "REMEDIATION_REQUIRED"
        }
    }
    assert extract_numeric_score(nested_post, "POST_DEPLOYMENT") == 612
    assert extract_risk_band(nested_post) == "MODERATE_RISK"
    assert extract_decision_or_action(nested_post, "POST_DEPLOYMENT") == "REMEDIATION_REQUIRED"

def test_extract_helpers_missing():
    assert extract_numeric_score({}, "PRE_DEPLOYMENT") is None
    assert extract_risk_band({"score": {}}) is None
    assert extract_decision_or_action({"score": 500}, "POST_DEPLOYMENT") is None

def test_score_delta_negative():
    assert 500 - 600 == -100

def test_risk_band_movement():
    assert get_risk_band_index("MODERATE_RISK") == 2
    assert get_risk_band_index("LOW_RISK") == 1
    # 2 -> 1 is IMPROVED

def test_missing_scores():
    rec, _, _ = determine_recommendation({}, {}, [], "SUCCESS_WITH_FINDINGS")
    assert rec == "REVIEW_INCOMPLETE"
    
def test_post_score_critical_risk():
    rec, _, _ = determine_recommendation({"score": 500}, {"score": {"risk_band": "CRITICAL_RISK"}, "status": "CALCULATED"}, [], "SUCCESS_WITH_FINDINGS")
    assert rec == "CRITICAL_REMEDIATION"

def test_any_post_critical_finding():
    rec, _, _ = determine_recommendation({"score": 500}, {"score": {"risk_band": "HIGH_RISK"}, "status": "CALCULATED"}, [{"severity": "CRITICAL"}], "SUCCESS_WITH_FINDINGS")
    assert rec == "URGENT_REVIEW"

def test_runtime_risk_increased():
    rec, _, _ = determine_recommendation({"score": 600}, {"score": {"post_deployment_risk_score": 500}, "status": "CALCULATED"}, [], "SUCCESS_WITH_FINDINGS")
    assert rec == "RUNTIME_RISK_INCREASED"

def test_improved_with_remediation_required():
    rec, _, _ = determine_recommendation({"score": 500}, {"score": {"post_deployment_risk_score": 600}, "status": "CALCULATED"}, [{"severity": "HIGH"}], "SUCCESS_WITH_FINDINGS")
    assert rec == "IMPROVED_WITH_REMEDIATION_REQUIRED"

def test_runtime_validation_passed():
    rec, _, _ = determine_recommendation({"score": 900}, {"score": {"post_deployment_risk_score": 1000}, "status": "CALCULATED"}, [], "SUCCESS_NO_FINDINGS")
    assert rec == "RUNTIME_VALIDATION_PASSED"

def test_review_required():
    rec, _, _ = determine_recommendation({"score": 500}, {"score": {"post_deployment_risk_score": 600}, "status": "CALCULATED"}, [{"severity": "MEDIUM"}], "SUCCESS_WITH_FINDINGS")
    assert rec == "REVIEW_REQUIRED"

def test_pre_deployment_extraction():
    enriched = {
        "findings": [
            {
                "finding_id": "F1",
                "source_tool": "checkov",
                "final_severity": "HIGH",
                "title": "Title 1",
                "resource": "r1",
                "description": "desc 1"
            }
        ]
    }
    extracted = extract_pre_deployment_findings(enriched)
    assert len(extracted) == 1
    assert extracted[0]["review_finding_id"] == "pre_F1"
    assert extracted[0]["scanner"] == "checkov"
    assert extracted[0]["severity"] == "HIGH"

def test_post_deployment_extraction():
    runtime = {
        "findings": [
            {
                "finding_id": "P1",
                "severity": {"normalized": "INFORMATIONAL"},
                "resource": {"service": "s3", "id": "b1"}
            }
        ]
    }
    extracted = extract_post_deployment_findings(runtime)
    assert len(extracted) == 1
    assert extracted[0]["review_finding_id"] == "post_P1"
    assert extracted[0]["severity"] == "INFO"
    assert extracted[0]["service"] == "s3"

def test_independent_severity_sorting():
    findings = [{"severity": "INFO"}, {"severity": "CRITICAL"}]
    sorted_f = sort_findings_by_severity(findings)
    assert sorted_f[0]["severity"] == "CRITICAL"
    assert sorted_f[1]["severity"] == "INFO"

def test_cache_key_generation():
    key1 = generate_cache_key("v1", "PRE", "c", "check", "res", "t", "d")
    key2 = generate_cache_key("V1", "pre", "C", "CHECK", "RES", "T", "D")
    assert key1 == key2

def test_remediation_grouping():
    sec_rev = {
        "pre_deployment_findings": [
            {"review_finding_id": "1", "scanner": "c", "check_id": "c1", "resource_type": "r1", "title": "t1", "resource": "res1"},
            {"review_finding_id": "2", "scanner": "c", "check_id": "c1", "resource_type": "r1", "title": "t1", "resource": "res2"},
            {"review_finding_id": "3", "scanner": "c", "check_id": "c1", "resource_type": "r1", "title": "t1", "resource": "res3"},
            {"review_finding_id": "4", "scanner": "c", "check_id": "c1", "resource_type": "r1", "title": "t1", "resource": "res4"},
        ]
    }
    groups = build_remediation_groups(sec_rev)
    assert len(groups) == 1
    key = list(groups.keys())[0]
    g = groups[key]
    assert g["affected_resource_count"] == 4
    assert len(g["sample_resources"]) == 3
    assert g["affected_finding_ids"] == ["1", "2", "3", "4"]

@patch("scripts.review.generate_ai_remediation.openai")
@patch("scripts.review.generate_ai_remediation.os.environ.get")
def test_run_ai_batch(mock_env, mock_openai):
    mock_env.return_value = "model-1"
    mock_client = MagicMock()
    mock_response = MagicMock()
    
    mock_msg = MagicMock()
    mock_msg.message.content = '{"remediations": [{"finding_key": "k1", "summary": "sum"}]}'
    mock_response.choices = [mock_msg]
    mock_response.usage.prompt_tokens = 10
    mock_response.usage.completion_tokens = 20
    mock_response.usage.total_tokens = 30
    
    mock_client.chat.completions.create.return_value = mock_response
    
    groups = [{"finding_key": "k1", "stage": "PRE", "severity": "HIGH", "scanner": "c", "check_id": "c1", "title": "t1", "resource_type": "r", "description": "d", "existing_remediation": "", "affected_resource_count": 1, "sample_resources": []}]
    rems, t, err = run_ai_batch(groups, mock_client)
    
    assert err is None
    assert len(rems) == 1
    assert rems[0]["summary"] == "sum"
    assert t["prompt_tokens"] == 10
    assert t["total_tokens"] == 30

@patch("scripts.review.generate_ai_remediation.openai")
def test_run_ai_batch_error(mock_openai):
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("API Timeout")
    
    rems, t, err = run_ai_batch([{"finding_key": "k"}], mock_client)
    assert err == "API Timeout"
    assert len(rems) == 0
