import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from scripts.runtime.normalize_runtime_findings import _normalize_severity, parse_ocsf, get_check_status, normalize_prowler
from scripts.runtime.run_prowler import run_prowler

def test_normalize_severity():
    assert _normalize_severity("critical") == "CRITICAL"
    assert _normalize_severity("high") == "HIGH"
    assert _normalize_severity("medium") == "MEDIUM"
    assert _normalize_severity("low") == "LOW"
    assert _normalize_severity("informational") == "INFORMATIONAL"
    assert _normalize_severity("info") == "INFORMATIONAL"
    assert _normalize_severity("unknown") == "UNKNOWN"
    assert _normalize_severity("") == "UNKNOWN"

def test_parse_ocsf_json_array(tmp_path):
    # Test JSON array OCSF output
    content = [{"status": "FAIL", "finding_info": {"uid": "test_uid"}}]
    f = tmp_path / "test.ocsf.json"
    f.write_text(json.dumps(content))
    
    parsed = parse_ocsf(f)
    assert len(parsed) == 1
    assert parsed[0]["finding_info"]["uid"] == "test_uid"

def test_parse_ocsf_ndjson(tmp_path):
    # Test NDJSON OCSF output
    f = tmp_path / "test.ocsf.json"
    f.write_text('{"status": "FAIL", "uid": "1"}\n{"status": "PASS", "uid": "2"}\n')
    
    parsed = parse_ocsf(f)
    assert len(parsed) == 2
    assert parsed[0]["uid"] == "1"
    assert parsed[1]["uid"] == "2"

def test_get_check_status():
    assert get_check_status({"status_code": "FAIL", "status": "New"}) == "FAIL"
    assert get_check_status({"status_code": "PASS", "status": "New"}) == "PASS"

def test_normalize_prowler_extraction(tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.runtime.normalize_runtime_findings.ROOT_DIR", tmp_path)
    
    scan_id = "SCAN-TEST"
    runtime_dir = tmp_path / "reports" / "runtime" / scan_id
    raw_dir = runtime_dir / "prowler" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    
    # Write mock execution JSON
    exec_path = runtime_dir / "prowler" / "prowler-execution.json"
    exec_path.write_text('{}')
    
    # Write mock OCSF
    ocsf_data = [
        {
            "status_code": "FAIL",
            "status": "New",
            "metadata": {"event_code": "test_check_1"},
            "unmapped": {"compliance": {"CIS": {"1.0": ["1.1"]}}},
            "resources": [{"uid": "arn:aws:s3:::test-bucket", "group": {"name": "s3"}}],
            "severity": "High"
        },
        {
            "status_code": "PASS",
            "status": "New",
            "metadata": {"event_code": "test_check_2"}
        }
    ]
    (raw_dir / "test.ocsf.json").write_text(json.dumps(ocsf_data))
    
    # Also write a mock registry to avoid error
    registry_path = tmp_path / "mappings" / "runtime" / "prowler-security-hub-standards.json"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text('{"checks": {}}')
    
    normalize_prowler(scan_id)
    
    norm_file = runtime_dir / "normalized" / "runtime-findings.json"
    assert norm_file.exists()
    
    data = json.loads(norm_file.read_text())
    
    # Ensure PASS was excluded, and FAIL was included
    assert data["summary"]["raw_findings"] == 1
    
    finding = data["findings"][0]
    
    # Check extraction logic
    assert finding["control_id"] == "TEST_CHECK_1"
    assert finding["resource"]["arn"] == "arn:aws:s3:::test-bucket"
    assert finding["resource"]["id"] == "test-bucket"
    
    # Check compliance
    assert len(finding["compliance"]) == 1
    assert finding["compliance"][0]["framework"] == "CIS"
    assert finding["compliance"][0]["control_id"] == "1.1"

@patch("scripts.runtime.run_prowler.boto3")
@patch("scripts.runtime.run_prowler.subprocess")
def test_run_prowler_success(mock_subprocess, mock_boto3, tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.runtime.run_prowler.ROOT_DIR", tmp_path)
    
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/Test"}
    
    mock_rg = MagicMock()
    mock_rg.get_resources.return_value = {"ResourceTagMappingList": [{"ResourceARN": "arn:test"}]}
    
    def boto3_client(service, **kwargs):
        if service == "sts":
            return mock_sts
        elif service == "resourcegroupstaggingapi":
            return mock_rg
    
    mock_boto3.client.side_effect = boto3_client
    mock_boto3.__version__ = "1.34.0"
    
    mock_proc = MagicMock()
    mock_proc.returncode = 3
    mock_proc.stdout = "{}"
    mock_proc.stderr = ""
    mock_subprocess.run.return_value = mock_proc
    mock_subprocess.PIPE = -1
    
    scan_id = "SCAN-123"
    run_prowler(scan_id)
    
    evidence_path = tmp_path / "reports" / "runtime" / scan_id / "prowler" / "prowler-execution.json"
    assert evidence_path.exists()
    
    data = json.loads(evidence_path.read_text())
    assert data["scan_scope"] == "TAGGED_DEPLOYMENT_RESOURCES_ONLY"
    assert data["execution"]["return_code"] == 3
    assert data["execution"]["status"] == "SUCCESS_WITH_FINDINGS"
    
    # Assert long options are used
    assert "--resource-tags" in data["command"]
    assert "scan-id=SCAN-123" in data["command"]
    assert "managed-by=iac-security-framework" in data["command"]
    assert "--output-modes" in data["command"]
    assert "json-ocsf" in data["command"]

@patch("scripts.runtime.run_prowler.boto3")
def test_run_prowler_empty_scope(mock_boto3, tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.runtime.run_prowler.ROOT_DIR", tmp_path)
    
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/Test"}
    
    mock_rg = MagicMock()
    mock_rg.get_resources.return_value = {"ResourceTagMappingList": []} # Empty scope
    
    def boto3_client(service, **kwargs):
        if service == "sts":
            return mock_sts
        elif service == "resourcegroupstaggingapi":
            return mock_rg
            
    mock_boto3.client.side_effect = boto3_client
    
    with pytest.raises(SystemExit) as excinfo:
        run_prowler("SCAN-123")
        
    assert excinfo.value.code == 1
    
    op_error_path = tmp_path / "reports" / "runtime" / "SCAN-123" / "normalized" / "runtime-operational-error.json"
    assert op_error_path.exists()
    
    data = json.loads(op_error_path.read_text())
    assert data["code"] == "SCAN_SCOPE_EMPTY"
    assert data["classification"] == "OPERATIONAL_ERROR"
