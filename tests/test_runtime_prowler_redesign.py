import pytest
from scripts.runtime.normalize_runtime_findings import match_resource, _normalize_severity

def test_normalize_severity():
    assert _normalize_severity("critical") == "CRITICAL"
    assert _normalize_severity("high") == "HIGH"
    assert _normalize_severity("medium") == "MEDIUM"
    assert _normalize_severity("low") == "LOW"
    assert _normalize_severity("informational") == "INFORMATIONAL"
    assert _normalize_severity("unknown") == "UNKNOWN"
    assert _normalize_severity("") == "UNKNOWN"

def test_match_resource_deployment():
    finding = {
        "ResourceArn": "arn:aws:s3:::my-bucket",
        "ResourceId": "my-bucket",
        "AccountId": "123456789012",
        "Region": "us-east-1",
        "Tags": {"scan-id": "SCAN-123"}
    }
    manifest = [
        {"resource_arn": "arn:aws:s3:::my-bucket", "resource_id": "my-bucket"}
    ]
    matched, method, reason = match_resource(finding, manifest, "SCAN-123")
    assert matched is not None
    assert method == "RESOURCE_ARN"
    assert reason is None

def test_match_resource_account_level():
    finding = {
        "ResourceId": "123456789012",
        "AccountId": "123456789012",
        "Region": "us-east-1"
    }
    manifest = [
        {"resource_arn": "arn:aws:s3:::my-bucket"}
    ]
    matched, method, reason = match_resource(finding, manifest, "SCAN-123")
    assert matched is None
    assert method == "ACCOUNT_LEVEL"
    assert reason is None

def test_match_resource_unmatched():
    finding = {
        "ResourceId": "other-bucket",
        "AccountId": "123456789012",
        "Region": "us-east-1",
        "ServiceName": "s3"
    }
    manifest = [
        {"resource_arn": "arn:aws:s3:::my-bucket"}
    ]
    matched, method, reason = match_resource(finding, manifest, "SCAN-123")
    assert matched is None
    assert method == "UNMATCHED"
    assert reason == "RESOURCE_ID_NOT_IN_MANIFEST"
