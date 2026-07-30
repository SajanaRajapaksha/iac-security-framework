import json
import pytest
from pathlib import Path
from scripts.deployment.build_state_resource_inventory import (
    process_resource_values, infer_aws_service, walk_resources
)
from scripts.runtime.normalize_runtime_findings import match_resource

# Mock Fixtures
MOCK_STATE = {
    "values": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.root_bucket",
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "name": "root_bucket",
                    "provider_name": "aws",
                    "values": {
                        "id": "my-root-bucket",
                        "arn": "arn:aws:s3:::my-root-bucket",
                        "region": "eu-west-1",
                        "tags": {"scan-id": "SCAN-123", "managed-by": "iac-security-framework"}
                    }
                },
                {
                    "address": "aws_instance.server[0]",
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "server",
                    "index": 0,
                    "provider_name": "aws",
                    "values": {
                        "id": "i-1234567890abcdef0",
                        "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
                        "availability_zone": "us-east-1a",
                        "tags": {"ResearchScanId": "SCAN-123"}
                    }
                },
                {
                    "address": "aws_iam_role.my_role",
                    "mode": "managed",
                    "type": "aws_iam_role",
                    "name": "my_role",
                    "provider_name": "aws",
                    "values": {
                        "id": "my_role",
                        "arn": "arn:aws:iam::123456789012:role/my_role",
                        "name": "my_role",
                        "tags": {"research-scan-id": "SCAN-123"}
                    }
                }
            ],
            "child_modules": [
                {
                    "address": "module.vpc",
                    "resources": [
                        {
                            "address": "module.vpc.aws_vpc.main",
                            "mode": "managed",
                            "type": "aws_vpc",
                            "name": "main",
                            "provider_name": "aws",
                            "values": {
                                "id": "vpc-0abc123",
                                "arn": "arn:aws:ec2:eu-west-1:123456789012:vpc/vpc-0abc123",
                                "tags": {}
                            }
                        }
                    ]
                }
            ]
        }
    }
}

MANIFEST_RESOURCES = [
    {
        "resource_arn": "arn:aws:s3:::my-root-bucket",
        "resource_id": "my-root-bucket",
        "resource_name": "my-root-bucket",
        "aws_service": "s3",
        "tags": {"scan-id": "SCAN-123"}
    },
    {
        "resource_arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        "resource_id": "i-1234567890abcdef0",
        "aws_service": "ec2",
        "tags": {"ResearchScanId": "SCAN-123"}
    }
]

def test_infer_aws_service():
    assert infer_aws_service("aws_security_group") == "ec2"
    assert infer_aws_service("aws_s3_bucket") == "s3"
    assert infer_aws_service("aws_iam_role") == "iam"
    assert infer_aws_service("aws_rds_cluster") == "rds"
    assert infer_aws_service("aws_random_pet") == "unknown"

def test_az_to_region_conversion():
    resource = MOCK_STATE["values"]["root_module"]["resources"][1]
    parsed = process_resource_values(resource["values"], "", resource)
    assert parsed["aws_region"] == "us-east-1"

def test_walk_resources_all_types():
    records = walk_resources(MOCK_STATE)
    assert len(records) == 4
    
    s3_rec = next(r for r in records if r["terraform_type"] == "aws_s3_bucket")
    assert s3_rec["terraform_address"] == "aws_s3_bucket.root_bucket"
    assert s3_rec["aws_region"] == "eu-west-1"
    
    ec2_rec = next(r for r in records if r["terraform_type"] == "aws_instance")
    assert ec2_rec["terraform_address"] == "aws_instance.server[0]"
    
    iam_rec = next(r for r in records if r["terraform_type"] == "aws_iam_role")
    assert iam_rec["aws_service"] == "iam"
    
    vpc_rec = next(r for r in records if r["terraform_type"] == "aws_vpc")
    assert vpc_rec["terraform_address"] == "module.vpc.aws_vpc.main"

def test_match_exact_arn():
    finding = {"ResourceArn": "arn:aws:s3:::my-root-bucket"}
    r, method, reason = match_resource(finding, MANIFEST_RESOURCES, "SCAN-123")
    assert method == "RESOURCE_ARN"
    assert r["resource_id"] == "my-root-bucket"

def test_match_exact_id():
    finding = {"ResourceId": "i-1234567890abcdef0", "AccountId": "123456789012", "Region": "us-east-1"}
    r, method, reason = match_resource(finding, MANIFEST_RESOURCES, "SCAN-123")
    assert method == "RESOURCE_ID"

def test_match_scan_id_tag():
    finding = {"Tags": {"scan-id": "SCAN-123"}}
    r, method, reason = match_resource(finding, MANIFEST_RESOURCES, "SCAN-123")
    assert method == "SCAN_ID_TAG"

def test_match_legacy_tag():
    finding = {"Tags": {"ResearchScanId": "SCAN-123"}}
    r, method, reason = match_resource(finding, MANIFEST_RESOURCES, "SCAN-123")
    assert method == "SCAN_ID_TAG"
    
def test_match_tag_mismatch():
    finding = {"Tags": {"scan-id": "SCAN-999"}}
    r, method, reason = match_resource(finding, MANIFEST_RESOURCES, "SCAN-123")
    assert method == "UNMATCHED"

def test_account_level_finding():
    finding = {"ResourceId": "123456789012", "AccountId": "123456789012"}
    r, method, reason = match_resource(finding, MANIFEST_RESOURCES, "SCAN-123")
    assert method == "ACCOUNT_LEVEL"

def test_unmatched_reasons():
    finding = {"ResourceId": "unknown-id", "AccountId": "1234", "Region": "us-east-1"}
    r, method, reason = match_resource(finding, MANIFEST_RESOURCES, "SCAN-123")
    assert method == "UNMATCHED"
    assert reason == "RESOURCE_ID_NOT_IN_MANIFEST"
    
    finding = {"ServiceName": "sqs"}
    r, method, reason = match_resource(finding, MANIFEST_RESOURCES, "SCAN-123")
    assert method == "UNMATCHED"
    assert reason == "SERVICE_MISMATCH"
