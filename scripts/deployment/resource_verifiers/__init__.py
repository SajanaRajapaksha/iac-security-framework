# scripts/deployment/resource_verifiers/__init__.py
"""
Resource verifier registry.

Import the factory function ``get_verifier`` to obtain the correct verifier
for a given Terraform resource type.
"""

from scripts.deployment.resource_verifiers.s3 import S3Verifier
from scripts.deployment.resource_verifiers.ec2 import EC2Verifier
from scripts.deployment.resource_verifiers.iam import IAMVerifier
from scripts.deployment.resource_verifiers.rds import RDSVerifier
from scripts.deployment.resource_verifiers.kms import KMSVerifier
from scripts.deployment.resource_verifiers.generic import GenericVerifier

# Map Terraform resource type → verifier class
VERIFIER_MAP: dict = {
    # S3
    "aws_s3_bucket": S3Verifier,
    "aws_s3_bucket_public_access_block": S3Verifier,
    "aws_s3_bucket_versioning": S3Verifier,
    "aws_s3_bucket_server_side_encryption_configuration": S3Verifier,
    # EC2 / VPC
    "aws_instance": EC2Verifier,
    "aws_security_group": EC2Verifier,
    "aws_vpc": EC2Verifier,
    "aws_subnet": EC2Verifier,
    "aws_route_table": EC2Verifier,
    "aws_internet_gateway": EC2Verifier,
    "aws_network_acl": EC2Verifier,
    # IAM
    "aws_iam_role": IAMVerifier,
    "aws_iam_policy": IAMVerifier,
    "aws_iam_user": IAMVerifier,
    "aws_iam_group": IAMVerifier,
    # RDS
    "aws_db_instance": RDSVerifier,
    "aws_rds_cluster": RDSVerifier,
    # KMS
    "aws_kms_key": KMSVerifier,
    "aws_kms_alias": KMSVerifier,
}


def get_verifier(terraform_type: str):
    """Return an instantiated verifier for the given Terraform resource type."""
    verifier_cls = VERIFIER_MAP.get(terraform_type, GenericVerifier)
    return verifier_cls()
