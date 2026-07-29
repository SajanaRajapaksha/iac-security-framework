"""scripts/deployment/resource_verifiers/s3.py — S3 resource verifier."""

from __future__ import annotations
from botocore.exceptions import ClientError
from scripts.deployment.resource_verifiers.base import (
    BaseVerifier, STATUS_VERIFIED, STATUS_VERIFIED_WITH_WARNING,
    STATUS_NOT_FOUND, STATUS_ACCESS_DENIED, STATUS_ERROR, STATUS_INVALID_IDENTITY,
    _check_framework_tags,
)


class S3Verifier(BaseVerifier):
    service = "s3"

    # Sub-resource types that are verified through the parent bucket
    SUB_RESOURCE_TYPES = {
        "aws_s3_bucket_public_access_block",
        "aws_s3_bucket_versioning",
        "aws_s3_bucket_server_side_encryption_configuration",
    }

    def _get_bucket_name(self, resource: dict) -> str | None:
        rid = resource.get("resource_id") or ""
        rname = resource.get("resource_name") or ""
        return rid or rname or None

    def verify(self, resource: dict, scan_id: str) -> dict:
        rtype = resource.get("terraform_type", "")
        bucket = self._get_bucket_name(resource)
        errors: list[str] = []
        warnings: list[str] = []
        method = "s3.head_bucket"

        if not bucket:
            return self._result(resource, False, "UNKNOWN", None,
                                STATUS_INVALID_IDENTITY, method, 0,
                                ["Cannot determine bucket name from resource identity"], [])

        client = self._client()

        # 1. Check bucket exists via head_bucket
        resp, attempts, err = self._with_retry(client.head_bucket, Bucket=bucket)
        if err:
            if "ACCESS_DENIED" in err:
                return self._result(resource, True, "EXISTS_ACCESS_DENIED", None,
                                    STATUS_ACCESS_DENIED, method, attempts,
                                    [err], [])
            if "NOT_FOUND" in err:
                return self._result(resource, False, "NOT_FOUND", None,
                                    STATUS_NOT_FOUND, method, attempts, [err], [])
            return self._result(resource, False, "ERROR", None,
                                STATUS_ERROR, method, attempts, [err], [])

        # 2. Check tags on parent bucket
        tag_resp, tag_attempts, tag_err = self._with_retry(
            client.get_bucket_tagging, Bucket=bucket
        )
        tags_valid = None
        if tag_err:
            if "NOT_FOUND" in tag_err or "NoSuchTagSet" in tag_err:
                tags_valid = False
                warnings.append("Bucket has no tags — framework tags not applied")
            else:
                warnings.append(f"Could not retrieve bucket tags: {tag_err}")
        else:
            raw_tags = tag_resp.get("TagSet", [])
            tag_dict = {t["Key"]: t["Value"] for t in raw_tags}
            ok, tag_warnings = _check_framework_tags(tag_dict, scan_id)
            tags_valid = ok
            warnings.extend(tag_warnings)

        status = STATUS_VERIFIED if tags_valid else STATUS_VERIFIED_WITH_WARNING
        return self._result(resource, True, "AVAILABLE", tags_valid,
                            status, method, attempts + tag_attempts, errors, warnings)
