"""
scripts/deployment/resource_verifiers/base.py

Abstract base class for all resource verifiers.

Each verifier must implement ``verify`` which receives a resource inventory
record and returns a standardised verification result dict.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Retry configuration
# ---------------------------------------------------------------------------
MAX_ATTEMPTS = 5
INITIAL_DELAY = 5       # seconds
BACKOFF_FACTOR = 2
MAX_DELAY = 30          # seconds

# ---------------------------------------------------------------------------
# Verification status values
# ---------------------------------------------------------------------------
STATUS_VERIFIED = "VERIFIED"
STATUS_VERIFIED_WITH_WARNING = "VERIFIED_WITH_WARNING"
STATUS_NOT_FOUND = "NOT_FOUND"
STATUS_ACCESS_DENIED = "ACCESS_DENIED"
STATUS_UNSUPPORTED = "UNSUPPORTED"
STATUS_INVALID_IDENTITY = "INVALID_IDENTITY"
STATUS_ERROR = "ERROR"

from scripts.utils.evidence import utc_now_iso


class BaseVerifier(ABC):
    """Abstract base class for AWS resource verifiers."""

    # The boto3 service client name to use (e.g. "s3", "ec2")
    service: str = ""

    def _client(self, region: str | None = None):
        kwargs = {}
        if region:
            kwargs["region_name"] = region
        return boto3.client(self.service, **kwargs)

    def _with_retry(self, fn, *args, **kwargs):
        """
        Call fn(*args, **kwargs) with bounded exponential back-off.

        Returns (result, attempts, None) on success.
        Returns (None, attempts, error_str) on exhaustion.
        """
        delay = INITIAL_DELAY
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                result = fn(*args, **kwargs)
                return result, attempt, None
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
                    return None, attempt, f"ACCESS_DENIED: {exc}"
                if code in ("NoSuchBucket", "NoSuchEntity", "DBInstanceNotFound",
                            "InvalidKeyId.NotFound", "NotFoundException",
                            "NoSuchKey", "ResourceNotFoundException"):
                    return None, attempt, f"NOT_FOUND: {exc}"
                # Retryable: ThrottlingException, etc.
                if attempt < MAX_ATTEMPTS:
                    time.sleep(min(delay, MAX_DELAY))
                    delay *= BACKOFF_FACTOR
                else:
                    return None, attempt, f"ERROR: {exc}"
            except Exception as exc:
                return None, attempt, f"ERROR: {exc}"

    def _result(
        self,
        resource: dict,
        exists: bool,
        lifecycle_state: str,
        tags_valid: bool | None,
        status: str,
        method: str,
        attempts: int,
        errors: list[str],
        warnings: list[str],
    ) -> dict:
        return {
            "terraform_address": resource.get("terraform_address"),
            "terraform_type": resource.get("terraform_type"),
            "resource_id": resource.get("resource_id"),
            "resource_arn": resource.get("resource_arn"),
            "exists": exists,
            "lifecycle_state": lifecycle_state,
            "framework_tags_valid": tags_valid,
            "verification_status": status,
            "verification_method": method,
            "attempts": attempts,
            "verified_at_utc": utc_now_iso(),
            "errors": errors,
            "warnings": warnings,
        }

    @abstractmethod
    def verify(self, resource: dict, scan_id: str) -> dict:
        """
        Verify the given resource exists and has correct framework tags.

        Args:
            resource: A record from terraform-state-resource-inventory.json
            scan_id:  The current SCAN_ID

        Returns:
            Standardised verification result dict.
        """


def _check_framework_tags(tags: dict, scan_id: str) -> tuple[bool, list[str]]:
    """
    Verify scan-id and managed-by tags.

    Returns (all_valid, list_of_warnings).
    """
    warnings: list[str] = []
    ok = True
    if tags.get("scan-id") != scan_id:
        warnings.append(
            f"scan-id tag mismatch: expected={scan_id} actual={tags.get('scan-id')}"
        )
        ok = False
    if tags.get("managed-by") != "iac-security-framework":
        warnings.append(
            f"managed-by tag mismatch: expected=iac-security-framework "
            f"actual={tags.get('managed-by')}"
        )
        ok = False
    return ok, warnings
