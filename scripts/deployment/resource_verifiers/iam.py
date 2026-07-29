"""scripts/deployment/resource_verifiers/iam.py — IAM resource verifier."""

from __future__ import annotations
from scripts.deployment.resource_verifiers.base import (
    BaseVerifier, STATUS_VERIFIED, STATUS_VERIFIED_WITH_WARNING,
    STATUS_NOT_FOUND, STATUS_ACCESS_DENIED, STATUS_ERROR, STATUS_INVALID_IDENTITY,
    _check_framework_tags,
)


class IAMVerifier(BaseVerifier):
    service = "iam"

    def _get_tags(self, client, rtype: str, resource_id: str) -> tuple[dict, str | None]:
        """Return (tag_dict, error_str)."""
        try:
            if rtype == "aws_iam_role":
                resp = client.list_role_tags(RoleName=resource_id)
            elif rtype == "aws_iam_user":
                resp = client.list_user_tags(UserName=resource_id)
            elif rtype == "aws_iam_policy":
                resp = client.list_policy_tags(PolicyArn=resource_id)
            else:
                return {}, None
            raw = resp.get("Tags", [])
            return {t["Key"]: t["Value"] for t in raw}, None
        except Exception as exc:
            return {}, str(exc)

    def verify(self, resource: dict, scan_id: str) -> dict:
        rtype = resource.get("terraform_type", "")
        resource_id = resource.get("resource_id") or resource.get("resource_arn") or ""
        errors: list[str] = []
        warnings: list[str] = []
        client = self._client()

        if not resource_id:
            return self._result(resource, False, "UNKNOWN", None,
                                STATUS_INVALID_IDENTITY, "iam.verify", 0,
                                ["No IAM resource identifier available"], [])

        # Determine verify method per type
        if rtype == "aws_iam_role":
            fn = lambda: client.get_role(RoleName=resource_id)
            method = "iam.get_role"
        elif rtype == "aws_iam_user":
            fn = lambda: client.get_user(UserName=resource_id)
            method = "iam.get_user"
        elif rtype == "aws_iam_policy":
            fn = lambda: client.get_policy(PolicyArn=resource_id)
            method = "iam.get_policy"
        elif rtype == "aws_iam_group":
            fn = lambda: client.get_group(GroupName=resource_id)
            method = "iam.get_group"
        else:
            return self._result(resource, False, "UNKNOWN", None,
                                "UNSUPPORTED", "iam.verify", 0,
                                [f"IAM verifier does not support {rtype}"], [])

        resp, attempts, err = self._with_retry(fn)
        if err:
            if "ACCESS_DENIED" in err:
                return self._result(resource, True, "EXISTS_ACCESS_DENIED", None,
                                    STATUS_ACCESS_DENIED, method, attempts, [err], [])
            if "NOT_FOUND" in err or "NoSuchEntity" in err:
                return self._result(resource, False, "NOT_FOUND", None,
                                    STATUS_NOT_FOUND, method, attempts, [err], [])
            return self._result(resource, False, "ERROR", None,
                                STATUS_ERROR, method, attempts, [err], [])

        # IAM groups don't support tags — mark as VERIFIED_WITH_WARNING
        if rtype == "aws_iam_group":
            return self._result(resource, True, "AVAILABLE", None,
                                STATUS_VERIFIED_WITH_WARNING, method, attempts, errors,
                                ["IAM Groups do not support resource tags"])

        tag_dict, tag_err = self._get_tags(client, rtype, resource_id)
        if tag_err:
            warnings.append(f"Could not retrieve IAM tags: {tag_err}")
            return self._result(resource, True, "AVAILABLE", None,
                                STATUS_VERIFIED_WITH_WARNING, method, attempts, errors, warnings)

        ok, tag_warnings = _check_framework_tags(tag_dict, scan_id)
        warnings.extend(tag_warnings)
        status = STATUS_VERIFIED if ok else STATUS_VERIFIED_WITH_WARNING
        return self._result(resource, True, "AVAILABLE", ok,
                            status, method, attempts, errors, warnings)
