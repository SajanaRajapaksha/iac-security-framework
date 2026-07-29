"""scripts/deployment/resource_verifiers/kms.py — KMS resource verifier."""

from __future__ import annotations
from scripts.deployment.resource_verifiers.base import (
    BaseVerifier, STATUS_VERIFIED, STATUS_VERIFIED_WITH_WARNING,
    STATUS_NOT_FOUND, STATUS_ACCESS_DENIED, STATUS_ERROR, STATUS_INVALID_IDENTITY,
    _check_framework_tags,
)


class KMSVerifier(BaseVerifier):
    service = "kms"

    def verify(self, resource: dict, scan_id: str) -> dict:
        rtype = resource.get("terraform_type", "")
        resource_id = resource.get("resource_id") or resource.get("resource_arn") or ""
        errors: list[str] = []
        warnings: list[str] = []
        client = self._client()

        if rtype == "aws_kms_key":
            if not resource_id:
                return self._result(resource, False, "UNKNOWN", None,
                                    STATUS_INVALID_IDENTITY, "kms.describe_key", 0,
                                    ["No KMS key ID"], [])

            resp, attempts, err = self._with_retry(
                client.describe_key, KeyId=resource_id
            )
            if err:
                if "ACCESS_DENIED" in err:
                    return self._result(resource, True, "EXISTS_ACCESS_DENIED", None,
                                        STATUS_ACCESS_DENIED, "kms.describe_key", attempts,
                                        [err], [])
                if "NOT_FOUND" in err or "InvalidKeyId" in err:
                    return self._result(resource, False, "NOT_FOUND", None,
                                        STATUS_NOT_FOUND, "kms.describe_key", attempts,
                                        [err], [])
                return self._result(resource, False, "ERROR", None,
                                    STATUS_ERROR, "kms.describe_key", attempts, [err], [])

            key_state = resp.get("KeyMetadata", {}).get("KeyState", "unknown")

            # Get tags
            tag_resp, tag_attempts, tag_err = self._with_retry(
                client.list_resource_tags, KeyId=resource_id
            )
            if tag_err:
                warnings.append(f"Could not retrieve KMS tags: {tag_err}")
                return self._result(resource, True, key_state.upper(), None,
                                    STATUS_VERIFIED_WITH_WARNING, "kms.describe_key",
                                    attempts + (tag_attempts or 0), errors, warnings)

            raw = tag_resp.get("Tags", [])
            tag_dict = {t["TagKey"]: t["TagValue"] for t in raw}
            ok, tag_warnings = _check_framework_tags(tag_dict, scan_id)
            warnings.extend(tag_warnings)
            status = STATUS_VERIFIED if ok else STATUS_VERIFIED_WITH_WARNING
            return self._result(resource, True, key_state.upper(), ok,
                                status, "kms.describe_key",
                                attempts + (tag_attempts or 0), errors, warnings)

        elif rtype == "aws_kms_alias":
            alias_name = resource.get("resource_name") or resource_id
            if not alias_name:
                return self._result(resource, False, "UNKNOWN", None,
                                    STATUS_INVALID_IDENTITY, "kms.list_aliases", 0,
                                    ["No alias name"], [])

            resp, attempts, err = self._with_retry(
                client.list_aliases, KeyId=resource_id if resource_id else None
            )
            if err:
                return self._result(resource, False, "ERROR", None,
                                    STATUS_ERROR, "kms.list_aliases", attempts, [err], [])

            aliases = [a.get("AliasName") for a in resp.get("Aliases", [])]
            exists = alias_name in aliases or f"alias/{alias_name}" in aliases
            status = STATUS_VERIFIED if exists else STATUS_NOT_FOUND
            return self._result(resource, exists, "AVAILABLE" if exists else "NOT_FOUND",
                                None, status, "kms.list_aliases", attempts, errors,
                                ["KMS aliases do not support resource-level tagging"] if exists else [])

        return self._result(resource, False, "UNKNOWN", None,
                            "UNSUPPORTED", "kms.verify", 0,
                            [f"KMS verifier does not support {rtype}"], [])
