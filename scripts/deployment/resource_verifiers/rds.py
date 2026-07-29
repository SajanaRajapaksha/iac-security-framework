"""scripts/deployment/resource_verifiers/rds.py — RDS resource verifier."""

from __future__ import annotations
from scripts.deployment.resource_verifiers.base import (
    BaseVerifier, STATUS_VERIFIED, STATUS_VERIFIED_WITH_WARNING,
    STATUS_NOT_FOUND, STATUS_ACCESS_DENIED, STATUS_ERROR, STATUS_INVALID_IDENTITY,
    _check_framework_tags,
)


class RDSVerifier(BaseVerifier):
    service = "rds"

    def verify(self, resource: dict, scan_id: str) -> dict:
        rtype = resource.get("terraform_type", "")
        resource_id = resource.get("resource_id") or ""
        resource_arn = resource.get("resource_arn") or ""
        errors: list[str] = []
        warnings: list[str] = []
        client = self._client()

        if not resource_id:
            return self._result(resource, False, "UNKNOWN", None,
                                STATUS_INVALID_IDENTITY, "rds.verify", 0,
                                ["No RDS resource identifier"], [])

        if rtype == "aws_db_instance":
            method = "rds.describe_db_instances"
            resp, attempts, err = self._with_retry(
                client.describe_db_instances, DBInstanceIdentifier=resource_id
            )
            if err:
                if "ACCESS_DENIED" in err:
                    return self._result(resource, True, "EXISTS_ACCESS_DENIED", None,
                                        STATUS_ACCESS_DENIED, method, attempts, [err], [])
                if "NOT_FOUND" in err:
                    return self._result(resource, False, "NOT_FOUND", None,
                                        STATUS_NOT_FOUND, method, attempts, [err], [])
                return self._result(resource, False, "ERROR", None,
                                    STATUS_ERROR, method, attempts, [err], [])

            instances = resp.get("DBInstances", [])
            if not instances:
                return self._result(resource, False, "NOT_FOUND", None,
                                    STATUS_NOT_FOUND, method, attempts, [], [])

            db = instances[0]
            state = db.get("DBInstanceStatus", "unknown")
            db_arn = db.get("DBInstanceArn", resource_arn)

        elif rtype == "aws_rds_cluster":
            method = "rds.describe_db_clusters"
            resp, attempts, err = self._with_retry(
                client.describe_db_clusters, DBClusterIdentifier=resource_id
            )
            if err:
                if "ACCESS_DENIED" in err:
                    return self._result(resource, True, "EXISTS_ACCESS_DENIED", None,
                                        STATUS_ACCESS_DENIED, method, attempts, [err], [])
                if "NOT_FOUND" in err:
                    return self._result(resource, False, "NOT_FOUND", None,
                                        STATUS_NOT_FOUND, method, attempts, [err], [])
                return self._result(resource, False, "ERROR", None,
                                    STATUS_ERROR, method, attempts, [err], [])

            clusters = resp.get("DBClusters", [])
            if not clusters:
                return self._result(resource, False, "NOT_FOUND", None,
                                    STATUS_NOT_FOUND, method, attempts, [], [])

            db = clusters[0]
            state = db.get("Status", "unknown")
            db_arn = db.get("DBClusterArn", resource_arn)
        else:
            return self._result(resource, False, "UNKNOWN", None,
                                "UNSUPPORTED", "rds.verify", 0,
                                [f"RDS verifier does not support {rtype}"], [])

        # Get tags via ARN
        tag_resp, tag_attempts, tag_err = self._with_retry(
            client.list_tags_for_resource, ResourceName=db_arn
        )
        tags_valid = None
        if tag_err:
            warnings.append(f"Could not retrieve RDS tags: {tag_err}")
        else:
            raw = tag_resp.get("TagList", [])
            tag_dict = {t["Key"]: t["Value"] for t in raw}
            ok, tag_warnings = _check_framework_tags(tag_dict, scan_id)
            tags_valid = ok
            warnings.extend(tag_warnings)

        status = STATUS_VERIFIED if tags_valid else STATUS_VERIFIED_WITH_WARNING
        return self._result(resource, True, state.upper(), tags_valid,
                            status, method, attempts + (tag_attempts or 0), errors, warnings)
