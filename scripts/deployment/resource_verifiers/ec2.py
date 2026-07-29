"""scripts/deployment/resource_verifiers/ec2.py — EC2/VPC resource verifier."""

from __future__ import annotations
from scripts.deployment.resource_verifiers.base import (
    BaseVerifier, STATUS_VERIFIED, STATUS_VERIFIED_WITH_WARNING,
    STATUS_NOT_FOUND, STATUS_ACCESS_DENIED, STATUS_ERROR, STATUS_INVALID_IDENTITY,
    _check_framework_tags,
)

# Maps Terraform type → (describe API method, ID filter name, tag extraction path)
EC2_DESCRIBE_MAP = {
    "aws_instance": ("describe_instances", "instance-id", lambda r: r["Reservations"][0]["Instances"][0]),
    "aws_security_group": ("describe_security_groups", "group-id", lambda r: r["SecurityGroups"][0]),
    "aws_vpc": ("describe_vpcs", "vpc-id", lambda r: r["Vpcs"][0]),
    "aws_subnet": ("describe_subnets", "subnet-id", lambda r: r["Subnets"][0]),
    "aws_route_table": ("describe_route_tables", "route-table-id", lambda r: r["RouteTables"][0]),
    "aws_internet_gateway": ("describe_internet_gateways", "internet-gateway-id", lambda r: r["InternetGateways"][0]),
    "aws_network_acl": ("describe_network_acls", "network-acl-id", lambda r: r["NetworkAcls"][0]),
}


class EC2Verifier(BaseVerifier):
    service = "ec2"

    def verify(self, resource: dict, scan_id: str) -> dict:
        rtype = resource.get("terraform_type", "")
        resource_id = resource.get("resource_id") or ""
        errors: list[str] = []
        warnings: list[str] = []

        if rtype not in EC2_DESCRIBE_MAP:
            return self._result(resource, False, "UNKNOWN", None,
                                "UNSUPPORTED", f"ec2.{rtype}", 0,
                                [f"EC2 verifier does not support {rtype}"], [])

        if not resource_id:
            return self._result(resource, False, "UNKNOWN", None,
                                "INVALID_IDENTITY", "ec2.describe", 0,
                                ["Resource has no ID to describe"], [])

        method_name, filter_name, extractor = EC2_DESCRIBE_MAP[rtype]
        client = self._client()
        describe_fn = getattr(client, method_name)
        method_label = f"ec2.{method_name}"

        resp, attempts, err = self._with_retry(
            describe_fn, Filters=[{"Name": filter_name, "Values": [resource_id]}]
        )
        if err:
            if "ACCESS_DENIED" in err:
                return self._result(resource, True, "EXISTS_ACCESS_DENIED", None,
                                    STATUS_ACCESS_DENIED, method_label, attempts, [err], [])
            return self._result(resource, False, "ERROR", None,
                                STATUS_ERROR, method_label, attempts, [err], [])

        try:
            item = extractor(resp)
        except (IndexError, KeyError):
            return self._result(resource, False, "NOT_FOUND", None,
                                STATUS_NOT_FOUND, method_label, attempts, [], [])

        raw_tags = item.get("Tags", [])
        tag_dict = {t["Key"]: t["Value"] for t in raw_tags}
        ok, tag_warnings = _check_framework_tags(tag_dict, scan_id)
        warnings.extend(tag_warnings)
        tags_valid = ok
        status = STATUS_VERIFIED if tags_valid else STATUS_VERIFIED_WITH_WARNING

        return self._result(resource, True, "AVAILABLE", tags_valid,
                            status, method_label, attempts, errors, warnings)
