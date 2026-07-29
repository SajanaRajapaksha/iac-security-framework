"""scripts/deployment/resource_verifiers/generic.py — Fallback verifier for unsupported types."""

from __future__ import annotations
from scripts.deployment.resource_verifiers.base import BaseVerifier


class GenericVerifier(BaseVerifier):
    service = ""

    def verify(self, resource: dict, scan_id: str) -> dict:
        rtype = resource.get("terraform_type", "unknown")
        return self._result(
            resource,
            exists=False,
            lifecycle_state="UNKNOWN",
            tags_valid=None,
            status="UNSUPPORTED",
            method="generic.unsupported",
            attempts=0,
            errors=[],
            warnings=[
                f"No verifier implemented for resource type '{rtype}'. "
                "Resource existence cannot be confirmed or denied by this framework version."
            ],
        )

    def _client(self, region=None):
        return None  # Not used — no AWS calls made
