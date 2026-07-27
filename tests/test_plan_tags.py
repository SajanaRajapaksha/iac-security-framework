#!/usr/bin/env python3
"""
tests/test_plan_tags.py

Unit tests for the Terraform plan tag validator.

Run:  python -m pytest tests/test_plan_tags.py -v
"""

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.deployment.validate_plan_tags import validate_tags

SCAN_ID = "SCAN-TAG-TEST01"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_plan(resource_changes: list[dict]) -> dict:
    """Build a minimal Terraform plan JSON with the given resource_changes."""
    return {"resource_changes": resource_changes}


def _rc(
    address: str,
    rtype: str = "aws_instance",
    actions: list[str] | None = None,
    tags: dict | None = None,
    tags_all: dict | None = None,
    has_tags_key: bool = True,
    after_unknown: dict | None = None,
) -> dict:
    """Build a single resource_change entry."""
    if actions is None:
        actions = ["create"]

    after: dict = {}
    if has_tags_key:
        if tags is not None:
            after["tags"] = tags
        else:
            after["tags"] = None
        if tags_all is not None:
            after["tags_all"] = tags_all
        else:
            after["tags_all"] = None

    return {
        "address": address,
        "type": rtype,
        "change": {
            "actions": actions,
            "after": after,
            "after_unknown": after_unknown or {},
        },
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestValidateTags:
    def test_correct_tags_pass(self):
        """Resources with correct scan-id and managed-by should pass."""
        plan = _make_plan([
            _rc("aws_instance.web", tags_all={
                "scan-id": SCAN_ID,
                "managed-by": "iac-security-framework",
            }),
            _rc("aws_s3_bucket.data", tags_all={
                "scan-id": SCAN_ID,
                "managed-by": "iac-security-framework",
                "env": "research",
            }),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "PASS"
        assert result["resources_passed"] == 2
        assert result["resources_failed"] == 0

    def test_missing_scan_id_fails(self):
        """A resource missing scan-id should fail."""
        plan = _make_plan([
            _rc("aws_instance.web", tags_all={
                "managed-by": "iac-security-framework",
            }),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "FAIL"
        assert result["resources_failed"] == 1
        assert "scan-id" in result["failures"][0]["missing_tags"]

    def test_incorrect_scan_id_fails(self):
        """A resource with wrong scan-id value should fail."""
        plan = _make_plan([
            _rc("aws_instance.web", tags_all={
                "scan-id": "SCAN-WRONG-ID",
                "managed-by": "iac-security-framework",
            }),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "FAIL"
        assert result["resources_failed"] == 1
        assert len(result["failures"][0]["incorrect_tags"]) == 1
        assert result["failures"][0]["incorrect_tags"][0]["tag"] == "scan-id"

    def test_missing_managed_by_fails(self):
        """A resource missing managed-by should fail."""
        plan = _make_plan([
            _rc("aws_instance.web", tags_all={
                "scan-id": SCAN_ID,
            }),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "FAIL"
        assert "managed-by" in result["failures"][0]["missing_tags"]

    def test_tags_all_inheritance_passes(self):
        """Tags flowing via tags_all (default_tags) should be accepted."""
        # tags is empty but tags_all has the values (from default_tags)
        plan = _make_plan([
            _rc("aws_instance.web",
                tags={},
                tags_all={
                    "scan-id": SCAN_ID,
                    "managed-by": "iac-security-framework",
                }),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "PASS"

    def test_untaggable_resource_skipped(self):
        """Resources without tags/tags_all keys should be untaggable."""
        plan = _make_plan([
            _rc("aws_iam_policy.example", has_tags_key=False),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "PASS"
        assert result["taggable_resources_checked"] == 0
        assert len(result["untaggable_or_not_applicable"]) == 1

    def test_null_tags_fail(self):
        """Resources with null tags should fail (taggable but empty)."""
        plan = _make_plan([
            _rc("aws_instance.web", tags=None, tags_all=None),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "FAIL"
        assert result["resources_failed"] == 1

    def test_delete_action_skipped(self):
        """Delete-only resources should be skipped entirely."""
        plan = _make_plan([
            _rc("aws_instance.old", actions=["delete"], tags_all={
                "scan-id": "SCAN-OLDVALUE",
                "managed-by": "something-else",
            }),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "PASS"
        assert result["taggable_resources_checked"] == 0
        assert len(result["skipped_actions"]) == 1

    def test_noop_action_skipped(self):
        """No-op resources should be skipped."""
        plan = _make_plan([
            _rc("aws_instance.existing", actions=["no-op"], tags_all={
                "scan-id": SCAN_ID,
                "managed-by": "iac-security-framework",
            }),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "PASS"
        assert result["taggable_resources_checked"] == 0

    def test_no_resource_changes_pass(self):
        """An empty resource_changes list should pass."""
        plan = _make_plan([])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "PASS"
        assert result["taggable_resources_checked"] == 0

    def test_mixed_pass_and_fail(self):
        """Mix of passing and failing resources."""
        plan = _make_plan([
            _rc("aws_instance.good", tags_all={
                "scan-id": SCAN_ID,
                "managed-by": "iac-security-framework",
            }),
            _rc("aws_instance.bad", tags_all={
                "scan-id": SCAN_ID,
                # missing managed-by
            }),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "FAIL"
        assert result["resources_passed"] == 1
        assert result["resources_failed"] == 1

    def test_update_action_checked(self):
        """Update actions should be checked for tags."""
        plan = _make_plan([
            _rc("aws_instance.updated", actions=["update"], tags_all={
                "scan-id": SCAN_ID,
                "managed-by": "iac-security-framework",
            }),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "PASS"
        assert result["taggable_resources_checked"] == 1

    def test_tags_in_raw_tags_not_tags_all(self):
        """If tags_all is absent but tags has the values, should pass."""
        plan = _make_plan([
            _rc("aws_instance.web",
                tags={
                    "scan-id": SCAN_ID,
                    "managed-by": "iac-security-framework",
                },
                tags_all=None),
        ])
        result = validate_tags(plan, SCAN_ID)
        assert result["status"] == "PASS"

    def test_scan_id_in_result(self):
        """Result should contain the correct scan_id."""
        plan = _make_plan([])
        result = validate_tags(plan, SCAN_ID)
        assert result["scan_id"] == SCAN_ID
        assert result["required_tags"]["scan-id"] == SCAN_ID
