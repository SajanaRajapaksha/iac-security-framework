#!/usr/bin/env python3
"""
tests/test_plan_tags.py

Unit tests for the strict plan tag validator.

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

SCAN_ID = "SCAN-TAGTEST1"
WRONG_ID = "SCAN-WRONGGGG"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _plan(resource_changes: list[dict]) -> dict:
    return {"resource_changes": resource_changes}


def _rc(
    address: str = "aws_instance.web",
    rtype: str = "aws_instance",
    actions: list[str] | None = None,
    tags_all: dict | None = None,
    tags: dict | None = None,
    tags_all_unknown: dict | None = None,
    has_tags_key: bool = True,
) -> dict:
    if actions is None:
        actions = ["create"]
    after: dict = {}
    after_unknown: dict = {}
    if has_tags_key:
        after["tags"] = tags
        after["tags_all"] = tags_all
    if tags_all_unknown is not None:
        after_unknown["tags_all"] = tags_all_unknown
    return {
        "address": address,
        "type": rtype,
        "change": {
            "actions": actions,
            "after": after,
            "after_unknown": after_unknown,
        },
    }


def _good(address: str = "aws_instance.web") -> dict:
    return _rc(address, tags_all={
        "scan-id": SCAN_ID,
        "managed-by": "iac-security-framework",
    })


# ---------------------------------------------------------------------------
# Correct tags
# ---------------------------------------------------------------------------

class TestCorrectTags:
    def test_correct_scan_id_in_tags_all(self):
        result = validate_tags(_plan([_good()]), SCAN_ID)
        assert result["status"] == "PASS"
        assert result["resources_passed"] == 1

    def test_correct_managed_by_in_tags_all(self):
        result = validate_tags(_plan([_good()]), SCAN_ID)
        assert result["status"] == "PASS"

    def test_correct_tags_in_tags_when_no_tags_all(self):
        """Fall back to tags when tags_all is None."""
        rc = _rc(tags={"scan-id": SCAN_ID, "managed-by": "iac-security-framework"},
                 tags_all=None)
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "PASS"

    def test_create_action_checked(self):
        result = validate_tags(_plan([_good()]), SCAN_ID)
        assert result["taggable_resources_checked"] == 1

    def test_update_action_checked(self):
        rc = _rc(actions=["update"], tags_all={
            "scan-id": SCAN_ID, "managed-by": "iac-security-framework"
        })
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["taggable_resources_checked"] == 1
        assert result["status"] == "PASS"

    def test_replacement_action_checked(self):
        """create-delete is a taggable action."""
        rc = _rc(actions=["create", "delete"], tags_all={
            "scan-id": SCAN_ID, "managed-by": "iac-security-framework"
        })
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "PASS"

    def test_multiple_resources_all_pass(self):
        rcs = [_good(f"aws_s3_bucket.b{i}") for i in range(3)]
        result = validate_tags(_plan(rcs), SCAN_ID)
        assert result["resources_passed"] == 3
        assert result["resources_failed"] == 0


# ---------------------------------------------------------------------------
# Missing tags
# ---------------------------------------------------------------------------

class TestMissingTags:
    def test_missing_scan_id(self):
        rc = _rc(tags_all={"managed-by": "iac-security-framework"})
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "FAIL"
        assert "scan-id" in result["failures"][0]["missing_tags"]

    def test_missing_managed_by(self):
        rc = _rc(tags_all={"scan-id": SCAN_ID})
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "FAIL"
        assert "managed-by" in result["failures"][0]["missing_tags"]

    def test_null_tags_fail(self):
        rc = _rc(tags=None, tags_all=None)
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "FAIL"


# ---------------------------------------------------------------------------
# Incorrect tag values
# ---------------------------------------------------------------------------

class TestIncorrectTags:
    def test_incorrect_scan_id(self):
        rc = _rc(tags_all={"scan-id": WRONG_ID, "managed-by": "iac-security-framework"})
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "FAIL"
        failure = result["failures"][0]
        assert any(it["tag"] == "scan-id" for it in failure["incorrect_tags"])

    def test_incorrect_managed_by(self):
        rc = _rc(tags_all={"scan-id": SCAN_ID, "managed-by": "wrong-owner"})
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "FAIL"
        failure = result["failures"][0]
        assert any(it["tag"] == "managed-by" for it in failure["incorrect_tags"])

    def test_resource_tag_overrides_framework_default_scan_id(self):
        """Resource-level tag with wrong scan-id is detected as override."""
        rc = _rc(tags_all={"scan-id": WRONG_ID, "managed-by": "iac-security-framework"})
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "FAIL"
        it = result["failures"][0]["incorrect_tags"][0]
        assert it["tag"] == "scan-id"
        assert it["actual"] == WRONG_ID

    def test_resource_tag_overrides_managed_by(self):
        rc = _rc(tags_all={"scan-id": SCAN_ID, "managed-by": "overridden"})
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "FAIL"


# ---------------------------------------------------------------------------
# Unknown / known-after-apply values
# ---------------------------------------------------------------------------

class TestUnknownTagValues:
    def test_known_after_apply_scan_id_fails(self):
        """scan-id that is 'known after apply' must FAIL — SCAN_ID is known before planning."""
        rc = _rc(
            tags_all=None,
            tags_all_unknown={"scan-id": True},
        )
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "FAIL"
        assert result["resources_unknown"] > 0

    def test_known_after_apply_managed_by_fails(self):
        rc = _rc(
            tags_all=None,
            tags_all_unknown={"managed-by": True},
        )
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "FAIL"
        assert result["resources_unknown"] > 0

    def test_unknown_scan_id_does_not_pass(self):
        """Any unknown scan-id is rejected — do NOT treat unknown as pass."""
        rc = _rc(
            tags_all={"managed-by": "iac-security-framework"},
            tags_all_unknown={"scan-id": True},
        )
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "FAIL"


# ---------------------------------------------------------------------------
# Untaggable / skipped
# ---------------------------------------------------------------------------

class TestSkippedAndUntaggable:
    def test_delete_only_skipped(self):
        rc = _rc(actions=["delete"], tags_all={"scan-id": WRONG_ID, "managed-by": "x"})
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "PASS"
        assert result["taggable_resources_checked"] == 0
        assert len(result["skipped_actions"]) == 1

    def test_noop_skipped(self):
        rc = _rc(actions=["no-op"])
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "PASS"
        assert result["taggable_resources_checked"] == 0

    def test_untaggable_resource_not_counted(self):
        rc = _rc("aws_iam_policy.p", has_tags_key=False)
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["status"] == "PASS"
        assert result["taggable_resources_checked"] == 0
        assert len(result["untaggable_or_not_applicable"]) == 1

    def test_untaggable_not_in_passed_count(self):
        rc = _rc("aws_iam_policy.p", has_tags_key=False)
        result = validate_tags(_plan([rc]), SCAN_ID)
        assert result["resources_passed"] == 0

    def test_empty_resource_changes(self):
        result = validate_tags(_plan([]), SCAN_ID)
        assert result["status"] == "PASS"
        assert result["taggable_resources_checked"] == 0


# ---------------------------------------------------------------------------
# Mixed scenarios
# ---------------------------------------------------------------------------

class TestMixedScenarios:
    def test_one_pass_one_fail(self):
        rcs = [
            _good("aws_instance.good"),
            _rc("aws_instance.bad", tags_all={"scan-id": WRONG_ID, "managed-by": "iac-security-framework"}),
        ]
        result = validate_tags(_plan(rcs), SCAN_ID)
        assert result["status"] == "FAIL"
        assert result["resources_passed"] == 1
        assert result["resources_failed"] == 1

    def test_malformed_plan_json_empty_dict(self):
        result = validate_tags({}, SCAN_ID)
        assert result["status"] == "PASS"  # no resource_changes key
        assert result["taggable_resources_checked"] == 0

    def test_null_after_treated_as_untaggable(self):
        rc = {
            "address": "aws_instance.web",
            "type": "aws_instance",
            "change": {"actions": ["create"], "after": None, "after_unknown": {}},
        }
        result = validate_tags(_plan([rc]), SCAN_ID)
        # after=None → no tags key found → untaggable
        assert result["taggable_resources_checked"] == 0


# ---------------------------------------------------------------------------
# Schema and metadata
# ---------------------------------------------------------------------------

class TestSchemaAndMetadata:
    def test_schema_version(self):
        result = validate_tags(_plan([]), SCAN_ID)
        assert result["schema_version"] == "1.0"

    def test_injection_mode(self):
        result = validate_tags(_plan([]), SCAN_ID)
        assert result["injection_mode"] == "aws_provider_environment_variables"

    def test_required_tags_in_result(self):
        result = validate_tags(_plan([]), SCAN_ID)
        assert result["required_tags"]["scan-id"] == SCAN_ID
        assert result["required_tags"]["managed-by"] == "iac-security-framework"

    def test_scan_id_in_result(self):
        result = validate_tags(_plan([]), SCAN_ID)
        assert result["scan_id"] == SCAN_ID
