# Controlled AWS Deployment Preparation

## Overview

The IaC Security Framework performs a **forensic-ready Terraform plan** for each scan without executing `terraform apply`. Tags are injected automatically — target Terraform repositories require **no manual modification**.

---

## Automatic Scan Tag Injection

```text
Target Terraform repository
        |
        | remains unchanged
        v
GitHub Actions receives SCAN_ID
        |
        v
AWS Provider default tags injected through environment variables
        |
        v
Terraform saved plan (-out=tfplan)
        |
        v
Plan JSON tag verification (tags_all validated)
        |
        v
Source integrity verified (no .tf files changed)
        |
        v
Future deployment (NOT IMPLEMENTED — terraform apply not present)
        |
        v
AWS resource tracking by scan-id tag
```

### Injected Tags

Every taggable AWS resource in the Terraform plan receives:

| Tag | Value |
|-----|-------|
| `scan-id` | Current SCAN_ID (e.g. `SCAN-f1fd2835`) |
| `managed-by` | `iac-security-framework` |

### Injection Mechanism

Tags are passed to the AWS Provider using environment variables:

```bash
env \
  "TF_AWS_DEFAULT_TAGS_scan-id=${SCAN_ID}" \
  "TF_AWS_DEFAULT_TAGS_managed-by=iac-security-framework" \
  terraform plan \
    -input=false \
    -out=tfplan
```

The `env` command (not `export`) is required because hyphenated names (`scan-id`) are not valid shell variable identifiers.

### Required AWS Provider Version

```
>= 5.62.0
```

The `TF_AWS_DEFAULT_TAGS_*` environment variable mechanism requires AWS Provider **5.62.0 or later**. The framework validates this automatically after `terraform init` by reading `.terraform.lock.hcl`.

### Source Repository Unchanged

**The framework does not modify target Terraform source files to add tracking tags.**

- No `variable "scan_id"` declaration is required.
- No `provider "aws" { default_tags {...} }` block is required.
- No `_override.tf` files are created.
- No generated provider blocks are injected.
- Source integrity is SHA256-verified before and after planning.

---

## Deployment Contract (Revised)

The deployment contract now checks only:

| Check | Requirement |
|-------|-------------|
| Discovery data | `terraform-directories.json` must exist |
| Single root | Exactly one Terraform root discovered |
| Resolvable path | Root resolvable from `deployment-source/<relative_path>` |
| .tf files present | At least one `.tf` file in the root |
| AWS provider detected | Best-effort check for `provider "aws"` or `hashicorp/aws` |
| Source not modified | Validation reads files only |

**Not required:**
- `variable "scan_id"`
- `variable "aws_region"`
- `provider "aws" { default_tags {...} }`
- Any framework-specific Terraform configuration

---

## Pipeline Flow (Stages 19–24)

```text
security-pipeline job
    Stage 19: Upload deployment-source artifact
              Upload scan-metadata artifact
    ↓
terraform-plan job (push to dev only, never PRs)
    Stage 19: Download deployment-source artifact
              Download scan-metadata artifact
    Stage 20: AWS OIDC Authentication
    Stage 21a: Validate deployment contract
    Stage 21b: Save source integrity baseline (.tf SHA256s)
    Stage 21c: terraform init -backend-config (S3, scan-isolated)
    Stage 21d: Validate AWS provider version (>= 5.62.0)
    Stage 22:  terraform plan with TF_AWS_DEFAULT_TAGS_* injection
               Generate human-readable plan (terraform show -no-color)
               Generate JSON plan (terraform show -json)
               Copy plan evidence to reports/
    Stage 22e: Verify source integrity after plan (no .tf changes)
    Stage 23:  Validate tags in plan JSON (strict — scan-id, managed-by)
    Stage 24a: Capture Terraform + provider versions
    Stage 24b: Generate deployment plan evidence JSON
    Stage 24c: Hash all evidence files (SHA256 manifest)
    ↑
    Upload: terraform-plan-<SCAN_ID> artifact (if: always())
```

**`terraform apply` is NOT implemented in this stage.**

---

## Evidence Structure

```text
reports/deployment/<SCAN_ID>/
├── deployment-contract-validation.json     # Contract check results
├── aws-provider-validation.json            # Provider version check
├── deployment-source-baseline.json         # SHA256 baseline (before plan)
├── deployment-source-integrity.json        # Integrity verification (after plan)
├── terraform-plan.txt                      # Human-readable plan
├── terraform-plan.json                     # Machine-readable plan
├── terraform-plan.sha256                   # Binary plan hash
├── tag-validation.json                     # Tag propagation results
├── deployment-plan-evidence.json           # Full forensic evidence
└── deployment-evidence-manifest.json       # SHA256 of all evidence
```

### deployment-contract-validation.json

```json
{
  "schema_version": "1.0",
  "scan_id": "SCAN-f1fd2835",
  "generated_at_utc": "...",
  "status": "PASS",
  "deployment_root_relative": ".",
  "deployment_root_runtime": "/home/runner/.../deployment-source",
  "tf_files_found": 4,
  "source_modification": false,
  "tag_injection": {
    "mode": "aws_provider_environment_variables",
    "required_provider": "registry.terraform.io/hashicorp/aws",
    "minimum_provider_version": "5.62.0",
    "required_tags": {
      "scan-id": "SCAN-f1fd2835",
      "managed-by": "iac-security-framework"
    }
  }
}
```

### aws-provider-validation.json

```json
{
  "schema_version": "1.0",
  "scan_id": "SCAN-f1fd2835",
  "status": "PASS",
  "provider": "registry.terraform.io/hashicorp/aws",
  "selected_version": "6.53.0",
  "minimum_version": "5.62.0",
  "environment_default_tags_supported": true
}
```

### tag-validation.json

```json
{
  "schema_version": "1.0",
  "scan_id": "SCAN-f1fd2835",
  "status": "PASS",
  "injection_mode": "aws_provider_environment_variables",
  "required_tags": {
    "scan-id": "SCAN-f1fd2835",
    "managed-by": "iac-security-framework"
  },
  "taggable_resources_checked": 6,
  "resources_passed": 6,
  "resources_failed": 0,
  "resources_unknown": 0,
  "untaggable_or_not_applicable": [],
  "skipped_actions": [],
  "failures": []
}
```

---

## Security Requirements

| Requirement | Status |
|-------------|--------|
| No static AWS access keys | ✅ OIDC only |
| No PR AWS credentials | ✅ Job condition: push to dev only |
| No re-cloning | ✅ Uses deployment-source artifact |
| No .tf file modification | ✅ Source integrity verified |
| No _override.tf injection | ✅ Not implemented |
| No terraform apply | ✅ Not implemented |
| Scan-isolated state | ✅ `research/<SCAN_ID>/terraform.tfstate` |
| S3 state locking | ✅ `use_lockfile=true` |
| Tags validated in plan | ✅ Strict tag validation |
| All evidence linked to SCAN_ID | ✅ Every file uses scan_id |

---

## Future Apply Stage (Not Yet Implemented)

When `terraform apply` is added in a future iteration, it must use:

```bash
env \
  "TF_AWS_DEFAULT_TAGS_scan-id=${SCAN_ID}" \
  "TF_AWS_DEFAULT_TAGS_managed-by=iac-security-framework" \
  terraform apply \
    -input=false \
    tfplan
```

The same saved plan binary (`tfplan`) must be used — not a new plan.

---

## Post-Deployment Resource Tracking (Future)

After deployment, tagged resources can be enumerated:

```bash
aws resourcegroupstaggingapi get-resources \
  --region "$AWS_REGION" \
  --tag-filters "Key=scan-id,Values=${SCAN_ID}" \
  --output json
```

**Important notes:**
- Terraform state remains the authoritative list of all deployed resources.
- The `scan-id` tag is the runtime correlation mechanism for taggable resources.
- Some AWS resource types do not support resource tags (e.g. IAM inline policies, some networking primitives).
- Not every taggable resource is returned through a single AWS tagging API call.
- Auto Scaling-created EC2 instances may require explicit tag propagation configuration.
- The plan validator reports genuinely non-taggable resources separately — they do not cause pipeline failures.

**The current deployment status is: `NOT_APPLIED`**
