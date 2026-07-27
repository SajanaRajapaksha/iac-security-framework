# Controlled AWS Deployment Preparation

This document describes the controlled, forensic-ready Terraform deployment
preparation implemented in the IaC Security Framework.

## Overview

After the security scanning, policy validation, finding enrichment and
pre-deployment risk scoring stages complete, the framework can prepare a
controlled Terraform deployment to AWS.  The preparation stage generates a
saved Terraform plan with full forensic evidence — **it intentionally does
not execute `terraform apply`**.

```text
Security Analysis
      ↓
Risk Score
      ↓
Exact Source Preservation  (Stage 19)
      ↓
OIDC Authentication        (Stage 20)
      ↓
Scan-Isolated State Init   (Stage 21)
      ↓
Terraform Plan             (Stage 22)
      ↓
SCAN_ID Tag Verification   (Stage 23)
      ↓
Forensic Plan Evidence     (Stage 24)
```

> **Terraform Apply is intentionally not implemented in this stage.**

## Single SCAN_ID Lifecycle

The framework uses exactly one `SCAN_ID` (e.g. `SCAN-a8f713c2`) to trace
every artefact from source acquisition through to deployment preparation:

```text
source acquisition  →  static scanning  →  policy validation  →
risk scoring  →  Terraform planning  →  future deployment  →  future runtime validation
```

The SCAN_ID is generated once in the `security-pipeline` job and passed to
the `terraform-plan` job via GitHub Actions job outputs.

## Source Preservation

The Terraform code that enters the plan stage is the **exact repository
snapshot** that passed through all prior validation, scanning, policy and
enrichment stages.  It is uploaded as a GitHub Actions artifact at the end
of the security pipeline and downloaded in the plan job — no repository
re-cloning occurs.

## AWS Authentication

The framework authenticates to AWS exclusively via **GitHub OIDC federation**.
No static AWS access keys are used.  AWS credentials only exist in the
`terraform-plan` job — the security scanning job never receives AWS
permissions.  Pull-request workflows never obtain AWS credentials.

## Scan-Isolated Terraform State

Every scan gets its own Terraform state file:

```text
s3://<TF_STATE_BUCKET>/research/<SCAN_ID>/terraform.tfstate
```

S3 native state locking is enabled via `use_lockfile=true`.

## Deployment Contract

Terraform repositories eligible for **controlled AWS deployment** must
satisfy a deployment contract.  Repositories that do not satisfy the contract
remain valid for security scanning but are not eligible for deployment.

### Required Elements

```hcl
variable "scan_id" {
  description = "IaC Security Framework scan identifier"
  type        = string
}

variable "aws_region" {
  description = "AWS deployment region"
  type        = string
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      scan-id    = var.scan_id
      managed-by = "iac-security-framework"
    }
  }
}

terraform {
  backend "s3" {}
}
```

The framework validates this contract before planning.  If the contract is
missing, deployment preparation stops with:

```text
DEPLOYMENT_CONTRACT_FAILED

Required framework tagging configuration was not detected.

Required tags:
  scan-id=<SCAN_ID>
  managed-by=iac-security-framework

Terraform source remains valid for security scanning
but is not eligible for controlled AWS deployment.
```

## Tag Validation

After `terraform plan`, the framework reads the plan JSON and verifies that
every taggable AWS resource change carries:

- `scan-id = <SCAN_ID>`
- `managed-by = iac-security-framework`

Resources that do not support AWS tagging are skipped.  Delete-only and
no-op changes are also skipped.  Tags flowing from `default_tags` into
`tags_all` are accepted.

## Evidence Directory Structure

```text
reports/
└── deployment/
    └── <SCAN_ID>/
        ├── deployment-contract-validation.json
        ├── terraform-plan.txt
        ├── terraform-plan.json
        ├── terraform-plan.sha256
        ├── tag-validation.json
        ├── deployment-plan-evidence.json
        └── deployment-evidence-manifest.json
```

## Security Requirements

1. No static AWS access keys.
2. AWS authentication only via GitHub OIDC.
3. AWS credentials only exist in the deployment job.
4. Pull-request workflows never receive AWS deployment credentials.
5. `terraform apply` is not implemented.
6. No secrets in evidence files.
7. Existing scan evidence is never overwritten.
8. Scanned Terraform source is never silently modified.
9. Deployment uses the saved scanned-source artifact, not a fresh clone.
10. Every deployment candidate is linked to the existing SCAN_ID.
11. Terraform state is isolated by SCAN_ID.
12. All taggable AWS resources must contain the SCAN_ID tag.

## AWS IAM Permissions Required

The `GitHubTerraformDeployRole` needs (at minimum):

- `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` on the state bucket
- `s3:ListBucket` on the state bucket
- `sts:GetCallerIdentity`
- Permissions for whatever AWS resources the target Terraform declares
  (e.g. `ec2:*`, `s3:*`, etc. as appropriate for the research deployment)
