# Controlled AWS Deployment Architecture

## Overview

The IaC Security Framework implements a forensic-ready, manually approved, controlled deployment pipeline that applies a reviewed and SHA-256-verified Terraform plan to an isolated AWS environment and validates the result.

```text
security-pipeline (automatic on push to dev)
        ↓
terraform-plan (automatic, AWS plan only)
        ↓ artifact upload: terraform-plan-<SCAN_ID>
[MANUAL APPROVAL via GitHub Environment]
        ↓
terraform-apply (Stages 25–36)
        ↓ artifact upload: terraform-deployment-<SCAN_ID>
[NEXT: runtime validation — not yet implemented]
```

---

## Terraform Plan vs. Terraform State

| Concept | What it is | Where stored |
|---------|-----------|--------------|
| `tfplan` | Saved binary plan reviewed and SHA-256 signed | GitHub Actions artifact |
| `terraform.tfstate` | Live AWS resource state after apply | S3 backend (`research/<SCAN_ID>/terraform.tfstate`) |

The apply job uses the **exact saved `tfplan`**, not a new plan. The S3 state is the authoritative record after deployment.

---

## GitHub OIDC Deployment Model

### How it works

```text
GitHub Actions runner
        ↓ short-lived OIDC token (no static credentials)
AWS STS AssumeRoleWithWebIdentity
        ↓
Temporary IAM credentials (valid ~1 hour)
        ↓
terraform apply
```

### Important

- No long-lived IAM user credentials are stored in GitHub Secrets.
- The plan job uses `AWS_ROLE_ARN`.
- The apply job uses `AWS_APPLY_ROLE_ARN` (falls back to `AWS_ROLE_ARN`).
- Credentials do not persist between jobs — the apply job re-authenticates.

---

## Required GitHub Repository Variables

Configure these in **Repository Settings → Secrets and variables → Actions → Variables**:

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_REGION` | Yes | AWS region for deployment (e.g. `eu-north-1`) |
| `AWS_ROLE_ARN` | Yes | IAM role ARN for plan-stage OIDC |
| `AWS_APPLY_ROLE_ARN` | No | IAM role ARN for apply-stage; falls back to `AWS_ROLE_ARN` |
| `TF_STATE_BUCKET` | Yes | S3 bucket for Terraform backend state |

---

## GitHub Environment

### Create the environment

1. Go to **Repository Settings → Environments → New environment**
2. Name it exactly: `research-aws-deployment`
3. Save the environment

The environment is used to scope deployment-specific credentials (e.g. `AWS_APPLY_ROLE_ARN`) separately from the scanning phase. It provides an isolated configuration namespace for the apply job.

**Required reviewers are optional for this research project.** The workflow initiator can proceed with deployment without an independent reviewer. If you later want to add a reviewer gate — for example before extending this to a production account — configure it in:

> Repository Settings → Environments → research-aws-deployment → Required reviewers

---

## Required AWS IAM Role Trust Policy

The trust policy must restrict OIDC access to the exact repository, branch, and environment:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": [
            "repo:SajanaRajapaksha/iac-security-framework:ref:refs/heads/dev",
            "repo:SajanaRajapaksha/iac-security-framework:environment:research-aws-deployment"
          ]
        }
      }
    }
  ]
}
```

> **Important**: The plan role should use `ref:refs/heads/dev`. The apply role should additionally require the `environment:research-aws-deployment` subject claim.

---

## Required Backend Permissions (IAM Policy)

The apply role requires:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TerraformStateBackend",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::<TF_STATE_BUCKET>",
        "arn:aws:s3:::<TF_STATE_BUCKET>/research/*"
      ]
    },
    {
      "Sid": "FrameworkVerification",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "tag:GetResources",
        "ec2:Describe*",
        "s3:GetBucket*",
        "s3:ListBucket",
        "iam:Get*",
        "iam:List*",
        "rds:Describe*",
        "kms:DescribeKey",
        "kms:ListAliases",
        "kms:ListResourceTags"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Note**: Resource creation/update/delete permissions required by the **target Terraform plan** must be added to this policy separately. The above covers only the framework's own verification needs. Wildcard permissions should be narrowed for real production deployments.

---

## Deployment Flow

```text
1. Developer pushes to dev branch
        ↓
2. security-pipeline runs automatically
        ↓
3. terraform-plan runs automatically
        ↓
4. Framework generates and SHA-256 signs tfplan
        ↓
5. Uploads: terraform-plan-<SCAN_ID> artifact
        ↓
6. GitHub Environment 'research-aws-deployment' gates the apply job
   (No mandatory reviewer for this research scope —
    the workflow initiator may proceed immediately)
        ↓
7. terraform-apply job proceeds:
     - plan SHA-256 verified
     - AWS account verified
     - deployment authorized
     - exact tfplan applied
```

---

## Deployment Evidence Structure

```text
reports/deployment/<SCAN_ID>/
├── plan-artifact-verification.json        Stage 25: plan SHA-256 and gate check results
├── apply-aws-identity-validation.json     Stage 26: AWS account match verification
├── deployment-authorization.json          Stage 27: authorization type and decision
├── terraform-apply.txt                    Stage 29: full terraform apply output
├── deployment-apply-evidence.json         Stage 29: apply forensic evidence
├── terraform-state-pull.json             Stage 30: raw Terraform state (SENSITIVE)
├── terraform-state.sha256                Stage 30: state file hash
├── terraform-state-addresses.txt         Stage 30: resource address list
├── deployed-state.json                   Stage 30: terraform show -json output
├── terraform-outputs.json                Stage 30: terraform outputs
├── terraform-state-resource-inventory.json Stage 30: sanitized state inventory
├── tagged-aws-resource-inventory.json    Stage 31: tagging API discovery results
├── deployment-resource-reconciliation.json Stage 32: state vs. discovery reconciliation
├── deployed-resource-verification.json   Stage 32: service API verification results
├── deployment-validation.json            Stage 33: final decision
└── deployment-apply-evidence-manifest.json Stage 35: SHA-256 manifest
```

---

## Research Exception Mode

When deploying intentionally misconfigured Terraform for controlled research evaluation, trigger the workflow manually with:

- `allow_research_exception: true`
- `research_exception_reason: "<mandatory non-empty reason>"`

The framework will:
1. Record the authorization type as `RESEARCH_EXCEPTION`
2. Still validate the plan SHA-256, SCAN_ID, and AWS account
3. Still require GitHub Environment approval
4. Generate a `deployment-authorization.json` recording the reason

This mode exists because the MSc research project intentionally deploys insecure IaC to evaluate the runtime scanning stage. It must never be used in production.

---

## Resource Verification Process

For each resource in `terraform-state-resource-inventory.json`:

1. A service-specific verifier is selected from the registry
2. The verifier calls the relevant AWS describe/get API
3. Framework tags (`scan-id` and `managed-by`) are checked
4. A bounded retry (max 5 attempts, exponential back-off) handles eventual consistency

### Supported resource types

| Service | Types verified |
|---------|----------------|
| S3 | `aws_s3_bucket` and sub-resources |
| EC2/VPC | `aws_instance`, `aws_security_group`, `aws_vpc`, `aws_subnet`, `aws_route_table`, `aws_internet_gateway`, `aws_network_acl` |
| IAM | `aws_iam_role`, `aws_iam_user`, `aws_iam_policy`, `aws_iam_group` |
| RDS | `aws_db_instance`, `aws_rds_cluster` |
| KMS | `aws_kms_key`, `aws_kms_alias` |

Unsupported types return `verification_status: UNSUPPORTED` — they are never classified as missing.

---

## Known Limitations

1. **Resource Groups Tagging API coverage**: Not all AWS resource types return from `get-resources`. The tagging API inventory is supplementary. Terraform state is the authoritative list.

2. **Eventually consistent resources**: RDS instances take minutes to become AVAILABLE. The verifier uses bounded retries but may report `REVIEW_REQUIRED` for slow resources.

3. **IAM groups**: Do not support resource tags. They are always verified with a warning.

4. **KMS aliases**: Do not support resource-level tagging. Verified by alias name presence.

5. **Sensitive Terraform outputs**: Marked outputs are not printed; they appear as `<sensitive>` in the captured outputs.

6. **No `terraform apply` on PRs**: The apply job condition explicitly excludes pull requests. Only `dev` branch pushes reach the apply job.

7. **AWS provider >= 5.62.0 required**: For `TF_AWS_DEFAULT_TAGS_*` environment variable support.

---

## Sensitive Evidence Handling

| Artifact | Retention | Sensitivity |
|----------|-----------|-------------|
| `terraform-deployment-<SCAN_ID>` | 30 days | Normal |
| `terraform-sensitive-state-<SCAN_ID>` | 7 days | HIGH — contains resource state |

The raw Terraform state (`terraform-state-pull.json`, `deployed-state.json`) may contain sensitive values including ARNs, resource IDs, and (if not marked sensitive in HCL) attribute values.

**Never share state artifacts outside the research team.**

---

## Next Phase: Runtime Validation

The `deployment-validation.json` output includes:

```json
"next_stage": "RUNTIME_VALIDATION"
```

The runtime validation phase (not yet implemented) will:

1. Run security scanning tools against the **live deployed AWS resources** (e.g. Prowler, AWS Config, Security Hub)
2. Correlate live findings with pre-deployment enriched findings using `SCAN_ID`
3. Calculate a runtime risk score
4. Compare pre-deployment vs. runtime posture
5. Generate a final forensic comparison report

Extension points for the runtime phase are visible in:
- `terraform-state-resource-inventory.json` (expected resources for scanning correlation)
- `deployment-validation.json` (gateway for the next stage)
- `deployed-resource-verification.json` (per-resource existence and tag status)
