# IaC Security Framework

An end-to-end forensic-ready Infrastructure-as-Code security pipeline for cloud environments.

This is the implementation repository for an MSc research project:
**"Designing an End-to-End Forensic-Ready Infrastructure-as-Code Security Framework for Cloud Environments"**

---

## Pipeline Overview

Each execution is identified by a unique `SCAN_ID` (e.g. `SCAN-a8f713c2`) that traces every
artefact from static scanning through to post-deployment resource verification.

| Job | Trigger | Stages |
|-----|---------|--------|
| `security-pipeline` | Push to `dev`, PR to `dev`, `workflow_dispatch` | 1–18: clone, validate, Checkov, OPA, enrich, risk score |
| `terraform-plan` | Push to `dev`, `workflow_dispatch` | 19–24: S3 backend init, tag injection, saved plan, plan evidence |
| `terraform-apply` | Push to `dev`, `workflow_dispatch` (after plan succeeds) | 25–36: verify plan, apply, state capture, resource verification, validation |

Pull requests never obtain AWS deployment credentials.

---

## GitHub Environment — `research-aws-deployment`

The `terraform-apply` job uses the GitHub Environment named **`research-aws-deployment`**. This environment:

- Scopes the `AWS_APPLY_ROLE_ARN` variable to the apply job only (separate from the plan role)
- Provides an optional protection layer that can be configured with required reviewers if needed
- Restricts OIDC credential issuance to the `environment:research-aws-deployment` subject claim

**Required reviewers are not enforced for this research project.** The workflow initiator
(e.g. the researcher) can proceed with deployment without an independent reviewer.

If you want to add a reviewer gate in the future — for example before using a production AWS
account — configure it in:

> Repository Settings → Environments → research-aws-deployment → Required reviewers

The environment must exist even without reviewers, because the `environment:` key in the
workflow controls which OIDC subject claim is presented to AWS STS.

---

## Required Repository Variables

Configure in **Repository Settings → Secrets and variables → Actions → Variables**:

| Variable | Required | Purpose |
|----------|----------|---------|
| `AWS_REGION` | Yes | AWS region (e.g. `eu-north-1`) |
| `AWS_ROLE_ARN` | Yes | OIDC role for `terraform-plan` |
| `AWS_APPLY_ROLE_ARN` | No | OIDC role for `terraform-apply`; falls back to `AWS_ROLE_ARN` |
| `TF_STATE_BUCKET` | Yes | S3 bucket for Terraform backend state |

---

## Deployment Controls

All of the following controls remain active regardless of the reviewer configuration:

- **`dev`-branch restriction** — apply job never runs on PRs or other branches
- **AWS OIDC authentication** — no static credentials; short-lived tokens per job
- **Plan SHA-256 verification** — exact `tfplan` from `terraform-plan` job is verified before apply
- **AWS account verification** — apply account must match plan account
- **Source integrity check** — deployment source hash verified before and after plan
- **Framework tag injection** — `scan-id` and `managed-by` injected via `TF_AWS_DEFAULT_TAGS_*`
- **Deployment authorization evidence** — `deployment-authorization.json` records every apply
- **Post-deployment resource verification** — every AWS resource verified via service APIs
- **Evidence hashing** — SHA-256 manifest of all deployment artefacts

---

## Documentation

- [`docs/controlled-deployment.md`](docs/controlled-deployment.md) — full deployment architecture
- [`docs/workflow.md`](docs/workflow.md) — pipeline stage reference

---

## Running Tests

```bash
# All unit tests (no real AWS calls)
python -m pytest tests/ -v

# Deployment module tests only
python -m pytest tests/deployment/ -v
```
