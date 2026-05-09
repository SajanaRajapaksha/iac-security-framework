# Architecture Overview

## Project: Designing an End-to-End Forensic-Ready Infrastructure-as-Code Security Framework for Cloud Environments

---

## 1. Introduction

This framework implements a **forensic-ready DevSecOps security pipeline** for Terraform-based AWS Infrastructure-as-Code (IaC). The framework accepts a **GitHub repository URL** as its primary input, dynamically clones and analyses the target repository, and produces a complete, cryptographically verifiable forensic audit trail.

The architecture combines **repository cloning**, **dynamic Terraform discovery**, **static analysis**, **policy enforcement**, **runtime validation**, and **risk scoring** into a unified, traceable pipeline anchored by a unique **Scan ID** (`SCAN-<UUID-prefix>`) that propagates through every stage.

The framework is **repository-agnostic** — it does not require any specific Terraform project structure and adapts to whatever layout exists in the target repository.

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    INPUT LAYER                          │
│  GitHub Repository URL → Branch → Scan ID Generation   │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│               CLONING & DISCOVERY LAYER                 │
│  git clone → repositories/cloned/<scan_id>/             │
│  Recursive .tf discovery → Root module identification   │
│  SHA256 hashing → Scan metadata record                  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│               GITHUB ACTIONS CI/CD PIPELINE             │
│  Automated multi-stage security validation              │
└────────┬─────────────────────────────┬──────────────────┘
         │                             │
┌────────▼──────────┐        ┌─────────▼──────────────────┐
│  STATIC ANALYSIS  │        │  POLICY-AS-CODE            │
│  Terraform CLI    │        │  OPA / Rego / Conftest      │
│  Checkov          │        │  terraform.rego             │
│  (per root module)│        │  aws-security.rego          │
└────────┬──────────┘        └──────────┬─────────────────┘
         └──────────┬────────────────────┘
                    │
         ┌──────────▼──────────────────────────────────────┐
         │   INITIAL RISK SCORING                          │
         │   Static findings + Policy violations           │
         │   → Risk Band → ALLOW / REVIEW / BLOCK          │
         └──────────┬──────────────────────────────────────┘
                    │ (if ALLOW or REVIEW)
                    ▼
         ┌──────────────────────────────────────────────────┐
         │   AWS SANDBOX DEPLOYMENT                        │
         │   Isolated account → Resources tagged with      │
         │   scan_id for targeted runtime validation        │
         └──────────┬──────────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────────────────────────────────┐
         │   RUNTIME VALIDATION LAYER (Prowler)            │
         │   Live AWS scanning against scan_id-tagged       │
         │   resources → Drift detection                   │
         └──────────┬──────────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────────────────────────────────┐
         │   FINAL RISK SCORING                            │
         │   Static + Runtime → Combined score             │
         │   Deployment Trust Score → Final decision        │
         └──────────┬──────────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────────────────────────────────┐
         │   FORENSIC EVIDENCE LAYER                       │
         │   Assemble all artifacts per scan_id            │
         │   SHA256 sealed evidence package                │
         └──────────┬──────────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────────────────────────────────┐
         │   GITHUB ACTIONS ARTIFACTS                      │
         │   All reports & evidence archived per scan_id   │
         └──────────┬──────────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────────────────────────────────┐
         │   FUTURE: Centralized Dashboard                 │
         │   Upload management, visualization, review      │
         └──────────────────────────────────────────────────┘
```

---

## 3. Layer Descriptions

### 3.1 Input Layer

The entry point of the pipeline. Every scan begins with a GitHub repository URL.

- **Repository URL**: The target GitHub repository to scan
- **Branch**: The specific branch to scan (defaults to `main`)
- **Scan ID**: `SCAN-<8-char-UUID-prefix>` — globally unique, generated once per scan
- **Input method (current)**: GitHub Actions `workflow_dispatch` manual trigger
- **Input method (future)**: Centralized dashboard upload form → API → pipeline trigger

### 3.2 Cloning & Discovery Layer

The repository is cloned into an isolated per-scan directory and analysed for Terraform content.

**Repository Cloning** (`clone_repository.py`):
- Shallow clone of the target repository into `repositories/cloned/<scan_id>/`
- Records: commit SHA, branch, clone timestamp
- Each scan fully isolated — multiple concurrent scans supported

**Terraform Discovery** (`discover_terraform.py`):
- Recursively walks the entire cloned repository directory
- Identifies all `.tf` files at any depth
- Classifies directories as root modules or child modules
- Supports flat layouts, multi-module structures, and monorepos

**Scan Metadata Generation** (`generate_scan_metadata.py`):
- SHA256 hashes every discovered `.tf` file
- Assembles structured scan metadata JSON
- Saves to `repositories/metadata/scan-<scan_id>.json`
- This becomes the root anchor of the forensic evidence chain

### 3.3 GitHub Actions CI/CD Pipeline

The automation backbone. Orchestrates all security validation stages in sequence.

- **Trigger**: Manual (`workflow_dispatch`) with repository URL and branch inputs
- **Future trigger**: Dashboard API call → GitHub Actions API → workflow dispatch
- Every pipeline run has a unique GitHub Actions run ID (included in forensic evidence)

### 3.4 Static Analysis Layer

Two complementary static tools validate the discovered Terraform code.

**Terraform CLI** (per discovered root module):
- `terraform fmt -check` — formatting standards
- `terraform init` — provider plugin initialisation
- `terraform validate` — HCL syntax and configuration validation

**Checkov** (entire cloned directory, recursive):
- Scans all discovered `.tf` files in a single recursive run
- Reports findings tagged with their relative file paths
- Output normalised and tagged with `scan_id`

### 3.5 Policy-as-Code Layer (OPA / Rego / Conftest)

Custom governance and security rules enforced against Terraform plan output.

- `policies/terraform.rego` — required tags, allowed environments, allowed resource types
- `policies/aws-security.rego` — open ingress, S3 encryption, CloudTrail, IAM wildcard rules
- Violations tagged with `scan_id` and relative module path

### 3.6 Static Risk Scoring

Combines Checkov findings and OPA policy violations into an initial risk score.

- Weighted severity scoring (CRITICAL/HIGH/MEDIUM/LOW)
- Risk band classification: LOW / MEDIUM / HIGH / CRITICAL
- Initial deployment decision: **ALLOW / REVIEW / BLOCK**

### 3.7 AWS Sandbox Deployment

Terraform is deployed to an isolated AWS sandbox account.

- All resources tagged with `scan_id` for targeted Prowler scanning
- Deployment metadata captured and added to the forensic chain
- Automatic teardown after runtime validation

### 3.8 Runtime Validation Layer (Prowler)

Prowler validates the live AWS environment post-deployment.

- Targets resources tagged with the current `scan_id`
- Detects misconfigurations that only manifest at runtime
- Identifies infrastructure drift between IaC intent and deployed state

### 3.9 Final Risk Scoring

Combines static and runtime findings into a final risk assessment.

- Runtime findings carry higher severity weight (confirmed live exposure)
- Drift detection: runtime findings not present in static scanning
- **Deployment Trust Score** (0–100) quantifies deployment confidence
- Final decision: **TRUSTED / ACCEPTABLE / CAUTION / UNTRUSTED**

### 3.10 Forensic Evidence Layer

All pipeline artifacts assembled into a single sealed evidence package per scan.

- Evidence package path: `evidence/<scan_id>/evidence-<evidence_id>.json`
- SHA256 integrity hash — tamper detection
- Evidence ID (`EV-<UUID>`) is separate from Scan ID
- Complete chain: Repository → Clone → Discovery → Analysis → Runtime → Decision → Evidence

### 3.11 Future Dashboard Integration

A centralized dashboard will provide:
- Repository URL submission and scan trigger
- Real-time pipeline stage progress
- Risk score visualization and trends
- Evidence package viewer and download
- Multi-scan comparison and history
- GitHub Actions artifact retrieval via API

---

## 4. Per-Scan Isolation Model

Every scan run produces an isolated artifact namespace:

```
repositories/cloned/<scan_id>/     ← Cloned repository content
repositories/metadata/             ← Scan metadata JSON
reports/static/<scan_id>/          ← Static analysis reports
reports/runtime/<scan_id>/         ← Runtime validation reports
reports/final/<scan_id>/           ← Final risk score and decision
evidence/<scan_id>/                ← Forensic evidence package
```

This isolation guarantees:
- Concurrent scans do not interfere
- Historical scan data is preserved independently
- The same repository can be re-scanned without overwriting previous results

---

## 5. Key Design Principles

| Principle | Implementation |
|---|---|
| **Repository-Agnostic** | Dynamic Terraform discovery handles any project structure |
| **Forensic Readiness** | SHA256 hashes, scan_id propagation, sealed evidence package |
| **Per-Scan Isolation** | All artifacts namespaced under scan_id |
| **Non-Repudiation** | Commit SHA records exact code state at scan time |
| **Traceability** | scan_id links every artifact to its source repository and commit |
| **Defence in Depth** | Static + Policy + Runtime = multi-layer validation |
| **Auditability** | Complete forensic package per scan for investigation support |

---

## 6. Future Enhancements

- Frontend dashboard (React or Next.js) for repository URL submission
- Backend API (Node.js or FastAPI) for scan management
- Persistent database for scan history and evidence storage
- SIEM integration for real-time alerting
- GitLab / Bitbucket repository support
- Multi-cloud runtime validation (Azure, GCP)
- Comparative scan analysis (track security posture over time)
