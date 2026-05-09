# Tools Reference

## Project: Designing an End-to-End Forensic-Ready Infrastructure-as-Code Security Framework for Cloud Environments

---

## 1. Terraform

### Why Selected
Terraform is the industry-standard, vendor-neutral Infrastructure-as-Code tool. Its declarative HCL syntax and extensive AWS provider make it the most widely adopted IaC tool in enterprise DevSecOps pipelines. By targeting Terraform, this framework addresses a technology with significant real-world security research relevance.

### Role in This Project
- **Primary IaC artefact**: Terraform templates are the subject of all security analysis
- **Upload target**: Users will upload Terraform directories to the framework
- **Validation target**: `terraform fmt`, `terraform init`, and `terraform validate` run in the pipeline
- **Deployment tool**: `terraform apply` deploys infrastructure to the AWS sandbox
- **Cleanup tool**: `terraform destroy` tears down sandbox resources after validation

**Key commands used:**
```bash
terraform fmt -check          # Enforce formatting
terraform init                # Initialise providers
terraform validate            # Validate HCL syntax
terraform plan -out=plan.bin  # Generate deployment plan (for OPA/Conftest input)
terraform apply -auto-approve # Deploy to sandbox
terraform destroy             # Clean up sandbox resources
```

---

## 2. Amazon Web Services (AWS)

### Why Selected
AWS is the world's leading cloud provider. AWS infrastructure misconfigurations are a leading cause of cloud security incidents (S3 bucket exposures, open security groups, permissive IAM policies). Targeting AWS gives this research maximum relevance to real-world cloud security challenges.

### Role in This Project
- **Target deployment environment**: Terraform templates deploy AWS resources
- **Sandbox account**: An isolated AWS account receives all test deployments
- **Validation target**: Prowler scans the AWS environment post-deployment
- **Evidence source**: AWS CloudTrail and resource configurations contribute to the forensic record

**Key AWS services targeted by security checks:**
- S3 (encryption, public access, logging)
- EC2 / Security Groups (open ports, public access)
- IAM (least privilege, MFA, password policy)
- CloudTrail (audit logging)
- VPC (flow logs, default VPC)
- GuardDuty (threat detection — sandbox monitoring)

---

## 3. GitHub Actions

### Why Selected
GitHub Actions is a native, tightly integrated CI/CD platform requiring zero additional infrastructure. It provides a reproducible, cloud-hosted execution environment with built-in secrets management, artifact storage, and audit logging. All pipeline runs are version-controlled alongside the codebase.

### Role in This Project
- **Pipeline orchestrator**: Defines and runs all security validation stages
- **Trigger mechanism**: Automatically starts the pipeline on Terraform uploads
- **Secrets management**: Securely injects AWS credentials and other secrets
- **Artifact storage**: Retains all reports and evidence packages after each run
- **Audit trail**: Every pipeline run has a unique Run ID, logs, and timestamps

**Key GitHub Actions features used:**
- `workflow_dispatch` — manual trigger with inputs
- `actions/checkout` — repository access
- `actions/upload-artifact` — report and evidence archival
- `hashicorp/setup-terraform` — Terraform CLI installation
- Environment variables — upload_id propagation across steps

---

## 4. Terraform CLI

### Why Selected
Terraform CLI is the execution engine for all Terraform operations. It is the authoritative tool for validating Terraform code syntax, initialising providers, and deploying infrastructure. Using the official CLI ensures that validation results are accurate and reproducible.

### Role in This Project
- **Code formatting validation**: `terraform fmt -check` enforces consistent formatting
- **Provider initialisation**: `terraform init` prepares the working directory
- **Syntax validation**: `terraform validate` catches HCL errors before scanning
- **Deployment**: `terraform apply` deploys to the sandbox
- **Plan output**: `terraform plan -out` generates a plan file for OPA/Conftest to consume

---

## 5. Checkov

### Why Selected
Checkov is the most comprehensive open-source static analysis tool for IaC security. It covers 1,000+ built-in checks across Terraform, CloudFormation, Kubernetes, and more. It natively outputs JSON reports, making automated integration straightforward. Checkov is actively maintained by Bridgecrew (Prisma Cloud) and is widely adopted in production DevSecOps pipelines.

### Role in This Project
- **Primary static scanning engine**: Scans all uploaded Terraform templates
- **Finding source**: Produces the raw data for static risk scoring
- **Forensic input**: Normalized Checkov findings are included in the evidence package
- **Test validation**: The `insecure-aws` templates should trigger known Checkov rules

**Key Checkov checks targeted:**
- `CKV_AWS_18` — CloudTrail log validation enabled
- `CKV_AWS_19` — S3 bucket encryption enabled
- `CKV_AWS_21` — S3 bucket versioning enabled
- `CKV_AWS_54` — S3 bucket public access block
- `CKV_AWS_25` — Security group no open ingress on SSH
- `CKV_AWS_9` — CloudTrail multi-region enabled

**Command:**
```bash
checkov -d <terraform_directory> \
        --output json \
        --output-file-path reports/static/
```

---

## 6. Open Policy Agent (OPA)

### Why Selected
OPA is the industry standard for Policy-as-Code. It decouples policy decisions from application code and is widely used for Kubernetes admission control, API authorization, and IaC governance. Using OPA allows custom, organisation-specific security policies to be expressed as code and version-controlled alongside the infrastructure.

### Role in This Project
- **Policy engine**: Evaluates custom Rego rules against Terraform plan output
- **Governance enforcement**: Enforces required tags, allowed environments, approved resource types
- **AWS security rules**: Enforces AWS-specific security requirements not covered by Checkov
- **Violation source**: OPA violations contribute to static risk scoring and the forensic evidence package

---

## 7. Rego

### Why Selected
Rego is OPA's purpose-built policy language. It is declarative, readable, and purpose-designed for expressing security and compliance policies against structured data (JSON). Rego policies are version-controllable, testable, and can be shared across teams as a policy library.

### Role in This Project
- **Policy language**: All custom policies are written in Rego
- **terraform.rego**: Governance rules for Terraform structure and deployment requirements
- **aws-security.rego**: AWS-specific security rules (encryption, networking, IAM, logging)
- **Extensible**: New Rego rules can be added incrementally as research progresses

---

## 8. Conftest

### Why Selected
Conftest is the CLI bridge between Terraform and OPA/Rego. It enables Rego policies to be run directly against Terraform plan JSON output or HCL files without requiring a running OPA server. This makes it ideal for CI/CD pipeline integration.

### Role in This Project
- **OPA execution wrapper**: Runs Rego policies against Terraform plan/HCL files
- **Pipeline step**: Invoked as a single CLI command in the GitHub Actions workflow
- **Policy runner**: Executes both `terraform.rego` and `aws-security.rego` in sequence

**Command:**
```bash
conftest test <terraform-plan.json> \
         --policy policies/ \
         --output json
```

---

## 9. Prowler

### Why Selected
Prowler is the leading open-source AWS security assessment tool, covering 400+ security checks mapped to CIS, NIST, SOC2, ISO 27001, and PCI DSS. It is purpose-built for AWS runtime security validation and integrates natively with AWS APIs. Prowler is actively maintained and widely used in enterprise AWS security teams.

### Role in This Project
- **Runtime security scanner**: Scans the deployed AWS sandbox environment
- **Drift detection enabler**: Runtime findings compared to static findings to detect drift
- **Runtime finding source**: Normalized Prowler output feeds into runtime risk scoring
- **Forensic input**: Runtime findings are included in the forensic evidence package

**Key categories of Prowler checks:**
- S3 security configuration
- Security group ingress rules
- IAM configuration and policies
- CloudTrail logging status
- VPC flow logs
- GuardDuty status
- EC2 instance exposure

**Command:**
```bash
prowler aws \
  --output-formats json \
  --output-directory reports/runtime/ \
  --severity critical high medium
```

---

## 10. Python

### Why Selected
Python is the most widely used language for security automation, data processing, and scripting. Its standard library provides all required capabilities (JSON, UUID, hashlib, datetime) without external dependencies. Python is the natural choice for the data processing scripts that normalise, score, and package the pipeline outputs.

### Role in This Project
- **Upload metadata generation**: `generate_upload_metadata.py`
- **Checkov normalisation**: `normalize_checkov.py`
- **Prowler normalisation**: `normalize_prowler.py`
- **Static risk scoring**: `risk_score.py`
- **Runtime risk scoring**: `runtime_risk_score.py`
- **Forensic evidence packaging**: `forensic_log.py`

**Python standard library modules used (planned):**
- `uuid` — Upload ID and Evidence ID generation
- `hashlib` — SHA256 file and evidence hashing
- `json` — JSON reading, writing, and serialisation
- `os` / `pathlib` — File system operations
- `datetime` — UTC timestamps
- `argparse` — CLI argument parsing for scripts

---

## 11. JSON

### Why Selected
JSON is the universal data interchange format. All pipeline tools (Checkov, Prowler, OPA/Conftest) natively output JSON. Using JSON as the internal data format enables seamless integration between all pipeline stages and future dashboard integration.

### Role in This Project
- **Report format**: All static and runtime reports stored as JSON
- **Evidence format**: Forensic evidence packages stored as JSON
- **Metadata format**: Upload metadata stored as JSON
- **Inter-stage data exchange**: Every script reads and writes JSON
- **Dashboard integration**: JSON outputs are ready for future frontend consumption

---

## 12. GitHub Actions Artifacts

### Why Selected
GitHub Actions Artifacts provide built-in, versioned, pipeline-native storage for all generated reports and evidence. They require no external storage infrastructure and are automatically linked to the specific pipeline run that produced them. Retention policies can be configured to support compliance requirements.

### Role in This Project
- **Report archival**: Static, runtime, and final reports uploaded as artifacts
- **Evidence archival**: Forensic evidence packages uploaded as artifacts
- **Audit trail**: Artifacts linked to specific pipeline run IDs
- **Future retrieval**: Evidence can be downloaded for investigation or compliance review
- **Dashboard integration**: Artifacts can be consumed by future dashboard via GitHub API

**Artifact categories (planned):**
- `static-reports-<upload_id>` — Checkov, OPA, initial risk score
- `runtime-reports-<upload_id>` — Prowler, runtime risk score
- `final-reports-<upload_id>` — Final decision, combined summary
- `forensic-evidence-<upload_id>` — Complete forensic evidence package
