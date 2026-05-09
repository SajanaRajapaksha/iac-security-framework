# Runtime Validation

## Project: Designing an End-to-End Forensic-Ready Infrastructure-as-Code Security Framework for Cloud Environments

---

## 1. Why Static Validation Alone is Insufficient

Static Infrastructure-as-Code analysis validates the **intent** expressed in Terraform files. It answers the question: *"Is this configuration written securely?"*

However, static analysis has fundamental limitations:

### 1.1 The Gap Between Code and Reality

| Static Analysis Can Detect | Static Analysis Cannot Detect |
|---|---|
| Missing encryption configuration in .tf files | Whether encryption is actually enabled in AWS |
| Open security group rules in code | Security groups modified outside of Terraform |
| Missing tags in resource definitions | AWS resources created without IaC (shadow IT) |
| IAM wildcard policies in code | IAM effective permissions in live environment |
| Missing CloudTrail resource | Whether CloudTrail is actually logging |

Static tools scan the code that **should** create the infrastructure — not the infrastructure itself. The deployed reality can differ from the IaC template due to:

- **Manual changes** made directly to AWS resources after deployment
- **Terraform state drift** where real infrastructure diverges from state files
- **Third-party modifications** by other teams or automated processes
- **AWS service defaults** that differ from what Terraform explicitly configures
- **Partial deployments** where some resources succeed and others fail

### 1.2 False Sense of Security

An organisation that relies solely on static IaC scanning may believe their infrastructure is secure when in fact:
- A developer has manually changed a security group rule in the AWS console
- An S3 bucket policy was modified via AWS CLI without updating Terraform code
- A resource was created outside the IaC pipeline entirely
- Terraform apply failed partway through, leaving infrastructure in an inconsistent state

### 1.3 Research Motivation

This gap between **declared security** (IaC) and **actual security** (deployed AWS) is a core research concern. The framework explicitly validates both layers to measure and quantify this gap.

---

## 2. Infrastructure Drift

**Infrastructure drift** occurs when the actual deployed state of cloud resources diverges from the configuration defined in IaC templates.

### 2.1 Types of Drift Relevant to This Framework

**Configuration Drift:**
A resource attribute defined in Terraform is changed directly in AWS (e.g., security group rule modified in the console).

**Resource Drift:**
A new resource exists in AWS that is not defined in any Terraform file (shadow infrastructure).

**State Drift:**
The Terraform state file no longer accurately reflects the deployed resources.

**Remediation Drift:**
After Checkov or manual review, a developer fixes the code but forgets to redeploy, leaving the old (insecure) configuration running.

### 2.2 Drift Detection in This Framework

Drift is detected by comparing:
1. **Static findings** from Checkov and OPA (what the code says should exist)
2. **Runtime findings** from Prowler (what actually exists in AWS)

Findings that appear in **runtime but not in static scanning** indicate:
- Resources created outside the IaC pipeline
- Post-deployment manual modifications
- Configuration defaults applied by AWS that differ from IaC intent

These **drift findings** carry an additional penalty in the risk scoring model.

---

## 3. AWS Sandbox Validation

### 3.1 Why a Sandbox?

The framework deploys all Terraform templates to an **isolated AWS sandbox account** — a dedicated AWS account used exclusively for security testing. This ensures:

- **Zero production impact** — no real workloads are affected
- **Reproducibility** — each test runs in a clean, consistent environment
- **Cost control** — resources are automatically destroyed after validation
- **Safety** — insecure templates can be deployed safely for testing

### 3.2 Sandbox Design Principles (Planned)

| Principle | Implementation |
|---|---|
| Isolation | Dedicated AWS account separate from dev/staging/prod |
| Auto-teardown | `terraform destroy` runs after Prowler validation |
| Tagging enforcement | All resources tagged with `upload_id` |
| Minimal IAM | Sandbox deployment role uses least-privilege IAM |
| Monitoring | CloudTrail and GuardDuty enabled in sandbox |
| Cost limits | AWS Budgets alert configured for sandbox account |

### 3.3 Resource Targeting

After deployment, Prowler is configured to target resources tagged with the current `upload_id`. This ensures that:
- Runtime findings are attributed to the correct Terraform upload
- Multiple concurrent pipeline runs do not interfere with each other
- Evidence packages contain only findings relevant to their specific upload

---

## 4. Prowler Runtime Security Scanning

### 4.1 What is Prowler?

**Prowler** is an open-source AWS security assessment tool that performs over 400+ security checks against live AWS environments. It maps findings to:
- **CIS AWS Foundations Benchmark**
- **NIST SP 800-53**
- **AWS Well-Architected Framework**
- **SOC 2**
- **ISO 27001**
- **PCI DSS**

### 4.2 Role in This Framework

Prowler is the runtime counterpart to Checkov's static scanning. Together, they provide:

```
Checkov (Static)    →    "Your code says S3 encryption is disabled"
Prowler (Runtime)   →    "Your deployed S3 bucket has encryption disabled"
```

When both agree, confidence in the finding is maximised. When they disagree, drift has been detected.

### 4.3 Key Prowler Checks (Planned)

| Category | Example Checks |
|---|---|
| S3 | Bucket encryption, public access block, versioning, logging |
| EC2 | Instance public IP, security group open ports, EBS encryption |
| IAM | Root account MFA, password policy, access key rotation |
| CloudTrail | Logging enabled, log validation, multi-region |
| VPC | Flow logs enabled, default VPC unused |
| RDS | Encryption, public accessibility, backup retention |
| Lambda | Function URL auth, dead letter queue, encryption |

### 4.4 Prowler Output Integration

Prowler output is processed by `normalize_prowler.py`:
1. Raw Prowler JSON ingested
2. Each finding normalized to the framework's standard finding format
3. `upload_id` attached to every finding
4. Findings saved to `reports/runtime/normalized-runtime-findings.json`
5. Runtime findings fed into the final risk scoring calculation

---

## 5. Runtime-Aware Risk Scoring

### 5.1 Why Runtime Findings Carry Higher Weight

A security misconfiguration detected **only at runtime** is more severe than one detected at the static analysis stage, because:

- It represents a **confirmed live exposure** — not just a potential risk
- It means the static analysis **missed** the issue (detection gap)
- The misconfiguration is **actively present** in a deployed environment
- It may have been in production for an unknown period (if drift occurred)

Therefore, runtime findings carry **higher severity weights** in the final risk score calculation.

### 5.2 Runtime Risk Score Components

```
Final Risk Score = Static Score + Runtime Score + Drift Penalty

Where:
  Static Score    = Weighted Checkov + OPA findings
  Runtime Score   = Weighted Prowler findings (higher multiplier)
  Drift Penalty   = Additional penalty per drift finding
```

### 5.3 Deployment Trust Score

The **Deployment Trust Score** (0–100) represents the inverse of the final risk score. It answers the question: *"How much should we trust this deployment?"*

| Trust Score | Band | Meaning |
|---|---|---|
| 80–100 | TRUSTED | Deployment meets security standards |
| 60–79 | ACCEPTABLE | Minor issues, proceed with monitoring |
| 40–59 | CAUTION | Significant issues, mandatory review |
| 0–39 | UNTRUSTED | Deployment should be reverted immediately |

---

## 6. Runtime Validation in the Forensic Chain

Runtime validation findings are a critical component of the forensic evidence package. They demonstrate:

- **What the live environment looked like** at the time of validation
- **Whether the IaC code** accurately represented the deployed state
- **Whether drift** occurred between code and deployment
- **The actual security posture** of the deployed infrastructure

This makes runtime validation an essential bridge between the static code review and the forensic evidence record — ensuring that the evidence package reflects **reality**, not just **intent**.
