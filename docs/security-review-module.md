# Security Review Module

## Module Purpose
The Security Review Module automatically compares pre-deployment static analysis security posture against the post-deployment runtime validation posture. It provides a deterministic, rule-based recommendation and produces AI-assisted remediation guidance using OpenAI for actionable fixes.

## Input and Output Artifacts

### Inputs:
- `reports/risk/<SCAN_ID>/predeployment-risk-score.json`
- `reports/risk/<SCAN_ID>/enriched-findings.json`
- `reports/runtime/<SCAN_ID>/risk/postdeployment-risk-score.json`
- `reports/runtime/<SCAN_ID>/normalized/runtime-findings.json`
- `reports/runtime/<SCAN_ID>/prowler/prowler-execution.json`

### Outputs:
- `reports/review/<SCAN_ID>/security-review.json`
- `reports/review/<SCAN_ID>/security-review.md`
- `reports/review/<SCAN_ID>/remediation-guidance.json`
- `reports/review/<SCAN_ID>/remediation-guidance.md`
- `reports/review/<SCAN_ID>/openai-usage.json`
- `reports/review/<SCAN_ID>/review-evidence-manifest.json`
- Local Cache: `cache/review/remediation-guidance.json`

## Score Comparison Logic
The module compares aggregate pre-deployment and post-deployment security posture but **does not claim direct equivalence between static Checkov findings and live Prowler findings**.
Scanner coverage differs fundamentally between static IaC analysis and live AWS assessment.

### Score Delta Interpretation
The score delta is a raw point difference (Post-Deployment Score minus Pre-Deployment Score).
- Positive delta: `RUNTIME_POSTURE_BETTER`
- Negative delta: `RUNTIME_POSTURE_WORSE`
- Zero delta: `SCORES_EQUAL`

### Risk-Band Movement
Risk bands (VERY_LOW_RISK, LOW_RISK, MODERATE_RISK, HIGH_RISK, CRITICAL_RISK) are ordered. Movement to a lower-risk band is classed as `IMPROVED`, movement to a higher-risk band is `DEGRADED`, and staying the same is `NO_CHANGE`.

## Deterministic Recommendation Rules
The final recommendation is determined strictly without AI via rules evaluated in this priority order:
1. Missing or invalid score/runtime evidence -> `REVIEW_INCOMPLETE`
2. Post-deployment score is CRITICAL_RISK -> `CRITICAL_REMEDIATION`
3. Any post-deployment CRITICAL finding -> `URGENT_REVIEW`
4. Post-deployment score is lower than pre-deployment score -> `RUNTIME_RISK_INCREASED`
5. Post score improved but HIGH or CRITICAL runtime findings remain -> `IMPROVED_WITH_REMEDIATION_REQUIRED`
6. Successful runtime scan, score 1000 and no runtime findings -> `RUNTIME_VALIDATION_PASSED`
7. Otherwise -> `REVIEW_REQUIRED`

## Finding-List Structure
Findings are extracted independently into `PRE_DEPLOYMENT` and `POST_DEPLOYMENT` blocks, sorted by severity (CRITICAL down to UNKNOWN).

## Scanner-Provided Remediation
Remediation recommendations provided by the scanners natively (e.g. Checkov metadata, Prowler runtime checks) are preserved as authoritative. OpenAI guidance only supplements this information.

## AI Remediation Boundaries
OpenAI is used purely to generate compact, actionable remediation steps.
- **DO NOT** send complete reports, full state files, credentials, full ARNs, or execution logs to OpenAI.
- **DO NOT** let AI determine the security verdict.
- **DO NOT** automatically apply remediation or claim a remediation has been implemented.
- **DO NOT** use AI to evaluate risk or scores.

### Token Reduction Strategy, Batching, Grouping
- Findings are grouped by `stage, scanner, check_id, resource_type, normalized_title`.
- Only a maximum of 3 sample resource names are sent per group.
- Batched to a maximum of 10 groups per OpenAI request.
- Uses strict structured output limits (e.g., Summary < 25 words).

### Local Caching and Prompt Stability
- Cache Key: `sha256(prompt_version + stage + scanner + check_id + resource_type + title + description)`.
- If a group hashes to an existing cache key, OpenAI is entirely bypassed.
- Cache doesn't contain SCAN_ID, exact AWS accounts, or timestamps.
- Stable Prompt Version: `iac-security-review-remediation-v1`.

## AI Failure Behavior
If OpenAI fails (Timeout, API key missing, quota exceeded):
- Scanner remediation is preserved.
- The workflow logs an error.
- Generation of the `security-review.json` and Markdown continues perfectly.
- The pipeline does not fail.

## Usage Evidence
Token metrics, cache hits/misses, model names, and errors are stored in `openai-usage.json` for attribution.

## Known Limitations
- Pre-deployment findings (Checkov) and post-deployment findings (Prowler) are not 1-to-1 correlated.
- AI Guidance relies on the model's accuracy, which is not verified programmatically.
