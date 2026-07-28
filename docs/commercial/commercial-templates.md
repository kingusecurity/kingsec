# KingSec Commercial Templates

**Version:** 1.0  
**Last Updated:** 2026-07-27

---

## Template 1: Customer Proposal

```markdown
# Security Assessment Proposal

**Prepared for:** [Client Name]
**Prepared by:** [Your Name / Company]
**Date:** [Date]

## Executive Summary

[Client Name] engaged [Your Company] to perform a comprehensive security
assessment using KingSec, a professional-grade Attack Surface Management
and Vulnerability Management platform. This proposal outlines the scope,
methodology, deliverables, and investment required.

## Scope of Work

### Assessment Profiles

- [ ] Quick Host Scan — [count] targets
- [ ] Web Application Scan — [count] targets
- [ ] Network Assessment — [count] targets
- [ ] API Assessment — [count] targets
- [ ] Full Assessment — [count] targets

### Targets

| Target | Type | Profile |
|--------|------|---------|
| [target 1] | [URL/IP] | [profile] |
| [target 2] | [URL/IP] | [profile] |

## Deliverables

1. Detailed security findings report (HTML or PDF)
2. Executive summary with risk scoring
3. Remediation recommendations
4. Raw scan data (JSON/CSV) for integration

## Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| Scanning | [X] days | Automated assessment execution |
| Analysis | [X] days | Finding validation and enrichment |
| Reporting | [X] days | Report generation and review |
| Delivery | [X] days | Final report presentation |

## Investment

| Item | Cost |
|------|------|
| Assessment Services | $[amount] |
| [Additional items] | $[amount] |
| **Total** | **$[amount]** |

## Terms

- Payment: Net 30
- Validity: 14 days
- NDA required before engagement

---

**Accepted by:**

Name: _______________________
Signature: ___________________
Date: _______________________
```

---

## Template 2: Quote

```markdown
# Quote #[Number]

**Date:** [Date]
**Valid Until:** [Date + 14 days]
**Quote Number:** Q-[Year]-[Sequence]

**To:**
[Client Company Name]
[Contact Name]
[Email]

**From:**
[Your Company Name]
[Your Email]

## Services

| # | Description | Quantity | Unit Price | Total |
|---|-------------|----------|------------|-------|
| 1 | KingSec Security Assessment — Quick Host Scan | [X] | $[price] | $[total] |
| 2 | KingSec Security Assessment — Web Application Scan | [X] | $[price] | $[total] |
| 3 | Report (PDF + HTML format) | [X] | $[price] | $[total] |

## Total

**Subtotal:** $[amount]
**Tax:** $[amount]
**Total:** $[amount]

## Payment Terms

- Payment method: Bank transfer / credit card
- Payment due: Net 30
- Late payment: 1.5% monthly

---

**Accepted by:**

Name: _______________________
Signature: ___________________
Date: _______________________
```

---

## Template 3: Customer Onboarding

```markdown
# KingSec Customer Onboarding Checklist

**Customer:** [Name]
**Start Date:** [Date]
**Onboarding Lead:** [Name]

## Week 1: Setup

- [ ] Customer receives installation instructions
- [ ] KingSec deployed (Docker or pip)
- [ ] First admin account created
- [ ] JWT secret key configured
- [ ] Scanner dependencies installed
- [ ] Scanner health verified (>80% usable)
- [ ] Database migration completed
- [ ] API connectivity verified

## Week 1: Orientation

- [ ] Customer briefed on KingSec capabilities
- [ ] Assessment profiles explained
- [ ] User roles assigned (ADMIN, ANALYST, VIEWER)
- [ ] MFA enabled for admin accounts
- [ ] Initial assessment targets identified

## Week 2: First Assessment

- [ ] First assessment created and executed
- [ ] Results reviewed with customer
- [ ] Report generated and delivered
- [ ] Customer trained on Report Center
- [ ] Findings interpretation explained

## Week 2: Configuration

- [ ] Custom report preferences set
- [ ] Scanner-specific configuration (if needed)
- [ ] AI enrichment key configured (optional)
- [ ] Backup schedule configured

## Week 3: Review

- [ ] Customer Q&A session
- [ ] Usage review and optimization tips
- [ ] Additional assessments scheduled
- [ ] Escalation path provided

## Support Handoff

- [ ] Support contact confirmed: [email]
- [ ] GitHub issues access granted (if applicable)
- [ ] Documentation links provided
```

---

## Template 4: Support Request

```markdown
# KingSec Support Request

**Date:** [Date]
**Priority:** [Low / Medium / High / Critical]

## Contact Information

- **Name:** [Your Name]
- **Company:** [Company]
- **Email:** [Email]
- **KingSec Version:** [Version]

## Issue Description

[Detailed description of the issue]

## Steps to Reproduce

1. [Step 1]
2. [Step 2]
3. [Step 3]

## Expected Behavior

[What should happen]

## Actual Behavior

[What actually happens]

## Environment

- **Deployment:** [Docker / pip / source]
- **Operating System:** [Windows / Linux / macOS]
- **Browser:** [Chrome / Firefox / Edge / Safari]
- **Scanners Installed:** [list]

## Logs

```
[paste relevant log output]
```

## Attachments

- [Screenshots]
- [Configuration files (redacted)]
- [Log files]
```

---

## Template 5: Bug Report

```markdown
# KingSec Bug Report

**Date:** [Date]
**Severity:** [Cosmetic / Minor / Major / Critical]

## Description

[Clear description of the bug]

## Environment

- **Version:** [e.g., 1.1.0]
- **Deployment:** [Docker / pip / source]
- **OS:** [Windows / Linux / macOS]
- **Python Version:** [if applicable]

## Steps to Reproduce

1. [Step 1]
2. [Step 2]
3. [Step 3]

## Expected vs Actual

| | Description |
|---|-------------|
| **Expected** | [Expected behavior] |
| **Actual** | [Actual behavior] |

## Evidence

- [ ] Screenshot attached
- [ ] Log output attached
- [ ] API request/response attached

## Workaround

[If known, describe a temporary workaround]

## Suggested Fix

[Optional: describe the fix or link to a PR]
```

---

## Template 6: Feature Request

```markdown
# KingSec Feature Request

**Date:** [Date]

## Summary

[One-line summary of the requested feature]

## Problem Statement

[What problem does this feature solve?]

## Proposed Solution

[Describe the feature in as much detail as possible]

## Use Case

[Describe the scenario where this feature would be used]

## Alternatives Considered

[Other approaches you've considered or tried]

## Priority

[ ] Nice to have
[ ] Important
[ ] Critical for my workflow

## Additional Context

[Any other information, links, references]
```
