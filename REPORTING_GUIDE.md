# KingSec Reporting Guide

**Version:** 1.1.0  
**Last Updated:** 2026-07-27

## Overview

KingSec generates professional security assessment reports in multiple formats. The Report Center provides a unified interface for searching, previewing, downloading, and regenerating reports.

## Report Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| JSON | `.json` | Programmatic consumption, integration with SIEM/SOAR |
| HTML | `.html` | Interactive browser viewing with styling |
| PDF | `.pdf` | Client delivery, printed reports, compliance evidence |
| CSV | `.csv` | Spreadsheet import, data analysis |
| Markdown | `.md` | Version control, documentation embedding |

## Executive Score

Each report includes an executive score from 0 to 100:

| Range | Rating | Color | Meaning |
|-------|--------|-------|---------|
| 80-100 | Good | Green | Low risk, well-secured target |
| 60-79 | Fair | Yellow | Moderate issues, address high-severity items |
| 40-59 | Poor | Orange | Significant security gaps |
| 0-39 | Critical | Red | Urgent action required |

The score is computed from finding severity distribution, finding count, and asset criticality.

## Finding Severity Levels

| Severity | Description | Response |
|----------|-------------|----------|
| CRITICAL | Immediate exploitation risk, remote code execution, data breach | Fix within 24 hours |
| HIGH | Significant vulnerability, privilege escalation, sensitive data exposure | Fix within 7 days |
| MEDIUM | Moderate risk, information disclosure, misconfiguration | Fix within 30 days |
| LOW | Minor issues, best practice violations, informational | Fix within 90 days |
| INFORMATIONAL | Observations, recommendations, no direct risk | Review and track |

## Finding Statuses

| Status | Meaning |
|--------|---------|
| OPEN | Finding identified, no action taken |
| IN_PROGRESS | Remediation in progress |
| RESOLVED | Fix verified |
| FALSE_POSITIVE | Confirmed false positive |

## Report Sections

### Executive Summary
High-level overview of the assessment results, including total findings, severity breakdown, and key risks.

### Risk Summary
Visual severity breakdown with count per severity level and relative distribution.

### Findings Detail
Complete list of findings with severity, title, target, status, evidence count, and discovery date.

### Metadata
Assessment ID, target, generation date, report format, file size.

## Report Center (Frontend)

The Report Center is available at `/reports` and provides:

- **Card grid** — each report shows executive score ring, target name, date, verdict headline, finding counts
- **Search** — debounced text search across target, assessment ID, and verdict
- **Severity filter** — pill-style buttons for Critical, High, Medium, Low
- **Sort** — newest, oldest, highest/lowest risk, A-Z, Z-A
- **Preview drawer** — slide-out panel with full executive score, risk summary bars, metadata, download/regenerate buttons
- **Download** — single-click download of report file
- **Regenerate** — regenerate report with updated data
- **Pagination** — page controls with result counter

## Download via API

```bash
GET /api/v1/assessments/{assessment_id}/report
```

Response is the report file with appropriate Content-Type header.

## Regenerate via API

```bash
POST /api/v1/assessments/{assessment_id}/report
```

Returns the updated report metadata.

## Interpreting Results

1. Review the executive score and severity breakdown first
2. Examine critical and high severity findings individually
3. Check evidence details for each finding
4. Verify false positives before closing findings
5. Track remediation progress using the finding status field

## Action Items

- CRITICAL findings require immediate remediation
- HIGH findings should be scheduled for the next maintenance window
- Schedule recurring assessments to track security posture over time
- Use the trend data in the Findings page to monitor improvement
