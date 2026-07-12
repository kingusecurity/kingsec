export interface ReportData {
  assessment_id: string
  verdict: string
  action_required: boolean
  highest_severity: string | null
  total_findings: number
  severity_counts: SeverityCount[]
  artifact_media_type: string
  artifact_filename: string
  artifact_bytes: number
  generated_at?: string
}

export interface SeverityCount {
  severity: string
  count: number
}

export interface ReportListItem {
  assessment_id: string
  target: string
  status: string
  findings_count: number
  created_at: string
  report: ReportData | null
}

export type ReportVerdict = "pass" | "fail" | "warning" | "info"
