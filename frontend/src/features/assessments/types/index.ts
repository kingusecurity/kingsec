export interface AssessmentSummary {
  assessment_id: string
  target: string
  status: AssessmentStatus
  is_authorized: boolean
  created_at: string
  findings_count: number
}

export type AssessmentStatus = "CREATED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED"

export interface AssessmentDetail {
  assessment_id: string
  target: string
  status: AssessmentStatus
  is_authorized: boolean
  created_at: string
  findings: AssessmentFinding[]
}

export interface AssessmentFinding {
  finding_id: string
  title: string
  severity: string
  status: string
  evidence_count: number
  recommendation_count: number
}

export interface ListAssessmentsResponse {
  items: AssessmentSummary[]
  total: number
  limit: number
  offset: number
}

export interface ListAssessmentsParams {
  limit?: number
  offset?: number
}

export interface CreateAssessmentRequest {
  target_value: string
  target_type: string
  authorized_by: string
  scope: string
}

export interface CreateAssessmentResponse {
  assessment_id: string
  status: string
  target: string
}

export interface StartAssessmentResponse {
  assessment_id: string
  status: string
  job_id: string | null
}

export interface CancelAssessmentResponse {
  assessment_id: string
  status: string
}

export interface GenerateReportResponse {
  assessment_id: string
  verdict: string
  action_required: boolean
  highest_severity: string | null
  total_findings: number
  severity_counts: Array<{ severity: string; count: number }>
  artifact_media_type: string
  artifact_filename: string
  artifact_bytes: number
}
