export interface UserResponse {
  user_id: string
  username: string
  email: string
  role: string
  is_active: boolean
  created_at: string
  last_login_at: string | null
}

export interface LoginBody {
  username: string
  password: string
}

export interface LoginResponse {
  user_id: string
  username: string
  role: string
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export interface RefreshTokenBody {
  refresh_token: string
}

export interface RefreshTokenResponse {
  access_token: string
  token_type: string
  expires_in: number
}

export interface RegisterUserBody {
  username: string
  email: string
  password: string
}

export interface RegisterUserResponse {
  user_id: string
  username: string
  email: string
  role: string
}

export interface AssignRoleBody {
  role: string
}

export interface AssignRoleResponse {
  user_id: string
  username: string
  email: string
  new_role: string
}

export interface AssessmentSummary {
  assessment_id: string
  target: string
  status: string
  is_authorized: boolean
  created_at: string
  findings_count: number
}

export interface ListAssessmentsResponse {
  items: AssessmentSummary[]
  total: number
  limit: number
  offset: number
}

export interface FindingResponse {
  finding_id: string
  title: string
  severity: string
  status: string
  evidence_count: number
  recommendation_count: number
}

export interface AssessmentResponse {
  assessment_id: string
  target: string
  status: string
  is_authorized: boolean
  created_at: string
  findings: FindingResponse[]
}

export interface CreateAssessmentBody {
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

export interface SeverityCount {
  severity: string
  count: number
}

export interface GenerateReportResponse {
  assessment_id: string
  verdict: string
  action_required: boolean
  highest_severity: string | null
  total_findings: number
  severity_counts: SeverityCount[]
  artifact_media_type: string
  artifact_filename: string
  artifact_bytes: number
}

export interface ErrorResponse {
  error_code: string
  message: string
}

export interface PaginatedParams {
  limit?: number
  offset?: number
}

export type AssessmentSortField = 'created_at' | 'status' | 'target' | 'findings_count'
export type SortOrder = 'asc' | 'desc'

export interface AssessmentListParams {
  limit?: number
  offset?: number
  search?: string
  status?: string
  severity?: string
  sort_by?: AssessmentSortField
  sort_order?: SortOrder
}

export interface StartAssessmentResponse {
  assessment_id: string
  status: string
  started_at: string
}

export interface CancelAssessmentResponse {
  assessment_id: string
  status: string
  cancelled_at: string
}

export interface DeleteAssessmentResponse {
  assessment_id: string
  deleted: boolean
}

export interface DashboardSummaryResponse {
  total_scans: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface RecentAssessmentItem {
  assessment_id: string
  target: string
  status: string
  findings_count: number
  created_at: string
}

export interface RecentReportItem {
  assessment_id: string
  target: string
  verdict: string
  generated_at: string
}

export interface QuickAction {
  label: string
  description: string
  href: string
  icon: string
}

export interface SystemStatus {
  scanners: { total: number; active: number; healthy: number; degraded: number; down: number }
  workers: { total: number; active: number; idle: number }
  last_updated: string
}
