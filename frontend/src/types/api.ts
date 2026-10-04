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
  access_token?: string
  refresh_token?: string
  mfa_required: boolean
  pending_token?: string
  token_type: string
  expires_in: number
}

export interface VerifyMfaBody {
  pending_token: string
  totp_code: string
}

export interface UseRecoveryCodeBody {
  pending_token: string
  recovery_code: string
}

export interface MfaLoginResponse {
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
  // Concrete host/asset the scanner observed the finding on. Present on
  // API responses since the affected_asset backend fix; optional so older
  // fixtures and cached responses still typecheck. Null/absent means the
  // scanner reported no per-host asset - callers fall back to the
  // assessment target, same as the report does.
  affected_asset?: string | null
}

export interface ScannerSummaryResponse {
  scanner_id: string
  name: string
  status: string
  findings_count: number
  skipped_reason: string | null
}

export interface AssessmentResponse {
  assessment_id: string
  target: string
  status: string
  is_authorized: boolean
  created_at: string
  findings: FindingResponse[]
  profile_id: string | null
  scanner_summary: ScannerSummaryResponse[]
}

export interface CreateAssessmentBody {
  target_value: string
  target_type: string
  authorized_by: string
  scope: string
  profile_id?: string
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
}

export interface RecentAssessmentItem {
  assessment_id: string
  target: string
  status: string
  findings_count: number
  created_at: string
}

export interface FindingDetail extends FindingResponse {
  assessment_id?: string
  target?: string
  cve?: string[]
  cwe?: string[]
  cvss_score?: number
  cvss_vector?: string
  description?: string
  remediation?: string
  evidence?: { label: string; content: string }[]
  references?: { title: string; url: string }[]
  scanner?: string
  asset?: string
  port?: number
  protocol?: string
}

export interface QuickAction {
  label: string
  description: string
  href: string
  icon: string
}

export interface UserListEntry {
  user_id: string
  username: string
  email: string
  role: string
  is_active: boolean
  created_at: string
  last_login_at: string | null
}

export interface ListUsersResponse {
  items: UserListEntry[]
  total: number
  limit: number
  offset: number
}

export interface Agent {
  id: string
  name: string
  status: string
  last_heartbeat: string | null
}

export interface BackupEntry {
  id: string
  type: string
  status: string
  created_at: string
  size_bytes: number
}

export interface PluginEntry {
  id: string
  name: string
  version: string
  enabled: boolean
  status: string
}

export interface HealthStatus {
  status: string
  uptime: string
  version: string
}

export interface SystemMetrics {
  cpu_usage: number
  memory_usage: number
  disk_usage: number
}

export interface FindingListEntry {
  finding_id: string
  assessment_id: string
  target: string
  title: string
  description: string
  severity: string
  status: string
  discovered_at: string
  evidence_count: number
  recommendation_count: number
}

export interface ListFindingsResponse {
  items: FindingListEntry[]
  total: number
  limit: number
  offset: number
}

export interface ReportListEntry {
  assessment_id: string
  target: string
  generated_at: string
  verdict_headline: string
  verdict_highest_severity: string | null
  verdict_action_required: boolean
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  executive_score: number
  format: string
  file_size: number
}

export interface ListReportsResponse {
  items: ReportListEntry[]
  total: number
  limit: number
  offset: number
}

export interface RolePermissionEntry {
  role: string
  description: string
  permissions: string[]
}

export interface ListRolesResponse {
  roles: RolePermissionEntry[]
}

export interface AdminUserActionEntry {
  user_id: string
  username: string
  email: string
  role: string
  is_active: boolean
}

export interface AdminResetPasswordBody {
  new_password: string
}
