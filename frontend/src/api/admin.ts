import { apiRequest, getAccessToken } from './client'

const API_BASE = '/api/v1'
import type { DashboardSummary } from './dashboard'
import type {
  ListUsersResponse,
  Agent,
  BackupEntry,
  PluginEntry,
  HealthStatus,
  SystemMetrics,
  ListFindingsResponse,
  ListReportsResponse,
  ReportListEntry,
  AdminUserActionEntry,
  AdminResetPasswordBody,
  ListRolesResponse,
} from '@/types/api'

export interface JobStats {
  pending: number
  running: number
  completed: number
  failed: number
  cancelled: number
  average_duration_seconds: number
}

export type UserSearchParams = Record<string, string | number | boolean | undefined | null> & {
  query?: string
  role?: string
  is_active?: boolean
  limit?: number
  offset?: number
  order_by?: string
  order_dir?: string
}

export type FindingsParams = Record<string, string | number | boolean | undefined | null> & {
  limit?: number
  offset?: number
  severity?: string
  status?: string
  assessment_id?: string
  search?: string
  order_by?: string
  order_dir?: string
}

export type ReportsParams = Record<string, string | number | boolean | undefined | null> & {
  limit?: number
  offset?: number
  search?: string
  severity?: string
  target?: string
  order_by?: string
  order_dir?: string
}

function reportDownloadFilename(response: Response, assessmentId: string): string {
  const disposition = response.headers.get('Content-Disposition')
  if (disposition) {
    const encoded = disposition.match(/filename\*\s*=\s*UTF-8''([^;]+)/i)?.[1]
    const basic = disposition.match(/filename\s*=\s*(?:"([^"]+)"|([^;]+))/i)
    let decoded: string | undefined
    if (encoded) {
      try {
        decoded = decodeURIComponent(encoded.trim())
      } catch {
        decoded = undefined
      }
    }
    const raw = decoded ?? (basic?.[1] ?? basic?.[2])?.trim()
    const filename = raw?.split(/[\\/]/).pop()
    if (filename) return filename
  }

  const contentType = response.headers.get('Content-Type')?.toLowerCase() ?? ''
  const extension = contentType.includes('text/html')
    ? 'html'
    : contentType.includes('application/pdf')
      ? 'pdf'
      : 'bin'
  return `kingsec-report-${assessmentId}.${extension}`
}

export const adminApi = {
  users: (params?: { limit?: number; offset?: number }) =>
    apiRequest<ListUsersResponse>('/users', { params }),
  usersSearch: (params?: UserSearchParams) =>
    apiRequest<ListUsersResponse>('/users/search', { params }),
  deactivateUser: (userId: string) =>
    apiRequest<AdminUserActionEntry>(`/users/${userId}/deactivate`, { method: 'PATCH' }),
  activateUser: (userId: string) =>
    apiRequest<AdminUserActionEntry>(`/users/${userId}/activate`, { method: 'PATCH' }),
  resetPassword: (userId: string, body: AdminResetPasswordBody) =>
    apiRequest<AdminUserActionEntry>(`/users/${userId}/reset-password`, { method: 'POST', body }),
  roles: () =>
    apiRequest<ListRolesResponse>('/roles'),
  findings: (params?: FindingsParams) =>
    apiRequest<ListFindingsResponse>('/findings', { params }),
  reports: (params?: ReportsParams) =>
    apiRequest<ListReportsResponse>('/reports', { params }),
  reportDetail: (assessmentId: string) =>
    apiRequest<ReportListEntry>(`/reports/${assessmentId}`),
  downloadReport: async (assessmentId: string) => {
    const token = getAccessToken()
    const res = await fetch(`${API_BASE}/reports/${assessmentId}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!res.ok) throw new Error('Download failed')
    const filename = reportDownloadFilename(res, assessmentId)
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  },
  agents: () =>
    apiRequest<{ agents: Agent[] }>('/agents'),
  backups: () =>
    apiRequest<{ backups: BackupEntry[] }>('/backups'),
  plugins: () =>
    apiRequest<{ plugins: PluginEntry[] }>('/plugins'),
  queueStats: () =>
    apiRequest<JobStats>('/queue/statistics'),
  pipelines: () =>
    apiRequest<{ pipelines: unknown[] }>('/pipelines'),
  secrets: () =>
    apiRequest<{ secrets: unknown[] }>('/admin/secrets'),
  health: () =>
    apiRequest<HealthStatus>('/healthz/health'),
  metrics: () =>
    apiRequest<SystemMetrics>('/healthz/metrics'),
  dashboardSummary: () =>
    apiRequest<DashboardSummary>('/dashboard/summary'),
}
