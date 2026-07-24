import { apiRequest, getAccessToken } from './client'
import type { ReportListParams, ReportSummary } from '@/types/api'

export interface ListReportsResponse {
  items: ReportSummary[]
  total: number
  limit: number
  offset: number
}

export interface ReportDetail {
  assessment_id: string
  target: string
  status: string
  verdict?: string
  highest_severity?: string | null
  total_findings: number
  severity_counts: { severity: string; count: number }[]
  created_at: string
  generated_at?: string
  artifact_filename?: string
  artifact_bytes?: number
  executive_summary?: string
  recommendations?: string[]
}

export const reportsApi = {
  list: (params?: ReportListParams) =>
    apiRequest<ListReportsResponse>('/reports', { params: params as Record<string, string | number | undefined> | undefined }),

  get: (id: string) =>
    apiRequest<ReportDetail>(`/reports/${id}`),

  delete: (id: string) =>
    apiRequest<{ deleted: boolean }>(`/reports/${id}`, { method: 'DELETE' }),

  getDownloadUrl: (reportId: string): string => {
    const token = getAccessToken()
    return `/api/v1/reports/${reportId}/download?token=${token}`
  },
}
