import { apiRequest } from './client'

export interface DashboardSummary {
  total_scans: number
  successful_scans: number
  failed_scans: number
  average_duration_seconds: number
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  active_scanners: number
  active_schedules: number
  pending_notifications: number
  failed_notifications: number
}

export interface TrendPoint {
  date: string
  value: number
}

export interface DashboardTrends {
  period: string
  points: TrendPoint[]
}

export interface JobStats {
  pending: number
  running: number
  completed: number
  failed: number
  cancelled: number
  average_duration_seconds: number
}

export const dashboardApi = {
  root: () =>
    apiRequest<{ summary: DashboardSummary; severity: Record<string, number> }>('/dashboard'),

  summary: () =>
    apiRequest<DashboardSummary>('/dashboard/summary'),

  severity: () =>
    apiRequest<{ critical: number; high: number; medium: number; low: number; info: number }>(
      '/dashboard/severity',
    ),

  trends: (params?: { period?: string; limit?: number }) =>
    apiRequest<DashboardTrends>('/dashboard/trends', { params }),

  scanners: () =>
    apiRequest<{ scanners: unknown[] }>('/dashboard/scanners'),

  workers: () =>
    apiRequest<{ workers: unknown[] }>('/dashboard/workers'),

  jobs: () =>
    apiRequest<JobStats>('/dashboard/jobs'),

  schedules: () =>
    apiRequest<{ total: number; active: number; paused: number; disabled: number }>('/dashboard/schedules'),

  notifications: () =>
    apiRequest<{ total: number; sent: number; failed: number; pending: number; read: number }>('/dashboard/notifications'),

  activity: (params?: { limit?: number }) =>
    apiRequest<{ activity: unknown[] }>('/dashboard/activity', { params }),
}
