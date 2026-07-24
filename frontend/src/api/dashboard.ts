import { apiRequest } from './client'

export interface DashboardSummary {
  total_scans: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface TrendPoint {
  date: string
  value: number
}

export interface DashboardTrends {
  period: string
  points: TrendPoint[]
}

export interface ScannerStats {
  scanners: unknown[]
}

export interface WorkerStats {
  workers: unknown[]
}

export interface JobStats {
  pending: number
  running: number
  completed: number
  failed: number
}

export interface ScheduleStats {
  total: number
  active: number
  paused: number
  disabled: number
}

export interface NotificationStats {
  total: number
  sent: number
  failed: number
  pending: number
  read: number
}

export interface RecentActivity {
  activity: unknown[]
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
    apiRequest<ScannerStats>('/dashboard/scanners'),

  workers: () =>
    apiRequest<WorkerStats>('/dashboard/workers'),

  jobs: () =>
    apiRequest<JobStats>('/dashboard/jobs'),

  schedules: () =>
    apiRequest<ScheduleStats>('/dashboard/schedules'),

  notifications: () =>
    apiRequest<NotificationStats>('/dashboard/notifications'),

  activity: (params?: { limit?: number }) =>
    apiRequest<RecentActivity>('/dashboard/activity', { params }),
}
