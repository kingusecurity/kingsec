import { apiRequest } from './client'

export interface ActivityEvent {
  id: string
  type: string
  message: string
  severity: string
  created_at: string
  user?: string
  assessment_id?: string
}

export interface ActivityResponse {
  activity: ActivityEvent[]
}

export interface WorkerInfo {
  id: string
  name: string
  status: string
  task: string | null
  cpu: number
  memory: number
  last_seen: string
}

export interface WorkerStatsResponse {
  workers: WorkerInfo[]
}

export interface JobStatsResponse {
  pending: number
  running: number
  completed: number
  failed: number
}

export interface ScannerInfo {
  id: string
  name: string
  type: string
  status: string
  version: string
}

export interface ScannerStatsResponse {
  scanners: ScannerInfo[]
}

export const activityApi = {
  activity: (params?: { limit?: number }) =>
    apiRequest<ActivityResponse>('/dashboard/activity', { params }),

  workers: () =>
    apiRequest<WorkerStatsResponse>('/dashboard/workers'),

  jobs: () =>
    apiRequest<JobStatsResponse>('/dashboard/jobs'),

  scanners: () =>
    apiRequest<ScannerStatsResponse>('/dashboard/scanners'),
}
