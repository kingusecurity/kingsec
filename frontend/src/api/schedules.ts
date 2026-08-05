import { apiRequest } from './client'

export interface Schedule {
  id: string
  name: string
  description: string
  owner_user_id: string
  target: string
  scanner_ids: string[]
  config: Record<string, unknown>
  schedule_type: string
  cron_expression: string
  timezone: string
  enabled: boolean
  paused: boolean
  status: string
  created_at: string
  updated_at: string
  last_run: string | null
  next_run: string | null
  retry_strategy: string
  max_retries: number
  retry_delay_seconds: number
  current_retry_count: number
}

export interface CreateScheduleBody {
  name: string
  description?: string
  target: string
  scanner_ids?: string[]
  config?: Record<string, unknown>
  schedule_type?: string
  cron_expression?: string
  timezone?: string
  retry_strategy?: string
  max_retries?: number
  retry_delay_seconds?: number
}

export type UpdateScheduleBody = Partial<CreateScheduleBody>

export async function listSchedules(): Promise<{ items: Schedule[] }> {
  return apiRequest('/schedules')
}

export async function getSchedule(id: string): Promise<{ schedule: Schedule }> {
  return apiRequest(`/schedules/${encodeURIComponent(id)}`)
}

export async function createSchedule(data: CreateScheduleBody): Promise<{ schedule: Schedule }> {
  return apiRequest('/schedules', { method: 'POST', body: data })
}

export async function updateSchedule(id: string, data: UpdateScheduleBody): Promise<{ schedule: Schedule }> {
  return apiRequest(`/schedules/${encodeURIComponent(id)}`, { method: 'PUT', body: data })
}

export async function deleteSchedule(id: string): Promise<{ success: boolean }> {
  return apiRequest(`/schedules/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export async function pauseSchedule(id: string): Promise<{ schedule: Schedule }> {
  return apiRequest(`/schedules/${encodeURIComponent(id)}/pause`, { method: 'POST' })
}

export async function resumeSchedule(id: string): Promise<{ schedule: Schedule }> {
  return apiRequest(`/schedules/${encodeURIComponent(id)}/resume`, { method: 'POST' })
}

export async function enableSchedule(id: string): Promise<{ schedule: Schedule }> {
  return apiRequest(`/schedules/${encodeURIComponent(id)}/enable`, { method: 'POST' })
}

export async function disableSchedule(id: string): Promise<{ schedule: Schedule }> {
  return apiRequest(`/schedules/${encodeURIComponent(id)}/disable`, { method: 'POST' })
}

export async function triggerSchedule(id: string): Promise<{ schedule: Schedule; job_id: string }> {
  return apiRequest(`/schedules/${encodeURIComponent(id)}/trigger`, { method: 'POST' })
}
