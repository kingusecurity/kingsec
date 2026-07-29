import { apiRequest } from './client'

export interface QueueEntry {
  entry_id: string
  job_id: string
  state: string
  target: string
  assigned_worker_id: string | null
  retry_count: number
  max_retries: number
  error_message: string
  created_at: string
  updated_at: string
  started_at: string | null
  completed_at: string | null
  payload?: string
  scanner_ids?: string[]
}

export interface QueueMetrics {
  total_queued: number
  total_assigned: number
  total_running: number
  total_completed: number
  total_failed: number
  total_cancelled: number
  total_retrying: number
  total_expired: number
  total_dead_letter: number
  average_wait_seconds: number
  oldest_job_age_seconds: number
}

export interface DeadLetterEntry {
  entry_id: string
  original_job_id: string
  original_entry_id: string
  reason: string
  retry_count: number
  failed_at: string
}

export async function listQueue(state?: string): Promise<{ entries: QueueEntry[]; total: number }> {
  const params: Record<string, string> = {}
  if (state) params.state = state
  return apiRequest('/queue', { params })
}

export async function getQueueEntry(entry_id: string): Promise<QueueEntry> {
  return apiRequest(`/queue/${encodeURIComponent(entry_id)}`)
}

export async function getQueueMetrics(): Promise<QueueMetrics> {
  return apiRequest('/queue/metrics')
}

export async function retryJob(entry_id: string): Promise<{ message: string; entry: { entry_id: string; state: string; retry_count: number } }> {
  return apiRequest(`/queue/retry/${encodeURIComponent(entry_id)}`, { method: 'POST' })
}

export async function cancelJob(entry_id: string): Promise<{ message: string; entry: { entry_id: string; state: string } }> {
  return apiRequest(`/queue/cancel/${encodeURIComponent(entry_id)}`, { method: 'POST' })
}

export async function listDeadLetter(): Promise<{ entries: DeadLetterEntry[]; total: number }> {
  return apiRequest('/queue/dead-letter')
}

export async function requeueDeadLetter(entry_id: string): Promise<{ message: string; entry: { entry_id: string; state: string } }> {
  return apiRequest(`/queue/dead-letter/${encodeURIComponent(entry_id)}/requeue`, { method: 'POST' })
}
