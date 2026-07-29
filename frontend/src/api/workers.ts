import { apiRequest } from './client'

export interface WorkerCapability {
  scanner_id: string
  scanner_name: string
  scanner_version: string
}

export interface Worker {
  worker_id: string
  hostname: string
  os: string
  cpu: string
  ram_mb: number
  status: string
  health: string
  last_heartbeat: string
  current_jobs: string[]
  capabilities: WorkerCapability[]
  created_at: string
  updated_at?: string
}

export interface WorkerListResponse {
  workers: Worker[]
  total: number
}

export interface WorkerDetailResponse {
  worker: Worker
}

export async function listWorkers(): Promise<WorkerListResponse> {
  return apiRequest('/workers')
}

export async function getWorker(id: string): Promise<WorkerDetailResponse> {
  return apiRequest(`/workers/${encodeURIComponent(id)}`)
}

export async function registerWorker(data: Partial<Worker> & { worker_id: string }): Promise<{ message: string; worker: Worker }> {
  return apiRequest('/workers/register', { method: 'POST', body: data })
}

export async function sendHeartbeat(worker_id: string, status?: string, current_jobs?: string[], health?: string): Promise<{ message: string; worker: Worker }> {
  return apiRequest('/workers/heartbeat', { method: 'POST', body: { worker_id, status, current_jobs, health } })
}

export async function deleteWorker(id: string): Promise<{ message: string }> {
  return apiRequest(`/workers/${encodeURIComponent(id)}`, { method: 'DELETE' })
}
