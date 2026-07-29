import { apiRequest } from './client'

export interface PlaybookAction {
  action_type: string
  config: Record<string, unknown>
  order: number
  timeout_seconds: number
  retry_count: number
  continue_on_failure: boolean
}

export interface PlaybookTrigger {
  trigger_type: string
  config: Record<string, unknown>
  conditions: Record<string, unknown>
}

export interface Playbook {
  id: string
  name: string
  description: string
  category: string
  severity: string
  tags: string[]
  enabled: boolean
  trigger: PlaybookTrigger
  actions: PlaybookAction[]
  rollback_actions: PlaybookAction[]
  created_at: string
  updated_at: string
}

export interface ActionExecutionLog {
  action_type: string
  status: string
  started_at: string
  completed_at: string
  duration_ms: number
  output: string
  error: string
  retry_attempts: number
}

export interface ExecutionHistory {
  id: string
  playbook_id: string
  playbook_name: string
  trigger_type: string
  trigger_entity_id: string
  status: string
  action_logs: ActionExecutionLog[]
  started_at: string
  completed_at: string
  duration_ms: number
  error: string
  rolled_back: boolean
  created_at: string
}

export interface PlaybookStats {
  playbook_count: number
  total_executions: number
  by_status: Record<string, number>
  success_rate: number
  average_duration_ms: number
  recent_executions: {
    id: string
    playbook_name: string
    status: string
    started_at: string
    duration_ms: number
  }[]
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  limit?: number
  offset?: number
}

export async function listPlaybooks(params?: {
  enabled?: boolean
  category?: string
  trigger_type?: string
  severity?: string
}): Promise<PaginatedResponse<Playbook>> {
  const search = new URLSearchParams()
  if (params?.enabled !== undefined) search.set('enabled', String(params.enabled))
  if (params?.category) search.set('category', params.category)
  if (params?.trigger_type) search.set('trigger_type', params.trigger_type)
  if (params?.severity) search.set('severity', params.severity)
  const qs = search.toString()
  return apiRequest(`/playbooks${qs ? `?${qs}` : ''}`)
}

export async function createPlaybook(data: {
  name: string
  description?: string
  category?: string
  severity?: string
  tags?: string[]
  trigger?: PlaybookTrigger
  actions?: PlaybookAction[]
  rollback_actions?: PlaybookAction[]
}): Promise<Playbook> {
  return apiRequest('/playbooks', { method: 'POST', body: data })
}

export async function getPlaybook(id: string): Promise<Playbook> {
  return apiRequest(`/playbooks/${id}`)
}

export async function updatePlaybook(id: string, data: Partial<Playbook>): Promise<Playbook> {
  return apiRequest(`/playbooks/${id}`, { method: 'PUT', body: data })
}

export async function deletePlaybook(id: string): Promise<void> {
  return apiRequest(`/playbooks/${id}`, { method: 'DELETE' })
}

export async function executePlaybook(id: string, context?: Record<string, unknown>): Promise<ExecutionHistory> {
  return apiRequest(`/playbooks/${id}/execute`, { method: 'POST', body: context ?? {} })
}

export async function enablePlaybook(id: string): Promise<Playbook> {
  return apiRequest(`/playbooks/${id}/enable`, { method: 'POST' })
}

export async function disablePlaybook(id: string): Promise<Playbook> {
  return apiRequest(`/playbooks/${id}/disable`, { method: 'POST' })
}

export async function listExecutions(params?: {
  status?: string
  trigger_type?: string
  limit?: number
  offset?: number
}): Promise<PaginatedResponse<ExecutionHistory>> {
  const search = new URLSearchParams()
  if (params?.status) search.set('status', params.status)
  if (params?.trigger_type) search.set('trigger_type', params.trigger_type)
  if (params?.limit) search.set('limit', String(params.limit))
  if (params?.offset) search.set('offset', String(params.offset))
  const qs = search.toString()
  return apiRequest(`/playbooks/history${qs ? `?${qs}` : ''}`)
}

export async function getExecution(id: string): Promise<ExecutionHistory> {
  return apiRequest(`/playbooks/history/${id}`)
}

export async function getPlaybookStats(): Promise<PlaybookStats> {
  return apiRequest('/playbooks/stats')
}
