import { apiRequest } from './client'

export interface AuditEntry {
  id: string
  user_id: string
  username: string
  action: string
  resource_type: string
  resource_id: string | null
  details: string | null
  severity: string
  ip_address: string | null
  success: boolean
  created_at: string
}

export interface AuditListResponse {
  items: AuditEntry[]
  total: number
  limit: number
  offset: number
}

export interface AuditListParams {
  limit?: number
  offset?: number
  search?: string
  user_id?: string
  action?: string
  resource_type?: string
  severity?: string
  success?: boolean
  since?: string
  until?: string
}

export const auditApi = {
  list: (params?: AuditListParams) =>
    apiRequest<AuditListResponse>('/audit', { params: params as Record<string, string | number | undefined> | undefined }),

  get: (id: string) =>
    apiRequest<AuditEntry>('/audit/events/' + id),
}
