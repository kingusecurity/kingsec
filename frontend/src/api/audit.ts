import { apiRequest } from './client'

export interface AuditEntry {
  action: string
  resource_type: string
  resource_id: string | null
  success: boolean
  reason: string
  timestamp: string
  user_id: string
  username: string
  role: string
  ip_address: string
  correlation_id: string | null
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
  user_id?: string
  action?: string
  resource_type?: string
  success?: boolean
  since?: string
  until?: string
}

export const auditApi = {
  list: (params?: AuditListParams) =>
    apiRequest<AuditListResponse>('/audit', { params: params as Record<string, string | number | undefined> | undefined }),
}
