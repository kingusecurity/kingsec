import { apiRequest } from './client'

export interface HealthResponse {
  status: string
  version: string
}

export interface SessionInfo {
  id: string
  user_id: string
  ip_address: string
  user_agent: string
  created_at: string
  last_active_at: string
  is_current: boolean
}

export interface ApiKeyInfo {
  id: string
  name: string
  key_prefix: string
  created_at: string
  last_used_at: string | null
}

export interface MfaStatus {
  enabled: boolean
  method: string | null
}

export interface HealthzResponse {
  status: string
  uptime: number
  version: string
}

export const settingsApi = {
  health: () =>
    apiRequest<HealthResponse>('/health'),

  healthz: () =>
    apiRequest<HealthzResponse>('/healthz/health'),

  sessions: () =>
    apiRequest<SessionInfo[]>('/sessions'),

  deleteSession: (id: string) =>
    apiRequest<void>('/sessions/' + id, { method: 'DELETE' }),

  deleteAllSessions: () =>
    apiRequest<void>('/sessions', { method: 'DELETE' }),

  deleteCurrentSession: () =>
    apiRequest<void>('/sessions/current', { method: 'DELETE' }),

  mfaStatus: () =>
    apiRequest<MfaStatus>('/mfa/status'),

  apiKeys: () =>
    apiRequest<ApiKeyInfo[]>('/apikeys/me'),
}
