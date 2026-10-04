import { apiRequest } from './client'

export interface SessionInfo {
  id: string
  user_id: string
  session_type: string
  jti: string
  issued_at: string
  expires_at: string
  last_activity: string
  client_ip: string
  user_agent: string
  device_name: string
  platform: string
  browser: string
  status: string
}

export interface ApiKeyInfo {
  api_key_id: string
  user_id: string
  name: string
  scope: string
  status: string
  last_used_at: string | null
  created_at: string
}

export interface MfaStatus {
  enabled: boolean
}

export const settingsApi = {
  health: () =>
    apiRequest<{ status: string; bootstrap_required: boolean }>('/health'),

  healthz: () =>
    apiRequest<Record<string, unknown>>('/healthz/health'),

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
