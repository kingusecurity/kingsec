import { apiRequest } from './client'

export interface IntegrationInfo {
  type: string
  configured: boolean
  label: string
}

export interface DeliveryRecordInfo {
  id: string
  integration_type: string
  event_type: string
  status: string
  attempt: number
  error: string | null
  timestamp: string
}

export interface TicketInfo {
  finding_id: string
  system: string
  external_id: string
  external_url: string
  created_at: string
  synced: boolean
}

export interface TestResult {
  status: string
  integration_type: string
  success: boolean
}

export const integrationsApi = {
  list: () =>
    apiRequest<{ integrations: IntegrationInfo[] }>('/integrations'),

  test: (integrationType: string) =>
    apiRequest<TestResult>(`/integrations/test/${integrationType}`, { method: 'POST' }),

  webhookHistory: (limit = 50) =>
    apiRequest<{ records: DeliveryRecordInfo[]; total: number }>(`/integrations/webhook/history?limit=${limit}`),

  emailHistory: (limit = 50) =>
    apiRequest<{ records: DeliveryRecordInfo[]; total: number }>(`/integrations/email/history?limit=${limit}`),

  tickets: (findingId?: string) =>
    apiRequest<{ tickets: TicketInfo[]; total: number }>(
      `/integrations/tickets${findingId ? `?finding_id=${findingId}` : ''}`,
    ),
}
