import { apiRequest } from './client'

export interface MonitoringSummary {
  total_events_24h: number
  total_alerts_open: number
  total_alerts_critical: number
  total_alerts_high: number
  total_rules_active: number
  asset_health_percentage: number
  last_scan_time: string | null
  upcoming_certificate_expirations: number
  assets_monitored: number
  recent_events: Array<{ id: string; event_type: string; title: string; timestamp: string }>
  recent_alerts: Array<{ id: string; title: string; severity: string; created_at: string }>
}

export interface MonitoringStats {
  events_last_24h: number
  events_last_7d: number
  alerts_last_24h: number
  alerts_open: number
  alerts_critical: number
  alerts_high: number
  rules_active: number
  rules_total: number
  assets_monitored: number
  assets_healthy: number
  assets_warning: number
  assets_critical: number
  total_changes_detected: number
}

export interface MonitorEventItem {
  id: string
  event_type: string
  asset_id: string | null
  assessment_id: string | null
  source: string
  title: string
  description: string
  severity: string
  context: Array<{ key: string; value: string; previous_value: string | null }>
  timestamp: string
}

export interface AlertItem {
  id: string
  rule_id: string
  title: string
  description: string
  severity: string
  status: string
  source_event_id: string | null
  asset_id: string | null
  assessment_id: string | null
  created_at: string
  acknowledged_at: string | null
  resolved_at: string | null
  acknowledged_by: string | null
  resolved_by: string | null
}

export interface RuleItem {
  id: string
  name: string
  description: string
  event_type: string | null
  conditions: Array<{ field: string; operator: string; value: string }>
  alert_severity: string
  enabled: boolean
  cooldown_minutes: number
  notify_channels: string[]
  created_at: string
  updated_at: string
}

export interface MonitoringTrends {
  events: Array<{ date: string; count: number }>
  alerts: Array<{ date: string; count: number; critical: number; high: number }>
  exposures: Array<{ date: string; total: number }>
  compliance: Array<{ date: string; score: number }>
  risk: Array<{ date: string; average_risk: number; max_risk: number }>
}

export const monitoringApi = {
  getSummary: () =>
    apiRequest<MonitoringSummary>('/monitoring/summary'),

  getStats: () =>
    apiRequest<MonitoringStats>('/monitoring/stats'),

  getHealth: () =>
    apiRequest<{ status: string }>('/monitoring/health'),

  getTrends: (days = 30) =>
    apiRequest<MonitoringTrends>(`/monitoring/trends?days=${days}`),

  listEvents: (params: {
    event_type?: string
    asset_id?: string
    severity?: string
    source?: string
    search?: string
    limit?: number
    offset?: number
  } = {}) =>
    apiRequest<{ items: MonitorEventItem[]; total: number; limit: number; offset: number }>(
      '/monitoring/events', { params },
    ),

  getEvent: (id: string) =>
    apiRequest<MonitorEventItem>(`/monitoring/events/${id}`),

  listAlerts: (params: {
    rule_id?: string
    severity?: string
    status?: string
    asset_id?: string
    search?: string
    limit?: number
    offset?: number
  } = {}) =>
    apiRequest<{ items: AlertItem[]; total: number; limit: number; offset: number }>(
      '/monitoring/alerts', { params },
    ),

  getAlert: (id: string) =>
    apiRequest<AlertItem>(`/monitoring/alerts/${id}`),

  acknowledgeAlert: (id: string) =>
    apiRequest<AlertItem>(`/monitoring/alerts/${id}/acknowledge`, { method: 'POST' }),

  resolveAlert: (id: string) =>
    apiRequest<AlertItem>(`/monitoring/alerts/${id}/resolve`, { method: 'POST' }),

  dismissAlert: (id: string) =>
    apiRequest<AlertItem>(`/monitoring/alerts/${id}/dismiss`, { method: 'POST' }),

  listRules: (params: {
    enabled?: boolean
    event_type?: string
    search?: string
    limit?: number
    offset?: number
  } = {}) =>
    apiRequest<{ items: RuleItem[]; total: number; limit: number; offset: number }>(
      '/monitoring/rules', { params },
    ),

  getRule: (id: string) =>
    apiRequest<RuleItem>(`/monitoring/rules/${id}`),

  createRule: (data: Record<string, unknown>) =>
    apiRequest<RuleItem>('/monitoring/rules', { method: 'POST', body: data }),

  updateRule: (id: string, data: Record<string, unknown>) =>
    apiRequest<RuleItem>(`/monitoring/rules/${id}`, { method: 'PUT', body: data }),

  deleteRule: (id: string) =>
    apiRequest<{ status: string }>(`/monitoring/rules/${id}`, { method: 'DELETE' }),

  enableRule: (id: string) =>
    apiRequest<RuleItem>(`/monitoring/rules/${id}/enable`, { method: 'POST' }),

  disableRule: (id: string) =>
    apiRequest<RuleItem>(`/monitoring/rules/${id}/disable`, { method: 'POST' }),

  seedRules: () =>
    apiRequest<RuleItem[]>('/monitoring/rules/seed', { method: 'POST' }),
}
