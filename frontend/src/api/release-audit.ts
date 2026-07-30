import { apiRequest } from './client'

export interface ReleaseEntry {
  version: string
  released_at: string
  release_type: string
  changes: string[]
  breaking_changes: string[]
  upgrade_from: string | null
  upgraded_at: string | null
  upgraded_by: string | null
  notes: string
}

export interface ReleaseAuditReport {
  current_version: string
  installed_at: string
  total_releases: number
  releases: ReleaseEntry[]
  upgrade_history: ReleaseEntry[]
}

export interface TelemetrySummary {
  period_days: number
  total_sessions: number
  total_events: number
  total_errors: number
  total_api_calls: number
  top_features: Record<string, number>
  avg_session_duration_ms: number
}

export const releaseAuditApi = {
  getReport: () =>
    apiRequest<ReleaseAuditReport>('/api/v1/deployment/release-audit'),

  recordRelease: (data: {
    version: string
    release_type?: string
    changes?: string[]
    breaking_changes?: string[]
    notes?: string
  }) =>
    apiRequest<ReleaseEntry>('/api/v1/deployment/release-audit/record', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getTelemetrySummary: (days?: number) =>
    apiRequest<TelemetrySummary>(
      `/api/v1/deployment/telemetry/summary${days ? `?days=${days}` : ''}`
    ),
}
