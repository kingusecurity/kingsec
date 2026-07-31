import { apiRequest } from './client'

export interface ExposureDetail {
  key: string
  value: string
}

export interface AttackSurfaceSummary {
  total_exposures: number
  by_severity: Record<string, number>
  by_type: Record<string, number>
  by_status: Record<string, number>
  by_source: Record<string, number>
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  mitigated_count: number
  average_risk_score: number
  total_assets_affected: number
  top_risk_items: Array<{
    id: string
    title: string
    type: string
    severity: string
    risk_score: number
  }>
}

export interface ExposureListItem {
  id: string
  asset_id: string
  exposure_type: string
  severity: string
  title: string
  description: string
  status: string
  source: string
  hostname: string | null
  ip_address: string | null
  domain: string | null
  port: number | null
  protocol: string | null
  url: string | null
  risk_score: number
  remediation: string | null
  created_at: string
  updated_at: string
}

export interface ExposureDetail extends ExposureListItem {
  detail: ExposureDetail[]
  tls_version: string | null
  certificate_issuer: string | null
  certificate_expiry: string | null
  header_name: string | null
  header_value: string | null
  technology_name: string | null
  technology_version: string | null
  cloud_provider: string | null
  cloud_bucket: string | null
  evidence: string | null
  first_seen: string
  last_seen: string
}

export interface ExposureRisk {
  exposure_score: number
  internet_exposure: number
  critical_asset_exposure: number
  public_service_count: number
  tls_score: number
  trend: string
}

export interface ExposureHistoryEntry {
  event_type: string
  description: string
  timestamp: string
  previous_value: string | null
  new_value: string | null
  actor: string
}

export interface TrendPoint {
  date: string
  critical: number
  high: number
  medium: number
  low: number
  info: number
  total: number
}

export const attackSurfaceApi = {
  getSummary: () =>
    apiRequest<AttackSurfaceSummary>('/attack-surface/summary'),

  getRisk: () =>
    apiRequest<ExposureRisk>('/attack-surface/risk'),

  getTrend: (days = 30) =>
    apiRequest<TrendPoint[]>(`/attack-surface/trend?days=${days}`),

  getAssetsWithExposures: () =>
    apiRequest<string[]>('/attack-surface/assets'),

  list: (params: {
    asset_id?: string
    exposure_type?: string
    severity?: string
    status?: string
    source?: string
    search?: string
    risk_score_min?: number
    risk_score_max?: number
    limit?: number
    offset?: number
  } = {}) =>
    apiRequest<{ items: ExposureListItem[]; total: number; limit: number; offset: number }>(
      '/attack-surface/exposures', { params },
    ),

  search: (q: string, limit = 20) =>
    apiRequest<ExposureListItem[]>(`/attack-surface/exposures/search?q=${encodeURIComponent(q)}&limit=${limit}`),

  get: (id: string) =>
    apiRequest<ExposureDetail>(`/attack-surface/exposures/${id}`),

  create: (data: Record<string, unknown>) =>
    apiRequest<ExposureDetail>('/attack-surface/exposures', { method: 'POST', body: data }),

  update: (id: string, data: Record<string, unknown>) =>
    apiRequest<ExposureDetail>(`/attack-surface/exposures/${id}`, { method: 'PUT', body: data }),

  delete: (id: string) =>
    apiRequest<{ status: string }>(`/attack-surface/exposures/${id}`, { method: 'DELETE' }),

  getAssetExposures: (assetId: string, limit = 50, offset = 0) =>
    apiRequest<{ items: ExposureListItem[]; total: number; limit: number; offset: number }>(
      `/attack-surface/assets/${assetId}/exposures?limit=${limit}&offset=${offset}`,
    ),

  mitigate: (id: string) =>
    apiRequest<ExposureDetail>(`/attack-surface/exposures/${id}/mitigate`, { method: 'POST' }),

  updateRemediation: (id: string, remediation: string) =>
    apiRequest<ExposureDetail>(`/attack-surface/exposures/${id}/remediation`, {
      method: 'PUT',
      body: { remediation },
    }),

  getHistory: (id: string, limit = 50) =>
    apiRequest<ExposureHistoryEntry[]>(`/attack-surface/exposures/${id}/history?limit=${limit}`),

  getHighRisk: (minScore = 50) =>
    apiRequest<ExposureListItem[]>(`/attack-surface/high-risk?min_score=${minScore}`),
}
