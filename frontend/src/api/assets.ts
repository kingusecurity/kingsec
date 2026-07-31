import { apiRequest } from './client'

export interface AssetTag {
  key: string
  value: string
}

export interface AssetTechnology {
  type: string
  name: string
  version: string | null
  vendor: string | null
}

export interface AssetSummary {
  total: number
  by_type: Record<string, number>
  by_criticality: Record<string, number>
  by_risk_range: Record<string, number>
  total_open_findings: number
  total_critical_findings: number
  total_high_findings: number
  total_relationships: number
}

export interface AssetListItem {
  id: string
  asset_type: string
  hostname: string | null
  ip_address: string | null
  domain: string | null
  operating_system: string | null
  criticality: string
  risk_score: number
  created_at: string
  updated_at: string
}

export interface AssetDetail extends AssetListItem {
  fqdn: string | null
  mac_address: string | null
  os_version: string | null
  owner: string | null
  location: string | null
  description: string | null
  tags: AssetTag[]
  technologies: AssetTechnology[]
  open_ports: number[]
  first_seen: string | null
  last_seen: string | null
  relationships: AssetRelationship[]
  history: AssetHistoryEntry[]
  finding_count: number
}

export interface AssetRelationship {
  source_asset_id: string
  target_asset_id: string
  relationship_type: string
  metadata: Record<string, unknown>
}

export interface AssetHistoryEntry {
  event_type: string
  description: string
  timestamp: string
  actor: string
}

export const assetsApi = {
  getSummary: () =>
    apiRequest<AssetSummary>('/assets/summary'),

  list: (params: {
    asset_type?: string
    criticality?: string
    search?: string
    owner?: string
    location?: string
    cloud_provider?: string
    risk_score_min?: number
    risk_score_max?: number
    limit?: number
    offset?: number
  } = {}) =>
    apiRequest<{ items: AssetListItem[]; total: number; limit: number; offset: number }>('/assets', { params }),

  search: (q: string, limit = 20) =>
    apiRequest<AssetListItem[]>(`/assets/search?q=${encodeURIComponent(q)}&limit=${limit}`),

  get: (id: string) =>
    apiRequest<AssetDetail>(`/assets/${id}`),

  create: (data: Record<string, unknown>) =>
    apiRequest<AssetDetail>('/assets', { method: 'POST', body: data }),

  update: (id: string, data: Record<string, unknown>) =>
    apiRequest<AssetDetail>(`/assets/${id}`, { method: 'PUT', body: data }),

  delete: (id: string) =>
    apiRequest<{ status: string }>(`/assets/${id}`, { method: 'DELETE' }),

  addTag: (id: string, key: string, value: string) =>
    apiRequest<AssetDetail>(`/assets/${id}/tags`, { method: 'POST', body: { key, value } }),

  removeTag: (id: string, key: string) =>
    apiRequest<AssetDetail>(`/assets/${id}/tags/${key}`, { method: 'DELETE' }),

  getRelationships: (id: string) =>
    apiRequest<AssetRelationship[]>(`/assets/${id}/relationships`),

  addRelationship: (sourceId: string, targetId: string, relType: string, metadata?: Record<string, unknown>) =>
    apiRequest<AssetRelationship>(`/assets/${sourceId}/relationships`, {
      method: 'POST',
      body: { target_asset_id: targetId, relationship_type: relType, metadata },
    }),

  recalculateRisk: (id: string, criticalFindings = 0, highFindings = 0, openFindings = 0) =>
    apiRequest<{ risk_score: number }>(`/assets/${id}/recalculate-risk`, {
      method: 'POST',
      body: { critical_findings: criticalFindings, high_findings: highFindings, open_findings: openFindings },
    }),

  updateCriticality: (id: string, criticality: string) =>
    apiRequest<AssetDetail>(`/assets/${id}/criticality`, {
      method: 'PUT',
      body: { criticality },
    }),

  getHistory: (id: string, limit = 50) =>
    apiRequest<AssetHistoryEntry[]>(`/assets/${id}/history?limit=${limit}`),
}
