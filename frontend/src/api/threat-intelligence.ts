import { apiRequest } from './client'

export interface TISummary {
  total_cves: number
  critical_cves: number
  high_cves: number
  medium_cves: number
  low_cves: number
  kev_count: number
  active_exploitations: number
  average_threat_score: number
  average_epss_score: number
  feeds_active: number
  feeds_total: number
  trending_threats: Array<{ cve_code: string; threat_score: number; severity: string; is_kev: boolean }>
  top_critical_cves: Array<{ cve_code: string; threat_score: number; description: string }>
  recent_kev_additions: number
}

export interface CvssData {
  version: string
  vector_string: string
  base_score: number
  base_severity: string
  exploitability_score: number
  impact_score: number
  attack_vector: string
  attack_complexity: string
  privileges_required: string
  user_interaction: string
  confidentiality_impact: string
  integrity_impact: string
  availability_impact: string
}

export interface EpssData {
  score: number
  percentile: number
  model_version: string
  date: string
}

export interface CveItem {
  id: string
  cve_code: string
  description: string
  severity: string
  published_date: string
  last_modified: string
  cvss_data: CvssData
  epss_data: EpssData | null
  exploit_maturity: string
  affected_products: Array<{ vendor: string; product: string; version: string; operator: string }>
  references: Array<{ url: string; source: string; tags: string[] }>
  vendor_advisories: string[]
  weaknesses: string[]
  is_kev: boolean
  kev_entry: KevEntry | null
  threat_score: number
  exploitability_score: number
  priority_score: number
  created_at: string
  updated_at: string
}

export interface KevEntry {
  id: string
  cve_id: string
  vendor_project: string
  product: string
  vulnerability_name: string
  date_added: string
  due_date: string
  required_action: string
  known_ransomware_campaign_use: boolean
  notes: string
}

export interface ThreatFeedItem {
  feed_id: string
  feed_type: string
  title: string
  description: string
  source_url: string
  entries: number
  last_synced: string
  status: string
}

export interface ThreatRiskAssessment {
  business_risk: number
  exploitability_score: number
  priority_score: number
  likelihood: number
  overall_threat_score: number
}

export interface TrendingThreat {
  cve_code: string
  description: string
  threat_score: number
  change: number
  severity: string
  is_kev: boolean
}

export interface TrendPoint {
  date: string
  new_cves: number
  critical_cves: number
  kev_additions: number
  average_score: number
}

export interface CveFilter {
  search?: string
  severity?: string
  min_score?: number
  max_score?: number
  is_kev?: boolean
  exploit_maturity?: string
  published_after?: string
  published_before?: string
  vendor?: string
  product?: string
  sort_by?: string
  page?: number
  page_size?: number
}

// --- Summary ---

export function getTISummary(): Promise<TISummary> {
  return apiRequest('/api/v1/threat-intelligence/summary')
}

// --- CVEs ---

export function listCves(filter?: CveFilter): Promise<{ items: CveItem[]; total: number; page: number; page_size: number }> {
  const params = new URLSearchParams()
  if (filter) {
    Object.entries(filter).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.set(k, String(v))
    })
  }
  return apiRequest(`/api/v1/cves?${params.toString()}`)
}

export function getCveById(id: string): Promise<CveItem> {
  return apiRequest(`/api/v1/cves/${encodeURIComponent(id)}`)
}

export function syncCve(cveCode: string): Promise<CveItem> {
  return apiRequest(`/api/v1/cves/${encodeURIComponent(cveCode)}/sync`, { method: 'POST' })
}

export function deleteCve(id: string): Promise<{ status: string }> {
  return apiRequest(`/api/v1/cves/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export function getCveRiskAssessment(id: string): Promise<ThreatRiskAssessment> {
  return apiRequest(`/api/v1/cves/${encodeURIComponent(id)}/risk`)
}

// --- KEV ---

export function listKevEntries(filter?: {
  search?: string
  known_ransomware?: boolean
  vendor?: string
  product?: string
  page?: number
  page_size?: number
}): Promise<{ items: CveItem[]; total: number; page: number; page_size: number }> {
  const params = new URLSearchParams()
  if (filter) {
    Object.entries(filter).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.set(k, String(v))
    })
  }
  return apiRequest(`/api/v1/kev?${params.toString()}`)
}

// --- EPSS ---

export function getEpssScore(cveCode: string): Promise<EpssData> {
  return apiRequest(`/api/v1/epss/${encodeURIComponent(cveCode)}`)
}

// --- Trending ---

export function getTrendingThreats(limit?: number): Promise<TrendingThreat[]> {
  const params = limit ? `?limit=${limit}` : ''
  return apiRequest(`/api/v1/threats/trending${params}`)
}

// --- Trends ---

export function getTITrends(days?: number): Promise<TrendPoint[]> {
  const params = days ? `?days=${days}` : ''
  return apiRequest(`/api/v1/threat-intelligence/trends${params}`)
}

// --- Timeline ---

export function getTITimeline(days?: number): Promise<Array<{ date: string; cve_code: string; severity: string; threat_score: number; is_kev: boolean; description: string }>> {
  const params = days ? `?days=${days}` : ''
  return apiRequest(`/api/v1/threat-intelligence/timeline${params}`)
}

// --- Feeds ---

export function listFeeds(): Promise<ThreatFeedItem[]> {
  return apiRequest('/api/v1/threat-intelligence/feeds')
}

export function registerFeed(feedType: string, title: string, sourceUrl?: string): Promise<{ feed_id: string; feed_type: string; title: string; last_synced: string }> {
  const params = new URLSearchParams({ feed_type: feedType, title })
  if (sourceUrl) params.set('source_url', sourceUrl)
  return apiRequest(`/api/v1/threat-intelligence/feeds?${params.toString()}`, { method: 'POST' })
}

// --- Critical ---

export function getCriticalCves(limit?: number): Promise<CveItem[]> {
  const params = limit ? `?limit=${limit}` : ''
  return apiRequest(`/api/v1/threat-intelligence/critical${params}`)
}

// --- Reports ---

export function generateThreatReport(days?: number): Promise<any> {
  const params = days ? `?days=${days}` : ''
  return apiRequest(`/api/v1/threat-intelligence/reports/threat${params}`)
}

export function generateExecutiveReport(days?: number): Promise<any> {
  const params = days ? `?days=${days}` : ''
  return apiRequest(`/api/v1/threat-intelligence/reports/executive${params}`)
}

export function generateKevReport(): Promise<any> {
  return apiRequest('/api/v1/threat-intelligence/reports/kev')
}

export function generateHighRiskReport(minScore?: number): Promise<any> {
  const params = minScore ? `?min_score=${minScore}` : ''
  return apiRequest(`/api/v1/threat-intelligence/reports/high-risk${params}`)
}
