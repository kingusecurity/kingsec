import { apiRequest } from './client'

export interface PluginRuntime {
  id: string
  name: string
  version: string
  type: string
  permissions: string[]
  loaded: boolean
  entry_point: string
  error: string
}

export interface PluginManifest {
  id: string
  name: string
  version: string
  author: string
  description: string
  category: string
  permissions: string[]
  entrypoint: string
  minimum_kingsec_version: string
}

export interface PluginDetail {
  id: string
  name: string
  version: string
  type: string
  permissions: string[]
  loaded: boolean
  entry_point: string
  error: string
  manifest: PluginManifest | null
}

export interface MarketplacePlugin {
  id: string
  name: string
  version: string
  author: string
  description: string
  category: string
  license: string
  website: string
  downloads: number
  rating: number
  verified: boolean
  tags: string[]
}

export interface PluginListResponse {
  plugins: PluginRuntime[]
  total: number
}

export interface MarketplaceListResponse {
  plugins: MarketplacePlugin[]
  total: number
}

export async function listSdkPlugins(typeFilter?: string): Promise<PluginListResponse> {
  const params = typeFilter ? `?type=${typeFilter}` : ''
  return apiRequest(`/plugin-sdk/plugins${params}`)
}

export async function getSdkPlugin(id: string): Promise<PluginDetail> {
  return apiRequest(`/plugin-sdk/plugins/${id}`)
}

export async function scanPluginDir(): Promise<{ message: string; count: number }> {
  return apiRequest('/plugin-sdk/plugins/scan', { method: 'POST' })
}

export async function loadPlugin(id: string): Promise<{ message: string; plugin: { id: string; name: string; loaded: boolean } }> {
  return apiRequest(`/plugin-sdk/plugins/${id}/load`, { method: 'POST' })
}

export async function unloadPlugin(id: string): Promise<{ message: string }> {
  return apiRequest(`/plugin-sdk/plugins/${id}/unload`, { method: 'POST' })
}

export async function listMarketplace(typeFilter?: string, search?: string): Promise<MarketplaceListResponse> {
  const params = new URLSearchParams()
  if (typeFilter) params.set('type', typeFilter)
  if (search) params.set('search', search)
  const qs = params.toString()
  return apiRequest(`/plugin-sdk/marketplace/available${qs ? `?${qs}` : ''}`)
}

export async function getMarketplacePlugin(id: string): Promise<MarketplacePlugin> {
  return apiRequest(`/plugin-sdk/marketplace/plugin/${id}`)
}

export async function getPermissions(): Promise<{ permissions: string[]; types: string[] }> {
  return apiRequest('/plugin-sdk/permissions')
}
