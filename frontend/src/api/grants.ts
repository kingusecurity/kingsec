import { apiRequest } from './client'

export type TargetSpecificationType =
  | 'ip_address'
  | 'network'
  | 'hostname'
  | 'wildcard_hostname'
  | 'url_prefix'

export interface AuthorizationGrant {
  id: string
  authorized_by: string
  authorizing_organization: string
  target_specification_type: TargetSpecificationType
  target_specification_value: string
  valid_from: string
  valid_until: string
  created_by: string
  revoked_at: string | null
}

export interface CreateAuthorizationGrantBody {
  authorized_by: string
  authorizing_organization: string
  target_specification_type: TargetSpecificationType
  target_specification_value: string
  valid_from: string
  valid_until: string
}

export interface CreateAuthorizationGrantResponse {
  grant_id: string
  target_specification_type: TargetSpecificationType
  target_specification_value: string
  valid_from: string
  valid_until: string
}

export interface ListGrantsResponse {
  items: AuthorizationGrant[]
  limit: number
  offset: number
}

export async function listGrants(params?: { limit?: number; offset?: number }): Promise<ListGrantsResponse> {
  return apiRequest('/authorization-grants', { params })
}

export async function createGrant(data: CreateAuthorizationGrantBody): Promise<CreateAuthorizationGrantResponse> {
  return apiRequest('/authorization-grants', { method: 'POST', body: data })
}

export async function revokeGrant(id: string): Promise<void> {
  return apiRequest(`/authorization-grants/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export interface GrantCoverageTierResult {
  tier: string
  covered: boolean
  grant_id: string | null
}

export interface CheckGrantCoverageResponse {
  enforced: boolean
  target_type: string
  target_value: string
  profile_id: string
  required_tiers: GrantCoverageTierResult[]
  fully_covered: boolean
}

export async function checkGrantCoverage(params: {
  target_type: string
  target_value: string
  profile_id: string
}): Promise<CheckGrantCoverageResponse> {
  return apiRequest('/authorization-grants/check', { params })
}
