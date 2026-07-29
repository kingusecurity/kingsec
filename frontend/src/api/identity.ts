import { apiRequest } from './client'

export interface RoleMappingRule {
  external_group: string
  kingsec_role: string
  priority: number
}

export interface GroupMapping {
  external_group: string
  kingsec_role: string
  organization_id: string
}

export interface Saml2Config {
  entity_id: string
  sso_url: string
  slo_url: string
  certificate: string
  private_key: string
  name_id_format: string
  assertion_encrypted: boolean
  authn_context: string
  signature_algorithm: string
  metadata_url: string
  clock_skew_seconds: number
}

export interface OidcConfig {
  issuer_url: string
  client_id: string
  client_secret: string
  authorization_url: string
  token_url: string
  userinfo_url: string
  jwks_url: string
  end_session_url: string
  scopes: string[]
  subject_claim: string
  clock_skew_seconds: number
}

export interface LdapConfig {
  server_url: string
  bind_dn: string
  bind_password: string
  base_dn: string
  user_filter: string
  group_filter: string
  username_attribute: string
  email_attribute: string
  display_name_attribute: string
  group_member_attribute: string
  use_tls: boolean
  timeout_seconds: number
}

export interface OAuth2Config {
  authorize_url: string
  token_url: string
  client_id: string
  client_secret: string
  scopes: string[]
  userinfo_endpoint: string
  subject_claim: string
}

export interface IdentityProvider {
  id: string
  name: string
  protocol: string
  status: string
  issuer: string
  domain_hint: string
  role_mappings: RoleMappingRule[]
  group_mappings: GroupMapping[]
  jit_provisioning: boolean
  auto_link_users: boolean
  enforce_sso: boolean
  metadata_xml: string
  saml_config: Saml2Config
  oidc_config: OidcConfig
  ldap_config: LdapConfig
  oauth2_config: OAuth2Config
  organization_id: string
  created_by: string
  created_at: string
  updated_at: string
}

export interface ProviderListResponse {
  providers: IdentityProvider[]
  total: number
}

export interface TestConnectionResult {
  success: boolean
  message: string
  provider_name: string
  protocol: string
  duration_ms: number
  attributes: Record<string, string>
  error: string
}

export async function listProviders(): Promise<ProviderListResponse> {
  return apiRequest('/identity/providers')
}

export async function getProvider(id: string): Promise<{ provider: IdentityProvider }> {
  return apiRequest(`/identity/providers/${encodeURIComponent(id)}`)
}

export async function createProvider(data: Partial<IdentityProvider> & { name: string; protocol: string }): Promise<{ message: string; provider: IdentityProvider }> {
  return apiRequest('/identity/providers', { method: 'POST', body: data })
}

export async function updateProvider(id: string, data: Partial<IdentityProvider>): Promise<{ message: string; provider: IdentityProvider }> {
  return apiRequest(`/identity/providers/${encodeURIComponent(id)}`, { method: 'PUT', body: data })
}

export async function deleteProvider(id: string): Promise<{ message: string }> {
  return apiRequest(`/identity/providers/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export async function activateProvider(id: string): Promise<{ message: string; provider: { id: string; status: string } }> {
  return apiRequest(`/identity/providers/${encodeURIComponent(id)}/activate`, { method: 'POST' })
}

export async function deactivateProvider(id: string): Promise<{ message: string; provider: { id: string; status: string } }> {
  return apiRequest(`/identity/providers/${encodeURIComponent(id)}/deactivate`, { method: 'POST' })
}

export async function testConnection(data: Partial<IdentityProvider> & { name: string; protocol: string }): Promise<TestConnectionResult> {
  return apiRequest('/identity/test', { method: 'POST', body: data })
}