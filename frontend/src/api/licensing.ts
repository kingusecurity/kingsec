import { apiRequest } from './client'

export interface LicenseInfo {
  id?: string
  edition: string
  status: string
  license_key?: string
  issued_to?: string
  company?: string
  email?: string
  expires_at?: string
  features: string[]
  limits?: Record<string, number | null>
  has_license: boolean
  max_users?: number | null
  max_organizations?: number | null
  max_api_keys?: number | null
  grace_days?: number
}

export interface LicenseStatus {
  edition: string
  status: string
}

export const licensingApi = {
  getLicense: () =>
    apiRequest<LicenseInfo>('/api/v1/license'),

  getFeatures: () =>
    apiRequest<LicenseInfo>('/api/v1/license/features'),

  getStatus: () =>
    apiRequest<LicenseStatus>('/api/v1/license/status'),

  activate: (licenseKey: string) =>
    apiRequest<{ id: string; edition: string; status: string }>('/api/v1/license/activate', {
      method: 'POST',
      body: JSON.stringify({ license_key: licenseKey }),
    }),

  deactivate: (licenseId: string) =>
    apiRequest<{ status: string }>('/api/v1/license/deactivate', {
      method: 'POST',
      body: JSON.stringify({ license_id: licenseId }),
    }),
}
