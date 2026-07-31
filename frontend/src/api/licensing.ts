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
    apiRequest<LicenseInfo>('/license'),

  getFeatures: () =>
    apiRequest<LicenseInfo>('/license/features'),

  getStatus: () =>
    apiRequest<LicenseStatus>('/license/status'),

  activate: (licenseKey: string) =>
    apiRequest<{ id: string; edition: string; status: string }>('/license/activate', {
      method: 'POST',
      body: JSON.stringify({ license_key: licenseKey }),
    }),

  deactivate: (licenseId: string) =>
    apiRequest<{ status: string }>('/license/deactivate', {
      method: 'POST',
      body: JSON.stringify({ license_id: licenseId }),
    }),
}
