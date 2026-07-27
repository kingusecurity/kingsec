import { apiRequest } from './client'

export interface ScannerStatus {
  scanner_id: string
  name: string
  installed: boolean
  executable_path: string | null
  version: string | null
  usable: boolean
  availability_reason: string | null
  warnings: string[]
  required_assets: string[]
  missing_assets: string[]
  install_hints: string[]
}

export interface HealthReport {
  total: number
  installed: number
  usable: number
  partial: number
  missing: number
  health_score: number
  scanners: ScannerStatus[]
}

export const scannerHealthApi = {
  list: () =>
    apiRequest<ScannerStatus[]>('/scanners'),

  health: () =>
    apiRequest<HealthReport>('/scanners/health'),

  detail: (scannerId: string) =>
    apiRequest<ScannerStatus>(`/scanners/${scannerId}`),
}
