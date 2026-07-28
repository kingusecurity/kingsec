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
  permissions_ok: boolean
  recommendations: string[]
}

export interface InstallCommand {
  manager: string
  command: string
  description: string
  requires_admin: boolean
}

export interface InstallInfo {
  scanner_id: string
  name: string
  platform: string
  available_package_managers: string[]
  commands: InstallCommand[]
  best_command: InstallCommand | null
  verify_command: string
  website: string
  min_version: string
  expected_binary: string
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

  installInfo: (scannerId: string) =>
    apiRequest<InstallInfo>(`/scanners/${scannerId}/install`),
}
