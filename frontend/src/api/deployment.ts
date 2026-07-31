import { apiRequest } from './client'

export interface SystemInfo {
  os: string
  os_version: string
  os_release: string
  python: string
  python_executable: string
  machine: string
  processor: string
  hostname: string
  pid: number
}

export interface ConfigSummary {
  kingsec_env: string
  kingsec_debug: string
  kingsec_log_level: string
  kingsec_data_dir: string
  database_url: string
}

export interface DiskUsage {
  total_gb?: number
  used_gb?: number
  free_gb?: number
  percent_used?: number
  error?: string
}

export interface StartupCheck {
  name: string
  passed: boolean
  message: string
  timestamp: string
}

export interface HealthStatus {
  status: string
  version?: string
  uptime_seconds?: number
  database?: string
  checks?: Record<string, string>
}

export interface UpgradeCheck {
  name: string
  passed: boolean
  message: string
  severity: string
}

export interface UpgradePlan {
  from_version: string
  to_version: string
  checks: UpgradeCheck[]
  migration_steps: string[]
  backup_required: boolean
  estimated_downtime: string
}

export interface DiagnosticsBundle {
  version: string
  collected_at: string
  system: SystemInfo
  config: ConfigSummary
  health: HealthStatus
  disk: DiskUsage
  database: { exists: boolean; path?: string; size_mb?: number }
  environment: Record<string, string>
  recent_logs: string[]
}

export const deploymentApi = {
  getSystemInfo: () =>
    apiRequest<SystemInfo>('/deployment/system-info'),

  getConfigSummary: () =>
    apiRequest<ConfigSummary>('/deployment/config'),

  getStartupReport: () =>
    apiRequest<StartupCheck[]>('/healthz/startup'),

  getHealth: () =>
    apiRequest<HealthStatus>('/healthz/live'),

  getDiagnostics: () =>
    apiRequest<DiagnosticsBundle>('/deployment/diagnostics'),

  downloadDiagnostics: () =>
    apiRequest<Blob>('/deployment/diagnostics/bundle', {
      headers: { Accept: 'application/octet-stream' },
    }),

  getUpgradePlan: (targetVersion: string) =>
    apiRequest<UpgradePlan>(`/deployment/upgrade/plan?target=${targetVersion}`),

  runUpgrade: (targetVersion: string) =>
    apiRequest<{ status: string; message: string }>('/deployment/upgrade/run', {
      method: 'POST',
      body: JSON.stringify({ target_version: targetVersion }),
    }),
}
