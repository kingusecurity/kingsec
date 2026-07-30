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
  total_gb: number
  used_gb: number
  free_gb: number
  percent_used: number
}

export interface StartupCheck {
  name: string
  passed: boolean
  message: string
  severity: string
  duration_ms: number
}

export interface StartupReport {
  checks: StartupCheck[]
  passed: boolean
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
    apiRequest<SystemInfo>('/api/v1/deployment/system-info'),

  getConfigSummary: () =>
    apiRequest<ConfigSummary>('/api/v1/deployment/config'),

  getStartupReport: () =>
    apiRequest<StartupReport>('/api/v1/healthz/startup'),

  getHealth: () =>
    apiRequest<HealthStatus>('/api/v1/healthz/health'),

  getDiagnostics: () =>
    apiRequest<DiagnosticsBundle>('/api/v1/deployment/diagnostics'),

  downloadDiagnostics: () =>
    apiRequest<Blob>('/api/v1/deployment/diagnostics/bundle', {
      headers: { Accept: 'application/octet-stream' },
    }),

  getUpgradePlan: (targetVersion: string) =>
    apiRequest<UpgradePlan>(`/api/v1/deployment/upgrade/plan?target=${targetVersion}`),

  runUpgrade: (targetVersion: string) =>
    apiRequest<{ status: string; message: string }>(`/api/v1/deployment/upgrade/run`, {
      method: 'POST',
      body: JSON.stringify({ target_version: targetVersion }),
    }),
}
