export interface ProfileSettings {
  full_name: string
  email: string
  timezone: string
  language: string
}

export interface AppearanceSettings {
  theme: "light" | "dark" | "cyber" | "terminal" | "corporate"
  compact_mode: boolean
  sidebar_collapsed: boolean
}

export interface SecuritySettings {
  current_password: string
  new_password: string
  confirm_password: string
}

export interface NotificationSettings {
  browser_notifications: boolean
  sse_notifications: boolean
  email_notifications: boolean
  report_generated: boolean
  scan_completed: boolean
  scan_failed: boolean
  security_alerts: boolean
}

export interface ScannerSettings {
  default_scan_profile: string
  timeout_seconds: number
  concurrent_jobs: number
  auto_generate_report: boolean
  auto_delete_reports: boolean
}

export interface ApiKey {
  key_id: string
  name: string
  key_prefix: string
  created_at: string
  last_used_at?: string
  expires_at?: string
}

export interface SystemInfo {
  frontend_version: string
  backend_version: string
  api_version: string
  build_date: string
  environment: string
  browser_info: string
}

export type SettingsSection = "profile" | "appearance" | "security" | "notifications" | "scanner" | "api-keys" | "advanced"
