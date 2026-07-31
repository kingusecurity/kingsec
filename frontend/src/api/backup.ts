import { apiRequest } from './client'

export interface BackupMetadata {
  backup_id: string
  backup_type: string
  status: string
  size_bytes: number
  checksum: string
  encrypted: boolean
  compressed: boolean
  file_path: string
  owner_user_id: string
  created_at: string
  completed_at: string
  error_message: string
}

export interface BackupSnapshot {
  snapshot_id: string
  label: string
  created_at: string
  size_bytes: number
}

export interface BackupSchedule {
  schedule_id: string
  name: string
  frequency: string
  backup_type: string
  includes: string[]
  encrypt: boolean
  compress: boolean
  cron_expression: string
  enabled: boolean
  last_run_at: string
  next_run_at: string
  created_at: string
  created_by: string
}

export interface BackupVerification {
  verification_id: string
  backup_id: string
  checksum_valid: boolean
  archive_integrity: boolean
  restore_simulation: boolean
  verified_at: string
  verified_by: string
  error_message: string
  duration_ms: number
}

export interface RecoveryPlan {
  plan_id: string
  name: string
  description: string
  estimated_downtime_minutes: number
  // list endpoint returns checklist_count; the detail endpoint returns the full checklist
  checklist?: { item_id: string; description: string; completed: boolean }[]
  checklist_count?: number
  last_tested_at: string
  status: string
  created_at: string
  created_by: string
}

export interface RecoveryTest {
  test_id: string
  plan_id: string
  status: string
  started_at: string
  completed_at: string
  executed_by: string
}

export interface ComponentHealth {
  component: string
  health: string
  message: string
  checked_at: string
}

export interface HealthReport {
  report_id: string
  overall: string
  database_healthy: boolean
  storage_healthy: boolean
  workers_healthy: boolean
  backup_service_healthy: boolean
  generated_at: string
  components: ComponentHealth[]
}

// --- Backups ---

export async function listBackups(): Promise<{ backups: BackupMetadata[]; total: number }> {
  return apiRequest('/backups')
}

export async function getBackup(id: string): Promise<BackupMetadata> {
  return apiRequest(`/backups/${encodeURIComponent(id)}`)
}

export async function createBackup(data: {
  backup_type?: string
  includes?: string[]
  encrypt?: boolean
  compress?: boolean
}): Promise<{ message: string; backup: BackupMetadata }> {
  return apiRequest('/backups', { method: 'POST', body: data })
}

export async function deleteBackup(id: string): Promise<{ message: string }> {
  return apiRequest(`/backups/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export async function restoreBackup(id: string, target_path?: string): Promise<{ message: string; restore_id: string; status: string }> {
  return apiRequest(`/backups/${encodeURIComponent(id)}/restore`, { method: 'POST', body: { target_path } })
}

export async function restoreWithScope(
  id: string,
  scope: string,
  dry_run: boolean,
): Promise<{ message: string; restore_id: string; status: string; scope: string; dry_run: boolean }> {
  return apiRequest(`/backups/${encodeURIComponent(id)}/restore-scope`, { method: 'POST', body: { scope, dry_run } })
}

export async function validateBackup(id: string): Promise<{ backup_id: string; valid: boolean }> {
  return apiRequest(`/backups/${encodeURIComponent(id)}/verify`, { method: 'POST' })
}

export async function cleanupExpired(): Promise<{ message: string; deleted: number }> {
  return apiRequest('/backups/cleanup', { method: 'POST' })
}

// --- Snapshots ---

export async function listSnapshots(): Promise<{ snapshots: BackupSnapshot[]; total: number }> {
  return apiRequest('/snapshots')
}

export async function createSnapshot(data: { label?: string; backup_ids?: string[] }): Promise<{ message: string; snapshot: BackupSnapshot }> {
  return apiRequest('/snapshots', { method: 'POST', body: data })
}

export async function restoreSnapshot(id: string): Promise<{ message: string; restore_id: string; status: string }> {
  return apiRequest(`/snapshots/${encodeURIComponent(id)}/restore`, { method: 'POST' })
}

// --- Verifications ---

export async function verifyBackupFull(id: string): Promise<BackupVerification> {
  return apiRequest(`/backups/${encodeURIComponent(id)}/verify-full`, { method: 'POST' })
}

export async function listVerifications(backup_id?: string): Promise<{ verifications: BackupVerification[]; total: number }> {
  const params = backup_id ? `?backup_id=${encodeURIComponent(backup_id)}` : ''
  return apiRequest(`/backup-verifications${params}`)
}

// --- Schedules ---

export async function listSchedules(): Promise<{ schedules: BackupSchedule[]; total: number }> {
  return apiRequest('/backup-schedules')
}

export async function createSchedule(data: Partial<BackupSchedule>): Promise<{ message: string; schedule: BackupSchedule }> {
  return apiRequest('/backup-schedules', { method: 'POST', body: data })
}

export async function updateSchedule(id: string, data: Partial<BackupSchedule>): Promise<{ message: string; schedule: BackupSchedule }> {
  return apiRequest(`/backup-schedules/${encodeURIComponent(id)}`, { method: 'PUT', body: data })
}

export async function deleteSchedule(id: string): Promise<{ message: string }> {
  return apiRequest(`/backup-schedules/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

// --- Recovery Plans ---

export async function listRecoveryPlans(): Promise<{ plans: RecoveryPlan[]; total: number }> {
  return apiRequest('/recovery-plans')
}

export async function getRecoveryPlan(id: string): Promise<{ plan: RecoveryPlan }> {
  return apiRequest(`/recovery-plans/${encodeURIComponent(id)}`)
}

export async function createRecoveryPlan(data: Partial<RecoveryPlan>): Promise<{ message: string; plan: RecoveryPlan }> {
  return apiRequest('/recovery-plans', { method: 'POST', body: data })
}

export async function updateRecoveryPlan(id: string, data: Partial<RecoveryPlan>): Promise<{ message: string; plan: RecoveryPlan }> {
  return apiRequest(`/recovery-plans/${encodeURIComponent(id)}`, { method: 'PUT', body: data })
}

export async function deleteRecoveryPlan(id: string): Promise<{ message: string }> {
  return apiRequest(`/recovery-plans/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export async function testRecovery(plan_id: string): Promise<{ message: string; test: RecoveryTest }> {
  return apiRequest(`/recovery-plans/${encodeURIComponent(plan_id)}/test`, { method: 'POST' })
}

export async function listRecoveryTests(plan_id?: string): Promise<{ tests: RecoveryTest[]; total: number }> {
  const params = plan_id ? `?plan_id=${encodeURIComponent(plan_id)}` : ''
  return apiRequest(`/recovery-tests${params}`)
}

// --- Health ---

export async function getBackupHealth(): Promise<HealthReport> {
  return apiRequest('/backup-health')
}
