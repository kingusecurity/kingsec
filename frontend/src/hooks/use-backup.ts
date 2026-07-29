import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as backupApi from '@/api/backup'

export function useBackups() {
  return useQuery({
    queryKey: ['backups'],
    queryFn: backupApi.listBackups,
  })
}

export function useBackup(id: string) {
  return useQuery({
    queryKey: ['backup', id],
    queryFn: () => backupApi.getBackup(id),
    enabled: !!id,
  })
}

export function useCreateBackup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.createBackup,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['backups'] }),
  })
}

export function useDeleteBackup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.deleteBackup,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['backups'] }),
  })
}

export function useRestoreBackup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, target_path }: { id: string; target_path?: string }) =>
      backupApi.restoreBackup(id, target_path),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['backups'] }),
  })
}

export function useRestoreWithScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, scope, dry_run }: { id: string; scope: string; dry_run: boolean }) =>
      backupApi.restoreWithScope(id, scope, dry_run),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['backups'] }),
  })
}

export function useValidateBackup() {
  return useMutation({
    mutationFn: backupApi.validateBackup,
  })
}

export function useCleanupExpired() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.cleanupExpired,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['backups'] }),
  })
}

export function useSnapshots() {
  return useQuery({
    queryKey: ['snapshots'],
    queryFn: backupApi.listSnapshots,
  })
}

export function useCreateSnapshot() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.createSnapshot,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['snapshots'] }),
  })
}

export function useRestoreSnapshot() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.restoreSnapshot,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['snapshots'] }),
  })
}

export function useVerifyBackupFull() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.verifyBackupFull,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['verifications'] }),
  })
}

export function useVerifications(backup_id?: string) {
  return useQuery({
    queryKey: ['verifications', backup_id],
    queryFn: () => backupApi.listVerifications(backup_id),
  })
}

export function useSchedules() {
  return useQuery({
    queryKey: ['backup-schedules'],
    queryFn: backupApi.listSchedules,
  })
}

export function useCreateSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.createSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['backup-schedules'] }),
  })
}

export function useUpdateSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<backupApi.BackupSchedule> }) =>
      backupApi.updateSchedule(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['backup-schedules'] }),
  })
}

export function useDeleteSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.deleteSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['backup-schedules'] }),
  })
}

export function useRecoveryPlans() {
  return useQuery({
    queryKey: ['recovery-plans'],
    queryFn: backupApi.listRecoveryPlans,
  })
}

export function useRecoveryPlan(id: string) {
  return useQuery({
    queryKey: ['recovery-plan', id],
    queryFn: () => backupApi.getRecoveryPlan(id),
    enabled: !!id,
  })
}

export function useCreateRecoveryPlan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.createRecoveryPlan,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['recovery-plans'] }),
  })
}

export function useUpdateRecoveryPlan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<backupApi.RecoveryPlan> }) =>
      backupApi.updateRecoveryPlan(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['recovery-plans'] }),
  })
}

export function useDeleteRecoveryPlan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.deleteRecoveryPlan,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['recovery-plans'] }),
  })
}

export function useTestRecovery() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: backupApi.testRecovery,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['recovery-tests'] }); qc.invalidateQueries({ queryKey: ['recovery-plans'] }) },
  })
}

export function useRecoveryTests(plan_id?: string) {
  return useQuery({
    queryKey: ['recovery-tests', plan_id],
    queryFn: () => backupApi.listRecoveryTests(plan_id),
  })
}

export function useBackupHealth() {
  return useQuery({
    queryKey: ['backup-health'],
    queryFn: backupApi.getBackupHealth,
    refetchInterval: 30000,
  })
}
