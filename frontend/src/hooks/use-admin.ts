import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminApi } from '@/api/admin'
import type { UserSearchParams } from '@/api/admin'
import type { AdminResetPasswordBody } from '@/types/api'

export function useAdminUsers(params?: { limit?: number; offset?: number }) {
  return useQuery({
    queryKey: ['admin', 'users', params],
    queryFn: () => adminApi.users(params),
  })
}

export function useAdminUsersSearch(params?: UserSearchParams) {
  return useQuery({
    queryKey: ['admin', 'users-search', params],
    queryFn: () => adminApi.usersSearch(params),
  })
}

export function useAdminAgents() {
  return useQuery({
    queryKey: ['admin', 'agents'],
    queryFn: () => adminApi.agents(),
  })
}

export function useAdminBackups() {
  return useQuery({
    queryKey: ['admin', 'backups'],
    queryFn: () => adminApi.backups(),
  })
}

export function useAdminPlugins() {
  return useQuery({
    queryKey: ['admin', 'plugins'],
    queryFn: () => adminApi.plugins(),
  })
}

export function useAdminQueueStats() {
  return useQuery({
    queryKey: ['admin', 'queue'],
    queryFn: () => adminApi.queueStats(),
  })
}

export function useAdminHealth() {
  return useQuery({
    queryKey: ['admin', 'health'],
    queryFn: () => adminApi.health(),
  })
}

export function useAdminMetrics() {
  return useQuery({
    queryKey: ['admin', 'metrics'],
    queryFn: () => adminApi.metrics(),
  })
}

export function useAdminDashboardSummary() {
  return useQuery({
    queryKey: ['admin', 'dashboard-summary'],
    queryFn: () => adminApi.dashboardSummary(),
  })
}

export function useAdminRoles() {
  return useQuery({
    queryKey: ['admin', 'roles'],
    queryFn: () => adminApi.roles(),
  })
}

export function useDeactivateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (userId: string) => adminApi.deactivateUser(userId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'users-search'] })
    },
  })
}

export function useActivateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (userId: string) => adminApi.activateUser(userId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'users-search'] })
    },
  })
}

export function useResetPassword() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ userId, body }: { userId: string; body: AdminResetPasswordBody }) =>
      adminApi.resetPassword(userId, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'users-search'] })
    },
  })
}
