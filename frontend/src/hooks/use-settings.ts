import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { settingsApi } from '@/api/settings'

export function useHealth() {
  return useQuery({
    queryKey: ['settings', 'health'],
    queryFn: () => settingsApi.health(),
    staleTime: 60 * 1000,
  })
}

export function useHealthz() {
  return useQuery({
    queryKey: ['settings', 'healthz'],
    queryFn: () => settingsApi.healthz(),
    staleTime: 60 * 1000,
  })
}

export function useSessions() {
  return useQuery({
    queryKey: ['settings', 'sessions'],
    queryFn: () => settingsApi.sessions(),
    staleTime: 30 * 1000,
  })
}

export function useDeleteSession() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => settingsApi.deleteSession(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'sessions'] })
    },
  })
}

export function useDeleteAllSessions() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: () => settingsApi.deleteAllSessions(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'sessions'] })
    },
  })
}

export function useApiKeys() {
  return useQuery({
    queryKey: ['settings', 'apikeys'],
    queryFn: () => settingsApi.apiKeys(),
    staleTime: 60 * 1000,
  })
}

export function useMfaStatus() {
  return useQuery({
    queryKey: ['settings', 'mfa'],
    queryFn: () => settingsApi.mfaStatus(),
    staleTime: 60 * 1000,
  })
}
