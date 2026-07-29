import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { monitoringApi } from '@/api/monitoring'

export function useMonitoringSummary() {
  return useQuery({
    queryKey: ['monitoring-summary'],
    queryFn: monitoringApi.getSummary,
    refetchInterval: 60000,
  })
}

export function useMonitoringStats() {
  return useQuery({
    queryKey: ['monitoring-stats'],
    queryFn: monitoringApi.getStats,
  })
}

export function useMonitoringHealth() {
  return useQuery({
    queryKey: ['monitoring-health'],
    queryFn: monitoringApi.getHealth,
    refetchInterval: 60000,
  })
}

export function useMonitoringTrends(days = 30) {
  return useQuery({
    queryKey: ['monitoring-trends', days],
    queryFn: () => monitoringApi.getTrends(days),
  })
}

export function useMonitorEvents(params: Record<string, unknown> = {}) {
  return useQuery({
    queryKey: ['monitor-events', params],
    queryFn: () => monitoringApi.listEvents(params as Parameters<typeof monitoringApi.listEvents>[0]),
    refetchInterval: 60000,
  })
}

export function useMonitorEvent(id: string | null) {
  return useQuery({
    queryKey: ['monitor-event', id],
    queryFn: () => monitoringApi.getEvent(id!),
    enabled: !!id,
  })
}

export function useAlerts(params: Record<string, unknown> = {}) {
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: () => monitoringApi.listAlerts(params as Parameters<typeof monitoringApi.listAlerts>[0]),
    refetchInterval: 30000,
  })
}

export function useAlert(id: string | null) {
  return useQuery({
    queryKey: ['alert', id],
    queryFn: () => monitoringApi.getAlert(id!),
    enabled: !!id,
  })
}

export function useAcknowledgeAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => monitoringApi.acknowledgeAlert(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })
}

export function useResolveAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => monitoringApi.resolveAlert(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })
}

export function useDismissAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => monitoringApi.dismissAlert(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })
}

export function useRules(params: Record<string, unknown> = {}) {
  return useQuery({
    queryKey: ['monitor-rules', params],
    queryFn: () => monitoringApi.listRules(params as Parameters<typeof monitoringApi.listRules>[0]),
  })
}

export function useRule(id: string | null) {
  return useQuery({
    queryKey: ['monitor-rule', id],
    queryFn: () => monitoringApi.getRule(id!),
    enabled: !!id,
  })
}

export function useCreateRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => monitoringApi.createRule(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitor-rules'] }),
  })
}

export function useUpdateRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => monitoringApi.updateRule(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitor-rules'] }),
  })
}

export function useDeleteRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => monitoringApi.deleteRule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitor-rules'] }),
  })
}

export function useEnableRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => monitoringApi.enableRule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitor-rules'] }),
  })
}

export function useDisableRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => monitoringApi.disableRule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitor-rules'] }),
  })
}

export function useSeedRules() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => monitoringApi.seedRules(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitor-rules'] }),
  })
}
