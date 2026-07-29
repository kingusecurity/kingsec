import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as api from '@/api/playbooks'

export function usePlaybooks(params?: {
  enabled?: boolean
  category?: string
  trigger_type?: string
  severity?: string
}) {
  return useQuery({
    queryKey: ['playbooks', params],
    queryFn: () => api.listPlaybooks(params),
  })
}

export function usePlaybook(id: string | undefined) {
  return useQuery({
    queryKey: ['playbook', id],
    queryFn: () => api.getPlaybook(id!),
    enabled: !!id,
  })
}

export function useCreatePlaybook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.createPlaybook,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] }),
  })
}

export function useUpdatePlaybook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<api.Playbook> }) =>
      api.updatePlaybook(id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['playbooks'] }); qc.invalidateQueries({ queryKey: ['playbook'] }) },
  })
}

export function useDeletePlaybook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.deletePlaybook,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] }),
  })
}

export function useExecutePlaybook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, context }: { id: string; context?: Record<string, unknown> }) =>
      api.executePlaybook(id, context),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['executions'] }); qc.invalidateQueries({ queryKey: ['playbook-stats'] }) },
  })
}

export function useEnablePlaybook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.enablePlaybook,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['playbooks'] }); qc.invalidateQueries({ queryKey: ['playbook'] }) },
  })
}

export function useDisablePlaybook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.disablePlaybook,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['playbooks'] }); qc.invalidateQueries({ queryKey: ['playbook'] }) },
  })
}

export function useExecutions(params?: {
  status?: string
  trigger_type?: string
  limit?: number
  offset?: number
}) {
  return useQuery({
    queryKey: ['executions', params],
    queryFn: () => api.listExecutions(params),
  })
}

export function useExecution(id: string | undefined) {
  return useQuery({
    queryKey: ['execution', id],
    queryFn: () => api.getExecution(id!),
    enabled: !!id,
  })
}

export function usePlaybookStats() {
  return useQuery({
    queryKey: ['playbook-stats'],
    queryFn: api.getPlaybookStats,
    refetchInterval: 30000,
  })
}
