import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { executionApi } from '@/api/execution'
import { toast } from '@/components/ui/Toast'
import type { ExecutionStatus } from '@/types/execution'

export function useExecutionStatus(assessmentId: string | undefined) {
  return useQuery({
    queryKey: ['execution', 'status', assessmentId],
    queryFn: () => executionApi.status(assessmentId!),
    enabled: !!assessmentId,
    refetchInterval: (query) => {
      const data = query.state.data as ExecutionStatus | undefined
      if (data && (data.phase === 'running_scanners' || data.phase === 'preparing' || data.phase === 'correlating' || data.phase === 'reporting')) {
        return 3000
      }
      return false
    },
  })
}

export function useExecutionEvents(assessmentId: string | undefined, enabled: boolean = true) {
  return useQuery({
    queryKey: ['execution', 'events', assessmentId],
    queryFn: () => executionApi.events(assessmentId!),
    enabled: !!assessmentId && enabled,
    refetchInterval: (query) => {
      const data = query.state.data as { events: unknown[] } | undefined
      if (data && data.events.length > 0) {
        const last = data.events[data.events.length - 1] as { event_type: string } | undefined
        if (last && !last.event_type.endsWith('.completed') && !last.event_type.endsWith('.failed') && !last.event_type.endsWith('.cancelled')) {
          return 3000
        }
      }
      return false
    },
  })
}

export function useExecutionProgress(assessmentId: string | undefined) {
  return useQuery({
    queryKey: ['execution', 'progress', assessmentId],
    queryFn: () => executionApi.progress(assessmentId!),
    enabled: !!assessmentId,
    refetchInterval: 3000,
  })
}

export function useCancelExecution() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => executionApi.cancel(id),
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: ['execution', 'status', id] })
      queryClient.invalidateQueries({ queryKey: ['execution', 'events', id] })
      toast.success('Execution cancelled', 'The assessment execution has been cancelled')
    },
    onError: (err: Error) => {
      toast.error('Failed to cancel execution', err.message)
    },
  })
}
