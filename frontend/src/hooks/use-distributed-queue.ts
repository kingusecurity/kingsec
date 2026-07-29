import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as queueApi from '@/api/distributed-queue'

export function useQueue(state?: string) {
  return useQuery({
    queryKey: ['queue', state],
    queryFn: () => queueApi.listQueue(state),
  })
}

export function useQueueEntry(entryId: string) {
  return useQuery({
    queryKey: ['queue', entryId],
    queryFn: () => queueApi.getQueueEntry(entryId),
    enabled: !!entryId,
  })
}

export function useQueueMetrics() {
  return useQuery({
    queryKey: ['queue', 'metrics'],
    queryFn: queueApi.getQueueMetrics,
    refetchInterval: 10000,
  })
}

export function useRetryJob() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: queueApi.retryJob,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['queue'] }),
  })
}

export function useCancelJob() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: queueApi.cancelJob,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['queue'] }),
  })
}

export function useDeadLetter() {
  return useQuery({
    queryKey: ['queue', 'dead-letter'],
    queryFn: queueApi.listDeadLetter,
  })
}

export function useRequeueDeadLetter() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: queueApi.requeueDeadLetter,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['queue', 'dead-letter'] })
      qc.invalidateQueries({ queryKey: ['queue'] })
    },
  })
}
