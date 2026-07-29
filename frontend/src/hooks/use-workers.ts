import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as workersApi from '@/api/workers'

export function useWorkers() {
  return useQuery({
    queryKey: ['workers'],
    queryFn: workersApi.listWorkers,
  })
}

export function useWorker(workerId: string) {
  return useQuery({
    queryKey: ['workers', workerId],
    queryFn: () => workersApi.getWorker(workerId),
    enabled: !!workerId,
  })
}

export function useRegisterWorker() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: workersApi.registerWorker,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['workers'] }),
  })
}

export function useDeleteWorker() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: workersApi.deleteWorker,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['workers'] }),
  })
}
