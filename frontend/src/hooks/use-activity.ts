import { useQuery } from '@tanstack/react-query'
import { activityApi } from '@/api/activity'

const POLL_INTERVAL = 5000

export function useLiveActivity(params?: { limit?: number }) {
  return useQuery({
    queryKey: ['live', 'activity', params],
    queryFn: () => activityApi.activity(params),
    refetchInterval: POLL_INTERVAL,
  })
}

export function useWorkerStatus() {
  return useQuery({
    queryKey: ['live', 'workers'],
    queryFn: () => activityApi.workers(),
    refetchInterval: POLL_INTERVAL,
  })
}

export function useQueueStatus() {
  return useQuery({
    queryKey: ['live', 'jobs'],
    queryFn: () => activityApi.jobs(),
    refetchInterval: POLL_INTERVAL,
  })
}

export function useScannerStatus() {
  return useQuery({
    queryKey: ['live', 'scanners'],
    queryFn: () => activityApi.scanners(),
    refetchInterval: POLL_INTERVAL,
  })
}
