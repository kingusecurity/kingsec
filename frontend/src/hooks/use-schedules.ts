import { useQuery } from '@tanstack/react-query'
import { apiRequest } from '@/api/client'

const SCHEDULES_KEY = ['schedules'] as const

export function useSchedules() {
  return useQuery({
    queryKey: SCHEDULES_KEY,
    queryFn: () => apiRequest<{ items: unknown[] }>('/schedules'),
  })
}

export function useSchedule(id: string) {
  return useQuery({
    queryKey: ['schedules', id],
    queryFn: () => apiRequest<unknown>(`/schedules/${id}`),
    enabled: !!id,
  })
}
