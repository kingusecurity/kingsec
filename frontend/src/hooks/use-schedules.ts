import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as schedulesApi from '@/api/schedules'

const SCHEDULES_KEY = ['schedules'] as const

export function useSchedules() {
  return useQuery({
    queryKey: SCHEDULES_KEY,
    queryFn: schedulesApi.listSchedules,
  })
}

export function useSchedule(id: string) {
  return useQuery({
    queryKey: ['schedules', id],
    queryFn: () => schedulesApi.getSchedule(id),
    enabled: !!id,
  })
}

export function useCreateSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: schedulesApi.createSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: SCHEDULES_KEY }),
  })
}

export function useUpdateSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: schedulesApi.UpdateScheduleBody }) =>
      schedulesApi.updateSchedule(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: SCHEDULES_KEY }),
  })
}

export function useDeleteSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: schedulesApi.deleteSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: SCHEDULES_KEY }),
  })
}

export function usePauseSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: schedulesApi.pauseSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: SCHEDULES_KEY }),
  })
}

export function useResumeSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: schedulesApi.resumeSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: SCHEDULES_KEY }),
  })
}

export function useEnableSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: schedulesApi.enableSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: SCHEDULES_KEY }),
  })
}

export function useDisableSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: schedulesApi.disableSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: SCHEDULES_KEY }),
  })
}

export function useTriggerSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: schedulesApi.triggerSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: SCHEDULES_KEY }),
  })
}
