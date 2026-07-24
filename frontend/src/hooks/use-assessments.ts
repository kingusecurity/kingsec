import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { assessmentsApi } from '@/api/assessments'
import type { CreateAssessmentBody } from '@/types/api'

const ASSESSMENTS_KEY = ['assessments'] as const

export function useAssessments(params?: { limit?: number; offset?: number }) {
  return useQuery({
    queryKey: [...ASSESSMENTS_KEY, params],
    queryFn: () => assessmentsApi.list(params),
  })
}

export function useAssessment(id: string) {
  return useQuery({
    queryKey: ['assessments', id],
    queryFn: () => assessmentsApi.get(id),
    enabled: !!id,
  })
}

export function useCreateAssessment() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: CreateAssessmentBody) => assessmentsApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ASSESSMENTS_KEY })
    },
  })
}

export function useStartAssessment() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => assessmentsApi.start(id),
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: ['assessments', id] })
      queryClient.invalidateQueries({ queryKey: ASSESSMENTS_KEY })
    },
  })
}

export function useCancelAssessment() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => assessmentsApi.cancel(id),
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: ['assessments', id] })
      queryClient.invalidateQueries({ queryKey: ASSESSMENTS_KEY })
    },
  })
}

export function useGenerateReport() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => assessmentsApi.report(id),
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: ['assessments', id] })
    },
  })
}

export function useDeleteAssessment() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => assessmentsApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ASSESSMENTS_KEY })
    },
  })
}
