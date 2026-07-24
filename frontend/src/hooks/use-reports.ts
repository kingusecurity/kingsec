import { useQuery } from '@tanstack/react-query'
import { assessmentsApi } from '@/api/assessments'
import type { AssessmentListParams } from '@/types/api'

export function useReports(params?: AssessmentListParams) {
  return useQuery({
    queryKey: ['reports', params],
    queryFn: () => assessmentsApi.list({ ...params, status: 'completed' }),
  })
}

export function useReport(id: string) {
  return useQuery({
    queryKey: ['reports', id],
    queryFn: () => assessmentsApi.get(id),
    enabled: !!id,
  })
}
