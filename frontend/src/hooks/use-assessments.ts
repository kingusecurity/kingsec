import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { assessmentsApi } from '@/api/assessments'
import { toast } from '@/components/ui/Toast'
import type { CreateAssessmentBody, AssessmentListParams } from '@/types/api'

const ASSESSMENTS_KEY = ['assessments'] as const

export function useAssessments(params?: AssessmentListParams) {
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
    refetchInterval: (query) => {
      const data = query.state.data
      if (data && (data.status === 'running' || data.status === 'pending')) {
        return 5000
      }
      return false
    },
  })
}

export function useFindings(assessmentId: string) {
  return useQuery({
    queryKey: ['assessments', assessmentId, 'findings'],
    queryFn: () => assessmentsApi.findings(assessmentId),
    enabled: !!assessmentId,
  })
}

export function useCreateAssessment() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: CreateAssessmentBody) => assessmentsApi.create(data),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ASSESSMENTS_KEY })
      toast.success('Assessment created', `Assessment ${result.assessment_id} created successfully`)
    },
    onError: (err: Error) => {
      toast.error('Failed to create assessment', err.message)
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
      toast.success('Assessment started', `Assessment ${id} is now running`)
    },
    onError: (err: Error) => {
      toast.error('Failed to start assessment', err.message)
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
      toast.success('Assessment cancelled', `Assessment ${id} has been cancelled`)
    },
    onError: (err: Error) => {
      toast.error('Failed to cancel assessment', err.message)
    },
  })
}

export function useGenerateReport() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => assessmentsApi.report(id),
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: ['assessments', id] })
      toast.success('Report generated', 'Report is ready for download')
    },
    onError: (err: Error) => {
      toast.error('Failed to generate report', err.message)
    },
  })
}

export function useDeleteAssessment() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => assessmentsApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ASSESSMENTS_KEY })
      toast.success('Assessment deleted', 'The assessment has been deleted')
    },
    onError: (err: Error) => {
      toast.error('Failed to delete assessment', err.message)
    },
  })
}
