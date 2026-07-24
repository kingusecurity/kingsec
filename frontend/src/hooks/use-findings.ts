import { useQuery } from '@tanstack/react-query'
import { findingsApi } from '@/api/findings'
import { assessmentsApi } from '@/api/assessments'
import type { FindingsListParams } from '@/types/api'

export function useFindingsList(params?: FindingsListParams) {
  return useQuery({
    queryKey: ['findings', 'list', params],
    queryFn: () => findingsApi.list(params),
  })
}

export function useFinding(assessmentId: string, findingId: string) {
  return useQuery({
    queryKey: ['findings', assessmentId, findingId],
    queryFn: async () => {
      const assessment = await assessmentsApi.get(assessmentId)
      const finding = assessment.findings.find((f) => f.finding_id === findingId)
      if (!finding) throw new Error('Finding not found')
      return { ...finding, assessment_id: assessmentId, target: assessment.target }
    },
    enabled: !!assessmentId && !!findingId,
  })
}

export function useGlobalFinding(findingId: string) {
  return useQuery({
    queryKey: ['findings', findingId],
    queryFn: () => findingsApi.get(findingId),
    enabled: !!findingId,
  })
}
