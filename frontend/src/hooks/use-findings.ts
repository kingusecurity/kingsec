import { useQuery } from '@tanstack/react-query'
import { assessmentsApi } from '@/api/assessments'
import type { AssessmentListParams } from '@/types/api'

export function useFindingsList(params?: AssessmentListParams) {
  return useQuery({
    queryKey: ['findings', 'list', params],
    queryFn: () => assessmentsApi.list(params),
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
