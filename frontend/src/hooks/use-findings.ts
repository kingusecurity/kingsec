import { useQuery } from '@tanstack/react-query'
import { dashboardApi } from '@/api/dashboard'
import { assessmentsApi } from '@/api/assessments'
import { adminApi } from '@/api/admin'
import type { FindingsParams } from '@/api/admin'

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

export function useFindingsSummary() {
  return useQuery({
    queryKey: ['dashboard', 'summary'],
    queryFn: () => dashboardApi.summary(),
  })
}

export function useFindingsSeverity() {
  return useQuery({
    queryKey: ['dashboard', 'severity'],
    queryFn: () => dashboardApi.severity(),
  })
}

export function useFindingsTrends(params?: { period?: string; limit?: number }) {
  return useQuery({
    queryKey: ['dashboard', 'trends', params],
    queryFn: () => dashboardApi.trends(params),
  })
}

export function useFindings(params?: FindingsParams) {
  return useQuery({
    queryKey: ['findings', 'list', params],
    queryFn: () => adminApi.findings(params),
    placeholderData: (prev) => prev,
  })
}
