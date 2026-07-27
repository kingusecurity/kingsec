import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminApi } from '@/api/admin'
import { getAccessToken } from '@/api/client'
import type { ReportsParams } from '@/api/admin'

export function useReports(params?: ReportsParams) {
  return useQuery({
    queryKey: ['reports', 'list', params],
    queryFn: () => adminApi.reports(params),
    placeholderData: (prev) => prev,
  })
}

export function useReportDetail(assessmentId: string | null) {
  return useQuery({
    queryKey: ['reports', 'detail', assessmentId],
    queryFn: () => adminApi.reportDetail(assessmentId!),
    enabled: !!assessmentId,
  })
}

export function useRegenerateReport() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (assessmentId: string) => {
      const token = getAccessToken()
      return fetch(`/api/v1/assessments/${assessmentId}/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      }).then((r) => {
        if (!r.ok) throw new Error('Failed to regenerate report')
        return r.json()
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] })
    },
  })
}
