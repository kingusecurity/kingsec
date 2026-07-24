import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { reportsApi } from '@/api/reports'
import { assessmentsApi } from '@/api/assessments'
import { toast } from '@/components/ui/Toast'
import type { ReportListParams } from '@/types/api'

const REPORTS_KEY = ['reports'] as const

export function useReports(params?: ReportListParams) {
  return useQuery({
    queryKey: [...REPORTS_KEY, params],
    queryFn: () => reportsApi.list(params),
  })
}

export function useReport(id: string) {
  return useQuery({
    queryKey: ['reports', id],
    queryFn: () => reportsApi.get(id),
    enabled: !!id,
  })
}

export function useReportFallback(id: string) {
  return useQuery({
    queryKey: ['reports', 'fallback', id],
    queryFn: () => assessmentsApi.get(id),
    enabled: !!id,
  })
}

export function useDeleteReport() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => reportsApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: REPORTS_KEY })
      toast.success('Report deleted', 'The report has been deleted')
    },
    onError: (err: Error) => {
      toast.error('Failed to delete report', err.message)
    },
  })
}

export function useDownloadReport() {
  return {
    getDownloadUrl: (reportId: string) => reportsApi.getDownloadUrl(reportId),
  }
}
