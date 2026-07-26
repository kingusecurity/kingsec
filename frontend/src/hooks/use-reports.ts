import { useQuery } from '@tanstack/react-query'
import { adminApi } from '@/api/admin'
import type { ReportsParams } from '@/api/admin'

export function useReports(params?: ReportsParams) {
  return useQuery({
    queryKey: ['reports', 'list', params],
    queryFn: () => adminApi.reports(params),
  })
}
