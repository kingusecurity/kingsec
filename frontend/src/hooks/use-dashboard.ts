import { useQuery } from '@tanstack/react-query'
import { dashboardApi } from '@/api/dashboard'

export function useDashboardSummary() {
  return useQuery({
    queryKey: ['dashboard', 'summary'],
    queryFn: () => dashboardApi.summary(),
  })
}

export function useDashboardSeverity() {
  return useQuery({
    queryKey: ['dashboard', 'severity'],
    queryFn: () => dashboardApi.severity(),
  })
}

export function useDashboardTrends(params?: { period?: string; limit?: number }) {
  return useQuery({
    queryKey: ['dashboard', 'trends', params],
    queryFn: () => dashboardApi.trends(params),
  })
}

export function useDashboardJobs() {
  return useQuery({
    queryKey: ['dashboard', 'jobs'],
    queryFn: () => dashboardApi.jobs(),
  })
}

export function useDashboardActivity(params?: { limit?: number }) {
  return useQuery({
    queryKey: ['dashboard', 'activity', params],
    queryFn: () => dashboardApi.activity(params),
  })
}
