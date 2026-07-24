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

export function useDashboardScanners() {
  return useQuery({
    queryKey: ['dashboard', 'scanners'],
    queryFn: () => dashboardApi.scanners(),
  })
}

export function useDashboardWorkers() {
  return useQuery({
    queryKey: ['dashboard', 'workers'],
    queryFn: () => dashboardApi.workers(),
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

export function useDashboardSchedules() {
  return useQuery({
    queryKey: ['dashboard', 'schedules'],
    queryFn: () => dashboardApi.schedules(),
  })
}

export function useDashboardNotifications() {
  return useQuery({
    queryKey: ['dashboard', 'notifications'],
    queryFn: () => dashboardApi.notifications(),
  })
}
