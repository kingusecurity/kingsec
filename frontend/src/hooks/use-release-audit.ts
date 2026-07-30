import { useQuery } from '@tanstack/react-query'
import { releaseAuditApi } from '@/api/release-audit'

export function useReleaseAuditReport() {
  return useQuery({
    queryKey: ['deployment', 'release-audit'],
    queryFn: () => releaseAuditApi.getReport(),
    staleTime: 60_000,
  })
}

export function useTelemetrySummary(days?: number) {
  return useQuery({
    queryKey: ['deployment', 'telemetry', days],
    queryFn: () => releaseAuditApi.getTelemetrySummary(days),
    staleTime: 60_000,
  })
}
