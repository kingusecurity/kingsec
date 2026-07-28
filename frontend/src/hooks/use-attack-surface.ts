import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { attackSurfaceApi } from '@/api/attack-surface'

export function useAttackSurfaceSummary() {
  return useQuery({
    queryKey: ['attack-surface-summary'],
    queryFn: attackSurfaceApi.getSummary,
  })
}

export function useAttackSurfaceRisk() {
  return useQuery({
    queryKey: ['attack-surface-risk'],
    queryFn: attackSurfaceApi.getRisk,
  })
}

export function useAttackSurfaceTrend(days = 30) {
  return useQuery({
    queryKey: ['attack-surface-trend', days],
    queryFn: () => attackSurfaceApi.getTrend(days),
  })
}

export function useAssetsWithExposures() {
  return useQuery({
    queryKey: ['assets-with-exposures'],
    queryFn: attackSurfaceApi.getAssetsWithExposures,
  })
}

export function useExposures(params: Record<string, unknown> = {}) {
  return useQuery({
    queryKey: ['exposures', params],
    queryFn: () => attackSurfaceApi.list(params as Parameters<typeof attackSurfaceApi.list>[0]),
  })
}

export function useExposureSearch(q: string) {
  return useQuery({
    queryKey: ['exposure-search', q],
    queryFn: () => attackSurfaceApi.search(q),
    enabled: q.length >= 2,
  })
}

export function useExposure(id: string | null) {
  return useQuery({
    queryKey: ['exposure', id],
    queryFn: () => attackSurfaceApi.get(id!),
    enabled: !!id,
  })
}

export function useExposureHistory(id: string | null) {
  return useQuery({
    queryKey: ['exposure-history', id],
    queryFn: () => attackSurfaceApi.getHistory(id!),
    enabled: !!id,
  })
}

export function useAssetExposures(assetId: string | null) {
  return useQuery({
    queryKey: ['asset-exposures', assetId],
    queryFn: () => attackSurfaceApi.getAssetExposures(assetId!),
    enabled: !!assetId,
  })
}

export function useHighRiskExposures(minScore = 50) {
  return useQuery({
    queryKey: ['high-risk-exposures', minScore],
    queryFn: () => attackSurfaceApi.getHighRisk(minScore),
  })
}

export function useCreateExposure() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => attackSurfaceApi.create(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['exposures'] }),
  })
}

export function useUpdateExposure() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => attackSurfaceApi.update(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['exposures'] }),
  })
}

export function useDeleteExposure() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => attackSurfaceApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['exposures'] }),
  })
}

export function useMitigateExposure() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => attackSurfaceApi.mitigate(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['exposures'] })
      qc.invalidateQueries({ queryKey: ['attack-surface-summary'] })
    },
  })
}

export function useUpdateRemediation() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, remediation }: { id: string; remediation: string }) =>
      attackSurfaceApi.updateRemediation(id, remediation),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['exposure'] }),
  })
}
