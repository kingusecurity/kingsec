import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { assetsApi } from '@/api/assets'

export function useAssetSummary() {
  return useQuery({
    queryKey: ['asset-summary'],
    queryFn: assetsApi.getSummary,
  })
}

export function useAssets(params: Record<string, unknown> = {}) {
  return useQuery({
    queryKey: ['assets', params],
    queryFn: () => assetsApi.list(params as Parameters<typeof assetsApi.list>[0]),
  })
}

export function useAssetSearch(q: string) {
  return useQuery({
    queryKey: ['asset-search', q],
    queryFn: () => assetsApi.search(q),
    enabled: q.length >= 2,
  })
}

export function useAsset(id: string | null) {
  return useQuery({
    queryKey: ['asset', id],
    queryFn: () => assetsApi.get(id!),
    enabled: !!id,
  })
}

export function useAssetRelationships(id: string | null) {
  return useQuery({
    queryKey: ['asset-relationships', id],
    queryFn: () => assetsApi.getRelationships(id!),
    enabled: !!id,
  })
}

export function useAssetHistory(id: string | null) {
  return useQuery({
    queryKey: ['asset-history', id],
    queryFn: () => assetsApi.getHistory(id!),
    enabled: !!id,
  })
}

export function useCreateAsset() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => assetsApi.create(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })
}

export function useUpdateAsset() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => assetsApi.update(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })
}

export function useDeleteAsset() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => assetsApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })
}

export function useAddTag() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, key, value }: { id: string; key: string; value: string }) => assetsApi.addTag(id, key, value),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['asset'] }),
  })
}

export function useRemoveTag() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, key }: { id: string; key: string }) => assetsApi.removeTag(id, key),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['asset'] }),
  })
}

export function useRecalculateRisk() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, criticalFindings = 0, highFindings = 0, openFindings = 0 }:
      { id: string; criticalFindings?: number; highFindings?: number; openFindings?: number }) =>
      assetsApi.recalculateRisk(id, criticalFindings, highFindings, openFindings),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['asset'] }),
  })
}

export function useUpdateCriticality() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, criticality }: { id: string; criticality: string }) => assetsApi.updateCriticality(id, criticality),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['asset'] }),
  })
}
