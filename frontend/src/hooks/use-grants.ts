import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as grantsApi from '@/api/grants'

const GRANTS_KEY = ['authorization-grants'] as const

export function useGrants(params?: { limit?: number; offset?: number }) {
  return useQuery({
    queryKey: [...GRANTS_KEY, params],
    queryFn: () => grantsApi.listGrants(params),
  })
}

export function useCreateGrant() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: grantsApi.createGrant,
    onSuccess: () => qc.invalidateQueries({ queryKey: GRANTS_KEY }),
  })
}

export function useRevokeGrant() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: grantsApi.revokeGrant,
    onSuccess: () => qc.invalidateQueries({ queryKey: GRANTS_KEY }),
  })
}

export function useCheckGrantCoverage() {
  return useMutation({
    mutationFn: grantsApi.checkGrantCoverage,
  })
}
