import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as identityApi from '@/api/identity'

export function useIdentityProviders() {
  return useQuery({
    queryKey: ['identity-providers'],
    queryFn: identityApi.listProviders,
  })
}

export function useIdentityProvider(id: string) {
  return useQuery({
    queryKey: ['identity-provider', id],
    queryFn: () => identityApi.getProvider(id),
    enabled: !!id,
  })
}

export function useCreateIdentityProvider() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: identityApi.createProvider,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['identity-providers'] }),
  })
}

export function useUpdateIdentityProvider() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<identityApi.IdentityProvider> }) =>
      identityApi.updateProvider(id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['identity-providers'] }); qc.invalidateQueries({ queryKey: ['identity-provider'] }) },
  })
}

export function useDeleteIdentityProvider() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: identityApi.deleteProvider,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['identity-providers'] }),
  })
}

export function useActivateIdentityProvider() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: identityApi.activateProvider,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['identity-providers'] }),
  })
}

export function useDeactivateIdentityProvider() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: identityApi.deactivateProvider,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['identity-providers'] }),
  })
}

export function useTestConnection() {
  return useMutation({
    mutationFn: identityApi.testConnection,
  })
}
