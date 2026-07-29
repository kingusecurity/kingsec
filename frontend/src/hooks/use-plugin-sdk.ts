import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as api from '@/api/plugin-sdk'

export function useSdkPlugins(typeFilter?: string) {
  return useQuery({
    queryKey: ['sdk-plugins', typeFilter],
    queryFn: () => api.listSdkPlugins(typeFilter),
  })
}

export function useSdkPlugin(id: string | undefined) {
  return useQuery({
    queryKey: ['sdk-plugin', id],
    queryFn: () => api.getSdkPlugin(id!),
    enabled: !!id,
  })
}

export function useScanPlugins() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.scanPluginDir,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sdk-plugins'] }),
  })
}

export function useLoadPlugin() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.loadPlugin,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sdk-plugins'] }); qc.invalidateQueries({ queryKey: ['sdk-plugin'] }) },
  })
}

export function useUnloadPlugin() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.unloadPlugin,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sdk-plugins'] }); qc.invalidateQueries({ queryKey: ['sdk-plugin'] }) },
  })
}

export function useMarketplace(typeFilter?: string, search?: string) {
  return useQuery({
    queryKey: ['marketplace', typeFilter, search],
    queryFn: () => api.listMarketplace(typeFilter, search),
  })
}

export function useMarketplacePlugin(id: string | undefined) {
  return useQuery({
    queryKey: ['marketplace-plugin', id],
    queryFn: () => api.getMarketplacePlugin(id!),
    enabled: !!id,
  })
}

export function usePluginPermissions() {
  return useQuery({
    queryKey: ['plugin-permissions'],
    queryFn: api.getPermissions,
    staleTime: Infinity,
  })
}
