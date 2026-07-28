import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { licensingApi } from '@/api/licensing'

export function useLicense() {
  return useQuery({
    queryKey: ['license'],
    queryFn: licensingApi.getLicense,
  })
}

export function useLicenseFeatures() {
  return useQuery({
    queryKey: ['license-features'],
    queryFn: licensingApi.getFeatures,
  })
}

export function useLicenseStatus() {
  return useQuery({
    queryKey: ['license-status'],
    queryFn: licensingApi.getStatus,
  })
}

export function useActivateLicense() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (licenseKey: string) => licensingApi.activate(licenseKey),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['license'] })
      queryClient.invalidateQueries({ queryKey: ['license-features'] })
      queryClient.invalidateQueries({ queryKey: ['license-status'] })
    },
  })
}

export function useDeactivateLicense() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (licenseId: string) => licensingApi.deactivate(licenseId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['license'] })
      queryClient.invalidateQueries({ queryKey: ['license-features'] })
      queryClient.invalidateQueries({ queryKey: ['license-status'] })
    },
  })
}
