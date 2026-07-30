import { useQuery } from '@tanstack/react-query'
import { deploymentApi } from '@/api/deployment'

export function useSystemInfo() {
  return useQuery({
    queryKey: ['deployment', 'system-info'],
    queryFn: () => deploymentApi.getSystemInfo(),
    staleTime: 60_000,
  })
}

export function useConfigSummary() {
  return useQuery({
    queryKey: ['deployment', 'config'],
    queryFn: () => deploymentApi.getConfigSummary(),
    staleTime: 60_000,
  })
}

export function useStartupReport() {
  return useQuery({
    queryKey: ['deployment', 'startup'],
    queryFn: () => deploymentApi.getStartupReport(),
    staleTime: 30_000,
  })
}

export function useDeploymentHealth() {
  return useQuery({
    queryKey: ['deployment', 'health'],
    queryFn: () => deploymentApi.getHealth(),
    staleTime: 15_000,
    refetchInterval: 30_000,
  })
}

export function useDiagnostics() {
  return useQuery({
    queryKey: ['deployment', 'diagnostics'],
    queryFn: () => deploymentApi.getDiagnostics(),
    staleTime: 60_000,
  })
}

export function useUpgradePlan(targetVersion: string) {
  return useQuery({
    queryKey: ['deployment', 'upgrade-plan', targetVersion],
    queryFn: () => deploymentApi.getUpgradePlan(targetVersion),
    enabled: !!targetVersion,
  })
}
