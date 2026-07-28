import { useQuery } from '@tanstack/react-query'
import { complianceApi } from '@/api/compliance'

export function useFrameworks() {
  return useQuery({
    queryKey: ['compliance-frameworks'],
    queryFn: complianceApi.listFrameworks,
  })
}

export function useFrameworkControls(frameworkId: string | null) {
  return useQuery({
    queryKey: ['compliance-controls', frameworkId],
    queryFn: () => complianceApi.getFrameworkControls(frameworkId!),
    enabled: !!frameworkId,
  })
}
