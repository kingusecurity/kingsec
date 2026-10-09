import { useMutation, useQuery } from '@tanstack/react-query'
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

export function useMapFindings() {
  return useMutation({ mutationFn: complianceApi.mapFindings })
}

export function useCalculateCoverage() {
  return useMutation({ mutationFn: complianceApi.calculateCoverage })
}

export function useAnalyzeComplianceGaps() {
  return useMutation({ mutationFn: complianceApi.analyzeGaps })
}

export function useGenerateComplianceReport() {
  return useMutation({ mutationFn: complianceApi.generateReport })
}
