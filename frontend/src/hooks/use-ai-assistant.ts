import { useQuery, useMutation } from '@tanstack/react-query'
import { aiAssistantApi } from '@/api/ai-assistant'

export function useAIHealth() {
  return useQuery({
    queryKey: ['ai-health'],
    queryFn: aiAssistantApi.health,
    retry: false,
    staleTime: 60_000,
  })
}

export function useExplainFinding() {
  return useMutation({
    mutationFn: ({ findingId, assessmentId }: { findingId: string; assessmentId: string }) =>
      aiAssistantApi.explainFinding(findingId, assessmentId),
  })
}

export function useExecutiveSummary() {
  return useMutation({
    mutationFn: (assessmentId: string) =>
      aiAssistantApi.executiveSummary(assessmentId),
  })
}

export function useRemediationPlan() {
  return useMutation({
    mutationFn: (assessmentId: string) =>
      aiAssistantApi.remediationPlan(assessmentId),
  })
}

export function useAIChat() {
  return useMutation({
    mutationFn: ({ question, history, assessmentId }: {
      question: string
      history: Array<{ role: string; content: string }>
      assessmentId?: string
    }) => aiAssistantApi.chat(question, history, assessmentId),
  })
}
