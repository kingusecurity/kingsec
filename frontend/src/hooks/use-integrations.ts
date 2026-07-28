import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { integrationsApi } from '@/api/integrations'

export function useIntegrations() {
  return useQuery({
    queryKey: ['integrations'],
    queryFn: () => integrationsApi.list(),
    staleTime: 30000,
  })
}

export function useTestIntegration() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (integrationType: string) => integrationsApi.test(integrationType),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] })
    },
  })
}

export function useWebhookHistory(limit = 50) {
  return useQuery({
    queryKey: ['webhook-history', limit],
    queryFn: () => integrationsApi.webhookHistory(limit),
    staleTime: 10000,
  })
}

export function useEmailHistory(limit = 50) {
  return useQuery({
    queryKey: ['email-history', limit],
    queryFn: () => integrationsApi.emailHistory(limit),
    staleTime: 10000,
  })
}

export function useTickets(findingId?: string) {
  return useQuery({
    queryKey: ['tickets', findingId],
    queryFn: () => integrationsApi.tickets(findingId),
    enabled: true,
  })
}
