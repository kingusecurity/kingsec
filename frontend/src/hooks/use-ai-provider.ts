import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { aiProviderApi, type SaveAIProviderConfigBody, type TestAIProviderConfigBody } from '@/api/ai-provider'

export function useAIProviderConfig() {
  return useQuery({
    queryKey: ['ai-provider-config'],
    queryFn: () => aiProviderApi.get(),
    staleTime: 10000,
  })
}

export function useSaveAIProviderConfig() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: SaveAIProviderConfigBody) => aiProviderApi.save(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-provider-config'] })
    },
  })
}

export function useTestAIProviderConfig() {
  return useMutation({
    mutationFn: (body: TestAIProviderConfigBody) => aiProviderApi.test(body),
  })
}
