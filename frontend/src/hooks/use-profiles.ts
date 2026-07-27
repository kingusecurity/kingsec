import { useQuery, useMutation } from '@tanstack/react-query'
import { profilesApi } from '@/api/profiles'
import type { PlanRequestBody } from '@/api/profiles'

export function useProfiles() {
  return useQuery({
    queryKey: ['profiles'],
    queryFn: () => profilesApi.list(),
    staleTime: 60_000,
  })
}

export function useProfile(profileId: string | null) {
  return useQuery({
    queryKey: ['profiles', profileId],
    queryFn: () => profilesApi.get(profileId!),
    enabled: !!profileId,
    staleTime: 60_000,
  })
}

export function usePlan() {
  return useMutation({
    mutationFn: ({ profileId, body }: { profileId: string; body: PlanRequestBody }) =>
      profilesApi.plan(profileId, body),
  })
}
