import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { organizationsApi } from '@/api/organizations'

export function useOrganizations() {
  return useQuery({
    queryKey: ['organizations'],
    queryFn: () => organizationsApi.list(),
    staleTime: 30000,
  })
}

export function useMyOrganizations() {
  return useQuery({
    queryKey: ['my-organizations'],
    queryFn: () => organizationsApi.myOrgs(),
    staleTime: 30000,
  })
}

export function useCreateOrganization() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: { name: string; slug?: string }) => organizationsApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
      queryClient.invalidateQueries({ queryKey: ['my-organizations'] })
    },
  })
}

export function useOrganizationMembers(orgId: string | null) {
  return useQuery({
    queryKey: ['organization-members', orgId],
    queryFn: () => organizationsApi.members(orgId!),
    enabled: !!orgId,
  })
}

export function useAddMember() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ orgId, ...data }: { orgId: string; user_id: string; role?: string }) =>
      organizationsApi.addMember(orgId, data),
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ['organization-members', vars.orgId] })
    },
  })
}

export function useRemoveMember() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ orgId, userId }: { orgId: string; userId: string }) =>
      organizationsApi.removeMember(orgId, userId),
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ['organization-members', vars.orgId] })
    },
  })
}

export function useTeams(orgId: string | null) {
  return useQuery({
    queryKey: ['teams', orgId],
    queryFn: () => organizationsApi.listTeams(orgId || undefined),
    enabled: true,
  })
}

export function useCreateTeam() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: { organization_id: string; name: string; description?: string }) =>
      organizationsApi.createTeam(data),
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ['teams', vars.organization_id] })
    },
  })
}

export function useOrgActivity(orgId: string | null) {
  return useQuery({
    queryKey: ['org-activity', orgId],
    queryFn: () => organizationsApi.activity(orgId!),
    enabled: !!orgId,
    refetchInterval: 15000,
  })
}
