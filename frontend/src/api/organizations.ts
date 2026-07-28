import { apiRequest } from './client'

export interface Organization {
  id: string
  name: string
  slug: string
  created_at: string
  updated_at?: string
  role?: string
}

export interface Team {
  id: string
  organization_id: string
  name: string
  description: string
  created_at: string
  updated_at: string
}

export interface Member {
  user_id: string
  organization_id: string
  role: string
  created_at: string
}

export interface ActivityEvent {
  id: string
  organization_id: string
  event_type: string
  actor_id: string
  message: string
  metadata: Record<string, string>
  timestamp: string
}

export const organizationsApi = {
  list: (limit = 50, offset = 0) =>
    apiRequest<{ organizations: Organization[]; total: number }>(`/organizations?limit=${limit}&offset=${offset}`),

  create: (data: { name: string; slug?: string }) =>
    apiRequest<Organization>('/organizations', { method: 'POST', body: data }),

  update: (id: string, data: { name?: string; slug?: string }) =>
    apiRequest<Organization>(`/organizations/${id}`, { method: 'PATCH', body: data }),

  delete: (id: string) =>
    apiRequest<void>(`/organizations/${id}`, { method: 'DELETE' }),

  members: (orgId: string) =>
    apiRequest<{ members: Member[]; total: number }>(`/organizations/${orgId}/members`),

  addMember: (orgId: string, data: { user_id: string; role?: string }) =>
    apiRequest<Member>(`/organizations/${orgId}/members`, { method: 'POST', body: data }),

  removeMember: (orgId: string, userId: string) =>
    apiRequest<void>(`/organizations/${orgId}/members/${userId}`, { method: 'DELETE' }),

  listTeams: (orgId?: string) =>
    apiRequest<{ teams: Team[]; total: number }>(`/teams${orgId ? `?organization_id=${orgId}` : ''}`),

  createTeam: (data: { organization_id: string; name: string; description?: string }) =>
    apiRequest<Team>('/teams', { method: 'POST', body: data }),

  updateTeam: (id: string, data: { name?: string; description?: string }) =>
    apiRequest<Team>(`/teams/${id}`, { method: 'PATCH', body: data }),

  deleteTeam: (id: string) =>
    apiRequest<void>(`/teams/${id}`, { method: 'DELETE' }),

  addTeamMember: (teamId: string, data: { user_id: string }) =>
    apiRequest<{ user_id: string; team_id: string }>(`/teams/${teamId}/members`, { method: 'POST', body: data }),

  removeTeamMember: (teamId: string, userId: string) =>
    apiRequest<void>(`/teams/${teamId}/members/${userId}`, { method: 'DELETE' }),

  activity: (orgId: string, limit = 50) =>
    apiRequest<{ events: ActivityEvent[]; total: number }>(`/organizations/${orgId}/activity?limit=${limit}`),

  myOrgs: () =>
    apiRequest<{ organizations: Organization[] }>('/me/organizations'),
}
