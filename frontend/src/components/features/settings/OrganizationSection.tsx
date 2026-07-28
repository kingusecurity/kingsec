import { useState } from 'react'
import {
  useOrganizations, useCreateOrganization, useOrganizationMembers,
  useAddMember, useRemoveMember, useTeams, useCreateTeam, useOrgActivity,
} from '@/hooks/use-organizations'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Input } from '@/components/ui/Input'
import { Skeleton } from '@/components/ui/Skeleton'
import { toast } from '@/components/ui/Toast'
import {
  Building2, Users, Activity, Plus, Trash2, UserPlus,
} from 'lucide-react'

export function OrganizationSection() {
  const [activeOrgId, setActiveOrgId] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState('')
  const [newSlug, setNewSlug] = useState('')
  const [memberUserId, setMemberUserId] = useState('')
  const [memberRole, setMemberRole] = useState('viewer')
  const [teamName, setTeamName] = useState('')
  const [teamDesc, setTeamDesc] = useState('')

  const { data: orgsData, isLoading: orgsLoading } = useOrganizations()
  const { data: membersData } = useOrganizationMembers(activeOrgId)
  const { data: teamsData } = useTeams(activeOrgId)
  const { data: activityData } = useOrgActivity(activeOrgId)
  const createOrg = useCreateOrganization()
  const addMember = useAddMember()
  const removeMember = useRemoveMember()
  const createTeam = useCreateTeam()

  const orgs = orgsData?.organizations || []
  const members = membersData?.members || []
  const teams = teamsData?.teams || []
  const events = activityData?.events || []

  const handleCreateOrg = async () => {
    if (!newName.trim()) return
    try {
      await createOrg.mutateAsync({ name: newName.trim(), slug: newSlug.trim() || undefined })
      toast.success('Organization created', newName.trim())
      setShowCreate(false)
      setNewName('')
      setNewSlug('')
    } catch {
      toast.error('Failed to create organization')
    }
  }

  const handleAddMember = async () => {
    if (!activeOrgId || !memberUserId.trim()) return
    try {
      await addMember.mutateAsync({ orgId: activeOrgId, user_id: memberUserId.trim(), role: memberRole })
      toast.success('Member added', memberUserId.trim())
      setMemberUserId('')
    } catch {
      toast.error('Failed to add member')
    }
  }

  const handleRemoveMember = async (userId: string) => {
    if (!activeOrgId) return
    try {
      await removeMember.mutateAsync({ orgId: activeOrgId, userId })
      toast.success('Member removed')
    } catch {
      toast.error('Failed to remove member')
    }
  }

  const handleCreateTeam = async () => {
    if (!activeOrgId || !teamName.trim()) return
    try {
      await createTeam.mutateAsync({ organization_id: activeOrgId, name: teamName.trim(), description: teamDesc.trim() })
      toast.success('Team created', teamName.trim())
      setTeamName('')
      setTeamDesc('')
    } catch {
      toast.error('Failed to create team')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-text-primary">Organizations</h2>
          <p className="text-sm text-text-muted">Manage organizations, teams, and members</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setShowCreate(!showCreate)} iconLeft={<Plus className="h-4 w-4" />}>
          New Organization
        </Button>
      </div>

      {showCreate && (
        <Card className="p-4 space-y-3">
          <h3 className="text-sm font-medium text-text-primary">Create Organization</h3>
          <Input placeholder="Organization name" value={newName} onChange={(e) => setNewName(e.target.value)} />
          <Input placeholder="Slug (optional, e.g. my-org)" value={newSlug} onChange={(e) => setNewSlug(e.target.value)} />
          <Button onClick={handleCreateOrg} loading={createOrg.isPending}>Create</Button>
        </Card>
      )}

      {orgsLoading ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-16 w-full rounded-lg" />)}
        </div>
      ) : orgs.length === 0 ? (
        <Card className="p-6 text-center text-text-muted text-sm">
          No organizations yet. Create one to get started.
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {orgs.map((org) => (
            <div
              key={org.id}
              role="button"
              tabIndex={0}
              className={`rounded-xl border p-4 transition-colors cursor-pointer ${
                activeOrgId === org.id ? 'ring-2 ring-accent border-accent' : 'border-border hover:bg-surface-tertiary'
              }`}
              onClick={() => setActiveOrgId(org.id === activeOrgId ? null : org.id)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setActiveOrgId(org.id === activeOrgId ? null : org.id) }}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Building2 className="h-5 w-5 text-text-muted" />
                  <div>
                    <h3 className="text-sm font-medium text-text-primary">{org.name}</h3>
                    <p className="text-xs text-text-muted">{org.slug}</p>
                  </div>
                </div>
                {org.role && <Badge variant="info" size="sm">{org.role}</Badge>}
              </div>
            </div>
          ))}
        </div>
      )}

      {activeOrgId && (
        <div className="space-y-6 pl-4 border-l-2 border-border">
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <Users className="h-4 w-4" /> Members ({members.length})
            </h3>
            <div className="flex gap-2">
              <Input
                placeholder="User ID"
                value={memberUserId}
                onChange={(e) => setMemberUserId(e.target.value)}
                className="flex-1"
              />
              <select
                value={memberRole}
                onChange={(e) => setMemberRole(e.target.value)}
                className="bg-surface-tertiary text-text-primary text-sm rounded-md px-2 border border-border"
              >
                <option value="viewer">Viewer</option>
                <option value="editor">Editor</option>
                <option value="admin">Admin</option>
              </select>
              <Button variant="outline" size="sm" onClick={handleAddMember} iconLeft={<UserPlus className="h-3 w-3" />}>
                Add
              </Button>
            </div>
            <div className="space-y-1">
              {members.map((m) => (
                <div key={m.user_id} className="flex items-center justify-between rounded-lg bg-surface-tertiary/50 px-3 py-2">
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-text-primary">{m.user_id}</span>
                    <Badge variant="info" size="sm">{m.role}</Badge>
                  </div>
                  <button onClick={() => handleRemoveMember(m.user_id)} className="text-red-400 hover:text-red-300">
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-text-primary">Teams ({teams.length})</h3>
            <div className="flex gap-2">
              <Input placeholder="Team name" value={teamName} onChange={(e) => setTeamName(e.target.value)} className="flex-1" />
              <Input placeholder="Description" value={teamDesc} onChange={(e) => setTeamDesc(e.target.value)} className="flex-1" />
              <Button variant="outline" size="sm" onClick={handleCreateTeam} iconLeft={<Plus className="h-3 w-3" />}>
                Add
              </Button>
            </div>
            <div className="space-y-1">
              {teams.map((t) => (
                <div key={t.id} className="rounded-lg bg-surface-tertiary/50 px-3 py-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-text-primary">{t.name}</span>
                  </div>
                  {t.description && <p className="text-xs text-text-muted mt-0.5">{t.description}</p>}
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <Activity className="h-4 w-4" /> Activity Feed
            </h3>
            <div className="space-y-1 max-h-60 overflow-y-auto">
              {events.length === 0 ? (
                <p className="text-xs text-text-muted">No recent activity</p>
              ) : (
                events.map((e) => (
                  <div key={e.id} className="flex items-start gap-2 text-xs text-text-secondary py-1.5 border-b border-border/50">
                    <span className="text-text-muted shrink-0">{new Date(e.timestamp).toLocaleString()}</span>
                    <span>{e.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
