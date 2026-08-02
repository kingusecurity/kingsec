import { useEffect, useState } from 'react'
import { Shield, Users, Activity, HardDrive, Package, LayoutList, Server, Database, Search, RotateCw } from 'lucide-react'
import { PageContainer, PageHeader, StatGrid } from '@/components/layout/PageContainer'
import { StatCard } from '@/components/features/dashboard/StatCard'
import { Card } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { Modal } from '@/components/ui/Modal'
import { useAdminAgents, useAdminBackups, useAdminPlugins, useAdminQueueStats, useAdminDashboardSummary } from '@/hooks/use-admin'
import { useAdminUsersSearch, useDeactivateUser, useActivateUser, useResetPassword } from '@/hooks/use-admin'
import { authApi } from '@/api/auth'

type Tab = 'overview' | 'users' | 'agents' | 'backups' | 'plugins' | 'queue'

const tabs: { key: Tab; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { key: 'overview', label: 'Overview', icon: Shield },
  { key: 'users', label: 'Users', icon: Users },
  { key: 'agents', label: 'Agents', icon: Activity },
  { key: 'backups', label: 'Backups', icon: HardDrive },
  { key: 'plugins', label: 'Plugins', icon: Package },
  { key: 'queue', label: 'Queue', icon: LayoutList },
]

function TabNav({ active, onChange }: { active: Tab; onChange: (t: Tab) => void }) {
  return (
    <div className="mb-6 flex flex-wrap gap-1 border-b border-border">
      {tabs.map((tab) => {
        const Icon = tab.icon
        return (
          <button
            key={tab.key}
            onClick={() => onChange(tab.key)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              active === tab.key
                ? 'border-accent text-accent'
                : 'border-transparent text-text-muted hover:text-text-primary hover:border-text-muted'
            }`}
          >
            <Icon className="h-4 w-4" />
            {tab.label}
          </button>
        )
      })}
    </div>
  )
}

function OverviewTab() {
  const { data: summary, isLoading: summaryLoading } = useAdminDashboardSummary()
  const { data: agents } = useAdminAgents()
  const { data: plugins } = useAdminPlugins()
  const { data: queue } = useAdminQueueStats()

  return (
    <div className="space-y-6">
      <StatGrid columns={4}>
        <StatCard icon={Server} label="Total Scans" value={summary?.total_scans ?? 0} loading={summaryLoading} />
        <StatCard icon={Activity} label="Agents" value={agents?.agents?.length ?? 0} loading={!agents} />
        <StatCard icon={Package} label="Plugins" value={plugins?.plugins?.length ?? 0} loading={!plugins} />
        <StatCard icon={LayoutList} label="Queue" value={queue?.pending ?? 0} loading={!queue} />
      </StatGrid>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <div className="p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-3">Findings Overview</h3>
            {summaryLoading ? (
              <Spinner size="sm" />
            ) : (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-2xl font-bold text-text-primary">{summary?.total_findings ?? 0}</p>
                  <p className="text-xs text-text-muted">Total Findings</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-red-400">{summary?.critical_findings ?? 0}</p>
                  <p className="text-xs text-text-muted">Critical</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-orange-400">{summary?.high_findings ?? 0}</p>
                  <p className="text-xs text-text-muted">High</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-yellow-400">{summary?.medium_findings ?? 0}</p>
                  <p className="text-xs text-text-muted">Medium</p>
                </div>
              </div>
            )}
          </div>
        </Card>

        <Card>
          <div className="p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-3">System Status</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-text-muted">Active Scanners</span>
                <span className="text-sm font-medium text-text-primary">{summary?.active_scanners ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-text-muted">Active Schedules</span>
                <span className="text-sm font-medium text-text-primary">{summary?.active_schedules ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-text-muted">Pending Notifications</span>
                <span className="text-sm font-medium text-text-primary">{summary?.pending_notifications ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-text-muted">Failed Notifications</span>
                <span className="text-sm font-medium text-red-400">{summary?.failed_notifications ?? 0}</span>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  )
}

function useDebouncedValue(value: string, delay: number): string {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debounced
}

function UsersTab() {
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState('')
  const [offset, setOffset] = useState(0)
  const {} = useState<string | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [resetPwUserId, setResetPwUserId] = useState<string | null>(null)
  const [newPassword, setNewPassword] = useState('')
  const [roleChangeUserId, setRoleChangeUserId] = useState<string | null>(null)
  const [newRole, setNewRole] = useState('')
  const [actionError, setActionError] = useState('')
  const limit = 25
  const debouncedSearch = useDebouncedValue(search, 300)

  const { data, isLoading, error, refetch } = useAdminUsersSearch({
    query: debouncedSearch || undefined,
    role: roleFilter || undefined,
    limit,
    offset,
  })

  const deactivateUser = useDeactivateUser()
  const activateUser = useActivateUser()
  const resetPassword = useResetPassword()

  const handleDeactivate = async (userId: string) => {
    setActionLoading(userId)
    setActionError('')
    try {
      await deactivateUser.mutateAsync(userId)
    } catch {
      setActionError('Failed to deactivate user')
    } finally {
      setActionLoading(null)
    }
  }

  const handleActivate = async (userId: string) => {
    setActionLoading(userId)
    setActionError('')
    try {
      await activateUser.mutateAsync(userId)
    } catch {
      setActionError('Failed to activate user')
    } finally {
      setActionLoading(null)
    }
  }

  const handleAssignRole = async (userId: string, role: string) => {
    setActionLoading(userId)
    setActionError('')
    try {
      await authApi.assignRole(userId, { role })
      setRoleChangeUserId(null)
      setNewRole('')
      refetch()
    } catch {
      setActionError('Failed to assign role')
    } finally {
      setActionLoading(null)
    }
  }

  const handleResetPassword = async () => {
    if (!resetPwUserId || !newPassword) return
    setActionLoading(resetPwUserId)
    setActionError('')
    try {
      await resetPassword.mutateAsync({ userId: resetPwUserId, body: { new_password: newPassword } })
      setResetPwUserId(null)
      setNewPassword('')
    } catch {
      setActionError('Failed to reset password')
    } finally {
      setActionLoading(null)
    }
  }

  if (isLoading) return <Spinner size="lg" />
  if (error) return <p className="text-sm text-red-400">Failed to load users</p>

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            placeholder="Search by username or email..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setOffset(0) }}
            className="w-full rounded-lg border border-border bg-surface-secondary py-2 pl-9 pr-3 text-sm text-text-primary placeholder-text-muted focus:border-accent focus:outline-none"
          />
        </div>
        <select value={roleFilter} onChange={(e) => { setRoleFilter(e.target.value); setOffset(0) }} className="rounded-lg border border-border bg-surface-secondary px-3 py-2 text-sm text-text-primary">
          <option value="">All Roles</option>
          <option value="ADMIN">Admin</option>
          <option value="ANALYST">Analyst</option>
          <option value="VIEWER">Viewer</option>
        </select>
      </div>

      {actionError && <p className="text-sm text-red-400">{actionError}</p>}

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-3 text-left font-medium text-text-muted">Username</th>
                <th className="px-4 py-3 text-left font-medium text-text-muted">Email</th>
                <th className="px-4 py-3 text-left font-medium text-text-muted">Role</th>
                <th className="px-4 py-3 text-left font-medium text-text-muted">Status</th>
                <th className="px-4 py-3 text-left font-medium text-text-muted">Created</th>
                <th className="px-4 py-3 text-left font-medium text-text-muted">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data?.items.map((user) => (
                <tr key={user.user_id} className="border-b border-border hover:bg-surface-tertiary/50">
                  <td className="px-4 py-3 text-text-primary">{user.username}</td>
                  <td className="px-4 py-3 text-text-muted">{user.email}</td>
                  <td className="px-4 py-3">
                    <span className="rounded bg-accent/10 px-2 py-0.5 text-xs text-accent">{user.role}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-block h-2 w-2 rounded-full ${user.is_active ? 'bg-emerald-500' : 'bg-red-500'}`} />
                  </td>
                  <td className="px-4 py-3 text-text-muted">{new Date(user.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {user.is_active ? (
                        <button
                          onClick={() => handleDeactivate(user.user_id)}
                          disabled={actionLoading === user.user_id}
                          className="rounded border border-border px-2 py-1 text-xs text-text-muted hover:text-red-400 hover:border-red-400/30 disabled:opacity-40"
                        >
                          {actionLoading === user.user_id ? <RotateCw className="h-3 w-3 animate-spin" /> : 'Deactivate'}
                        </button>
                      ) : (
                        <button
                          onClick={() => handleActivate(user.user_id)}
                          disabled={actionLoading === user.user_id}
                          className="rounded border border-border px-2 py-1 text-xs text-text-muted hover:text-emerald-400 hover:border-emerald-400/30 disabled:opacity-40"
                        >
                          {actionLoading === user.user_id ? <RotateCw className="h-3 w-3 animate-spin" /> : 'Activate'}
                        </button>
                      )}
                      <button
                        onClick={() => { setRoleChangeUserId(user.user_id); setNewRole(user.role) }}
                        className="rounded border border-border px-2 py-1 text-xs text-text-muted hover:text-accent disabled:opacity-40"
                      >
                        Change Role
                      </button>
                      <button
                        onClick={() => { setResetPwUserId(user.user_id); setNewPassword('') }}
                        className="rounded border border-border px-2 py-1 text-xs text-text-muted hover:text-accent disabled:opacity-40"
                      >
                        Reset Password
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {data?.items.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-sm text-text-muted">No users match the current filters.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between border-t border-border px-4 py-3 text-sm text-text-muted">
          <span>{(data?.total ?? 0)} total users</span>
          <div className="flex gap-2">
            <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))} className="rounded border border-border px-3 py-1 text-sm disabled:opacity-40 hover:bg-surface-tertiary">Previous</button>
            <button disabled={(data?.total ?? 0) <= offset + limit} onClick={() => setOffset(offset + limit)} className="rounded border border-border px-3 py-1 text-sm disabled:opacity-40 hover:bg-surface-tertiary">Next</button>
          </div>
        </div>
      </Card>

      <Modal open={!!roleChangeUserId} onClose={() => setRoleChangeUserId(null)} title="Change User Role">
        <div className="space-y-4">
          <select value={newRole} onChange={(e) => setNewRole(e.target.value)} className="w-full rounded-lg border border-border bg-surface-secondary px-3 py-2 text-sm text-text-primary">
            <option value="VIEWER">Viewer</option>
            <option value="ANALYST">Analyst</option>
            <option value="ADMIN">Admin</option>
          </select>
          <div className="flex justify-end gap-2">
            <button onClick={() => setRoleChangeUserId(null)} className="rounded border border-border px-4 py-2 text-sm text-text-muted hover:bg-surface-tertiary">Cancel</button>
            <button
              onClick={() => roleChangeUserId && handleAssignRole(roleChangeUserId, newRole)}
              disabled={actionLoading !== null}
              className="rounded bg-accent px-4 py-2 text-sm text-white hover:bg-accent/90 disabled:opacity-40"
            >
              {actionLoading ? <RotateCw className="h-4 w-4 animate-spin" /> : 'Save'}
            </button>
          </div>
        </div>
      </Modal>

      <Modal open={!!resetPwUserId} onClose={() => setResetPwUserId(null)} title="Reset User Password">
        <div className="space-y-4">
          <input
            type="password"
            placeholder="New password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="w-full rounded-lg border border-border bg-surface-secondary px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:border-accent focus:outline-none"
          />
          <div className="flex justify-end gap-2">
            <button onClick={() => setResetPwUserId(null)} className="rounded border border-border px-4 py-2 text-sm text-text-muted hover:bg-surface-tertiary">Cancel</button>
            <button
              onClick={handleResetPassword}
              disabled={!newPassword || actionLoading !== null}
              className="rounded bg-accent px-4 py-2 text-sm text-white hover:bg-accent/90 disabled:opacity-40"
            >
              {actionLoading ? <RotateCw className="h-4 w-4 animate-spin" /> : 'Reset'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

function AgentsTab() {
  const { data, isLoading, error } = useAdminAgents()

  if (isLoading) return <Spinner size="lg" />
  if (error) return <p className="text-sm text-red-400">Failed to load agents</p>

  return (
    <Card>
      <div className="p-5">
        {!data?.agents?.length ? (
          <div className="rounded-lg border border-border bg-surface-tertiary/50 px-5 py-8 text-center">
            <p className="text-sm text-text-muted">No agents registered</p>
          </div>
        ) : (
          <div className="space-y-2">
            {data.agents.map((agent) => (
              <div key={agent.id} className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div className="flex items-center gap-3">
                  <Activity className="h-4 w-4 text-text-muted" />
                  <span className="text-sm text-text-primary">{agent.name}</span>
                </div>
                <span className="text-xs text-text-muted">{agent.status}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  )
}

function BackupsTab() {
  const { data, isLoading, error } = useAdminBackups()

  if (isLoading) return <Spinner size="lg" />
  if (error) return <p className="text-sm text-red-400">Failed to load backups</p>

  return (
    <Card>
      <div className="p-5">
        {!data?.backups?.length ? (
          <div className="rounded-lg border border-border bg-surface-tertiary/50 px-5 py-8 text-center">
            <p className="text-sm text-text-muted">No backups available</p>
          </div>
        ) : (
          <div className="space-y-2">
            {data.backups.map((b) => (
              <div key={b.id} className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div className="flex items-center gap-3">
                  <HardDrive className="h-4 w-4 text-text-muted" />
                  <span className="text-sm text-text-primary">{b.type}</span>
                </div>
                <span className="text-xs text-text-muted">{b.status} — {new Date(b.created_at).toLocaleDateString()}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  )
}

function PluginsTab() {
  const { data, isLoading, error } = useAdminPlugins()

  if (isLoading) return <Spinner size="lg" />
  if (error) return <p className="text-sm text-red-400">Failed to load plugins</p>

  return (
    <Card>
      <div className="p-5">
        {!data?.plugins?.length ? (
          <div className="rounded-lg border border-border bg-surface-tertiary/50 px-5 py-8 text-center">
            <p className="text-sm text-text-muted">No plugins installed</p>
          </div>
        ) : (
          <div className="space-y-2">
            {data.plugins.map((p) => (
              <div key={p.id} className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div className="flex items-center gap-3">
                  <Package className="h-4 w-4 text-text-muted" />
                  <span className="text-sm text-text-primary">{p.name}</span>
                  <span className="text-xs text-text-muted">v{p.version}</span>
                </div>
                <span className={`rounded px-2 py-0.5 text-xs ${p.enabled ? 'bg-emerald-500/10 text-emerald-400' : 'bg-gray-500/10 text-text-muted'}`}>
                  {p.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  )
}

function QueueTab() {
  const { data, isLoading, error } = useAdminQueueStats()

  if (isLoading) return <Spinner size="lg" />
  if (error) return <p className="text-sm text-red-400">Failed to load queue stats</p>

  return (
    <Card>
      <div className="p-5">
        <div className="grid grid-cols-3 gap-4">
          <div className="rounded-lg border border-border p-4 text-center">
            <p className="text-2xl font-bold text-text-primary">{data?.pending ?? 0}</p>
            <p className="text-xs text-text-muted">Pending</p>
          </div>
          <div className="rounded-lg border border-border p-4 text-center">
            <p className="text-2xl font-bold text-blue-400">{data?.running ?? 0}</p>
            <p className="text-xs text-text-muted">Running</p>
          </div>
          <div className="rounded-lg border border-border p-4 text-center">
            <p className="text-2xl font-bold text-emerald-400">{data?.completed ?? 0}</p>
            <p className="text-xs text-text-muted">Completed</p>
          </div>
        </div>
      </div>
    </Card>
  )
}

export function AdministrationPage() {
  const [activeTab, setActiveTab] = useState<Tab>('overview')

  const tabContent: Record<Tab, React.ReactNode> = {
    overview: <OverviewTab />,
    users: <UsersTab />,
    agents: <AgentsTab />,
    backups: <BackupsTab />,
    plugins: <PluginsTab />,
    queue: <QueueTab />,
  }

  return (
    <PageContainer>
      <PageHeader
        title="Administration"
        description="User, system and platform management"
        actions={
          <div className="flex items-center gap-2 text-sm text-text-muted">
            <Database className="h-4 w-4" />
            <span>Administration panel</span>
          </div>
        }
      />
      <TabNav active={activeTab} onChange={setActiveTab} />
      {tabContent[activeTab]}
    </PageContainer>
  )
}
