import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  useBackups,
  useCreateBackup,
  useDeleteBackup,
  useCleanupExpired,
  useSchedules,
  useCreateSchedule,
  useDeleteSchedule,
  useRecoveryPlans,
  useCreateRecoveryPlan,
  useDeleteRecoveryPlan,
  useTestRecovery,
  useBackupHealth,
  useSnapshots,
  useCreateSnapshot,
} from '@/hooks/use-backup'
import { Button } from '@/components/ui/Button'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'

export function BackupCenterPage() {
  const { data: backups, isLoading: loadingBackups } = useBackups()
  const { data: schedules } = useSchedules()
  const { data: plans } = useRecoveryPlans()
  const { data: health } = useBackupHealth()
  const { data: snapshots } = useSnapshots()
  const createBackup = useCreateBackup()
  const deleteBackup = useDeleteBackup()
  const cleanup = useCleanupExpired()
  const createSchedule = useCreateSchedule()
  const deleteSchedule = useDeleteSchedule()
  const createPlan = useCreateRecoveryPlan()
  const deletePlan = useDeleteRecoveryPlan()
  const testRecovery = useTestRecovery()
  const createSnapshot = useCreateSnapshot()
  const navigate = useNavigate()
  const [tab, setTab] = useState<'backups' | 'schedules' | 'recovery' | 'health'>('backups')
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ backup_type: 'full', includes: '' })
  const [schedForm, setSchedForm] = useState({ name: '', frequency: 'daily', backup_type: 'full' })
  const [planForm, setPlanForm] = useState({ name: '', description: '', estimated_downtime_minutes: 60 })

  const backupList = useMemo(() => backups?.backups ?? [], [backups?.backups])
  const scheduleList = useMemo(() => schedules?.schedules ?? [], [schedules?.schedules])
  const planList = useMemo(() => plans?.plans ?? [], [plans?.plans])

  const handleCreateBackup = async () => {
    const includes = form.includes ? form.includes.split(',').map(s => s.trim()) : undefined
    await createBackup.mutateAsync({ backup_type: form.backup_type, includes })
    setShowCreate(false)
    setForm({ backup_type: 'full', includes: '' })
  }

  const handleCreateSchedule = async () => {
    await createSchedule.mutateAsync(schedForm as any)
    setSchedForm({ name: '', frequency: 'daily', backup_type: 'full' })
  }

  const handleCreatePlan = async () => {
    await createPlan.mutateAsync(planForm as any)
    setPlanForm({ name: '', description: '', estimated_downtime_minutes: 60 })
  }

  const statusColor = (s: string) => {
    switch (s) {
      case 'completed': return 'success'
      case 'running': return 'warning'
      case 'failed': return 'critical'
      case 'pending': return 'neutral'
      default: return 'neutral'
    }
  }

  const healthColor = (h: string) => {
    switch (h) {
      case 'healthy': return 'success'
      case 'degraded': return 'warning'
      case 'unhealthy': return 'critical'
      default: return 'neutral'
    }
  }

  const tabs = [
    { key: 'backups', label: 'Backups' },
    { key: 'schedules', label: 'Schedules' },
    { key: 'recovery', label: 'Recovery' },
    { key: 'health', label: 'Health' },
  ] as const

  if (loadingBackups) return <div className="flex justify-center py-12"><Spinner size="lg" /></div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Backup Center</h1>
          <p className="text-sm text-text-muted mt-1">
            {backups?.total ?? 0} backups &middot; {schedules?.total ?? 0} schedules &middot; {plans?.total ?? 0} DR plans
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={() => cleanup.mutateAsync()}>Cleanup Expired</Button>
          <Button onClick={() => setShowCreate(!showCreate)}>{showCreate ? 'Cancel' : 'New Backup'}</Button>
        </div>
      </div>

      <div className="flex gap-1 border-b border-border">
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              tab === t.key ? 'border-b-2 border-accent text-accent' : 'text-text-muted hover:text-text-primary'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {showCreate && (
        <Card className="p-4 space-y-3">
          <h3 className="font-medium">Create Backup</h3>
          <div className="grid grid-cols-2 gap-3">
            <select className="input" value={form.backup_type} onChange={e => setForm({ ...form, backup_type: e.target.value })}>
              <option value="full">Full</option>
              <option value="incremental">Incremental</option>
              <option value="differential">Differential</option>
            </select>
            <input className="input" placeholder="Includes (comma-separated)" value={form.includes} onChange={e => setForm({ ...form, includes: e.target.value })} />
          </div>
          <Button onClick={handleCreateBackup} disabled={createBackup.isPending}>
            {createBackup.isPending ? 'Creating...' : 'Create Backup'}
          </Button>
        </Card>
      )}

      {tab === 'backups' && (
        <div className="grid gap-4">
          {backupList.map(b => (
            <Card key={b.backup_id} className="p-4 cursor-pointer hover:border-accent/50 transition-colors" onClick={() => navigate(`/backup/${b.backup_id}`)}>
              <div className="flex items-start justify-between">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-text-primary">{b.backup_id}</span>
                    <Badge variant={statusColor(b.status)}>{b.status}</Badge>
                    <Badge variant="info">{b.backup_type}</Badge>
                  </div>
                  <div className="text-sm text-text-muted">
                    {b.size_bytes > 0 ? `${(b.size_bytes / 1024).toFixed(1)} KB` : 'Pending'}
                    {b.encrypted && ' &middot; Encrypted'}
                    {b.compressed && ' &middot; Compressed'}
                  </div>
                  <div className="text-xs text-text-muted">{new Date(b.created_at).toLocaleString()}</div>
                </div>
                <Button variant="ghost" size="sm" className="text-red-400" onClick={e => { e.stopPropagation(); deleteBackup.mutate(b.backup_id) }}>
                  Delete
                </Button>
              </div>
            </Card>
          ))}
          {backupList.length === 0 && (
            <Card className="p-8 text-center text-text-muted">No backups yet. Click "New Backup" to create one.</Card>
          )}
        </div>
      )}

      {tab === 'schedules' && (
        <div className="space-y-4">
          <Card className="p-4 space-y-3">
            <h3 className="font-medium">Create Schedule</h3>
            <div className="grid grid-cols-3 gap-3">
              <input className="input" placeholder="Name" value={schedForm.name} onChange={e => setSchedForm({ ...schedForm, name: e.target.value })} />
              <select className="input" value={schedForm.frequency} onChange={e => setSchedForm({ ...schedForm, frequency: e.target.value })}>
                <option value="manual">Manual</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
                <option value="cron">Cron</option>
              </select>
              <select className="input" value={schedForm.backup_type} onChange={e => setSchedForm({ ...schedForm, backup_type: e.target.value })}>
                <option value="full">Full</option>
                <option value="incremental">Incremental</option>
              </select>
            </div>
            <Button onClick={handleCreateSchedule} disabled={!schedForm.name}>Create</Button>
          </Card>
          <div className="grid gap-4">
            {scheduleList.map(s => (
              <Card key={s.schedule_id} className="p-4">
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-text-primary">{s.name}</span>
                      <Badge variant={s.enabled ? 'success' : 'neutral'}>{s.enabled ? 'Enabled' : 'Disabled'}</Badge>
                      <Badge variant="info">{s.frequency}</Badge>
                    </div>
                    <div className="text-sm text-text-muted">Type: {s.backup_type} &middot; Created: {new Date(s.created_at).toLocaleDateString()}</div>
                  </div>
                  <Button variant="ghost" size="sm" className="text-red-400" onClick={() => deleteSchedule.mutate(s.schedule_id)}>Delete</Button>
                </div>
              </Card>
            ))}
            {scheduleList.length === 0 && <Card className="p-8 text-center text-text-muted">No schedules configured.</Card>}
          </div>
        </div>
      )}

      {tab === 'recovery' && (
        <div className="space-y-4">
          <Card className="p-4 space-y-3">
            <h3 className="font-medium">Create Recovery Plan</h3>
            <div className="grid grid-cols-3 gap-3">
              <input className="input" placeholder="Plan Name" value={planForm.name} onChange={e => setPlanForm({ ...planForm, name: e.target.value })} />
              <input className="input" placeholder="Description" value={planForm.description} onChange={e => setPlanForm({ ...planForm, description: e.target.value })} />
              <input className="input" type="number" placeholder="Est. Downtime (min)" value={planForm.estimated_downtime_minutes} onChange={e => setPlanForm({ ...planForm, estimated_downtime_minutes: parseInt(e.target.value) || 0 })} />
            </div>
            <Button onClick={handleCreatePlan} disabled={!planForm.name}>Create Plan</Button>
          </Card>
          <div className="grid gap-4">
            {planList.map(p => (
              <Card key={p.plan_id} className="p-4">
                <div className="flex items-start justify-between">
                  <div className="space-y-1 cursor-pointer" onClick={() => navigate(`/backup/recovery/${p.plan_id}`)}>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-text-primary">{p.name}</span>
                      <Badge variant={p.status === 'active' ? 'success' : 'neutral'}>{p.status}</Badge>
                    </div>
                    <div className="text-sm text-text-muted">
                      {p.description} &middot; Est. downtime: {p.estimated_downtime_minutes}min &middot; Checklist: {p.checklist_count} items
                    </div>
                    {p.last_tested_at && <div className="text-xs text-text-muted">Last tested: {new Date(p.last_tested_at).toLocaleDateString()}</div>}
                  </div>
                  <div className="flex gap-2">
                    <Button variant="ghost" size="sm" onClick={() => testRecovery.mutate(p.plan_id)}>Test</Button>
                    <Button variant="ghost" size="sm" className="text-red-400" onClick={() => deletePlan.mutate(p.plan_id)}>Delete</Button>
                  </div>
                </div>
              </Card>
            ))}
            {planList.length === 0 && <Card className="p-8 text-center text-text-muted">No recovery plans configured.</Card>}
          </div>
        </div>
      )}

      {tab === 'health' && health && (
        <div className="grid gap-4">
          <Card className="p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-medium">System Health</h3>
              <Badge variant={healthColor(health.overall)}>{health.overall}</Badge>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex items-center gap-2">
                <div className={`h-3 w-3 rounded-full ${health.database_healthy ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-sm">Database</span>
              </div>
              <div className="flex items-center gap-2">
                <div className={`h-3 w-3 rounded-full ${health.storage_healthy ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-sm">Storage</span>
              </div>
              <div className="flex items-center gap-2">
                <div className={`h-3 w-3 rounded-full ${health.workers_healthy ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-sm">Workers</span>
              </div>
              <div className="flex items-center gap-2">
                <div className={`h-3 w-3 rounded-full ${health.backup_service_healthy ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-sm">Backup Service</span>
              </div>
            </div>
            <div className="text-xs text-text-muted">Generated: {new Date(health.generated_at).toLocaleString()}</div>
          </Card>
          {health.components.map(c => (
            <Card key={c.component} className="p-4">
              <div className="flex items-center justify-between">
                <span className="font-medium">{c.component}</span>
                <Badge variant={healthColor(c.health)}>{c.health}</Badge>
              </div>
              <p className="text-sm text-text-muted mt-1">{c.message}</p>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
