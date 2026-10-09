import { useState } from 'react'
import { PageContainer, PageHeader, ContentSection } from '@/components/layout/PageContainer'
import { Card, CardHeader } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import {
  useSchedules,
  useCreateSchedule,
  useUpdateSchedule,
  useDeleteSchedule,
  useEnableSchedule,
  useDisableSchedule,
  usePauseSchedule,
  useResumeSchedule,
} from '@/hooks/use-schedules'
import type { Schedule, CreateScheduleBody } from '@/api/schedules'
import { CalendarCheck, Clock, Power, PowerOff, PauseCircle } from 'lucide-react'
import { useAuthStore } from '@/store/auth'

const SCHEDULE_TYPES = ['one_time', 'hourly', 'daily', 'weekly', 'monthly', 'cron']

const statusVariant: Record<string, 'success' | 'warning' | 'neutral' | 'info' | 'critical'> = {
  active: 'success',
  paused: 'warning',
  disabled: 'neutral',
  completed: 'info',
  failed: 'critical',
}

interface ScheduleFormState {
  name: string
  description: string
  target: string
  schedule_type: string
  cron_expression: string
  timezone: string
}

const EMPTY_FORM: ScheduleFormState = {
  name: '',
  description: '',
  target: '',
  schedule_type: 'daily',
  cron_expression: '',
  timezone: 'UTC',
}

function scheduleToForm(s: Schedule): ScheduleFormState {
  return {
    name: s.name,
    description: s.description,
    target: s.target,
    schedule_type: s.schedule_type,
    cron_expression: s.cron_expression,
    timezone: s.timezone,
  }
}

export function SchedulesPage() {
  const role = useAuthStore((state) => state.user?.role.toLowerCase())
  const canManage = role === 'analyst' || role === 'admin'
  const { data, isLoading, error, refetch } = useSchedules()
  const createSchedule = useCreateSchedule()
  const updateSchedule = useUpdateSchedule()
  const deleteSchedule = useDeleteSchedule()
  const enableSchedule = useEnableSchedule()
  const disableSchedule = useDisableSchedule()
  const pauseSchedule = usePauseSchedule()
  const resumeSchedule = useResumeSchedule()

  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState<ScheduleFormState>(EMPTY_FORM)

  const isSaving = createSchedule.isPending || updateSchedule.isPending

  const openCreateForm = () => {
    setEditingId(null)
    setForm(EMPTY_FORM)
    setShowForm(true)
  }

  const openEditForm = (schedule: Schedule) => {
    setEditingId(schedule.id)
    setForm(scheduleToForm(schedule))
    setShowForm(true)
  }

  const closeForm = () => {
    setShowForm(false)
    setEditingId(null)
    setForm(EMPTY_FORM)
  }

  const handleSubmit = async () => {
    const payload: CreateScheduleBody = {
      name: form.name,
      description: form.description,
      target: form.target,
      schedule_type: form.schedule_type,
      cron_expression: form.cron_expression,
      timezone: form.timezone,
    }
    if (editingId) {
      await updateSchedule.mutateAsync({ id: editingId, data: payload })
    } else {
      await createSchedule.mutateAsync(payload)
    }
    closeForm()
  }

  const toggleEnabled = (schedule: Schedule) => {
    if (schedule.enabled) {
      disableSchedule.mutate(schedule.id)
    } else {
      enableSchedule.mutate(schedule.id)
    }
  }

  const togglePaused = (schedule: Schedule) => {
    if (schedule.paused) {
      resumeSchedule.mutate(schedule.id)
    } else {
      pauseSchedule.mutate(schedule.id)
    }
  }

  if (error) {
    return (
      <PageContainer>
        <PageHeader title="Schedules" />
        <ErrorState title="Failed to load schedules" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  const schedules = data?.items ?? []

  return (
    <PageContainer>
      <PageHeader
        title="Schedules"
        description="Scheduled security assessments"
        actions={canManage ? (
          <Button onClick={showForm ? closeForm : openCreateForm} variant={showForm ? 'outline' : 'primary'}>
            {showForm ? 'Cancel' : 'Create Schedule'}
          </Button>
        ) : undefined}
      />

      {canManage && showForm && (
        <Card className="p-4 space-y-3">
          <h3 className="font-medium text-text-primary">{editingId ? 'Edit Schedule' : 'Create Schedule'}</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <Input placeholder="Name *" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <Input placeholder="Target *" value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} />
            <select
              value={form.schedule_type}
              onChange={(e) => setForm({ ...form, schedule_type: e.target.value })}
              className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            >
              {SCHEDULE_TYPES.map((t) => (
                <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
              ))}
            </select>
            <Input placeholder="Timezone" value={form.timezone} onChange={(e) => setForm({ ...form, timezone: e.target.value })} />
            {form.schedule_type === 'cron' && (
              <Input placeholder="Cron expression *" value={form.cron_expression} onChange={(e) => setForm({ ...form, cron_expression: e.target.value })} />
            )}
          </div>
          <Input placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <Button
            onClick={handleSubmit}
            disabled={!form.name || !form.target || (form.schedule_type === 'cron' && !form.cron_expression) || isSaving}
          >
            {isSaving ? 'Saving...' : editingId ? 'Save Changes' : 'Create Schedule'}
          </Button>
        </Card>
      )}

      {isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <CardHeader>
                <Skeleton className="h-5 w-32" />
                <Skeleton className="h-4 w-24" />
              </CardHeader>
            </Card>
          ))}
        </div>
      ) : schedules.length > 0 ? (
        <ContentSection title="Active Schedules">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {schedules.map((s) => (
              <Card key={s.id}>
                <div className="p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CalendarCheck className="h-5 w-5 text-accent" />
                      <h3 className="text-sm font-semibold text-text-primary">{s.name || 'Unnamed'}</h3>
                    </div>
                    {canManage ? (
                      <button
                        onClick={() => toggleEnabled(s)}
                        disabled={enableSchedule.isPending || disableSchedule.isPending}
                        aria-label={s.enabled ? `Disable ${s.name}` : `Enable ${s.name}`}
                        title={s.enabled ? 'Disable schedule' : 'Enable schedule'}
                        className="rounded p-1 hover:bg-surface-tertiary disabled:opacity-50"
                      >
                        {s.enabled ? (
                          <Power className="h-4 w-4 text-emerald-400" />
                        ) : (
                          <PowerOff className="h-4 w-4 text-text-muted" />
                        )}
                      </button>
                    ) : (
                      <span title={s.enabled ? 'Enabled' : 'Disabled'} aria-label={s.enabled ? 'Enabled' : 'Disabled'}>
                      {s.enabled ? (
                        <Power className="h-4 w-4 text-emerald-400" />
                      ) : (
                        <PowerOff className="h-4 w-4 text-text-muted" />
                      )}
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-text-secondary">{s.target || 'No target specified'}</p>
                  {s.cron_expression && (
                    <div className="flex items-center gap-2 text-xs text-text-muted">
                      <Clock className="h-3 w-3" />
                      <code className="rounded bg-surface-tertiary px-1.5 py-0.5">{s.cron_expression}</code>
                    </div>
                  )}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs">
                      <PauseCircle className="h-3 w-3 text-text-muted" />
                      <Badge variant={statusVariant[s.status] ?? 'neutral'} size="sm">{s.status}</Badge>
                    </div>
                    {canManage && <div className="flex flex-wrap justify-end gap-1">
                      <Button
                        onClick={() => togglePaused(s)}
                        disabled={pauseSchedule.isPending || resumeSchedule.isPending}
                        variant="outline"
                        size="sm"
                        className="text-xs"
                      >
                        {s.paused ? 'Resume' : 'Pause'}
                      </Button>
                      <Button onClick={() => openEditForm(s)} variant="outline" size="sm" className="text-xs">Edit</Button>
                      <Button onClick={() => deleteSchedule.mutate(s.id)} variant="outline" size="sm" className="text-xs text-red-500">Delete</Button>
                    </div>}
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </ContentSection>
      ) : (
        <Card>
          <EmptyState
            icon={<CalendarCheck className="h-8 w-8" />}
            title="No schedules configured"
            description={canManage
              ? 'Create recurring assessment schedules to automate security scanning.'
              : 'No assessment schedules are available to view.'}
          />
        </Card>
      )}
    </PageContainer>
  )
}
