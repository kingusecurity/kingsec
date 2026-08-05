import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { useRules, useEnableRule, useDisableRule, useDeleteRule, useSeedRules, useCreateRule, useUpdateRule } from '@/hooks/use-monitoring'
import type { RuleItem } from '@/api/monitoring'

const EVENT_TYPES = [
  'new_host', 'host_disappeared', 'new_open_port', 'closed_port',
  'service_version_changed', 'technology_changed', 'certificate_expires_soon',
  'certificate_renewed', 'tls_downgraded', 'new_critical_finding',
  'finding_resolved', 'compliance_score_changed', 'exposure_score_changed',
  'risk_score_changed', 'asset_created', 'asset_updated',
]

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

const NOTIFY_CHANNELS = ['email', 'slack', 'teams']

interface RuleFormState {
  name: string
  description: string
  event_type: string
  alert_severity: string
  cooldown_minutes: string
  notify_channels: string[]
}

const EMPTY_FORM: RuleFormState = {
  name: '',
  description: '',
  event_type: '',
  alert_severity: 'medium',
  cooldown_minutes: '60',
  notify_channels: [],
}

function ruleToForm(rule: RuleItem): RuleFormState {
  return {
    name: rule.name,
    description: rule.description,
    event_type: rule.event_type ?? '',
    alert_severity: rule.alert_severity,
    cooldown_minutes: String(rule.cooldown_minutes),
    notify_channels: rule.notify_channels,
  }
}

export function MonitoringRulesPage() {
  const [showDisabled, setShowDisabled] = useState(false)
  const { data, isLoading } = useRules({ enabled: showDisabled ? undefined : true })
  const enableRule = useEnableRule()
  const disableRule = useDisableRule()
  const deleteRule = useDeleteRule()
  const seedRules = useSeedRules()
  const createRule = useCreateRule()
  const updateRule = useUpdateRule()

  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState<RuleFormState>(EMPTY_FORM)

  const rules = data?.items ?? []
  const isSaving = createRule.isPending || updateRule.isPending

  const openCreateForm = () => {
    setEditingId(null)
    setForm(EMPTY_FORM)
    setShowForm(true)
  }

  const openEditForm = (rule: RuleItem) => {
    setEditingId(rule.id)
    setForm(ruleToForm(rule))
    setShowForm(true)
  }

  const closeForm = () => {
    setShowForm(false)
    setEditingId(null)
    setForm(EMPTY_FORM)
  }

  const toggleChannel = (channel: string) => {
    setForm((f) => ({
      ...f,
      notify_channels: f.notify_channels.includes(channel)
        ? f.notify_channels.filter((c) => c !== channel)
        : [...f.notify_channels, channel],
    }))
  }

  const handleSubmit = async () => {
    const payload = {
      name: form.name,
      description: form.description,
      event_type: form.event_type || null,
      alert_severity: form.alert_severity,
      cooldown_minutes: Number(form.cooldown_minutes) || 0,
      notify_channels: form.notify_channels,
    }
    if (editingId) {
      await updateRule.mutateAsync({ id: editingId, data: payload })
    } else {
      await createRule.mutateAsync(payload)
    }
    closeForm()
  }

  return (
    <PageContainer>
      <PageHeader
        title="Monitoring Rules"
        description="Rules that evaluate monitoring events and trigger alerts"
        actions={
          <Button onClick={showForm ? closeForm : openCreateForm} variant={showForm ? 'outline' : 'primary'}>
            {showForm ? 'Cancel' : 'Create Rule'}
          </Button>
        }
      />

      {showForm && (
        <Card className="mb-4 p-4 space-y-3">
          <h3 className="font-medium text-text-primary">{editingId ? 'Edit Rule' : 'Create Rule'}</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <Input placeholder="Rule name *" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <Input placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            <select
              value={form.event_type}
              onChange={(e) => setForm({ ...form, event_type: e.target.value })}
              className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            >
              <option value="">Any event type</option>
              {EVENT_TYPES.map((t) => (
                <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
              ))}
            </select>
            <select
              value={form.alert_severity}
              onChange={(e) => setForm({ ...form, alert_severity: e.target.value })}
              className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <Input
              type="number"
              min={0}
              placeholder="Cooldown (minutes)"
              value={form.cooldown_minutes}
              onChange={(e) => setForm({ ...form, cooldown_minutes: e.target.value })}
            />
          </div>
          <div>
            <span className="mb-1 block text-xs text-text-muted">Notify channels</span>
            <div className="flex gap-3">
              {NOTIFY_CHANNELS.map((channel) => (
                <label key={channel} className="flex items-center gap-1.5 text-sm text-text-secondary">
                  <input
                    type="checkbox"
                    checked={form.notify_channels.includes(channel)}
                    onChange={() => toggleChannel(channel)}
                    className="rounded"
                  />
                  {channel}
                </label>
              ))}
            </div>
          </div>
          <Button onClick={handleSubmit} disabled={!form.name || isSaving}>
            {isSaving ? 'Saving...' : editingId ? 'Save Changes' : 'Create Rule'}
          </Button>
        </Card>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-text-muted">
          <input
            type="checkbox"
            checked={showDisabled}
            onChange={(e) => setShowDisabled(e.target.checked)}
            className="rounded"
          />
          Show disabled rules
        </label>
        <Button onClick={() => seedRules.mutate()} variant="outline" className="text-xs">
          Seed Default Rules
        </Button>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8"><Spinner /></div>
      ) : rules.length > 0 ? (
        <div className="space-y-3">
          {rules.map((rule) => (
            <Card key={rule.id}>
              <div className="flex items-start justify-between px-5 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-text-primary">{rule.name}</p>
                    <Badge variant="neutral" className={`text-xs ${rule.enabled ? 'text-emerald-500' : 'text-text-muted'}`}>
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                    {rule.event_type && (
                      <Badge variant="neutral" className="text-xs">{rule.event_type.replace(/_/g, ' ')}</Badge>
                    )}
                  </div>
                  {rule.description && (
                    <p className="mt-1 text-sm text-text-muted">{rule.description}</p>
                  )}
                  <div className="mt-1 flex flex-wrap gap-2 text-xs text-text-muted">
                    <span>Severity: {rule.alert_severity}</span>
                    <span>Cooldown: {rule.cooldown_minutes}m</span>
                    {rule.conditions.length > 0 && (
                      <span>Conditions: {rule.conditions.length}</span>
                    )}
                    {rule.notify_channels.length > 0 && (
                      <span>Notify: {rule.notify_channels.join(', ')}</span>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 gap-1">
                  <Button onClick={() => openEditForm(rule)} variant="outline" className="text-xs" size="sm">
                    Edit
                  </Button>
                  {rule.enabled ? (
                    <Button onClick={() => disableRule.mutate(rule.id)} variant="outline" className="text-xs" size="sm">
                      Disable
                    </Button>
                  ) : (
                    <Button onClick={() => enableRule.mutate(rule.id)} variant="outline" className="text-xs" size="sm">
                      Enable
                    </Button>
                  )}
                  <Button onClick={() => deleteRule.mutate(rule.id)} variant="outline" className="text-xs text-red-500" size="sm">
                    Delete
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      ) : (
        <div className="py-12 text-center text-text-muted">
          <p className="text-lg font-medium">No rules configured</p>
          <p className="mt-1 text-sm">Seed default rules or create custom ones to start monitoring.</p>
          <Button className="mt-4" onClick={() => seedRules.mutate()}>Seed Default Rules</Button>
        </div>
      )}
    </PageContainer>
  )
}
