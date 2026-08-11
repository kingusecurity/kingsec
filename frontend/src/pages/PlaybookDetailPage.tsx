import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import {
  usePlaybook,
  useEnablePlaybook,
  useDisablePlaybook,
  useExecutePlaybook,
  useExecutions,
  useUpdatePlaybook,
} from '@/hooks/use-playbooks'
import type { Playbook } from '@/api/playbooks'

const SEVERITIES = ['critical', 'high', 'medium', 'low']

interface PlaybookFormState {
  name: string
  description: string
  category: string
  severity: string
  tags: string
}

function playbookToForm(pb: Playbook): PlaybookFormState {
  return {
    name: pb.name,
    description: pb.description,
    category: pb.category,
    severity: pb.severity,
    tags: pb.tags.join(', '),
  }
}

const triggerLabels: Record<string, string> = {
  critical_finding: 'Critical Finding',
  new_cve: 'New CVE',
  kev_detected: 'KEV Detected',
  attack_surface_exposure: 'Attack Surface Exposure',
  high_risk_asset: 'High Risk Asset',
  monitoring_alert: 'Monitoring Alert',
  assessment_completed: 'Assessment Completed',
  manual: 'Manual',
}

const actionLabels: Record<string, string> = {
  generate_report: 'Generate Report',
  notify_slack: 'Notify Slack',
  notify_teams: 'Notify Teams',
  send_email: 'Send Email',
  create_jira_ticket: 'Create Jira Ticket',
  create_github_issue: 'Create GitHub Issue',
  run_assessment: 'Run Assessment',
  run_ai_copilot_summary: 'Run AI Copilot Summary',
  export_siem_event: 'Export SIEM Event',
  create_investigation_note: 'Create Investigation Note',
  mark_asset_critical: 'Mark Asset Critical',
  change_alert_status: 'Change Alert Status',
  custom_webhook: 'Custom Webhook',
}

export function PlaybookDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: pb, isLoading } = usePlaybook(id)
  const { data: execs } = useExecutions()
  const enablePb = useEnablePlaybook()
  const disablePb = useDisablePlaybook()
  const executePb = useExecutePlaybook()
  const updatePb = useUpdatePlaybook()
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState<PlaybookFormState | null>(null)

  if (isLoading) return <div className="flex justify-center py-16"><Spinner /></div>
  if (!pb) return <div className="flex justify-center py-16 text-text-muted">Playbook not found</div>

  const executions = execs?.items?.filter(e => e.playbook_id === pb.id) ?? []

  const openEdit = () => {
    setForm(playbookToForm(pb))
    setEditing(true)
  }

  const closeEdit = () => {
    setEditing(false)
    setForm(null)
  }

  const handleSave = async () => {
    if (!form) return
    await updatePb.mutateAsync({
      id: pb.id,
      data: {
        name: form.name,
        description: form.description,
        category: form.category,
        severity: form.severity,
        tags: form.tags.split(',').map((t) => t.trim()).filter(Boolean),
      },
    })
    closeEdit()
  }

  return (
    <PageContainer>
      <PageHeader
        title={pb.name}
        description={pb.description || 'No description'}
        actions={
          <div className="flex gap-2">
            <Button onClick={editing ? closeEdit : openEdit} variant="outline">{editing ? 'Cancel' : 'Edit'}</Button>
            {pb.enabled ? (
              <Button onClick={() => disablePb.mutate(pb.id)} variant="outline">Disable</Button>
            ) : (
              <Button onClick={() => enablePb.mutate(pb.id)} variant="outline">Enable</Button>
            )}
            <Button onClick={() => executePb.mutate({ id: pb.id })}>Run Now</Button>
          </div>
        }
      />

      {editing && form && (
        <Card className="mb-6 p-4 space-y-3">
          <h3 className="text-sm font-semibold text-text-primary">Edit Playbook</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <Input placeholder="Name *" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <Input placeholder="Category" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} />
            <select
              value={form.severity}
              onChange={(e) => setForm({ ...form, severity: e.target.value })}
              className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <Input placeholder="Tags (comma-separated)" value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />
          </div>
          <Input placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <p className="text-xs text-text-muted">
            Trigger and actions aren&apos;t editable here yet - only name, description, category, severity, and tags.
          </p>
          <Button onClick={handleSave} disabled={!form.name || updatePb.isPending}>
            {updatePb.isPending ? 'Saving...' : 'Save Changes'}
          </Button>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Details */}
        <Card className="lg:col-span-2">
          <div className="p-4">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Details</h3>
            <dl className="space-y-2 text-sm">
              <div className="flex items-start justify-between gap-4"><dt className="shrink-0 text-text-muted">Category</dt><dd className="break-words text-right">{pb.category}</dd></div>
              <div className="flex items-start justify-between gap-4"><dt className="shrink-0 text-text-muted">Severity</dt><dd><Badge className={pb.severity === 'critical' ? 'bg-red-100 text-red-800' : pb.severity === 'high' ? 'bg-orange-100 text-orange-800' : 'bg-yellow-100 text-yellow-800'}>{pb.severity}</Badge></dd></div>
              <div className="flex items-start justify-between gap-4"><dt className="shrink-0 text-text-muted">Status</dt><dd>{pb.enabled ? <Badge className="bg-green-100 text-green-800">Enabled</Badge> : <Badge className="bg-gray-100 text-gray-600">Disabled</Badge>}</dd></div>
              <div className="flex items-start justify-between gap-4"><dt className="shrink-0 text-text-muted">Trigger</dt><dd className="break-words text-right">{triggerLabels[pb.trigger?.trigger_type] ?? pb.trigger?.trigger_type}</dd></div>
              {pb.tags?.length > 0 && (
                <div className="flex items-start justify-between gap-4"><dt className="shrink-0 text-text-muted">Tags</dt><dd className="break-words text-right">{pb.tags.join(', ')}</dd></div>
              )}
            </dl>
          </div>
        </Card>

        {/* Actions */}
        <Card>
          <div className="p-4">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Actions ({pb.actions?.length ?? 0})</h3>
            <div className="space-y-2">
              {pb.actions?.map((a, i) => (
                <div key={i} className="rounded bg-gray-50 p-2 text-sm">
                  <p className="font-medium">{actionLabels[a.action_type] ?? a.action_type}</p>
                  {a.continue_on_failure && <p className="text-xs text-text-muted">Continue on failure</p>}
                  {a.retry_count > 0 && <p className="text-xs text-text-muted">Retries: {a.retry_count}</p>}
                </div>
              ))}
              {(!pb.actions || pb.actions.length === 0) && <p className="text-xs text-text-muted">No actions</p>}
            </div>
            {pb.rollback_actions?.length > 0 && (
              <>
                <h4 className="mt-3 mb-2 text-xs font-semibold text-text-muted">Rollback Actions</h4>
                <div className="space-y-1">
                  {pb.rollback_actions.map((a, i) => (
                    <div key={i} className="rounded bg-red-50 p-2 text-sm">
                      <p className="font-medium">{actionLabels[a.action_type] ?? a.action_type}</p>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </Card>
      </div>

      {/* Execution History */}
      <Card className="mt-6">
        <div className="p-4">
          <h3 className="mb-3 text-sm font-semibold text-text-primary">Execution History</h3>
          {executions.length === 0 ? (
            <p className="text-sm text-text-muted">No executions yet</p>
          ) : (
            <div className="space-y-2">
              {executions.map((ex) => (
                <div key={ex.id} className="flex items-center justify-between rounded bg-gray-50 p-3 text-sm">
                  <div>
                    <p className="font-medium">{ex.trigger_type} {ex.trigger_entity_id ? `(${ex.trigger_entity_id})` : ''}</p>
                    <p className="text-xs text-text-muted">{new Date(ex.started_at).toLocaleString()} &middot; {ex.duration_ms}ms</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={
                      ex.status === 'completed' ? 'bg-green-100 text-green-800' :
                      ex.status === 'failed' ? 'bg-red-100 text-red-800' :
                      ex.status === 'rolled_back' ? 'bg-purple-100 text-purple-800' :
                      'bg-yellow-100 text-yellow-800'
                    }>{ex.status}</Badge>
                    {ex.rolled_back && <Badge className="bg-purple-100 text-purple-800">Rolled Back</Badge>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </Card>

      {/* Execution Logs detail */}
      {executions.filter(e => e.action_logs?.length > 0).length > 0 && (
        <Card className="mt-6">
          <div className="p-4">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Recent Action Logs</h3>
            {executions.slice(0, 3).map((ex) => (
              <div key={ex.id} className="mb-4">
                <p className="mb-1 text-xs font-medium text-text-muted">{new Date(ex.started_at).toLocaleString()} - {ex.status}</p>
                <div className="space-y-1">
                  {ex.action_logs.map((log, i) => (
                    <div key={i} className="flex items-center justify-between rounded bg-gray-50 px-3 py-1.5 text-xs">
                      <span>{actionLabels[log.action_type] ?? log.action_type}</span>
                      <div className="flex items-center gap-2">
                        <Badge className={log.status === 'completed' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}>{log.status}</Badge>
                        <span className="text-text-muted">{log.duration_ms}ms</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </PageContainer>
  )
}
