import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import {
  usePlaybooks,
  useCreatePlaybook,
  useDeletePlaybook,
  useEnablePlaybook,
  useDisablePlaybook,
  usePlaybookStats,
  useExecutePlaybook,
} from '@/hooks/use-playbooks'
import type { Playbook } from '@/api/playbooks'

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-green-100 text-green-800',
}

const triggerLabels: Record<string, string> = {
  critical_finding: 'Critical Finding',
  new_cve: 'New CVE',
  kev_detected: 'KEV Detected',
  attack_surface_exposure: 'Attack Surface',
  high_risk_asset: 'High Risk Asset',
  monitoring_alert: 'Monitoring Alert',
  assessment_completed: 'Assessment Done',
  manual: 'Manual',
}

export function PlaybooksPage() {
  const navigate = useNavigate()
  const { data: pbData, isLoading } = usePlaybooks()
  const { data: stats } = usePlaybookStats()
  const createPb = useCreatePlaybook()
  const deletePb = useDeletePlaybook()
  const enablePb = useEnablePlaybook()
  const disablePb = useDisablePlaybook()
  const executePb = useExecutePlaybook()
  const [filter, setFilter] = useState<string>('all')

  const playbooks: Playbook[] = pbData?.items ?? []
  const filtered = filter === 'all' ? playbooks : filter === 'enabled' ? playbooks.filter(p => p.enabled) : playbooks.filter(p => !p.enabled)

  return (
    <PageContainer>
      <PageHeader
        title="Security Automation"
        description="Playbooks, actions, and automated incident response"
      />

      {/* Stats */}
      {stats && (
        <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
          <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-text-primary">{stats.playbook_count}</p><p className="text-xs text-text-muted">Playbooks</p></div></Card>
          <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-text-primary">{stats.total_executions}</p><p className="text-xs text-text-muted">Executions</p></div></Card>
          <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-green-500">{(stats.success_rate * 100).toFixed(0)}%</p><p className="text-xs text-text-muted">Success Rate</p></div></Card>
          <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-text-primary">{stats.average_duration_ms.toFixed(0)}ms</p><p className="text-xs text-text-muted">Avg Duration</p></div></Card>
        </div>
      )}

      {/* Recent executions */}
      {stats && stats.recent_executions.length > 0 && (
        <Card className="mb-6">
          <div className="p-4">
            <h3 className="mb-2 text-sm font-semibold text-text-primary">Recent Executions</h3>
            <div className="space-y-2">
              {stats.recent_executions.map((ex) => (
                <div key={ex.id} className="flex items-center justify-between text-sm">
                  <span className="text-text-muted">{ex.playbook_name}</span>
                  <div className="flex items-center gap-2">
                    <Badge className={ex.status === 'completed' ? 'bg-green-100 text-green-800' : ex.status === 'failed' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}>
                      {ex.status}
                    </Badge>
                    <span className="text-xs text-text-muted">{ex.duration_ms}ms</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Card>
      )}

      {/* Toolbar */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex gap-2">
          {['all', 'enabled', 'disabled'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded px-3 py-1 text-sm ${filter === f ? 'bg-primary-600 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
            >
              {f === 'all' ? 'All' : f === 'enabled' ? 'Enabled' : 'Disabled'}
            </button>
          ))}
        </div>
        <Button
          onClick={() => {
            const name = prompt('Playbook name:')
            if (name) createPb.mutate({ name }, { onSuccess: (pb) => navigate(`/playbooks/${pb.id}`) })
          }}
        >
          + New Playbook
        </Button>
      </div>

      {/* Playbook list */}
      {isLoading ? (
        <div className="flex justify-center py-16"><Spinner /></div>
      ) : filtered.length === 0 ? (
        <Card><div className="p-8 text-center text-text-muted">No playbooks found. Create one to get started.</div></Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((pb) => (
            <div key={pb.id} className="cursor-pointer rounded-lg bg-white shadow-sm hover:shadow-md" onClick={() => navigate(`/playbooks/${pb.id}`)}>
              <div className="flex items-center justify-between p-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-text-primary">{pb.name}</h3>
                    <Badge className={severityColors[pb.severity] ?? ''}>{pb.severity}</Badge>
                    {pb.enabled ? <Badge className="bg-green-100 text-green-800">Enabled</Badge> : <Badge className="bg-gray-100 text-gray-600">Disabled</Badge>}
                  </div>
                  <p className="mt-1 text-sm text-text-muted">{pb.description || 'No description'}</p>
                  <div className="mt-1 flex items-center gap-3 text-xs text-text-muted">
                    <span>{pb.category}</span>
                    <span>Trigger: {triggerLabels[pb.trigger?.trigger_type] ?? pb.trigger?.trigger_type}</span>
                    <span>{pb.actions?.length ?? 0} actions</span>
                  </div>
                </div>
                <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                  {pb.enabled ? (
                    <button className="rounded bg-yellow-100 px-2 py-1 text-xs text-yellow-700 hover:bg-yellow-200" onClick={() => disablePb.mutate(pb.id)}>Disable</button>
                  ) : (
                    <button className="rounded bg-green-100 px-2 py-1 text-xs text-green-700 hover:bg-green-200" onClick={() => enablePb.mutate(pb.id)}>Enable</button>
                  )}
                  <button className="rounded bg-blue-100 px-2 py-1 text-xs text-blue-700 hover:bg-blue-200" onClick={() => executePb.mutate({ id: pb.id })}>Run</button>
                  <button className="rounded bg-red-100 px-2 py-1 text-xs text-red-700 hover:bg-red-200" onClick={() => { if (confirm('Delete this playbook?')) deletePb.mutate(pb.id) }}>Delete</button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </PageContainer>
  )
}
