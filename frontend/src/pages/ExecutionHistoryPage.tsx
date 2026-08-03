import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { Badge } from '@/components/ui/Badge'
import { Pagination } from '@/components/ui/Pagination'
import { useExecutions, usePlaybookStats } from '@/hooks/use-playbooks'

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

const statusColors: Record<string, string> = {
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
  rolled_back: 'bg-purple-100 text-purple-800',
  running: 'bg-blue-100 text-blue-800',
  pending: 'bg-yellow-100 text-yellow-800',
  partially_completed: 'bg-orange-100 text-orange-800',
}

export function ExecutionHistoryPage() {
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [page, setPage] = useState(0)
  const limit = 25

  const { data, isLoading } = useExecutions({ status: statusFilter || undefined, limit, offset: page * limit })
  const { data: stats } = usePlaybookStats()

  const executions = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.ceil(total / limit)

  return (
    <PageContainer>
      <PageHeader
        title="Execution History"
        description="Playbook execution logs and results"
      />

      {/* Stats */}
      {stats && (
        <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
          <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-text-primary">{stats.total_executions}</p><p className="text-xs text-text-muted">Total</p></div></Card>
          <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-green-500">{(stats.success_rate * 100).toFixed(0)}%</p><p className="text-xs text-text-muted">Success</p></div></Card>
          <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-text-primary">{stats.average_duration_ms.toFixed(0)}ms</p><p className="text-xs text-text-muted">Avg Time</p></div></Card>
          <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-red-500">{stats.by_status?.failed ?? 0}</p><p className="text-xs text-text-muted">Failed</p></div></Card>
        </div>
      )}

      {/* Status filter */}
      <div className="mb-4 flex flex-wrap gap-2">
        {['', 'completed', 'failed', 'running', 'pending', 'rolled_back', 'partially_completed'].map((s) => (
          <button
            key={s}
            onClick={() => { setStatusFilter(s); setPage(0) }}
            className={`rounded px-3 py-1 text-sm ${statusFilter === s ? 'bg-primary-600 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
          >
            {s === '' ? 'All' : s.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Execution list */}
      {isLoading ? (
        <div className="flex justify-center py-16"><Spinner /></div>
      ) : executions.length === 0 ? (
        <Card><div className="p-8 text-center text-text-muted">No executions found</div></Card>
      ) : (
        <div className="space-y-3">
          {executions.map((ex) => (
            <Card key={ex.id}>
              <div className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold text-text-primary">{ex.playbook_name}</h3>
                    <p className="text-sm text-text-muted">
                      {triggerLabels[ex.trigger_type] ?? ex.trigger_type}
                      {ex.trigger_entity_id ? ` — ${ex.trigger_entity_id}` : ''}
                    </p>
                  </div>
                  <Badge className={statusColors[ex.status] ?? ''}>{ex.status.replace('_', ' ')}</Badge>
                </div>

                <div className="mt-2 flex items-center gap-4 text-xs text-text-muted">
                  <span>{new Date(ex.started_at).toLocaleString()}</span>
                  <span>{ex.duration_ms}ms</span>
                  {ex.rolled_back && <Badge className="bg-purple-100 text-purple-800">Rolled Back</Badge>}
                  {ex.error && <span className="text-red-500">Error: {ex.error}</span>}
                </div>

                {ex.action_logs && ex.action_logs.length > 0 && (
                  <div className="mt-3 space-y-1">
                    {ex.action_logs.map((log, i) => (
                      <div key={i} className="flex items-center justify-between rounded bg-gray-50 px-3 py-1.5 text-xs">
                        <span>{actionLabels[log.action_type] ?? log.action_type}</span>
                        <div className="flex items-center gap-2">
                          <Badge className={log.status === 'completed' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}>{log.status}</Badge>
                          <span className="text-text-muted">{log.duration_ms}ms</span>
                          {log.error && <span className="text-red-500">({log.error})</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="mt-6 flex justify-center">
          <Pagination
            currentPage={page + 1}
            totalPages={totalPages}
            onPageChange={(p) => setPage(p - 1)}
          />
        </div>
      )}
    </PageContainer>
  )
}
