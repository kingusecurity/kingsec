import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { useAlerts, useAcknowledgeAlert, useResolveAlert, useDismissAlert } from '@/hooks/use-monitoring'
import type { AlertItem } from '@/api/monitoring'

const severityColors: Record<string, string> = {
  critical: 'border-red-500 text-red-500',
  high: 'border-orange-500 text-orange-500',
  medium: 'border-yellow-500 text-yellow-500',
  low: 'border-green-500 text-green-500',
  info: 'border-blue-500 text-blue-500',
}

export function AlertsPage() {
  const nav = useNavigate()
  const [sevFilter, setSevFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const acknowledge = useAcknowledgeAlert()
  const resolve = useResolveAlert()
  const dismiss = useDismissAlert()

  const params: Record<string, unknown> = {}
  if (sevFilter) params.severity = sevFilter
  if (statusFilter) params.status = statusFilter

  const { data, isLoading } = useAlerts(params)
  const alerts = data?.items ?? []

  return (
    <PageContainer>
      <PageHeader
        title="Alerts"
        description="Monitor security alerts triggered by monitoring rules"
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <select
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value)}
          className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
          <option value="dismissed">Dismissed</option>
        </select>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8"><Spinner /></div>
      ) : alerts.length > 0 ? (
        <div className="space-y-2">
          {alerts.map((alrt) => (
            <AlertCard
              key={alrt.id}
              alert={alrt}
              onAcknowledge={() => acknowledge.mutate(alrt.id)}
              onResolve={() => resolve.mutate(alrt.id)}
              onDismiss={() => dismiss.mutate(alrt.id)}
              onView={() => nav(`/monitoring/alerts/${alrt.id}`)}
            />
          ))}
        </div>
      ) : (
        <div className="py-12 text-center text-text-muted">
          <p className="text-lg font-medium">No alerts found</p>
          <p className="mt-1 text-sm">Alerts are created when monitoring rules trigger on detected events.</p>
        </div>
      )}
    </PageContainer>
  )
}

function AlertCard({
  alert,
  onAcknowledge,
  onResolve,
  onDismiss,
  onView,
}: {
  alert: AlertItem
  onAcknowledge: () => void
  onResolve: () => void
  onDismiss: () => void
  onView: () => void
}) {
  return (
    <Card>
      <div className="flex items-start gap-3 px-5 py-3">
        <Badge variant="neutral" className={`border shrink-0 ${severityColors[alert.severity] || ''}`}>
          {alert.severity}
        </Badge>
        <Badge variant="neutral" className="shrink-0 text-xs">{alert.status}</Badge>
        <div className="min-w-0 flex-1">
          <p
            className="cursor-pointer text-sm font-medium text-text-primary hover:text-accent"
            onClick={onView}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && onView()}
          >
            {alert.title}
          </p>
          <p className="mt-0.5 text-xs text-text-muted">
            {alert.rule_id.slice(0, 12)}...{alert.asset_id ? ` · ${alert.asset_id}` : ''}
            <span className="ml-2">{alert.created_at.slice(0, 16).replace('T', ' ')}</span>
          </p>
        </div>
        <div className="flex shrink-0 gap-1">
          {alert.status === 'open' && (
            <Button onClick={onAcknowledge} variant="outline" className="text-xs" size="sm">Acknowledge</Button>
          )}
          {alert.status !== 'resolved' && alert.status !== 'dismissed' && (
            <>
              <Button onClick={onResolve} variant="outline" className="text-xs" size="sm">Resolve</Button>
              <Button onClick={onDismiss} variant="outline" className="text-xs" size="sm">Dismiss</Button>
            </>
          )}
        </div>
      </div>
    </Card>
  )
}
