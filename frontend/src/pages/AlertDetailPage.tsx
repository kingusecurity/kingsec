import { useParams, useNavigate } from 'react-router-dom'
import { PageContainer } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { useAlert, useAcknowledgeAlert, useResolveAlert, useDismissAlert } from '@/hooks/use-monitoring'

const severityColors: Record<string, string> = {
  critical: 'border-red-500 text-red-500',
  high: 'border-orange-500 text-orange-500',
  medium: 'border-yellow-500 text-yellow-500',
  low: 'border-green-500 text-green-500',
  info: 'border-blue-500 text-blue-500',
}

export function AlertDetailPage() {
  const { id } = useParams<{ id: string }>()
  const nav = useNavigate()
  const { data: alert, isLoading } = useAlert(id ?? null)
  const acknowledge = useAcknowledgeAlert()
  const resolve = useResolveAlert()
  const dismiss = useDismissAlert()

  if (isLoading) {
    return (
      <PageContainer>
        <div className="flex justify-center py-12"><Spinner size="lg" /></div>
      </PageContainer>
    )
  }

  if (!alert) {
    return (
      <PageContainer>
        <div className="py-12 text-center">
          <p className="text-lg font-medium">Alert not found</p>
          <Button className="mt-4" onClick={() => nav('/monitoring/alerts')}>Back to Alerts</Button>
        </div>
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <div className="mb-4">
        <button onClick={() => nav('/monitoring/alerts')} className="text-sm text-accent hover:underline">&larr; Back to Alerts</button>
      </div>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">{alert.title}</h1>
            <Badge variant="neutral" className={`border ${severityColors[alert.severity] || ''}`}>
              {alert.severity}
            </Badge>
            <Badge variant="neutral" className="border border-border text-xs">
              {alert.status}
            </Badge>
          </div>
          {alert.description && <p className="mt-1 text-sm text-text-muted">{alert.description}</p>}
        </div>
        <div className="flex gap-2">
          {alert.status === 'open' && (
            <Button onClick={() => acknowledge.mutate(alert.id)}>Acknowledge</Button>
          )}
          {alert.status !== 'resolved' && alert.status !== 'dismissed' && (
            <>
              <Button onClick={() => resolve.mutate(alert.id)} variant="outline">Resolve</Button>
              <Button onClick={() => dismiss.mutate(alert.id)} variant="outline">Dismiss</Button>
            </>
          )}
        </div>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm text-text-secondary">Alert Details</CardTitle></CardHeader>
        <div className="divide-y divide-border px-5 pb-5">
          {[
            ['Alert ID', alert.id],
            ['Rule ID', alert.rule_id],
            ['Severity', alert.severity],
            ['Status', alert.status],
            ['Source Event', alert.source_event_id ?? 'N/A'],
            ['Asset', alert.asset_id ?? 'N/A'],
            ['Assessment', alert.assessment_id ?? 'N/A'],
            ['Created', alert.created_at],
            ['Acknowledged', alert.acknowledged_at ?? 'N/A'],
            ['Acknowledged By', alert.acknowledged_by ?? 'N/A'],
            ['Resolved', alert.resolved_at ?? 'N/A'],
            ['Resolved By', alert.resolved_by ?? 'N/A'],
          ].map(([label, value]) => (
            <div key={label as string} className="flex justify-between py-3 text-sm">
              <span className="text-text-muted">{label as string}</span>
              <span className="text-text-primary">{value as string}</span>
            </div>
          ))}
        </div>
      </Card>
    </PageContainer>
  )
}
