import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/Tabs'
import { useMonitorEvents, useAlerts } from '@/hooks/use-monitoring'

const severityColors: Record<string, string> = {
  critical: 'border-red-500 text-red-500',
  high: 'border-orange-500 text-orange-500',
  medium: 'border-yellow-500 text-yellow-500',
  low: 'border-green-500 text-green-500',
  info: 'border-blue-500 text-blue-500',
}

export function MonitoringTimelinePage() {
  const nav = useNavigate()
  const [activeTab, setActiveTab] = useState('events')
  const [limit] = useState(100)
  const { data: events, isLoading: eventsLoading } = useMonitorEvents({ limit })
  const { data: alerts, isLoading: alertsLoading } = useAlerts({ limit })

  return (
    <PageContainer>
      <PageHeader
        title="Monitoring Timeline"
        description="Chronological view of all monitoring events and alerts"
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="events">Events</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
        </TabsList>

        <TabsContent value="events" className="pt-4">
          {eventsLoading ? (
            <div className="flex justify-center py-8"><Spinner /></div>
          ) : (events?.items ?? []).length > 0 ? (
            <div className="space-y-2">
              {events!.items.map((evt) => (
                <Card key={evt.id}>
                  <div className="flex items-start gap-3 px-5 py-3">
                    <div className="mt-1 h-2 w-2 shrink-0 rounded-full bg-accent" />
                    <Badge variant="neutral" className={`border text-xs ${severityColors[evt.severity] || ''}`}>
                      {evt.severity}
                    </Badge>
                    <Badge variant="neutral" className="text-xs">{evt.event_type.replace(/_/g, ' ')}</Badge>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-text-primary">{evt.title}</p>
                      <p className="text-xs text-text-muted">
                        {evt.source}{evt.asset_id ? ` · ${evt.asset_id}` : ''}
                        {evt.context.filter((c) => c.previous_value).map((c) => ` · ${c.key}: ${c.previous_value} -> ${c.value}`)}
                      </p>
                    </div>
                    <span className="shrink-0 text-xs text-text-muted">{evt.timestamp.slice(0, 19).replace('T', ' ')}</span>
                  </div>
                </Card>
              ))}
            </div>
          ) : (
            <p className="text-sm text-text-muted">No events recorded</p>
          )}
        </TabsContent>

        <TabsContent value="alerts" className="pt-4">
          {alertsLoading ? (
            <div className="flex justify-center py-8"><Spinner /></div>
          ) : (alerts?.items ?? []).length > 0 ? (
            <div className="space-y-2">
              {alerts!.items.map((alrt) => (
                <div
                  key={alrt.id}
                  className="cursor-pointer rounded-lg border border-border bg-surface-primary px-5 py-3 transition-shadow hover:shadow-md"
                  onClick={() => nav(`/monitoring/alerts/${alrt.id}`)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => e.key === 'Enter' && nav(`/monitoring/alerts/${alrt.id}`)}
                >
                  <div className="flex items-start gap-3">
                    <div className={`mt-1 h-2 w-2 shrink-0 rounded-full ${alrt.severity === 'critical' ? 'bg-red-500' : alrt.severity === 'high' ? 'bg-orange-500' : 'bg-yellow-500'}`} />
                    <Badge variant="neutral" className={`border text-xs ${severityColors[alrt.severity] || ''}`}>
                      {alrt.severity}
                    </Badge>
                    <Badge variant="neutral" className="text-xs">{alrt.status}</Badge>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-text-primary">{alrt.title}</p>
                      <p className="text-xs text-text-muted">{alrt.description || 'No description'}</p>
                    </div>
                    <span className="shrink-0 text-xs text-text-muted">{alrt.created_at.slice(0, 19).replace('T', ' ')}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-text-muted">No alerts recorded</p>
          )}
        </TabsContent>
      </Tabs>
    </PageContainer>
  )
}
