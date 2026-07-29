import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/Tabs'
import { useMonitoringSummary, useMonitoringTrends, useMonitorEvents, useAlerts } from '@/hooks/use-monitoring'

const severityColors: Record<string, string> = {
  critical: 'border-red-500 text-red-500',
  high: 'border-orange-500 text-orange-500',
  medium: 'border-yellow-500 text-yellow-500',
  low: 'border-green-500 text-green-500',
  info: 'border-blue-500 text-blue-500',
}

const statusColors: Record<string, string> = {
  healthy: 'text-emerald-500',
  warning: 'text-yellow-500',
  critical: 'text-red-500',
}

export function SecurityOperationsPage() {
  const nav = useNavigate()
  const [activeTab, setActiveTab] = useState('overview')
  const { data: summary, isLoading } = useMonitoringSummary()
  const { data: trends } = useMonitoringTrends()
  const { data: recentEvents } = useMonitorEvents({ limit: 20 })
  const { data: openAlerts } = useAlerts({ status: 'open', limit: 20 })

  if (isLoading) {
    return (
      <PageContainer>
        <div className="flex justify-center py-12"><Spinner size="lg" /></div>
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <PageHeader
        title="Security Operations"
        description="Continuous monitoring dashboard — live status, changes, and alerts"
      />

      <div className="space-y-6">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader><CardTitle className="text-sm text-text-secondary">Asset Health</CardTitle></CardHeader>
            <div className="px-5 pb-5">
              <p className={`text-2xl font-bold ${statusColors[summary?.asset_health_percentage != null && summary.asset_health_percentage >= 90 ? 'healthy' : summary?.asset_health_percentage != null && summary.asset_health_percentage >= 70 ? 'warning' : 'critical'] || ''}`}>
                {summary?.asset_health_percentage != null ? summary.asset_health_percentage.toFixed(0) : '100'}%
              </p>
              <p className="text-xs text-text-muted">{summary?.assets_monitored ?? 0} assets monitored</p>
            </div>
          </Card>
          <Card>
            <CardHeader><CardTitle className="text-sm text-text-secondary">Open Alerts</CardTitle></CardHeader>
            <div className="px-5 pb-5">
              <p className="text-2xl font-bold">{summary?.total_alerts_open ?? 0}</p>
              <p className="text-xs text-text-muted">
                {summary?.total_alerts_critical ?? 0} critical, {summary?.total_alerts_high ?? 0} high
              </p>
            </div>
          </Card>
          <Card>
            <CardHeader><CardTitle className="text-sm text-text-secondary">Events (24h)</CardTitle></CardHeader>
            <div className="px-5 pb-5">
              <p className="text-2xl font-bold">{summary?.total_events_24h ?? 0}</p>
              <p className="text-xs text-text-muted">{summary?.total_rules_active ?? 0} active rules</p>
            </div>
          </Card>
          <Card>
            <CardHeader><CardTitle className="text-sm text-text-secondary">Certificates Expiring</CardTitle></CardHeader>
            <div className="px-5 pb-5">
              <p className="text-2xl font-bold text-orange-500">{summary?.upcoming_certificate_expirations ?? 0}</p>
              <p className="text-xs text-text-muted">Need attention</p>
            </div>
          </Card>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="events">Recent Events</TabsTrigger>
            <TabsTrigger value="alerts">Open Alerts</TabsTrigger>
            <TabsTrigger value="trends">Trends</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4 pt-4">
            <div className="grid gap-4 lg:grid-cols-2">
              <Card>
                <CardHeader><CardTitle className="text-sm text-text-secondary">Recent Events</CardTitle></CardHeader>
                <div className="space-y-2 px-5 pb-5">
                  {(summary?.recent_events ?? []).length > 0 ? (
                    summary!.recent_events.map((evt) => (
                      <div key={evt.id} className="flex items-center gap-2 text-sm">
                        <Badge variant="neutral" className="text-xs">{evt.event_type.replace(/_/g, ' ')}</Badge>
                        <span className="flex-1 truncate text-text-primary">{evt.title}</span>
                        <span className="text-xs text-text-muted">{evt.timestamp.slice(0, 16).replace('T', ' ')}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-text-muted">No recent events</p>
                  )}
                </div>
              </Card>
              <Card>
                <CardHeader><CardTitle className="text-sm text-text-secondary">Open Alerts</CardTitle></CardHeader>
                <div className="space-y-2 px-5 pb-5">
                  {(summary?.recent_alerts ?? []).length > 0 ? (
                    summary!.recent_alerts.map((alrt) => (
                      <div
                        key={alrt.id}
                        className="flex cursor-pointer items-center gap-2 text-sm hover:text-accent"
                        onClick={() => nav(`/monitoring/alerts/${alrt.id}`)}
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => e.key === 'Enter' && nav(`/monitoring/alerts/${alrt.id}`)}
                      >
                        <Badge variant="neutral" className={`border text-xs ${severityColors[alrt.severity] || ''}`}>
                          {alrt.severity}
                        </Badge>
                        <span className="flex-1 truncate text-text-primary">{alrt.title}</span>
                        <span className="text-xs text-text-muted">{alrt.created_at.slice(0, 16).replace('T', ' ')}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-text-muted">No open alerts</p>
                  )}
                </div>
              </Card>
            </div>

            {trends && (
              <Card>
                <CardHeader><CardTitle className="text-sm text-text-secondary">Activity (30 days)</CardTitle></CardHeader>
                <div className="overflow-x-auto px-5 pb-5">
                  <div className="flex gap-1" style={{ minWidth: `${Math.max(trends.events.length * 20, 200)}px` }}>
                    {trends.events.slice(-30).map((t) => (
                      <div key={t.date} className="flex flex-col items-center gap-1">
                        <div className="flex items-end gap-0.5" style={{ height: '60px' }}>
                          <div
                            className="w-2 rounded-t bg-accent/60"
                            style={{ height: `${Math.min((t.count / Math.max(...trends.events.map((x) => x.count), 1)) * 60, 60)}px` }}
                            title={`${t.date}: ${t.count} events`}
                          />
                          <div
                            className="w-2 rounded-t bg-red-500/60"
                            style={{ height: `${Math.min((trends.alerts.find((a) => a.date === t.date)?.count ?? 0) / Math.max(...trends.alerts.map((x) => x.count), 1) * 60, 60)}px` }}
                            title={`${t.date}: ${trends.alerts.find((a) => a.date === t.date)?.count ?? 0} alerts`}
                          />
                        </div>
                        <span className="text-[10px] text-text-muted">{t.date.slice(5)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="events" className="space-y-4 pt-4">
            {(recentEvents?.items ?? []).length > 0 ? (
              <div className="space-y-2">
                {recentEvents!.items.map((evt) => (
                  <Card key={evt.id}>
                    <div className="flex items-center gap-3 px-5 py-3">
                      <Badge variant="neutral" className={`border text-xs ${severityColors[evt.severity] || ''}`}>
                        {evt.severity}
                      </Badge>
                      <Badge variant="neutral" className="text-xs">{evt.event_type.replace(/_/g, ' ')}</Badge>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm text-text-primary">{evt.title}</p>
                        <p className="text-xs text-text-muted">{evt.source}{evt.asset_id ? ` · ${evt.asset_id}` : ''}</p>
                      </div>
                      <span className="text-xs text-text-muted">{evt.timestamp.slice(0, 16).replace('T', ' ')}</span>
                    </div>
                  </Card>
                ))}
              </div>
            ) : (
              <p className="text-sm text-text-muted">No events recorded</p>
            )}
          </TabsContent>

          <TabsContent value="alerts" className="space-y-4 pt-4">
            {(openAlerts?.items ?? []).length > 0 ? (
              <div className="space-y-2">
                {openAlerts!.items.map((alrt) => (
                  <div
                    key={alrt.id}
                    className="cursor-pointer rounded-lg border border-border bg-surface-primary px-5 py-3 transition-shadow hover:shadow-md"
                    onClick={() => nav(`/monitoring/alerts/${alrt.id}`)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => e.key === 'Enter' && nav(`/monitoring/alerts/${alrt.id}`)}
                  >
                    <div className="flex items-center gap-3">
                      <Badge variant="neutral" className={`border ${severityColors[alrt.severity] || ''}`}>
                        {alrt.severity}
                      </Badge>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium text-text-primary">{alrt.title}</p>
                        <p className="text-xs text-text-muted">{alrt.rule_id.slice(0, 12)}...</p>
                      </div>
                      <span className="text-xs text-text-muted">{alrt.created_at.slice(0, 16).replace('T', ' ')}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-text-muted">No open alerts</p>
            )}
          </TabsContent>

          <TabsContent value="trends" className="space-y-4 pt-4">
            {trends ? (
              <div className="grid gap-4 lg:grid-cols-2">
                <Card>
                  <CardHeader><CardTitle className="text-sm text-text-secondary">Exposure Trend</CardTitle></CardHeader>
                  <div className="px-5 pb-5 text-sm text-text-muted">
                    {trends.exposures.length > 0 ? (
                      <p>Total exposures tracked: {trends.exposures[trends.exposures.length - 1]?.total ?? 0}</p>
                    ) : (
                      <p>No exposure data</p>
                    )}
                  </div>
                </Card>
                <Card>
                  <CardHeader><CardTitle className="text-sm text-text-secondary">Risk Trend</CardTitle></CardHeader>
                  <div className="px-5 pb-5 text-sm text-text-muted">
                    {trends.risk.length > 0 ? (
                      <p>Current average risk: {trends.risk[trends.risk.length - 1]?.average_risk ?? 0}</p>
                    ) : (
                      <p>No risk data</p>
                    )}
                  </div>
                </Card>
              </div>
            ) : (
              <p className="text-sm text-text-muted">Loading trends...</p>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </PageContainer>
  )
}
