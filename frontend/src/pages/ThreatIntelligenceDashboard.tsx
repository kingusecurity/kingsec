import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { Badge } from '@/components/ui/Badge'
import { ErrorState } from '@/components/ui/ErrorState'
import {
  useTISummary,
  useTrendingThreats,
  useCriticalCves,
  useTITrends,
} from '@/hooks/use-threat-intelligence'

export function ThreatIntelligenceDashboard() {
  const { data: summary, isLoading, isError, error, refetch } = useTISummary()
  const { data: trending } = useTrendingThreats(5)
  const { data: critical } = useCriticalCves(5)
  const { data: trends } = useTITrends(30)
  const [days] = useState(30)

  if (isError) {
    return (
      <ErrorState
        title="Failed to load threat intelligence"
        message={(error as Error)?.message}
        onRetry={() => refetch()}
      />
    )
  }

  if (isLoading) {
    return <div className="flex justify-center py-16"><Spinner /></div>
  }

  return (
    <PageContainer>
      <PageHeader
        title="Threat Intelligence"
        description="CVE enrichment, exploitability scoring, and threat context"
      />

      {/* Summary Cards */}
      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4 lg:grid-cols-6">
        <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-text-primary">{summary?.total_cves ?? 0}</p><p className="text-xs text-text-muted">Total CVEs</p></div></Card>
        <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-red-500">{summary?.critical_cves ?? 0}</p><p className="text-xs text-text-muted">Critical</p></div></Card>
        <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-orange-500">{summary?.high_cves ?? 0}</p><p className="text-xs text-text-muted">High</p></div></Card>
        <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-yellow-500">{summary?.medium_cves ?? 0}</p><p className="text-xs text-text-muted">Medium</p></div></Card>
        <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-amber-600">{summary?.kev_count ?? 0}</p><p className="text-xs text-text-muted">KEV</p></div></Card>
        <Card><div className="p-4 text-center"><p className="text-2xl font-bold text-purple-500">{summary?.active_exploitations ?? 0}</p><p className="text-xs text-text-muted">Active Exploits</p></div></Card>
      </div>

      {/* Score row */}
      <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <div className="p-4">
            <p className="text-sm text-text-muted">Average Threat Score</p>
            <p className="text-2xl font-bold text-text-primary">{summary?.average_threat_score.toFixed(1) ?? '0.0'}</p>
          </div>
        </Card>
        <Card>
          <div className="p-4">
            <p className="text-sm text-text-muted">Average EPSS Score</p>
            <p className="text-2xl font-bold text-text-primary">{((summary?.average_epss_score ?? 0) * 100).toFixed(2)}%</p>
          </div>
        </Card>
        <Card>
          <div className="p-4">
            <p className="text-sm text-text-muted">Feeds Active</p>
            <p className="text-2xl font-bold text-text-primary">{summary?.feeds_active ?? 0} / {summary?.feeds_total ?? 0}</p>
          </div>
        </Card>
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Trending Threats */}
        <Card>
          <div className="p-5">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Trending Threats</h3>
            {trending && trending.length > 0 ? (
              <div className="space-y-2">
                {trending.map((t) => (
                  <div key={t.cve_code} className="flex items-center justify-between rounded bg-bg-secondary px-3 py-2">
                    <div className="flex items-center gap-2">
                      <a href={`/threat-intelligence/cves/${encodeURIComponent(t.cve_code)}`} className="text-sm font-medium text-accent-primary hover:underline">{t.cve_code}</a>
                      <Badge variant={t.severity === 'CRITICAL' ? 'danger' : t.severity === 'HIGH' ? 'warning' : 'neutral'}>{t.severity}</Badge>
                      {t.is_kev && <Badge variant="danger">KEV</Badge>}
                    </div>
                    <span className="text-sm font-bold text-text-primary">{t.threat_score.toFixed(1)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-text-muted">No trending threats</p>
            )}
          </div>
        </Card>

        {/* Critical CVEs */}
        <Card>
          <div className="p-5">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Critical CVEs</h3>
            {critical && critical.length > 0 ? (
              <div className="space-y-2">
                {critical.map((c) => (
                  <div key={c.id} className="rounded bg-bg-secondary px-3 py-2">
                    <div className="flex items-center justify-between">
                      <a href={`/threat-intelligence/cves/${c.id}`} className="text-sm font-medium text-accent-primary hover:underline">{c.cve_code}</a>
                      <span className="text-sm font-bold text-red-500">{c.threat_score.toFixed(1)}</span>
                    </div>
                    <p className="mt-1 text-xs text-text-muted line-clamp-1">{c.description}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-text-muted">No critical CVEs found</p>
            )}
          </div>
        </Card>
      </div>

      {/* Trend Chart */}
      {trends && trends.length > 0 && (
        <div className="mt-6">
          <Card>
            <div className="p-5">
              <h3 className="mb-3 text-sm font-semibold text-text-primary">Trends (Last {days} Days)</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-text-muted">
                      <th className="pb-2 pr-4">Date</th>
                      <th className="pb-2 pr-4">New CVEs</th>
                      <th className="pb-2 pr-4">Critical</th>
                      <th className="pb-2 pr-4">KEV</th>
                      <th className="pb-2 pr-4">Avg Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {trends.slice(-14).map((tp) => (
                      <tr key={tp.date} className="border-t border-border-primary text-text-primary">
                        <td className="py-1 pr-4">{tp.date}</td>
                        <td className="py-1 pr-4">{tp.new_cves}</td>
                        <td className="py-1 pr-4 text-red-500">{tp.critical_cves}</td>
                        <td className="py-1 pr-4 text-amber-600">{tp.kev_additions}</td>
                        <td className="py-1 pr-4">{tp.average_score.toFixed(1)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </Card>
        </div>
      )}
    </PageContainer>
  )
}
