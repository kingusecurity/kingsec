import { useState } from 'react'
import { AlertTriangle, TrendingUp, ShieldAlert, Search } from 'lucide-react'
import { PageContainer, PageHeader, StatGrid } from '@/components/layout/PageContainer'
import { StatCard } from '@/components/features/dashboard/StatCard'
import { Card } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { useFindingsSummary, useFindingsSeverity, useFindingsTrends, useFindings } from '@/hooks/use-findings'
import { useAssessments } from '@/hooks/use-assessments'

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10',
  HIGH: 'text-orange-400 bg-orange-500/10',
  MEDIUM: 'text-yellow-400 bg-yellow-500/10',
  LOW: 'text-blue-400 bg-blue-500/10',
  INFORMATIONAL: 'text-gray-400 bg-gray-500/10',
}

const STATUS_COLORS: Record<string, string> = {
  OPEN: 'text-yellow-400 bg-yellow-500/10',
  IN_PROGRESS: 'text-blue-400 bg-blue-500/10',
  RESOLVED: 'text-emerald-400 bg-emerald-500/10',
  FALSE_POSITIVE: 'text-gray-400 bg-gray-500/10',
}

function RecentFindingsCard() {
  const { data: assessments } = useAssessments({ limit: 10 })
  const recentFindings = assessments?.items
    ?.filter((a) => a.findings_count > 0)
    .slice(0, 5)
    .map((a) => ({
      assessment_target: a.target,
      assessment_id: a.assessment_id,
      count: a.findings_count,
    }))
  if (!recentFindings?.length) return null
  return (
    <Card>
      <div className="p-5">
        <h3 className="mb-3 text-sm font-semibold text-text-primary">Recent Assessments with Findings</h3>
        <div className="space-y-2">
          {recentFindings.map((item) => (
            <div key={item.assessment_id} className="flex items-center justify-between rounded-lg border border-border px-4 py-2.5">
              <span className="text-sm text-text-primary">{item.assessment_target}</span>
              <span className="rounded bg-accent/10 px-2 py-0.5 text-xs text-accent">{item.count} findings</span>
            </div>
          ))}
        </div>
      </div>
    </Card>
  )
}

function FindingsList() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [offset, setOffset] = useState(0)
  const limit = 25

  const { data, isLoading } = useFindings({ limit, offset, search: search || undefined, severity: severity || undefined, status: status || undefined })

  if (isLoading) return <Spinner size="lg" />

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            placeholder="Search findings..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setOffset(0) }}
            className="w-full rounded-lg border border-border bg-surface-secondary py-2 pl-9 pr-3 text-sm text-text-primary placeholder-text-muted focus:border-accent focus:outline-none"
          />
        </div>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0) }} className="rounded-lg border border-border bg-surface-secondary px-3 py-2 text-sm text-text-primary">
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFORMATIONAL">Info</option>
        </select>
        <select value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0) }} className="rounded-lg border border-border bg-surface-secondary px-3 py-2 text-sm text-text-primary">
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="RESOLVED">Resolved</option>
          <option value="FALSE_POSITIVE">False Positive</option>
        </select>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-3 text-left font-medium text-text-muted">Severity</th>
                <th className="px-4 py-3 text-left font-medium text-text-muted">Title</th>
                <th className="px-4 py-3 text-left font-medium text-text-muted">Target</th>
                <th className="px-4 py-3 text-left font-medium text-text-muted">Status</th>
                <th className="px-4 py-3 text-left font-medium text-text-muted">Evidence</th>
                <th className="px-4 py-3 text-left font-medium text-text-muted">Discovered</th>
              </tr>
            </thead>
            <tbody>
              {data?.items.map((f) => (
                <tr key={f.finding_id} className="border-b border-border hover:bg-surface-tertiary/50">
                  <td className="px-4 py-3">
                    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${SEVERITY_COLORS[f.severity] || 'text-text-muted bg-surface-tertiary'}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-text-primary max-w-xs truncate">{f.title}</td>
                  <td className="px-4 py-3 text-text-muted">{f.target}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-block rounded px-2 py-0.5 text-xs ${STATUS_COLORS[f.status] || 'text-text-muted bg-surface-tertiary'}`}>
                      {f.status.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-text-muted">{f.evidence_count}</td>
                  <td className="px-4 py-3 text-text-muted">{new Date(f.discovered_at).toLocaleDateString()}</td>
                </tr>
              ))}
              {data?.items.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-sm text-text-muted">No findings match the current filters.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between border-t border-border px-4 py-3 text-sm text-text-muted">
          <span>{(data?.total ?? 0)} total findings</span>
          <div className="flex gap-2">
            <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))} className="rounded border border-border px-3 py-1 text-sm disabled:opacity-40 hover:bg-surface-tertiary">Previous</button>
            <button disabled={(data?.total ?? 0) <= offset + limit} onClick={() => setOffset(offset + limit)} className="rounded border border-border px-3 py-1 text-sm disabled:opacity-40 hover:bg-surface-tertiary">Next</button>
          </div>
        </div>
      </Card>
    </div>
  )
}

export function FindingsPage() {
  const { data: summary, isLoading: summaryLoading } = useFindingsSummary()
  const { data: severity, isLoading: severityLoading } = useFindingsSeverity()
  const { data: trends, isLoading: trendsLoading } = useFindingsTrends()

  return (
    <PageContainer>
      <PageHeader
        title="Findings"
        description="Security findings across all assessments"
        actions={
          <div className="flex items-center gap-2 text-sm text-text-muted">
            <AlertTriangle className="h-4 w-4" />
            <span>Findings overview</span>
          </div>
        }
      />

      <StatGrid columns={4}>
        <StatCard icon={ShieldAlert} label="Total Findings" value={summary?.total_findings ?? 0} variant="default" loading={summaryLoading} />
        <StatCard icon={AlertTriangle} label="Critical" value={summary?.critical_findings ?? 0} variant="danger" loading={summaryLoading} />
        <StatCard icon={AlertTriangle} label="High" value={summary?.high_findings ?? 0} variant="warning" loading={summaryLoading} />
        <StatCard icon={TrendingUp} label="Medium" value={summary?.medium_findings ?? 0} variant="default" loading={summaryLoading} />
      </StatGrid>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <div className="p-5">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Severity Breakdown</h3>
            {severityLoading ? (
              <div className="flex h-24 items-center justify-center"><span className="text-sm text-text-muted">Loading...</span></div>
            ) : severity ? (
              <div className="space-y-3">
                {[
                  { label: 'Critical', key: 'critical', color: 'bg-red-500' },
                  { label: 'High', key: 'high', color: 'bg-orange-500' },
                  { label: 'Medium', key: 'medium', color: 'bg-yellow-500' },
                  { label: 'Low', key: 'low', color: 'bg-blue-500' },
                  { label: 'Info', key: 'info', color: 'bg-gray-500' },
                ].map(({ label, key, color }) => {
                  const value = (severity as Record<string, number>)[key] ?? 0
                  const maxVal = Math.max(...Object.values(severity as Record<string, number>), 1)
                  return (
                    <div key={key}>
                      <div className="mb-1 flex items-center justify-between text-sm">
                        <span className="text-text-muted">{label}</span>
                        <span className="font-medium text-text-primary">{value}</span>
                      </div>
                      <div className="h-2 rounded-full bg-surface-tertiary">
                        <div className={`h-2 rounded-full ${color}`} style={{ width: `${(value / maxVal) * 100}%` }} />
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : null}
          </div>
        </Card>
        <RecentFindingsCard />
      </div>

      <div className="mt-6">
        <Card>
          <div className="p-5">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Finding Trends</h3>
            {trendsLoading ? (
              <div className="flex h-32 items-center justify-center"><span className="text-sm text-text-muted">Loading...</span></div>
            ) : trends?.points?.length ? (
              <div className="flex items-end gap-1" style={{ height: 120 }}>
                {trends.points.map((point, i) => {
                  const maxVal = Math.max(...trends.points.map((p) => p.value), 1)
                  const height = (point.value / maxVal) * 100
                  return (
                    <div key={i} className="flex flex-1 flex-col items-center gap-1">
                      <div className="w-full rounded-t bg-accent/60 hover:bg-accent transition-colors" style={{ height: `${height}%` }} title={`${point.date}: ${point.value}`} />
                      {i % Math.max(1, Math.floor(trends.points.length / 6)) === 0 && (
                        <span className="text-[10px] text-text-muted">{point.date.slice(5)}</span>
                      )}
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="flex h-32 items-center justify-center"><p className="text-sm text-text-muted">No trend data available</p></div>
            )}
          </div>
        </Card>
      </div>

      <div className="mt-6">
        <h2 className="mb-4 text-base font-semibold text-text-primary">All Findings</h2>
        <FindingsList />
      </div>
    </PageContainer>
  )
}
