import React from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/Tabs'
import { useReleaseAuditReport, useTelemetrySummary } from '@/hooks/use-release-audit'

function ReleaseHistorySection() {
  const { data: report, isLoading, error, refetch } = useReleaseAuditReport()

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Spinner size="lg" />
      </div>
    )
  }

  if (error) {
    return (
      <ErrorState
        title="Failed to load release audit"
        message={error.message}
        onRetry={refetch}
      />
    )
  }

  if (!report) return null

  const typeColors: Record<string, string> = {
    major: 'bg-red-600',
    minor: 'bg-blue-600',
    patch: 'bg-green-600',
    hotfix: 'bg-yellow-600',
    upgrade: 'bg-purple-600',
  }

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <div className="text-xs text-gray-500">Current Version</div>
            <div className="text-lg font-semibold">{report.current_version}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Installed</div>
            <div className="text-sm">{new Date(report.installed_at).toLocaleDateString()}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Total Releases</div>
            <div className="text-sm">{report.total_releases}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Upgrades</div>
            <div className="text-sm">{report.upgrade_history.length}</div>
          </div>
        </div>
      </Card>

      <Card className="p-4">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Release History</h3>
        <div className="space-y-2">
          {report.releases.length === 0 && (
            <p className="text-sm text-gray-500">No releases recorded yet.</p>
          )}
          {report.releases.map((release, i) => (
            <div
              key={`${release.version}-${i}`}
              className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0"
            >
              <div className="flex items-center gap-3">
                <span className={`px-2 py-0.5 rounded text-white text-xs font-medium ${typeColors[release.release_type] || 'bg-gray-600'}`}>
                  {release.release_type}
                </span>
                <span className="text-sm font-medium">v{release.version}</span>
                {release.upgrade_from && (
                  <span className="text-xs text-gray-500">
                    from v{release.upgrade_from}
                  </span>
                )}
              </div>
              <div className="text-xs text-gray-500">
                {new Date(release.released_at).toLocaleDateString()}
              </div>
            </div>
          ))}
        </div>
      </Card>

      {report.upgrade_history.length > 0 && (
        <Card className="p-4">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Upgrade History</h3>
          <div className="space-y-2">
            {report.upgrade_history.map((upgrade, i) => (
              <div
                key={`upgrade-${i}`}
                className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0"
              >
                <div className="flex items-center gap-3">
                  <Badge variant="success">upgrade</Badge>
                  <span className="text-sm">
                    v{upgrade.upgrade_from} → v{upgrade.version}
                  </span>
                </div>
                <div className="text-xs text-gray-500">
                  {upgrade.upgraded_by && <span>by {upgrade.upgraded_by} · </span>}
                  {new Date(upgrade.upgraded_at || upgrade.released_at).toLocaleDateString()}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}

function TelemetrySection() {
  const { data: telemetry, isLoading, error, refetch } = useTelemetrySummary(30)

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Spinner size="lg" />
      </div>
    )
  }

  if (error) {
    return (
      <ErrorState
        title="Failed to load telemetry"
        message={error.message}
        onRetry={refetch}
      />
    )
  }

  if (!telemetry) return null

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">
          Telemetry Summary (Last {telemetry.period_days} Days)
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <div className="text-xs text-gray-500">Sessions</div>
            <div className="text-lg font-semibold">{telemetry.total_sessions}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Events</div>
            <div className="text-lg font-semibold">{telemetry.total_events}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Errors</div>
            <div className="text-lg font-semibold">{telemetry.total_errors}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Avg Session</div>
            <div className="text-lg font-semibold">
              {telemetry.avg_session_duration_ms > 0
                ? `${(telemetry.avg_session_duration_ms / 1000).toFixed(1)}s`
                : 'N/A'}
            </div>
          </div>
        </div>
      </Card>

      {Object.keys(telemetry.top_features).length > 0 && (
        <Card className="p-4">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Top Features</h3>
          <div className="space-y-1.5">
            {Object.entries(telemetry.top_features).map(([feature, count]) => (
              <div key={feature} className="flex items-center justify-between py-1">
                <span className="text-sm capitalize">{feature.replace(/_/g, ' ')}</span>
                <span className="text-xs text-gray-500">{count} uses</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}

export default function ReleaseAuditPage() {
  const [activeTab, setActiveTab] = React.useState<string>('releases')

  return (
    <PageContainer>
      <PageHeader
        title="Release Audit"
        description="Release history, upgrade trail, and usage telemetry"
      />
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="releases">Release History</TabsTrigger>
          <TabsTrigger value="telemetry">Telemetry</TabsTrigger>
        </TabsList>
      </Tabs>
      <div className="mt-4">
        {activeTab === 'releases' && <ReleaseHistorySection />}
        {activeTab === 'telemetry' && <TelemetrySection />}
      </div>
    </PageContainer>
  )
}
