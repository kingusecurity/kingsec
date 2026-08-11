import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { toast } from '@/components/ui/Toast'
import { deploymentApi } from '@/api/deployment'
import { useDiagnostics } from '@/hooks/use-deployment'

function DiagnosticsSection() {
  const { data, isLoading, error, refetch } = useDiagnostics()

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
        title="Failed to load diagnostics"
        message={error.message}
        onRetry={refetch}
      />
    )
  }

  if (!data) return null

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide">System</h3>
          <span className="text-xs text-gray-500">Collected: {new Date(data.collected_at).toLocaleString()}</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <div className="text-xs text-gray-500">OS</div>
            <div className="text-sm font-medium">{data.system.os} {data.system.os_release}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Python</div>
            <div className="text-sm font-medium">{data.system.python}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Architecture</div>
            <div className="text-sm font-medium">{data.system.machine}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Version</div>
            <div className="text-sm font-medium">{data.version}</div>
          </div>
        </div>
      </Card>

      <Card className="p-4">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Health</h3>
        <div className="flex items-center gap-2">
          <Badge variant={data.health.status === 'ok' ? 'success' : 'danger'}>
            {data.health.status}
          </Badge>
          {data.health.version && (
            <span className="text-xs text-gray-500">v{data.health.version}</span>
          )}
        </div>
      </Card>

      <Card className="p-4">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Disk Usage</h3>
        {data.disk.error ? (
          <p className="text-sm text-gray-400">{data.disk.error}</p>
        ) : (
          <div className="grid grid-cols-3 gap-4">
            <div>
              <div className="text-xs text-gray-500">Total</div>
              <div className="text-sm font-medium">{data.disk.total_gb} GB</div>
            </div>
            <div>
              <div className="text-xs text-gray-500">Used</div>
              <div className="text-sm font-medium">{data.disk.used_gb} GB ({data.disk.percent_used}%)</div>
            </div>
            <div>
              <div className="text-xs text-gray-500">Free</div>
              <div className="text-sm font-medium">{data.disk.free_gb} GB</div>
            </div>
          </div>
        )}
      </Card>

      <Card className="p-4">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Database</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <div className="text-xs text-gray-500">Exists</div>
            <div className="text-sm font-medium">{data.database.exists ? 'Yes' : 'No'}</div>
          </div>
          {data.database.size_mb && (
            <div>
              <div className="text-xs text-gray-500">Size</div>
              <div className="text-sm font-medium">{data.database.size_mb} MB</div>
            </div>
          )}
        </div>
      </Card>

      {data.recent_logs.length > 0 && (
        <Card className="p-4">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Recent Logs</h3>
          <div className="bg-gray-900 rounded p-3 max-h-64 overflow-y-auto font-mono text-xs">
            {data.recent_logs.map((line, i) => (
              <div key={i} className="text-gray-300 py-0.5">{line}</div>
            ))}
          </div>
        </Card>
      )}

      <div className="flex gap-3">
        <Button variant="outline" onClick={() => refetch()}>
          Refresh Diagnostics
        </Button>
        <Button
          variant="outline"
          onClick={() => deploymentApi.downloadDiagnostics().catch(() => toast.error('Failed to download diagnostics bundle'))}
        >
          Download Bundle
        </Button>
      </div>
    </div>
  )
}

export default function DiagnosticsPage() {
  return (
    <PageContainer>
      <PageHeader
        title="Diagnostics"
        description="System diagnostics and support bundle"
      />
      <DiagnosticsSection />
    </PageContainer>
  )
}
