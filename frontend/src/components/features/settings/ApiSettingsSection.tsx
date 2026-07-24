import { Wifi, WifiOff } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { useHealth, useHealthz, useApiKeys } from '@/hooks/use-settings'
import type { ApiKeyInfo } from '@/api/settings'

export function ApiSettingsSection() {
  const { data: health, isLoading: healthLoading, error: healthError, refetch: refetchHealth } = useHealth()
  const { data: healthz, isLoading: healthzLoading } = useHealthz()
  const { data: apiKeys, isLoading: apiKeysLoading } = useApiKeys()

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>API Status</CardTitle>
          <CardDescription>Backend and API connection information</CardDescription>
        </CardHeader>
        <div className="p-5 space-y-4">
          {healthError ? (
            <ErrorState message={(healthError as Error).message} onRetry={() => refetchHealth()} />
          ) : healthLoading || healthzLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-3/4" />
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <p className="text-xs text-text-muted">Backend Version</p>
                <p className="text-sm font-medium text-text-primary">{health?.version ?? healthz?.version ?? '-'}</p>
              </div>
              <div>
                <p className="text-xs text-text-muted">API Version</p>
                <p className="text-sm font-medium text-text-primary">v1</p>
              </div>
              <div>
                <p className="text-xs text-text-muted">Connection Status</p>
                <div className="flex items-center gap-1.5 mt-0.5">
                  {health ? (
                    <Wifi className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <WifiOff className="h-4 w-4 text-red-400" />
                  )}
                  <span className="text-sm font-medium text-text-primary">
                    {health ? 'Connected' : 'Disconnected'}
                  </span>
                </div>
              </div>
              <div>
                <p className="text-xs text-text-muted">Health Status</p>
                <Badge variant={healthz?.status === 'healthy' ? 'success' : healthz?.status === 'degraded' ? 'warning' : 'critical'} size="sm">
                  {healthz?.status ?? 'unknown'}
                </Badge>
              </div>
            </div>
          )}
        </div>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>API Keys</CardTitle>
          <CardDescription>Your active API keys</CardDescription>
        </CardHeader>
        <div className="p-5">
          {apiKeysLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-12 w-full rounded-lg" />
            </div>
          ) : !apiKeys || apiKeys.length === 0 ? (
            <p className="text-sm text-text-secondary">No API keys configured</p>
          ) : (
            <div className="space-y-3">
              {apiKeys.map((key: ApiKeyInfo) => (
                <div key={key.id} className="flex items-center justify-between rounded-lg bg-surface-tertiary/50 p-3">
                  <div>
                    <p className="text-sm font-medium text-text-primary">{key.name}</p>
                    <p className="text-xs text-text-muted font-mono">{key.key_prefix}...</p>
                  </div>
                  <p className="text-xs text-text-muted">
                    {key.last_used_at ? 'Last used ' + key.last_used_at : 'Never used'}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </Card>
    </div>
  )
}
