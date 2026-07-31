import React from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/Tabs'
import { useSystemInfo, useConfigSummary, useStartupReport, useDeploymentHealth } from '@/hooks/use-deployment'

function StatusDot({ passed }: { passed: boolean }) {
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full ${passed ? 'bg-green-500' : 'bg-red-500'}`}
    />
  )
}

function SystemInfoSection() {
  const { data: systemInfo, isLoading: systemLoading, error: systemError, refetch: refetchSystem } = useSystemInfo()
  const { data: config, isLoading: configLoading, error: configError, refetch: refetchConfig } = useConfigSummary()

  if (systemLoading || configLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Spinner size="lg" />
      </div>
    )
  }

  if (systemError || configError) {
    return (
      <ErrorState
        title="Failed to load system info"
        message={systemError?.message || configError?.message || 'Unknown error'}
        onRetry={() => { refetchSystem(); refetchConfig() }}
      />
    )
  }

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">System</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {systemInfo && (
            <>
              <div>
                <div className="text-xs text-gray-500">OS</div>
                <div className="text-sm font-medium">{systemInfo.os} {systemInfo.os_release}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500">Python</div>
                <div className="text-sm font-medium">{systemInfo.python}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500">Architecture</div>
                <div className="text-sm font-medium">{systemInfo.machine}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500">PID</div>
                <div className="text-sm font-medium">{systemInfo.pid}</div>
              </div>
            </>
          )}
        </div>
      </Card>

      <Card className="p-4">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Configuration</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {config && (
            <>
              <div>
                <div className="text-xs text-gray-500">Environment</div>
                <Badge variant={config.kingsec_env === 'production' ? 'success' : 'warning'}>
                  {config.kingsec_env}
                </Badge>
              </div>
              <div>
                <div className="text-xs text-gray-500">Debug</div>
                <div className="text-sm font-medium">{config.kingsec_debug}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500">Log Level</div>
                <div className="text-sm font-medium">{config.kingsec_log_level}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500">Data Dir</div>
                <div className="text-sm font-medium truncate" title={config.kingsec_data_dir}>
                  {config.kingsec_data_dir}
                </div>
              </div>
            </>
          )}
        </div>
      </Card>
    </div>
  )
}

function HealthSection() {
  const { data: health, isLoading, error, refetch } = useDeploymentHealth()
  const { data: startup, isLoading: startupLoading } = useStartupReport()

  if (isLoading || startupLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Spinner size="lg" />
      </div>
    )
  }

  if (error) {
    return (
      <ErrorState
        title="Failed to load health status"
        message={error.message}
        onRetry={refetch}
      />
    )
  }

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide">Service Health</h3>
          <Badge variant={health?.status === 'healthy' ? 'success' : 'danger'}>
            {health?.status || 'unknown'}
          </Badge>
        </div>
        {health && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <div className="text-xs text-gray-500">Version</div>
              <div className="text-sm font-medium">{health.version || 'N/A'}</div>
            </div>
            <div>
              <div className="text-xs text-gray-500">Uptime</div>
              <div className="text-sm font-medium">
                {health.uptime_seconds ? `${Math.floor(health.uptime_seconds / 3600)}h` : 'N/A'}
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-500">Database</div>
              <div className="text-sm font-medium">{health.database || 'N/A'}</div>
            </div>
          </div>
        )}
      </Card>

      {startup && (
        <Card className="p-4">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">
            Startup Checks
          </h3>
          <div className="space-y-2">
            {startup.map((check) => (
              <div key={check.name} className="flex items-center justify-between py-1.5 border-b border-gray-800 last:border-0">
                <div className="flex items-center gap-2">
                  <StatusDot passed={check.passed} />
                  <span className="text-sm font-medium capitalize">{check.name.replace(/_/g, ' ')}</span>
                </div>
                <span className="text-xs text-gray-500">{check.message}</span>
              </div>
            ))}
          </div>
          <div className="mt-3 text-xs text-gray-500">
            {startup.every((c) => c.passed) ? 'All checks passed' : 'Some checks failed'}
          </div>
        </Card>
      )}
    </div>
  )
}

function UpgradeSection() {
  return (
    <Card className="p-4">
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Upgrade</h3>
      <p className="text-sm text-gray-400 mb-4">
        Check for available upgrades and run version migrations.
      </p>
      <div className="flex gap-3">
        <Button variant="outline" size="sm" disabled>
          Check for Updates
        </Button>
        <Button variant="outline" size="sm" disabled>
          View Changelog
        </Button>
      </div>
    </Card>
  )
}

export default function DeploymentPage() {
  const [activeTab, setActiveTab] = React.useState<string>('system')

  return (
    <PageContainer>
      <PageHeader
        title="Deployment"
        description="System information, health checks, and upgrade management"
      />
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="system">System Info</TabsTrigger>
          <TabsTrigger value="health">Health & Startup</TabsTrigger>
          <TabsTrigger value="upgrade">Upgrade</TabsTrigger>
        </TabsList>
      </Tabs>
      <div className="mt-4">
        {activeTab === 'system' && <SystemInfoSection />}
        {activeTab === 'health' && <HealthSection />}
        {activeTab === 'upgrade' && <UpgradeSection />}
      </div>
    </PageContainer>
  )
}
