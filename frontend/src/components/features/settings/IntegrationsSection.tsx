import { useState } from 'react'
import { useIntegrations, useTestIntegration } from '@/hooks/use-integrations'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { toast } from '@/components/ui/Toast'
import { RefreshCw, CheckCircle, HelpCircle } from 'lucide-react'

interface IntegrationCardProps {
  type: string
  label: string
  configured: boolean
  onTest: (type: string) => void
  testing: boolean
}

const ICONS: Record<string, string> = {
  slack: '💬',
  microsoft_teams: '💼',
  discord: '🎮',
  generic_webhook: '🔗',
  email: '📧',
  jira: '📋',
  github_issues: '🐙',
  gitlab_issues: '🦊',
  splunk: '📊',
  sentinel: '🔍',
  elastic: '🔎',
}

function IntegrationCard({ type, label, configured, onTest, testing }: IntegrationCardProps) {
  return (
    <Card className="p-4">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <span className="text-2xl">{ICONS[type] || '🔌'}</span>
          <div>
            <h3 className="text-sm font-medium text-text-primary">{label}</h3>
            <div className="flex items-center gap-2 mt-1">
              {configured ? (
                <Badge variant="success" size="sm" className="flex items-center gap-1">
                  <CheckCircle className="h-3 w-3" />
                  Configured
                </Badge>
              ) : (
                <Badge variant="neutral" size="sm" className="flex items-center gap-1">
                  <HelpCircle className="h-3 w-3" />
                  Not Configured
                </Badge>
              )}
            </div>
          </div>
        </div>
        <Button
          variant="outline"
          size="xs"
          onClick={() => onTest(type)}
          disabled={!configured || testing}
          iconLeft={testing ? <RefreshCw className="h-3 w-3 animate-spin" /> : undefined}
        >
          {testing ? 'Testing...' : 'Test Connection'}
        </Button>
      </div>
    </Card>
  )
}

export function IntegrationsSection() {
  const { data, isLoading, error } = useIntegrations()
  const testMutation = useTestIntegration()
  const [testingType, setTestingType] = useState<string | null>(null)

  if (isLoading) {
    return (
      <div className="space-y-4">
        <h2 className="text-lg font-semibold text-text-primary">Integrations</h2>
        <p className="text-sm text-text-muted">Connect KingSec to your enterprise tools</p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[...Array(6)].map((_, i) => (
            <Skeleton key={i} className="h-24 w-full rounded-lg" />
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-4">
        <h2 className="text-lg font-semibold text-text-primary">Integrations</h2>
        <div className="rounded-lg bg-red-900/20 p-4 text-sm text-red-300">
          Failed to load integrations
        </div>
      </div>
    )
  }

  const handleTest = async (type: string) => {
    setTestingType(type)
    try {
      const result = await testMutation.mutateAsync(type)
      if (result.success) {
        toast.success('Connection successful', `${type} integration is working`)
      } else {
        toast.warning('Connection failed', `Could not connect to ${type}`)
      }
    } catch {
      toast.error('Test failed', `Connection test for ${type} failed`)
    } finally {
      setTestingType(null)
    }
  }

  const integrations = data?.integrations || []

  const chatGroup = integrations.filter(i =>
    ['slack', 'microsoft_teams', 'discord', 'generic_webhook'].includes(i.type),
  )
  const emailGroup = integrations.filter(i => i.type === 'email')
  const ticketingGroup = integrations.filter(i =>
    ['jira', 'github_issues', 'gitlab_issues'].includes(i.type),
  )
  const siemGroup = integrations.filter(i =>
    ['splunk', 'sentinel', 'elastic'].includes(i.type),
  )

  const SectionGroup = ({ title, description, items }: { title: string; description: string; items: typeof integrations }) => (
    <div className="space-y-3">
      <div>
        <h3 className="text-sm font-medium text-text-primary">{title}</h3>
        <p className="text-xs text-text-muted">{description}</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {items.map((integration) => (
          <IntegrationCard
            key={integration.type}
            type={integration.type}
            label={integration.label}
            configured={integration.configured}
            onTest={handleTest}
            testing={testingType === integration.type}
          />
        ))}
      </div>
    </div>
  )

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-text-primary">Integrations</h2>
        <p className="text-sm text-text-muted">
          Connect KingSec to your enterprise tools. Configure these via environment variables (KINGSEC_INTEGRATIONS__*).
        </p>
      </div>

      {chatGroup.length > 0 && (
        <SectionGroup
          title="Notifications & Webhooks"
          description="Send alerts to your team's chat platform"
          items={chatGroup}
        />
      )}

      {emailGroup.length > 0 && (
        <SectionGroup
          title="Email"
          description="SMTP-based email notifications"
          items={emailGroup}
        />
      )}

      {ticketingGroup.length > 0 && (
        <SectionGroup
          title="Ticketing"
          description="Create tickets from critical findings"
          items={ticketingGroup}
        />
      )}

      {siemGroup.length > 0 && (
        <SectionGroup
          title="SIEM Export"
          description="Export findings to your security information platform"
          items={siemGroup}
        />
      )}

      <div className="rounded-lg bg-surface-tertiary p-4 text-xs text-text-muted">
        <p className="font-medium text-text-secondary mb-1">Configuration</p>
        <p>Integration settings are configured via environment variables with the prefix KINGSEC_INTEGRATIONS__.</p>
        <p className="mt-1">Example: KINGSEC_INTEGRATIONS__SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...</p>
      </div>
    </div>
  )
}
