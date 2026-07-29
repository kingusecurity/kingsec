import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { useRules, useEnableRule, useDisableRule, useDeleteRule, useSeedRules } from '@/hooks/use-monitoring'

export function MonitoringRulesPage() {
  const [showDisabled, setShowDisabled] = useState(false)
  const { data, isLoading } = useRules({ enabled: showDisabled ? undefined : true })
  const enableRule = useEnableRule()
  const disableRule = useDisableRule()
  const deleteRule = useDeleteRule()
  const seedRules = useSeedRules()

  const rules = data?.items ?? []

  return (
    <PageContainer>
      <PageHeader
        title="Monitoring Rules"
        description="Rules that evaluate monitoring events and trigger alerts"
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-text-muted">
          <input
            type="checkbox"
            checked={showDisabled}
            onChange={(e) => setShowDisabled(e.target.checked)}
            className="rounded"
          />
          Show disabled rules
        </label>
        <Button onClick={() => seedRules.mutate()} variant="outline" className="text-xs">
          Seed Default Rules
        </Button>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8"><Spinner /></div>
      ) : rules.length > 0 ? (
        <div className="space-y-3">
          {rules.map((rule) => (
            <Card key={rule.id}>
              <div className="flex items-start justify-between px-5 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-text-primary">{rule.name}</p>
                    <Badge variant="neutral" className={`text-xs ${rule.enabled ? 'text-emerald-500' : 'text-text-muted'}`}>
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                    {rule.event_type && (
                      <Badge variant="neutral" className="text-xs">{rule.event_type.replace(/_/g, ' ')}</Badge>
                    )}
                  </div>
                  {rule.description && (
                    <p className="mt-1 text-sm text-text-muted">{rule.description}</p>
                  )}
                  <div className="mt-1 flex flex-wrap gap-2 text-xs text-text-muted">
                    <span>Severity: {rule.alert_severity}</span>
                    <span>Cooldown: {rule.cooldown_minutes}m</span>
                    {rule.conditions.length > 0 && (
                      <span>Conditions: {rule.conditions.length}</span>
                    )}
                    {rule.notify_channels.length > 0 && (
                      <span>Notify: {rule.notify_channels.join(', ')}</span>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 gap-1">
                  {rule.enabled ? (
                    <Button onClick={() => disableRule.mutate(rule.id)} variant="outline" className="text-xs" size="sm">
                      Disable
                    </Button>
                  ) : (
                    <Button onClick={() => enableRule.mutate(rule.id)} variant="outline" className="text-xs" size="sm">
                      Enable
                    </Button>
                  )}
                  <Button onClick={() => deleteRule.mutate(rule.id)} variant="outline" className="text-xs text-red-500" size="sm">
                    Delete
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      ) : (
        <div className="py-12 text-center text-text-muted">
          <p className="text-lg font-medium">No rules configured</p>
          <p className="mt-1 text-sm">Seed default rules or create custom ones to start monitoring.</p>
          <Button className="mt-4" onClick={() => seedRules.mutate()}>Seed Default Rules</Button>
        </div>
      )}
    </PageContainer>
  )
}
