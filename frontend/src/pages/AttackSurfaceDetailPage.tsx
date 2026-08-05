import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { PageContainer } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/Tabs'
import { useExposure, useExposureHistory, useMitigateExposure, useUpdateRemediation } from '@/hooks/use-attack-surface'

const severityColors: Record<string, string> = {
  critical: 'border-red-500 text-red-500',
  high: 'border-orange-500 text-orange-500',
  medium: 'border-yellow-500 text-yellow-500',
  low: 'border-green-500 text-green-500',
  info: 'border-blue-500 text-blue-500',
}

export function AttackSurfaceDetailPage() {
  const { id } = useParams<{ id: string }>()
  const nav = useNavigate()
  const [activeTab, setActiveTab] = useState('overview')
  const [remediationText, setRemediationText] = useState('')
  const { data: exposure, isLoading } = useExposure(id ?? null)
  const { data: history } = useExposureHistory(id ?? null)
  const mitigate = useMitigateExposure()
  const updateRemediation = useUpdateRemediation()

  if (isLoading) {
    return (
      <PageContainer>
        <div className="flex justify-center py-12"><Spinner size="lg" /></div>
      </PageContainer>
    )
  }

  if (!exposure) {
    return (
      <PageContainer>
        <div className="py-12 text-center">
          <p className="text-lg font-medium">Exposure not found</p>
          <Button className="mt-4" onClick={() => nav('/attack-surface')}>Back to Attack Surface</Button>
        </div>
      </PageContainer>
    )
  }

  const handleMitigate = () => {
    if (id) mitigate.mutate(id)
  }

  const handleSaveRemediation = () => {
    if (id && remediationText.trim()) {
      updateRemediation.mutate({ id, remediation: remediationText.trim() })
      setRemediationText('')
    }
  }

  return (
    <PageContainer>
      <div className="mb-4">
        <button onClick={() => nav('/attack-surface')} className="text-sm text-accent hover:underline">&larr; Back to Attack Surface</button>
      </div>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">
              {exposure.title || exposure.exposure_type.replace(/_/g, ' ')}
            </h1>
            <Badge variant="neutral" className={`border ${severityColors[exposure.severity] || ''}`}>
              {exposure.severity}
            </Badge>
            <Badge variant="neutral" className="border border-border text-xs">
              {exposure.exposure_type.replace(/_/g, ' ')}
            </Badge>
            <Badge variant="neutral" className="border border-border text-xs">
              {exposure.status}
            </Badge>
          </div>
          {exposure.description && <p className="mt-1 text-sm text-text-muted">{exposure.description}</p>}
        </div>
        <div className="flex items-center gap-2 text-sm text-text-muted">
          <span>Risk: <strong className="text-text-primary">{exposure.risk_score.toFixed(1)}</strong></span>
          {exposure.status === 'active' && (
            <Button onClick={handleMitigate} variant="outline" className="text-xs">
              Mitigate
            </Button>
          )}
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="details">Details</TabsTrigger>
          <TabsTrigger value="remediation">Remediation</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="grid gap-4 pt-4 sm:grid-cols-2 lg:grid-cols-3">
          {exposure.hostname && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">Hostname</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{exposure.hostname}</div></Card>
          )}
          {exposure.ip_address && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">IP Address</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{exposure.ip_address}</div></Card>
          )}
          {exposure.domain && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">Domain</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{exposure.domain}</div></Card>
          )}
          {exposure.port && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">Port</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{exposure.port}/{exposure.protocol || 'tcp'}</div></Card>
          )}
          {exposure.url && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">URL</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm break-all">{exposure.url}</div></Card>
          )}
          {exposure.source && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">Source</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{exposure.source}</div></Card>
          )}
        </TabsContent>

        <TabsContent value="details" className="space-y-4 pt-4">
          <Card>
            <div className="divide-y divide-border">
              {[
                ['Asset ID', exposure.asset_id],
                ['Exposure Type', exposure.exposure_type.replace(/_/g, ' ')],
                ['Severity', exposure.severity],
                ['Status', exposure.status],
                ['Source', exposure.source],
                ['Risk Score', String(exposure.risk_score.toFixed(2))],
                ['TLS Version', exposure.tls_version],
                ['Certificate Issuer', exposure.certificate_issuer],
                ['Certificate Expiry', exposure.certificate_expiry],
                ['Header', exposure.header_name ? `${exposure.header_name}: ${exposure.header_value}` : null],
                ['Technology', exposure.technology_name ? `${exposure.technology_name} ${exposure.technology_version || ''}`.trim() : null],
                ['Cloud Provider', exposure.cloud_provider],
                ['Cloud Bucket', exposure.cloud_bucket],
                ['Evidence', exposure.evidence],
                ['First Seen', exposure.first_seen],
                ['Last Seen', exposure.last_seen],
                ['Created', exposure.created_at],
                ['Updated', exposure.updated_at],
              ].filter(([_, v]) => v).map(([label, value]) => (
                <div key={label as string} className="flex justify-between px-5 py-3 text-sm">
                  <span className="shrink-0 text-text-muted">{label as string}</span>
                  <span className="break-all text-right text-text-primary">{value as string}</span>
                </div>
              ))}
            </div>
          </Card>

          {exposure.detail && exposure.detail.length > 0 && (
            <Card>
              <CardHeader><CardTitle className="text-sm text-text-secondary">Details</CardTitle></CardHeader>
              <div className="divide-y divide-border px-5 pb-4">
                {exposure.detail.map((d, i) => (
                  <div key={i} className="flex justify-between py-2 text-sm">
                    <span className="text-text-muted">{d.key}</span>
                    <span className="text-text-primary">{d.value}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="remediation" className="space-y-4 pt-4">
          {exposure.remediation && (
            <Card>
              <CardHeader><CardTitle className="text-sm text-text-secondary">Current Remediation</CardTitle></CardHeader>
              <div className="px-5 pb-4">
                <p className="text-sm text-text-primary whitespace-pre-wrap">{exposure.remediation}</p>
              </div>
            </Card>
          )}

          <Card>
            <CardHeader><CardTitle className="text-sm text-text-secondary">Update Remediation</CardTitle></CardHeader>
            <div className="space-y-3 px-5 pb-5">
              <textarea
                placeholder="Enter remediation steps..."
                value={remediationText}
                onChange={(e) => setRemediationText(e.target.value)}
                className="w-full rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
                rows={4}
              />
              <Button onClick={handleSaveRemediation} disabled={!remediationText.trim()}>
                Save Remediation
              </Button>
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="history" className="space-y-4 pt-4">
          {history && history.length > 0 ? (
            <div className="space-y-2">
              {history.map((h, i) => (
                <Card key={i}>
                  <div className="flex items-start gap-3 px-5 py-3">
                    <Badge variant="neutral" className="shrink-0 text-xs">{h.event_type.replace(/_/g, ' ')}</Badge>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-text-primary">{h.description}</p>
                      <p className="text-xs text-text-muted">{h.timestamp}{h.actor !== 'system' ? ` by ${h.actor}` : ''}</p>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          ) : (
            <p className="text-sm text-text-muted">No history recorded</p>
          )}
        </TabsContent>
      </Tabs>
    </PageContainer>
  )
}
