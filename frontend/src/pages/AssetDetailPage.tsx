import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { PageContainer } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/Tabs'
import {
  useAsset,
  useAssetRelationships,
  useAssetHistory,
  useAddTag,
  useRemoveTag,
  useRecalculateRisk,
  useUpdateCriticality,
} from '@/hooks/use-assets'

const criticalityColors: Record<string, string> = {
  critical: 'border-red-500 text-red-500',
  high: 'border-orange-500 text-orange-500',
  medium: 'border-yellow-500 text-yellow-500',
  low: 'border-green-500 text-green-500',
}

const CRITICALITY_LEVELS = ['low', 'medium', 'high', 'critical']

export function AssetDetailPage() {
  const { id } = useParams<{ id: string }>()
  const nav = useNavigate()
  const [activeTab, setActiveTab] = useState('overview')
  const [tagKey, setTagKey] = useState('')
  const [tagValue, setTagValue] = useState('')
  const { data: asset, isLoading } = useAsset(id ?? null)
  const { data: relationships } = useAssetRelationships(id ?? null)
  const { data: history } = useAssetHistory(id ?? null)
  const addTag = useAddTag()
  const removeTag = useRemoveTag()
  const recalculateRisk = useRecalculateRisk()
  const updateCriticality = useUpdateCriticality()

  const [showCriticalityForm, setShowCriticalityForm] = useState(false)
  const [newCriticality, setNewCriticality] = useState('medium')
  const [showRiskForm, setShowRiskForm] = useState(false)
  const [riskInputs, setRiskInputs] = useState({ critical: '0', high: '0', open: '0' })

  if (isLoading) {
    return (
      <PageContainer>
        <div className="flex justify-center py-12"><Spinner size="lg" /></div>
      </PageContainer>
    )
  }

  if (!asset) {
    return (
      <PageContainer>
        <div className="py-12 text-center">
          <p className="text-lg font-medium">Asset not found</p>
          <Button className="mt-4" onClick={() => nav('/assets')}>Back to Inventory</Button>
        </div>
      </PageContainer>
    )
  }

  const handleAddTag = () => {
    if (tagKey.trim() && tagValue.trim() && id) {
      addTag.mutate({ id, key: tagKey.trim(), value: tagValue.trim() })
      setTagKey('')
      setTagValue('')
    }
  }

  const handleRemoveTag = (key: string) => {
    if (id) removeTag.mutate({ id, key })
  }

  const openCriticalityForm = () => {
    setNewCriticality(asset.criticality)
    setShowCriticalityForm(true)
  }

  const handleSaveCriticality = async () => {
    if (!id) return
    await updateCriticality.mutateAsync({ id, criticality: newCriticality })
    setShowCriticalityForm(false)
  }

  const handleRecalculateRisk = async () => {
    if (!id) return
    await recalculateRisk.mutateAsync({
      id,
      criticalFindings: Number(riskInputs.critical) || 0,
      highFindings: Number(riskInputs.high) || 0,
      openFindings: Number(riskInputs.open) || 0,
    })
    setShowRiskForm(false)
  }

  return (
    <PageContainer>
      <div className="mb-4">
        <button onClick={() => nav('/assets')} className="text-sm text-accent hover:underline">&larr; Back to Inventory</button>
      </div>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">
              {asset.hostname || asset.ip_address || asset.domain || asset.id}
            </h1>
            <Badge variant="neutral" className={`border ${criticalityColors[asset.criticality] || ''}`}>
              {asset.criticality}
            </Badge>
            <Badge variant="neutral" className="border border-border text-xs">
              {asset.asset_type.replace(/_/g, ' ')}
            </Badge>
          </div>
          {asset.description && <p className="mt-1 text-sm text-text-muted">{asset.description}</p>}
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="flex items-center gap-2 text-sm text-text-muted">
            <span>Risk: <strong className="text-text-primary">{asset.risk_score.toFixed(1)}</strong></span>
            <span>Findings: <strong>{asset.finding_count}</strong></span>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={showCriticalityForm ? () => setShowCriticalityForm(false) : openCriticalityForm}>
              {showCriticalityForm ? 'Cancel' : 'Change Criticality'}
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowRiskForm(!showRiskForm)}>
              {showRiskForm ? 'Cancel' : 'Override Risk Score'}
            </Button>
          </div>
        </div>
      </div>

      {showCriticalityForm && (
        <Card className="mb-4 p-4">
          <div className="flex items-end gap-3">
            <div className="space-y-1.5">
              <span className="block text-xs text-text-muted">New criticality</span>
              <select
                value={newCriticality}
                onChange={(e) => setNewCriticality(e.target.value)}
                className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
              >
                {CRITICALITY_LEVELS.map((level) => (
                  <option key={level} value={level}>{level}</option>
                ))}
              </select>
            </div>
            <Button onClick={handleSaveCriticality} disabled={updateCriticality.isPending}>
              {updateCriticality.isPending ? 'Saving...' : 'Save'}
            </Button>
          </div>
        </Card>
      )}

      {showRiskForm && (
        <Card className="mb-4 p-4">
          <p className="mb-3 text-xs text-text-muted">
            Manually override the risk score from finding counts you enter below. There is no automatic
            way to pull this asset&apos;s real finding counts yet, so these values aren&apos;t verified against
            actual data - enter them carefully.
          </p>
          <div className="flex items-end gap-3">
            <div className="space-y-1.5">
              <span className="block text-xs text-text-muted">Critical findings</span>
              <Input
                type="number"
                min={0}
                value={riskInputs.critical}
                onChange={(e) => setRiskInputs({ ...riskInputs, critical: e.target.value })}
                className="w-28"
              />
            </div>
            <div className="space-y-1.5">
              <span className="block text-xs text-text-muted">High findings</span>
              <Input
                type="number"
                min={0}
                value={riskInputs.high}
                onChange={(e) => setRiskInputs({ ...riskInputs, high: e.target.value })}
                className="w-28"
              />
            </div>
            <div className="space-y-1.5">
              <span className="block text-xs text-text-muted">Open findings</span>
              <Input
                type="number"
                min={0}
                value={riskInputs.open}
                onChange={(e) => setRiskInputs({ ...riskInputs, open: e.target.value })}
                className="w-28"
              />
            </div>
            <Button onClick={handleRecalculateRisk} disabled={recalculateRisk.isPending}>
              {recalculateRisk.isPending ? 'Saving...' : 'Apply Override'}
            </Button>
          </div>
        </Card>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="details">Details</TabsTrigger>
          <TabsTrigger value="tags">Tags</TabsTrigger>
          <TabsTrigger value="technologies">Technologies</TabsTrigger>
          <TabsTrigger value="relationships">Relationships</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="grid gap-4 pt-4 sm:grid-cols-2 lg:grid-cols-3">
          {asset.hostname && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">Hostname</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{asset.hostname}</div></Card>
          )}
          {asset.ip_address && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">IP Address</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{asset.ip_address}</div></Card>
          )}
          {asset.domain && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">Domain</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{asset.domain}</div></Card>
          )}
          {asset.operating_system && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">OS</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{asset.operating_system}{asset.os_version ? ` ${asset.os_version}` : ''}</div></Card>
          )}
          {asset.owner && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">Owner</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{asset.owner}</div></Card>
          )}
          {asset.location && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">Location</CardTitle></CardHeader>
              <div className="px-5 pb-4 text-sm">{asset.location}</div></Card>
          )}
          {asset.open_ports && asset.open_ports.length > 0 && (
            <Card><CardHeader><CardTitle className="text-xs text-text-secondary">Open Ports</CardTitle></CardHeader>
              <div className="flex flex-wrap gap-1 px-5 pb-4">
                {asset.open_ports.map((p) => <Badge key={p} variant="neutral">{p}</Badge>)}
              </div></Card>
          )}
        </TabsContent>

        <TabsContent value="details" className="space-y-4 pt-4">
          <Card>
            <div className="divide-y divide-border">
              {[
                ['Asset Type', asset.asset_type.replace(/_/g, ' ')],
                ['FQDN', asset.fqdn],
                ['MAC Address', asset.mac_address],
                ['OS Version', asset.os_version],
                ['Owner', asset.owner],
                ['Location', asset.location],
                ['First Seen', asset.first_seen],
                ['Last Seen', asset.last_seen],
                ['Created', asset.created_at],
                ['Updated', asset.updated_at],
              ].filter(([_, v]) => v).map(([label, value]) => (
                <div key={label as string} className="flex justify-between px-5 py-3 text-sm">
                  <span className="text-text-muted">{label as string}</span>
                  <span className="text-text-primary">{value as string}</span>
                </div>
              ))}
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="tags" className="space-y-4 pt-4">
          <div className="flex gap-2">
            <input
              placeholder="Key"
              value={tagKey}
              onChange={(e) => setTagKey(e.target.value)}
              className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            />
            <input
              placeholder="Value"
              value={tagValue}
              onChange={(e) => setTagValue(e.target.value)}
              className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            />
            <Button onClick={handleAddTag} disabled={!tagKey.trim() || !tagValue.trim()}>Add Tag</Button>
          </div>
          {asset.tags && asset.tags.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {asset.tags.map((t) => (
                <Badge key={t.key} variant="neutral" className="flex items-center gap-1">
                  {t.key}={t.value}
                  <button onClick={() => handleRemoveTag(t.key)} className="ml-1 text-text-muted hover:text-red-500">&times;</button>
                </Badge>
              ))}
            </div>
          ) : (
            <p className="text-sm text-text-muted">No tags</p>
          )}
        </TabsContent>

        <TabsContent value="technologies" className="space-y-4 pt-4">
          {asset.technologies && asset.technologies.length > 0 ? (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {asset.technologies.map((t, i) => (
                <Card key={i}>
                  <div className="px-5 py-3">
                    <p className="text-sm font-medium">{t.name}</p>
                    <p className="text-xs text-text-muted">{t.type}{t.version ? ` ${t.version}` : ''}</p>
                    {t.vendor && <p className="text-xs text-text-muted">{t.vendor}</p>}
                  </div>
                </Card>
              ))}
            </div>
          ) : (
            <p className="text-sm text-text-muted">No technologies detected</p>
          )}
        </TabsContent>

        <TabsContent value="relationships" className="space-y-4 pt-4">
          {relationships && relationships.length > 0 ? (
            <div className="space-y-2">
              {relationships.map((r, i) => (
                <Card key={i}>
                  <div className="flex items-center gap-3 px-5 py-3 text-sm">
                    <Badge variant="neutral">{r.relationship_type.replace(/_/g, ' ')}</Badge>
                    <span className="text-text-muted">{r.source_asset_id}</span>
                    <span className="text-text-muted">&rarr;</span>
                    <span className="text-text-primary">{r.target_asset_id}</span>
                  </div>
                </Card>
              ))}
            </div>
          ) : (
            <p className="text-sm text-text-muted">No relationships</p>
          )}
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
