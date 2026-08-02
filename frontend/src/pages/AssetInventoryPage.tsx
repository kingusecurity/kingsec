import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { Input } from '@/components/ui/Input'
import { useAssetSummary, useAssets } from '@/hooks/use-assets'
import type { AssetListItem } from '@/api/assets'

const typeColors: Record<string, string> = {
  host: 'bg-blue-500',
  server: 'bg-indigo-500',
  domain: 'bg-green-500',
  website: 'bg-teal-500',
  database: 'bg-purple-500',
  container: 'bg-cyan-500',
  cloud_resource: 'bg-orange-500',
  network_device: 'bg-yellow-500',
  certificate: 'bg-pink-500',
  api_endpoint: 'bg-red-500',
}

const criticalityColors: Record<string, string> = {
  critical: 'border-red-500 text-red-500',
  high: 'border-orange-500 text-orange-500',
  medium: 'border-yellow-500 text-yellow-500',
  low: 'border-green-500 text-green-500',
}

function AssetCard({ asset }: { asset: AssetListItem }) {
  const nav = useNavigate()
  return (
    <div
      className="cursor-pointer rounded-lg border border-border bg-surface-primary transition-shadow hover:shadow-md"
      onClick={() => nav(`/assets/${asset.id}`)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && nav(`/assets/${asset.id}`)}
    >
      <div className="flex items-start gap-3 px-5 py-4">
        <span className={`mt-1 h-3 w-3 shrink-0 rounded-full ${typeColors[asset.asset_type] || 'bg-gray-500'}`} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-text-primary">
            {asset.hostname || asset.ip_address || asset.domain || asset.id}
          </p>
          <p className="text-xs text-text-muted">
            {asset.asset_type.replace(/_/g, ' ')}
            {asset.ip_address && ` · ${asset.ip_address}`}
          </p>
          {asset.operating_system && (
            <p className="mt-1 text-xs text-text-muted">{asset.operating_system}</p>
          )}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <Badge variant="neutral" className={`border ${criticalityColors[asset.criticality] || ''}`}>
            {asset.criticality}
          </Badge>
          {asset.risk_score > 0 && (
            <span className="text-xs font-medium text-text-muted">
              Risk: {asset.risk_score.toFixed(0)}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

export function AssetInventoryPage() {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [critFilter, setCritFilter] = useState('')
  const { data: summary, isLoading: summaryLoading, isError, error, refetch } = useAssetSummary()
  const { data: listData, isLoading: listLoading } = useAssets({ search: search || undefined, asset_type: typeFilter || undefined, criticality: critFilter || undefined })

  const assets = listData?.items ?? []
  const total = listData?.total ?? 0

  return (
    <PageContainer>
      <PageHeader
        title="Asset Inventory"
        description="Discover, track, and manage all assets across your infrastructure"
      />

      {isError ? (
        <ErrorState
          title="Failed to load asset inventory"
          message={(error as Error)?.message}
          onRetry={() => refetch()}
        />
      ) : summaryLoading ? (
        <div className="flex justify-center py-12">
          <Spinner size="lg" />
        </div>
      ) : (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader><CardTitle className="text-sm text-text-secondary">Total Assets</CardTitle></CardHeader>
              <div className="px-5 pb-5">
                <p className="text-2xl font-bold">{summary?.total ?? 0}</p>
              </div>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm text-text-secondary">Critical</CardTitle></CardHeader>
              <div className="px-5 pb-5">
                <p className="text-2xl font-bold text-red-500">{summary?.by_criticality?.critical ?? 0}</p>
              </div>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm text-text-secondary">High Risk</CardTitle></CardHeader>
              <div className="px-5 pb-5">
                <p className="text-2xl font-bold text-orange-500">{summary?.by_risk_range?.high ?? 0}</p>
              </div>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm text-text-secondary">Relationships</CardTitle></CardHeader>
              <div className="px-5 pb-5">
                <p className="text-2xl font-bold">{summary?.total_relationships ?? 0}</p>
              </div>
            </Card>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Input
              placeholder="Search assets..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-64"
            />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            >
              <option value="">All Types</option>
              {summary?.by_type && Object.entries(summary.by_type).map(([t, c]) => (
                <option key={t} value={t}>{t.replace(/_/g, ' ')} ({c})</option>
              ))}
            </select>
            <select
              value={critFilter}
              onChange={(e) => setCritFilter(e.target.value)}
              className="flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            >
              <option value="">All Criticality</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <p className="text-sm text-text-muted">{total} asset{total !== 1 ? 's' : ''}</p>
          </div>

          {listLoading ? (
            <div className="flex justify-center py-8">
              <Spinner />
            </div>
          ) : assets.length > 0 ? (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {assets.map((a) => <AssetCard key={a.id} asset={a} />)}
            </div>
          ) : (
            <div className="py-12 text-center text-text-muted">
              <p className="text-lg font-medium">No assets found</p>
              <p className="mt-1 text-sm">Assets are discovered and tracked automatically during scans.</p>
            </div>
          )}
        </div>
      )}
    </PageContainer>
  )
}
