import React from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { licensingApi } from '@/api/licensing'
import type { LicenseInfo } from '@/api/licensing'

function LicenseInfoCard({ license }: { license: LicenseInfo }) {
  const queryClient = useQueryClient()
  const deactivateMutation = useMutation({
    mutationFn: (id: string) => licensingApi.deactivate(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['license'] }),
  })

  const editionColors: Record<string, string> = {
    COMMUNITY: 'bg-gray-600',
    PROFESSIONAL: 'bg-blue-600',
    ENTERPRISE: 'bg-purple-600',
  }

  const statusColors: Record<string, 'success' | 'warning' | 'danger' | 'neutral'> = {
    ACTIVE: 'success',
    GRACE_PERIOD: 'warning',
    EXPIRED: 'danger',
    REVOKED: 'danger',
    INACTIVE: 'neutral',
  }

  return (
    <Card className="p-6">
      <div className="flex items-start justify-between mb-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h3 className="text-lg font-semibold">{license.company || 'KingSec'}</h3>
            <Badge variant={statusColors[license.status] || 'neutral'}>
              {license.status}
            </Badge>
          </div>
          <p className="text-sm text-gray-400">{license.issued_to}</p>
        </div>
        <div className={`px-3 py-1 rounded text-white text-sm font-medium ${editionColors[license.edition] || 'bg-gray-600'}`}>
          {license.edition}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
        <div>
          <div className="text-xs text-gray-500">License Key</div>
          <div className="text-sm font-mono">{license.license_key ? `${license.license_key.slice(0, 8)}...` : 'N/A'}</div>
        </div>
        <div>
          <div className="text-xs text-gray-500">Email</div>
          <div className="text-sm">{license.email || 'N/A'}</div>
        </div>
        <div>
          <div className="text-xs text-gray-500">Expires</div>
          <div className="text-sm">
            {license.expires_at
              ? new Date(license.expires_at).toLocaleDateString()
              : 'Never'}
          </div>
        </div>
        <div>
          <div className="text-xs text-gray-500">Grace Days</div>
          <div className="text-sm">{license.grace_days ?? 'N/A'}</div>
        </div>
      </div>

      {license.features.length > 0 && (
        <div className="mb-4">
          <div className="text-xs text-gray-500 mb-2">Enabled Features</div>
          <div className="flex flex-wrap gap-1.5">
            {license.features.map((f) => (
              <Badge key={f} variant="info" className="text-xs">
                {f}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {license.limits && (
        <div className="mb-4">
          <div className="text-xs text-gray-500 mb-2">Limits</div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(license.limits).map(([key, val]) => (
              <div key={key}>
                <div className="text-xs text-gray-500 capitalize">{key.replace(/_/g, ' ')}</div>
                <div className="text-sm font-medium">{val ?? 'Unlimited'}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {license.id && (
        <div className="pt-3 border-t border-gray-800">
          <Button
            variant="danger"
            size="sm"
            onClick={() => license.id && deactivateMutation.mutate(license.id)}
            disabled={deactivateMutation.isPending}
          >
            {deactivateMutation.isPending ? 'Deactivating...' : 'Deactivate License'}
          </Button>
        </div>
      )}
    </Card>
  )
}

function ActivateSection() {
  const [key, setKey] = React.useState('')
  const queryClient = useQueryClient()
  const activateMutation = useMutation({
    mutationFn: (licenseKey: string) => licensingApi.activate(licenseKey),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['license'] })
      setKey('')
    },
  })

  return (
    <Card className="p-4">
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Activate License</h3>
      <div className="flex gap-3">
        <input
          type="text"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="Enter license key (KS-...)"
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
        />
        <Button
          onClick={() => activateMutation.mutate(key)}
          disabled={!key || activateMutation.isPending}
        >
          {activateMutation.isPending ? 'Activating...' : 'Activate'}
        </Button>
      </div>
      {activateMutation.isError && (
        <p className="text-red-400 text-xs mt-2">{activateMutation.error.message}</p>
      )}
      {activateMutation.isSuccess && (
        <p className="text-green-400 text-xs mt-2">License activated successfully</p>
      )}
    </Card>
  )
}

function FeatureGateInfo() {
  const { data: features, isLoading, error } = useQuery({
    queryKey: ['license', 'features'],
    queryFn: () => licensingApi.getFeatures(),
    staleTime: 60_000,
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-6">
        <Spinner />
      </div>
    )
  }

  if (error || !features) return null

  return (
    <Card className="p-4">
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Feature Access</h3>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
        {features.features.map((f) => (
          <div key={f} className="flex items-center gap-2 text-sm">
            <span className="text-green-400">&#10003;</span>
            <span className="capitalize">{f.replace(/_/g, ' ')}</span>
          </div>
        ))}
      </div>
    </Card>
  )
}

export default function LicensePage() {
  const { data: license, isLoading, error, refetch } = useQuery({
    queryKey: ['license'],
    queryFn: () => licensingApi.getLicense(),
    staleTime: 30_000,
  })

  return (
    <PageContainer>
      <PageHeader
        title="License"
        description="Manage your KingSec license and features"
      />

      <div className="space-y-4">
        {isLoading && (
          <div className="flex items-center justify-center py-12">
            <Spinner size="lg" />
          </div>
        )}

        {error && (
          <ErrorState
            title="Failed to load license"
            message={error.message}
            onRetry={refetch}
          />
        )}

        {license && <LicenseInfoCard license={license} />}
        <ActivateSection />
        <FeatureGateInfo />
      </div>
    </PageContainer>
  )
}
