import { useState } from 'react'
import { useLicense, useActivateLicense, useDeactivateLicense } from '@/hooks/use-licensing'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Input } from '@/components/ui/Input'
import { Skeleton } from '@/components/ui/Skeleton'
import { toast } from '@/components/ui/Toast'
import { KeyRound, ShieldCheck, ShieldX, Clock, Users, Building2, Zap, CheckCircle2 } from 'lucide-react'

const EDITION_LABELS: Record<string, string> = {
  community: 'Community',
  professional: 'Professional',
  enterprise: 'Enterprise',
}

const STATUS_LABELS: Record<string, string> = {
  active: 'Active',
  expired: 'Expired',
  revoked: 'Revoked',
  grace_period: 'Grace Period',
  inactive: 'Not Activated',
}

const STATUS_COLORS: Record<string, 'success' | 'critical' | 'warning' | 'info'> = {
  active: 'success',
  expired: 'critical',
  revoked: 'critical',
  grace_period: 'warning',
  inactive: 'info',
}

export function LicenseSection() {
  const [licenseKey, setLicenseKey] = useState('')
  const [showActivate, setShowActivate] = useState(false)

  const { data: license, isLoading, error } = useLicense()
  const activateLicense = useActivateLicense()
  const deactivateLicense = useDeactivateLicense()

  const handleActivate = async () => {
    if (!licenseKey.trim()) {
      toast.error('Please enter a license key')
      return
    }
    try {
      await activateLicense.mutateAsync(licenseKey.trim())
      toast.success('License activated')
      setShowActivate(false)
      setLicenseKey('')
    } catch {
      toast.error('Failed to activate license')
    }
  }

  const handleDeactivate = async () => {
    if (!license?.id) return
    try {
      await deactivateLicense.mutateAsync(license.id)
      toast.success('License deactivated')
    } catch {
      toast.error('Failed to deactivate license')
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-32 w-full rounded-lg" />
      </div>
    )
  }

  if (error) {
    return (
      <Card className="p-6 text-center text-text-muted text-sm">
        Failed to load license information.
      </Card>
    )
  }

  const isActive = license?.status === 'active' || license?.status === 'grace_period'
  const isExpired = license?.status === 'expired'
  const isInactive = !license?.has_license || license?.status === 'inactive'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-text-primary">License</h2>
          <p className="text-sm text-text-muted">Manage your KingSec edition and license key</p>
        </div>
        {!isActive && (
          <Button variant="outline" size="sm" onClick={() => setShowActivate(!showActivate)} iconLeft={<KeyRound className="h-4 w-4" />}>
            {showActivate ? 'Cancel' : 'Activate License'}
          </Button>
        )}
      </div>

      {showActivate && !isActive && (
        <Card className="p-4 space-y-3">
          <h3 className="text-sm font-medium text-text-primary">Activate License</h3>
          <p className="text-xs text-text-muted">Enter your license key to activate Professional or Enterprise edition.</p>
          <Input
            placeholder="License key"
            value={licenseKey}
            onChange={(e) => setLicenseKey(e.target.value)}
          />
          <Button onClick={handleActivate} loading={activateLicense.isPending}>Activate</Button>
        </Card>
      )}

      <Card className="p-6 space-y-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {isActive ? (
              <ShieldCheck className="h-6 w-6 text-emerald-400" />
            ) : isExpired ? (
              <ShieldX className="h-6 w-6 text-red-400" />
            ) : (
              <KeyRound className="h-6 w-6 text-text-muted" />
            )}
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-semibold text-text-primary">
                  {EDITION_LABELS[license?.edition ?? 'community'] ?? 'Community'}
                </span>
                <Badge variant={STATUS_COLORS[license?.status ?? 'inactive']} size="sm">
                  {STATUS_LABELS[license?.status ?? 'inactive']}
                </Badge>
              </div>
              {license?.expires_at && (
                <p className="text-xs text-text-muted mt-0.5">
                  Expires: {new Date(license.expires_at).toLocaleDateString()}
                </p>
              )}
            </div>
          </div>
          {isActive && (
            <Button variant="danger" size="sm" onClick={handleDeactivate} loading={deactivateLicense.isPending}>
              Deactivate
            </Button>
          )}
        </div>

        {license?.issued_to && (
          <div className="text-sm text-text-secondary border-t border-border pt-3">
            <p>Licensed to: <span className="text-text-primary">{license.issued_to}</span></p>
            {license.company && <p>Company: <span className="text-text-primary">{license.company}</span></p>}
            {license.email && <p>Email: <span className="text-text-primary">{license.email}</span></p>}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-border pt-4">
          <div>
            <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">Enabled Features</h4>
            <div className="space-y-1.5">
              {license?.features?.map((f) => (
                <div key={f} className="flex items-center gap-2 text-sm text-text-secondary">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                  <span className="capitalize">{f.replace(/_/g, ' ')}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">Limits</h4>
            <div className="space-y-2">
              {license?.limits && (
                <>
                  <div className="flex items-center gap-2 text-sm text-text-secondary">
                    <Users className="h-3.5 w-3.5 text-text-muted" />
                    <span>Max Users: <strong className="text-text-primary">{license.limits.max_users ?? 'Unlimited'}</strong></span>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-text-secondary">
                    <Building2 className="h-3.5 w-3.5 text-text-muted" />
                    <span>Max Orgs: <strong className="text-text-primary">{license.limits.max_organizations ?? 'Unlimited'}</strong></span>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </Card>

      {license?.grace_days && isExpired && (
        <Card variant="warning" className="p-4 flex items-center gap-3">
          <Clock className="h-5 w-5 shrink-0" />
          <div className="text-sm">
            Your license has expired. You have a {license.grace_days}-day grace period before features are restricted.
          </div>
        </Card>
      )}

      {isInactive && (
        <Card className="p-4 border-blue-800/50 bg-blue-900/10">
          <div className="flex items-center gap-3">
            <Zap className="h-5 w-5 shrink-0" />
            <div className="text-sm">
              <p className="font-medium text-text-primary">Community Edition</p>
              <p className="text-text-muted mt-0.5">
                You are running the free Community Edition. Activate a license to unlock Professional or Enterprise features.
              </p>
            </div>
          </div>
        </Card>
      )}
    </div>
  )
}
