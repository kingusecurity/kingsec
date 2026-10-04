import { useState } from 'react'
import { PageContainer, PageHeader, ContentSection } from '@/components/layout/PageContainer'
import { Card, CardHeader } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { Alert } from '@/components/ui/Alert'
import { SurfaceTierNotice } from '@/components/shared/SurfaceTierNotice'
import { useAuthStore } from '@/store/auth'
import { useGrants, useCreateGrant, useRevokeGrant } from '@/hooks/use-grants'
import type { AuthorizationGrant, CreateAuthorizationGrantBody, TargetSpecificationType } from '@/api/grants'
import { ShieldCheck } from 'lucide-react'

interface TargetTypeInfo {
  label: string
  example: string
  description: string
}

const TARGET_TYPE_INFO: Record<TargetSpecificationType, TargetTypeInfo> = {
  ip_address: {
    label: 'IP Address',
    example: '10.0.0.5',
    description: 'A single IP address. Authorizes scanning that one host directly, at any port.',
  },
  network: {
    label: 'Network (CIDR range)',
    example: '10.0.0.0/24',
    description: 'A range of IP addresses in CIDR notation. Authorizes scanning every host in that range.',
  },
  hostname: {
    label: 'Hostname',
    example: 'app.example.com',
    description: 'A single hostname. Authorizes scanning that host by name, at any port.',
  },
  wildcard_hostname: {
    label: 'Wildcard Hostname',
    example: '*.example.com',
    description: 'A wildcard pattern. Authorizes scanning any subdomain that matches it.',
  },
  url_prefix: {
    label: 'URL Prefix',
    example: 'https://app.example.com/',
    description: 'A specific web address. Authorizes scanning the web application at that URL.',
  },
}

const TARGET_TYPES = Object.keys(TARGET_TYPE_INFO) as TargetSpecificationType[]

interface GrantFormState {
  authorized_by: string
  authorizing_organization: string
  target_specification_type: TargetSpecificationType
  target_specification_value: string
  valid_from: string
  valid_until: string
}

function defaultValidWindow() {
  const now = new Date()
  const in90Days = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000)
  // datetime-local inputs need "YYYY-MM-DDTHH:mm", no timezone/seconds.
  const toLocalInput = (d: Date) => d.toISOString().slice(0, 16)
  return { valid_from: toLocalInput(now), valid_until: toLocalInput(in90Days) }
}

function emptyForm(): GrantFormState {
  return {
    authorized_by: '',
    authorizing_organization: '',
    target_specification_type: 'ip_address',
    target_specification_value: '',
    ...defaultValidWindow(),
  }
}

function grantStatus(grant: AuthorizationGrant): { label: string; variant: 'success' | 'warning' | 'neutral' | 'critical' } {
  if (grant.revoked_at) return { label: 'Revoked', variant: 'critical' }
  if (new Date(grant.valid_until) < new Date()) return { label: 'Expired', variant: 'warning' }
  if (new Date(grant.valid_from) > new Date()) return { label: 'Not yet active', variant: 'neutral' }
  return { label: 'Active', variant: 'success' }
}

export function GrantsPage() {
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.role?.toLowerCase() === 'admin'

  const { data, isLoading, error, refetch } = useGrants()
  const createGrant = useCreateGrant()
  const revokeGrant = useRevokeGrant()

  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState<GrantFormState>(emptyForm())

  const openCreateForm = () => {
    setForm(emptyForm())
    setShowForm(true)
  }

  const closeForm = () => {
    setShowForm(false)
    setForm(emptyForm())
  }

  const handleSubmit = async () => {
    const payload: CreateAuthorizationGrantBody = {
      authorized_by: form.authorized_by,
      authorizing_organization: form.authorizing_organization,
      target_specification_type: form.target_specification_type,
      target_specification_value: form.target_specification_value,
      valid_from: new Date(form.valid_from).toISOString(),
      valid_until: new Date(form.valid_until).toISOString(),
    }
    await createGrant.mutateAsync(payload)
    closeForm()
  }

  const canSubmit =
    !!form.authorized_by &&
    !!form.authorizing_organization &&
    !!form.target_specification_value &&
    !!form.valid_from &&
    !!form.valid_until

  const selectedTypeInfo = TARGET_TYPE_INFO[form.target_specification_type]

  if (error) {
    return (
      <PageContainer>
        <PageHeader title="Authorization Grants" />
        <ErrorState title="Failed to load grants" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  const grants = data?.items ?? []

  return (
    <PageContainer>
      <PageHeader
        title="Authorization Grants"
        description="Who has authorized scanning which targets. KingSec refuses to scan anything without a covering grant."
        actions={
          isAdmin ? (
            <Button onClick={showForm ? closeForm : openCreateForm} variant={showForm ? 'outline' : 'primary'}>
              {showForm ? 'Cancel' : 'Create Grant'}
            </Button>
          ) : undefined
        }
      />

      {!isAdmin && (
        <Alert variant="info" title="Read-only">
          Only an Administrator can create or revoke authorization grants. You can view the list below.
        </Alert>
      )}

      {showForm && isAdmin && (
        <Card className="p-4 space-y-4">
          <h3 className="font-medium text-text-primary">Create Authorization Grant</h3>

          <div className="grid gap-3 sm:grid-cols-2">
            <Input
              label="Authorized By *"
              placeholder="ciso@example.com"
              helperText="Who authorized this - a person, ticket, or engagement reference."
              value={form.authorized_by}
              onChange={(e) => setForm({ ...form, authorized_by: e.target.value })}
            />
            <Input
              label="Authorizing Organization *"
              placeholder="Example Corp"
              helperText="The organization this authorization was issued on behalf of."
              value={form.authorizing_organization}
              onChange={(e) => setForm({ ...form, authorizing_organization: e.target.value })}
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="target-type" className="block text-sm font-medium text-text-secondary">
              Target Type *
            </label>
            <select
              id="target-type"
              value={form.target_specification_type}
              onChange={(e) =>
                setForm({ ...form, target_specification_type: e.target.value as TargetSpecificationType })
              }
              className="flex h-10 w-full rounded-lg border border-border-light bg-surface px-3 py-2 text-sm text-text-primary"
            >
              {TARGET_TYPES.map((t) => (
                <option key={t} value={t}>
                  {TARGET_TYPE_INFO[t].label}
                </option>
              ))}
            </select>
            <p className="text-xs text-text-muted">{selectedTypeInfo.description}</p>
          </div>

          {form.target_specification_type === 'url_prefix' && <SurfaceTierNotice />}

          <Input
            label="Target Value *"
            placeholder={selectedTypeInfo.example}
            helperText={`Example: ${selectedTypeInfo.example}`}
            value={form.target_specification_value}
            onChange={(e) => setForm({ ...form, target_specification_value: e.target.value })}
          />

          <div className="grid gap-3 sm:grid-cols-2">
            <Input
              label="Valid From *"
              type="datetime-local"
              value={form.valid_from}
              onChange={(e) => setForm({ ...form, valid_from: e.target.value })}
            />
            <Input
              label="Valid Until *"
              type="datetime-local"
              value={form.valid_until}
              onChange={(e) => setForm({ ...form, valid_until: e.target.value })}
            />
          </div>

          <Button onClick={handleSubmit} disabled={!canSubmit || createGrant.isPending}>
            {createGrant.isPending ? 'Creating...' : 'Create Grant'}
          </Button>
        </Card>
      )}

      {isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <CardHeader>
                <Skeleton className="h-5 w-32" />
                <Skeleton className="h-4 w-24" />
              </CardHeader>
            </Card>
          ))}
        </div>
      ) : grants.length > 0 ? (
        <ContentSection title="Grants">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {grants.map((g) => {
              const status = grantStatus(g)
              return (
                <Card key={g.id}>
                  <div className="p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="h-5 w-5 text-accent" />
                        <h3 className="text-sm font-semibold text-text-primary">
                          {TARGET_TYPE_INFO[g.target_specification_type]?.label ?? g.target_specification_type}
                        </h3>
                      </div>
                      <Badge variant={status.variant} size="sm">{status.label}</Badge>
                    </div>
                    <p className="text-sm font-mono text-text-secondary break-all">{g.target_specification_value}</p>
                    <p className="text-xs text-text-muted">
                      Authorized by {g.authorized_by} ({g.authorizing_organization})
                    </p>
                    <p className="text-xs text-text-muted">
                      {new Date(g.valid_from).toLocaleString()} - {new Date(g.valid_until).toLocaleString()}
                    </p>
                    {isAdmin && !g.revoked_at && (
                      <Button
                        onClick={() => revokeGrant.mutate(g.id)}
                        disabled={revokeGrant.isPending}
                        variant="outline"
                        size="sm"
                        className="text-xs text-red-500"
                      >
                        Revoke
                      </Button>
                    )}
                  </div>
                </Card>
              )
            })}
          </div>
        </ContentSection>
      ) : (
        <Card>
          <EmptyState
            icon={<ShieldCheck className="h-8 w-8" />}
            title="No authorization grants"
            description="KingSec refuses to scan any target without a covering grant. Create one to authorize a scan."
          />
        </Card>
      )}
    </PageContainer>
  )
}
