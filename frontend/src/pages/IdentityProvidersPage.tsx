import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  useIdentityProviders,
  useCreateIdentityProvider,
  useDeleteIdentityProvider,
  useActivateIdentityProvider,
  useDeactivateIdentityProvider,
  useTestConnection,
} from '@/hooks/use-identity'
import type { IdentityProvider } from '@/api/identity'
import { Button } from '@/components/ui/Button'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'

const protocolLabels: Record<string, string> = {
  saml2: 'SAML 2.0',
  oidc: 'OpenID Connect',
  ldap: 'LDAP',
  active_directory: 'Active Directory',
  oauth2: 'OAuth 2.0',
}

export function IdentityProvidersPage() {
  const { data, isLoading } = useIdentityProviders()
  const createProvider = useCreateIdentityProvider()
  const deleteProvider = useDeleteIdentityProvider()
  const activateProvider = useActivateIdentityProvider()
  const deactivateProvider = useDeactivateIdentityProvider()
  const testConnection = useTestConnection()
  const navigate = useNavigate()

  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', protocol: 'oidc', issuer: '', domain_hint: '' })
  const [testResult, setTestResult] = useState<{ id: string; result: unknown } | null>(null)

  const handleCreate = async () => {
    await createProvider.mutateAsync(form as any)
    setShowCreate(false)
    setForm({ name: '', protocol: 'oidc', issuer: '', domain_hint: '' })
  }

  const handleTest = async (provider: IdentityProvider) => {
    const result = await testConnection.mutateAsync({
      name: provider.name,
      protocol: provider.protocol,
      issuer: provider.issuer,
      saml_config: provider.saml_config,
      oidc_config: provider.oidc_config,
      ldap_config: provider.ldap_config,
      oauth2_config: provider.oauth2_config,
    } as any)
    setTestResult({ id: provider.id, result })
  }

  const statusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success'
      case 'inactive': return 'neutral'
      case 'error': return 'critical'
      case 'pending': return 'warning'
      default: return 'neutral'
    }
  }

  if (isLoading) return <div className="flex justify-center py-12"><Spinner size="lg" /></div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Identity Providers</h1>
          <p className="text-sm text-text-muted mt-1">{data?.total ?? 0} configured providers</p>
        </div>
        <Button onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? 'Cancel' : 'Add Provider'}
        </Button>
      </div>

      {showCreate && (
        <Card className="p-4 space-y-3">
          <h3 className="font-medium">Add Identity Provider</h3>
          <div className="grid grid-cols-2 gap-3">
            <input className="input" placeholder="Provider Name *" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
            <select className="input" value={form.protocol} onChange={e => setForm({ ...form, protocol: e.target.value })}>
              <option value="oidc">OpenID Connect</option>
              <option value="saml2">SAML 2.0</option>
              <option value="ldap">LDAP</option>
              <option value="active_directory">Active Directory</option>
              <option value="oauth2">OAuth 2.0</option>
            </select>
            <input className="input" placeholder="Issuer URL" value={form.issuer} onChange={e => setForm({ ...form, issuer: e.target.value })} />
            <input className="input" placeholder="Domain Hint" value={form.domain_hint} onChange={e => setForm({ ...form, domain_hint: e.target.value })} />
          </div>
          <Button onClick={handleCreate} disabled={!form.name}>Create Provider</Button>
        </Card>
      )}

      {testResult && (
        <Card className="p-4">
          <h3 className="font-medium mb-2">Test Connection Result</h3>
          <pre className="text-sm bg-surface-tertiary p-3 rounded overflow-auto max-h-48">
            {JSON.stringify(testResult.result, null, 2)}
          </pre>
          <Button variant="ghost" size="sm" className="mt-2" onClick={() => setTestResult(null)}>Close</Button>
        </Card>
      )}

      <div className="grid gap-4">
        {data?.providers.map((p) => (
          <Card key={p.id} className="p-4">
            <div className="flex items-start justify-between">
              <div className="space-y-1 cursor-pointer" onClick={() => navigate(`/identity/${p.id}`)}>
                <div className="flex items-center gap-2">
                  <span className="font-medium text-text-primary">{p.name}</span>
                  <Badge variant={statusColor(p.status)}>{p.status}</Badge>
                  <Badge variant="info">{protocolLabels[p.protocol] ?? p.protocol}</Badge>
                </div>
                <div className="text-sm text-text-muted">
                  {p.issuer && <span>Issuer: {p.issuer}</span>}
                  {p.domain_hint && <span> &middot; Domain: {p.domain_hint}</span>}
                </div>
                <div className="text-xs text-text-muted space-x-3">
                  {p.jit_provisioning && <span>JIT Provisioning</span>}
                  {p.auto_link_users && <span>Auto-Link Users</span>}
                  {p.enforce_sso && <span>Enforce SSO</span>}
                </div>
              </div>
              <div className="flex gap-2 shrink-0">
                <Button variant="ghost" size="sm" onClick={() => handleTest(p)}>Test</Button>
                {p.status === 'active' ? (
                  <Button variant="ghost" size="sm" onClick={() => deactivateProvider.mutate(p.id)}>Deactivate</Button>
                ) : (
                  <Button variant="ghost" size="sm" onClick={() => activateProvider.mutate(p.id)}>Activate</Button>
                )}
                <Button variant="ghost" size="sm" className="text-red-400" onClick={() => deleteProvider.mutate(p.id)}>Delete</Button>
              </div>
            </div>
          </Card>
        ))}
        {data?.providers.length === 0 && (
          <Card className="p-8 text-center text-text-muted">
            No identity providers configured. Click "Add Provider" to get started.
          </Card>
        )}
      </div>
    </div>
  )
}
