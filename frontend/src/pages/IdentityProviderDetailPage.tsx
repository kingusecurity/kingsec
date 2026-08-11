import { useParams, useNavigate } from 'react-router-dom'
import { useIdentityProvider, useDeleteIdentityProvider, useActivateIdentityProvider, useDeactivateIdentityProvider, useTestConnection } from '@/hooks/use-identity'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'

const protocolLabels: Record<string, string> = {
  saml2: 'SAML 2.0',
  oidc: 'OpenID Connect',
  ldap: 'LDAP',
  active_directory: 'Active Directory',
  oauth2: 'OAuth 2.0',
}

export function IdentityProviderDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data, isLoading } = useIdentityProvider(id!)
  const deleteProvider = useDeleteIdentityProvider()
  const activateProvider = useActivateIdentityProvider()
  const deactivateProvider = useDeactivateIdentityProvider()
  const testConnection = useTestConnection()
  const navigate = useNavigate()

  if (isLoading) return <div className="flex justify-center py-12"><Spinner size="lg" /></div>
  if (!data?.provider) return <div className="text-center py-12 text-text-muted">Identity provider not found</div>

  const p = data.provider

  const statusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success'
      case 'inactive': return 'neutral'
      case 'error': return 'critical'
      case 'pending': return 'warning'
      default: return 'neutral'
    }
  }

  const handleDelete = async () => {
    await deleteProvider.mutateAsync(p.id)
    navigate('/identity')
  }

  const handleTest = async () => {
    await testConnection.mutateAsync({
      name: p.name,
      protocol: p.protocol,
      issuer: p.issuer,
      saml_config: p.saml_config,
      oidc_config: p.oidc_config,
      ldap_config: p.ldap_config,
      oauth2_config: p.oauth2_config,
    } as any)
  }

  const configSummary = () => {
    switch (p.protocol) {
      case 'saml2':
        return [
          { label: 'Entity ID', value: p.saml_config.entity_id },
          { label: 'SSO URL', value: p.saml_config.sso_url },
          { label: 'SLO URL', value: p.saml_config.slo_url },
          { label: 'Name ID Format', value: p.saml_config.name_id_format },
          { label: 'Signature Algorithm', value: p.saml_config.signature_algorithm },
          { label: 'Assertion Encrypted', value: p.saml_config.assertion_encrypted ? 'Yes' : 'No' },
        ]
      case 'oidc':
        return [
          { label: 'Issuer URL', value: p.oidc_config.issuer_url },
          { label: 'Client ID', value: p.oidc_config.client_id },
          { label: 'Authorization URL', value: p.oidc_config.authorization_url },
          { label: 'Token URL', value: p.oidc_config.token_url },
          { label: 'Scopes', value: p.oidc_config.scopes.join(', ') },
          { label: 'Subject Claim', value: p.oidc_config.subject_claim },
        ]
      case 'ldap':
      case 'active_directory':
        return [
          { label: 'Server URL', value: p.ldap_config.server_url },
          { label: 'Base DN', value: p.ldap_config.base_dn },
          { label: 'Bind DN', value: p.ldap_config.bind_dn },
          { label: 'User Filter', value: p.ldap_config.user_filter },
          { label: 'Use TLS', value: p.ldap_config.use_tls ? 'Yes' : 'No' },
          { label: 'Username Attr', value: p.ldap_config.username_attribute },
        ]
      case 'oauth2':
        return [
          { label: 'Authorize URL', value: p.oauth2_config.authorize_url },
          { label: 'Token URL', value: p.oauth2_config.token_url },
          { label: 'Client ID', value: p.oauth2_config.client_id },
          { label: 'Scopes', value: p.oauth2_config.scopes.join(', ') },
          { label: 'Subject Claim', value: p.oauth2_config.subject_claim },
        ]
      default:
        return []
    }
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">{p.name}</h1>
          <div className="flex items-center gap-2 mt-1">
            <Badge variant={statusColor(p.status)}>{p.status}</Badge>
            <Badge variant="info">{protocolLabels[p.protocol] ?? p.protocol}</Badge>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => navigate('/identity')}>Back</Button>
          <Button variant="ghost" onClick={handleTest} disabled={testConnection.isPending}>
            {testConnection.isPending ? 'Testing...' : 'Test Connection'}
          </Button>
          {p.status === 'active' ? (
            <Button variant="ghost" onClick={() => deactivateProvider.mutate(p.id)}>Deactivate</Button>
          ) : (
            <Button variant="ghost" onClick={() => activateProvider.mutate(p.id)}>Activate</Button>
          )}
          <Button variant="danger" onClick={handleDelete}>Delete</Button>
        </div>
      </div>

      {testConnection.data && (
        <Card className="p-4 space-y-2">
          <h3 className="font-medium text-text-primary">Test Connection Result</h3>
          <div className="flex items-center gap-2">
            <Badge variant={testConnection.data.success ? 'success' : 'critical'}>
              {testConnection.data.success ? 'Success' : 'Failed'}
            </Badge>
            <span className="text-sm text-text-muted">{testConnection.data.message || testConnection.data.error}</span>
          </div>
          {testConnection.data.duration_ms > 0 && (
            <p className="text-xs text-text-muted">Duration: {testConnection.data.duration_ms}ms</p>
          )}
        </Card>
      )}

      <div className="grid grid-cols-2 gap-4">
        <Card className="p-4 space-y-3">
          <h3 className="font-medium text-text-primary">Provider Info</h3>
          <div className="space-y-2 text-sm">
            <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-text-muted">Protocol</span><span className="text-right">{protocolLabels[p.protocol]}</span></div>
            <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-text-muted">Issuer</span><span className="break-all text-right">{p.issuer || '-'}</span></div>
            <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-text-muted">Domain Hint</span><span className="break-all text-right">{p.domain_hint || '-'}</span></div>
            <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-text-muted">Organization</span><span className="break-all text-right">{p.organization_id || '-'}</span></div>
            <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-text-muted">Created By</span><span className="break-all text-right">{p.created_by || '-'}</span></div>
          </div>
        </Card>

        <Card className="p-4 space-y-3">
          <h3 className="font-medium text-text-primary">Features</h3>
          <div className="space-y-2 text-sm">
            <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-text-muted">JIT Provisioning</span><span className="text-right">{p.jit_provisioning ? 'Enabled' : 'Disabled'}</span></div>
            <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-text-muted">Auto-Link Users</span><span className="text-right">{p.auto_link_users ? 'Enabled' : 'Disabled'}</span></div>
            <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-text-muted">Enforce SSO</span><span className="text-right">{p.enforce_sso ? 'Enabled' : 'Disabled'}</span></div>
            <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-text-muted">Created</span><span className="text-right">{p.created_at ? new Date(p.created_at).toLocaleDateString() : '-'}</span></div>
            <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-text-muted">Updated</span><span className="text-right">{p.updated_at ? new Date(p.updated_at).toLocaleDateString() : '-'}</span></div>
          </div>
        </Card>
      </div>

      <Card className="p-4 space-y-3">
        <h3 className="font-medium text-text-primary">Protocol Configuration</h3>
        <div className="space-y-2 text-sm">
          {configSummary().map((item) => (
            <div key={item.label} className="flex items-start justify-between gap-4">
              <span className="shrink-0 text-text-muted">{item.label}</span>
              <span className="truncate ml-4 max-w-xs text-right">{item.value || '-'}</span>
            </div>
          ))}
        </div>
      </Card>

      <Card className="p-4 space-y-3">
        <h3 className="font-medium text-text-primary">Role Mappings ({p.role_mappings.length})</h3>
        {p.role_mappings.length === 0 ? (
          <p className="text-sm text-text-muted">No role mappings configured</p>
        ) : (
          <div className="space-y-2">
            {p.role_mappings.map((r, i) => (
              <div key={i} className="flex items-center justify-between text-sm p-2 bg-surface-tertiary rounded">
                <span className="font-medium">{r.external_group}</span>
                <div className="flex items-center gap-2">
                  <Badge variant="info">{r.kingsec_role}</Badge>
                  <span className="text-xs text-text-muted">Priority: {r.priority}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card className="p-4 space-y-3">
        <h3 className="font-medium text-text-primary">Group Mappings ({p.group_mappings.length})</h3>
        {p.group_mappings.length === 0 ? (
          <p className="text-sm text-text-muted">No group mappings configured</p>
        ) : (
          <div className="space-y-2">
            {p.group_mappings.map((g, i) => (
              <div key={i} className="flex items-center justify-between text-sm p-2 bg-surface-tertiary rounded">
                <span className="font-medium">{g.external_group}</span>
                <div className="flex items-center gap-2">
                  <Badge variant="info">{g.kingsec_role}</Badge>
                  {g.organization_id && <span className="text-xs text-text-muted">Org: {g.organization_id}</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
