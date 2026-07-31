import { useParams } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { useCve, useSyncCve, useCveRiskAssessment } from '@/hooks/use-threat-intelligence'

export function CveDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: cve, isLoading } = useCve(id)
  const { data: risk } = useCveRiskAssessment(id)
  const syncCve = useSyncCve()

  if (isLoading) {
    return <div className="flex justify-center py-16"><Spinner /></div>
  }
  if (!cve) {
    return (
      <PageContainer>
        <p className="py-16 text-center text-text-muted">CVE not found</p>
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <PageHeader
        title={cve.cve_code}
        description={cve.description.slice(0, 200)}
        actions={
          <Button onClick={() => syncCve.mutate(cve.cve_code)} variant="outline" className="text-xs" disabled={syncCve.isPending}>
            {syncCve.isPending ? 'Syncing...' : 'Re-sync'}
          </Button>
        }
      />

      {/* Overview */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <div className="p-5">
              <h3 className="mb-3 text-sm font-semibold text-text-primary">Description</h3>
              <p className="text-sm text-text-primary">{cve.description}</p>
            </div>
          </Card>

          <Card>
            <div className="p-5">
              <h3 className="mb-3 text-sm font-semibold text-text-primary">CVSS v{cve.cvss_data.version}</h3>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div><span className="text-text-muted">Vector:</span> <span className="text-text-primary font-mono text-xs">{cve.cvss_data.vector_string}</span></div>
                <div><span className="text-text-muted">Base Score:</span> <span className="font-bold text-text-primary">{cve.cvss_data.base_score}</span></div>
                <div><span className="text-text-muted">Severity:</span> <span><Badge variant={cve.severity === 'CRITICAL' ? 'danger' : cve.severity === 'HIGH' ? 'warning' : 'neutral'}>{cve.severity}</Badge></span></div>
                <div><span className="text-text-muted">Exploitability:</span> <span className="text-text-primary">{cve.cvss_data.exploitability_score}</span></div>
                <div><span className="text-text-muted">Impact:</span> <span className="text-text-primary">{cve.cvss_data.impact_score}</span></div>
                <div><span className="text-text-muted">Attack Vector:</span> <span className="text-text-primary">{cve.cvss_data.attack_vector || 'N/A'}</span></div>
                <div><span className="text-text-muted">Attack Complexity:</span> <span className="text-text-primary">{cve.cvss_data.attack_complexity || 'N/A'}</span></div>
                <div><span className="text-text-muted">Privileges Required:</span> <span className="text-text-primary">{cve.cvss_data.privileges_required || 'N/A'}</span></div>
                <div><span className="text-text-muted">User Interaction:</span> <span className="text-text-primary">{cve.cvss_data.user_interaction || 'N/A'}</span></div>
              </div>
            </div>
          </Card>

          {cve.references.length > 0 && (
            <Card>
              <div className="p-5">
                <h3 className="mb-3 text-sm font-semibold text-text-primary">References</h3>
                <div className="space-y-1">
                  {cve.references.map((r, i) => (
                    <a key={i} href={r.url} target="_blank" rel="noopener noreferrer" className="block text-xs text-accent-primary hover:underline truncate">{r.url}</a>
                  ))}
                </div>
              </div>
            </Card>
          )}

          {cve.affected_products.length > 0 && (
            <Card>
              <div className="p-5">
                <h3 className="mb-3 text-sm font-semibold text-text-primary">Affected Products</h3>
                <div className="space-y-1 text-sm">
                  {cve.affected_products.map((p, i) => (
                    <div key={i} className="text-text-primary">{p.vendor}/{p.product} {p.version}</div>
                  ))}
                </div>
              </div>
            </Card>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <Card>
            <div className="p-5">
              <h3 className="mb-3 text-sm font-semibold text-text-primary">Threat Score</h3>
              <p className="text-3xl font-bold text-text-primary">{cve.threat_score.toFixed(1)}</p>
            </div>
          </Card>

          <Card>
            <div className="p-5">
              <h3 className="mb-3 text-sm font-semibold text-text-primary">Risk Assessment</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between"><span className="text-text-muted">Business Risk</span><span className="font-medium text-text-primary">{risk?.business_risk.toFixed(1) ?? '-'}</span></div>
                <div className="flex justify-between"><span className="text-text-muted">Exploitability</span><span className="font-medium text-text-primary">{risk?.exploitability_score.toFixed(1) ?? '-'}</span></div>
                <div className="flex justify-between"><span className="text-text-muted">Likelihood</span><span className="font-medium text-text-primary">{risk?.likelihood.toFixed(1) ?? '-'}</span></div>
                <div className="flex justify-between border-t border-border-primary pt-2"><span className="text-text-muted">Overall</span><span className="font-bold text-text-primary">{risk?.overall_threat_score.toFixed(1) ?? '-'}</span></div>
              </div>
            </div>
          </Card>

          {cve.epss_data && (
            <Card>
              <div className="p-5">
                <h3 className="mb-3 text-sm font-semibold text-text-primary">EPSS</h3>
                <p className="text-2xl font-bold text-text-primary">{(cve.epss_data.score * 100).toFixed(2)}%</p>
                <p className="text-xs text-text-muted">Percentile: {(cve.epss_data.percentile * 100).toFixed(1)}%</p>
              </div>
            </Card>
          )}

          {cve.is_kev && cve.kev_entry && (
            <Card>
              <div className="p-5">
                <h3 className="mb-3 text-sm font-semibold text-red-500">Known Exploited Vulnerability</h3>
                <div className="space-y-1 text-sm">
                  <p><span className="text-text-muted">Vendor:</span> <span className="text-text-primary">{cve.kev_entry.vendor_project}</span></p>
                  <p><span className="text-text-muted">Product:</span> <span className="text-text-primary">{cve.kev_entry.product}</span></p>
                  <p><span className="text-text-muted">Date Added:</span> <span className="text-text-primary">{cve.kev_entry.date_added}</span></p>
                  <p><span className="text-text-muted">Due Date:</span> <span className="text-text-primary">{cve.kev_entry.due_date}</span></p>
                  <p><span className="text-text-muted">Action:</span> <span className="text-text-primary">{cve.kev_entry.required_action}</span></p>
                  {cve.kev_entry.known_ransomware_campaign_use && (
                    <Badge variant="danger">Ransomware Campaign</Badge>
                  )}
                </div>
              </div>
            </Card>
          )}

          <Card>
            <div className="p-5">
              <h3 className="mb-3 text-sm font-semibold text-text-primary">Details</h3>
              <div className="space-y-1 text-sm">
                <p><span className="text-text-muted">Published:</span> <span className="text-text-primary">{cve.published_date || 'N/A'}</span></p>
                <p><span className="text-text-muted">Modified:</span> <span className="text-text-primary">{cve.last_modified || 'N/A'}</span></p>
                <p><span className="text-text-muted">Maturity:</span> <span className="text-text-primary">{cve.exploit_maturity.replace(/_/g, ' ')}</span></p>
                <p><span className="text-text-muted">Created:</span> <span className="text-text-primary">{new Date(cve.created_at).toLocaleDateString()}</span></p>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </PageContainer>
  )
}
