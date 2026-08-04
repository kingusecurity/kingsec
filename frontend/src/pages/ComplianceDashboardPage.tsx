import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/Tabs'
import { useFrameworks, useFrameworkControls } from '@/hooks/use-compliance'

const frameworkColors: Record<string, string> = {
  cis_v8: 'bg-blue-500',
  nist_csf_2: 'bg-green-500',
  owasp_top_10: 'bg-red-500',
  cwe: 'bg-purple-500',
  cve: 'bg-orange-500',
  mitre_att_ck: 'bg-yellow-500',
  iso_27001: 'bg-indigo-500',
  pci_dss_4: 'bg-pink-500',
}

// Single source of truth for the report types this page can generate — the
// "Reports" overview tile and the Reports tab's description cards both read
// from this array so they can't drift from each other or from what the
// backend's /compliance/report endpoint actually supports (type: 'executive'
// | 'technical' | 'gap_remediation').
const REPORT_TYPES = [
  { id: 'executive', label: 'Executive', description: 'High-level overview for stakeholders' },
  { id: 'technical', label: 'Technical', description: 'Detailed finding-to-control mappings' },
  { id: 'gap_remediation', label: 'Gap Remediation', description: 'Unaddressed controls with recommendations' },
] as const

function CoverageCharts({ frameworks }: { frameworks: { id: string; name: string }[] }) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {frameworks.map((fw) => (
        <Card key={fw.id}>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <span className={`h-3 w-3 rounded-full ${frameworkColors[fw.id] || 'bg-gray-500'}`} />
              {fw.name}
            </CardTitle>
          </CardHeader>
          <div className="px-5 pb-5">
            <p className="text-2xl font-bold">--%</p>
            <p className="text-xs text-text-muted">Connect findings to see coverage</p>
          </div>
        </Card>
      ))}
    </div>
  )
}

export function ComplianceDashboardPage() {
  const [activeTab, setActiveTab] = useState('overview')
  const [selectedFramework, setSelectedFramework] = useState<string>('')
  const { data: frameworks, isLoading: frameworksLoading, isError, error, refetch } = useFrameworks()
  const { data: controls, isLoading: controlsLoading } = useFrameworkControls(selectedFramework || null)

  return (
    <PageContainer>
      <PageHeader
        title="Compliance Dashboard"
        description="Map findings to security frameworks and track compliance coverage"
      />

      {isError ? (
        <ErrorState
          title="Failed to load compliance frameworks"
          message={(error as Error)?.message}
          onRetry={() => refetch()}
        />
      ) : frameworksLoading ? (
        <div className="flex justify-center py-12">
          <Spinner size="lg" />
        </div>
      ) : (
        <div className="space-y-6">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="frameworks">Frameworks</TabsTrigger>
              <TabsTrigger value="gaps">Gap Analysis</TabsTrigger>
              <TabsTrigger value="reports">Reports</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-6 pt-4">
              <div className="grid gap-4 sm:grid-cols-3">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm text-text-secondary">Frameworks</CardTitle>
                  </CardHeader>
                  <div className="px-5 pb-5">
                    <p className="text-2xl font-bold">{frameworks?.length ?? 0}</p>
                    <p className="text-xs text-text-muted">frameworks loaded</p>
                  </div>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-sm text-text-secondary">
                      Mapping
                      <Badge variant="neutral" size="sm">Platform</Badge>
                    </CardTitle>
                  </CardHeader>
                  <div className="px-5 pb-5">
                    <p className="text-2xl font-bold">Auto</p>
                    <p className="text-xs text-text-muted">keyword-based &middot; not specific to your data</p>
                  </div>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm text-text-secondary">Reports</CardTitle>
                  </CardHeader>
                  <div className="px-5 pb-5">
                    <p className="text-2xl font-bold">{REPORT_TYPES.length}</p>
                    <p className="text-xs text-text-muted">formats available</p>
                  </div>
                </Card>
              </div>

              <div>
                <h3 className="mb-3 text-lg font-medium">Framework Coverage</h3>
                <CoverageCharts frameworks={frameworks ?? []} />
              </div>
            </TabsContent>

            <TabsContent value="frameworks" className="space-y-4 pt-4">
              <div className="flex items-center gap-2">
                <select
                  value={selectedFramework}
                  onChange={(e) => setSelectedFramework(e.target.value)}
                  className="flex h-10 w-64 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent"
                >
                  <option value="">Select a framework...</option>
                  {frameworks?.map((fw) => (
                    <option key={fw.id} value={fw.id}>
                      {fw.name}
                    </option>
                  ))}
                </select>
                {selectedFramework && (
                  <Badge variant="info">
                    {(frameworks ?? []).find((f) => f.id === selectedFramework)?.mapping_only
                      ? 'Mapping Only'
                      : 'Full Support'}
                  </Badge>
                )}
              </div>

              {controlsLoading ? (
                <div className="flex justify-center py-8">
                  <Spinner />
                </div>
              ) : controls && controls.length > 0 ? (
                <div className="space-y-2">
                  {controls.map((ctrl) => (
                    <Card key={ctrl.control_id}>
                      <div className="flex items-start gap-3 px-5 py-3">
                        <Badge variant="neutral" className="shrink-0 font-mono text-xs">
                          {ctrl.control_id}
                        </Badge>
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium">{ctrl.title}</p>
                          <p className="text-xs text-text-muted line-clamp-1">{ctrl.description}</p>
                        </div>
                        {ctrl.category && (
                          <Badge variant="neutral" className="shrink-0 text-xs">
                            {ctrl.category}
                          </Badge>
                        )}
                      </div>
                    </Card>
                  ))}
                </div>
              ) : selectedFramework ? (
                <p className="py-8 text-center text-text-muted">No controls found for this framework.</p>
              ) : (
                <p className="py-8 text-center text-text-muted">Select a framework to view its controls.</p>
              )}
            </TabsContent>

            <TabsContent value="gaps" className="space-y-4 pt-4">
              <Card>
                <div className="px-5 py-8 text-center text-text-muted">
                  <p className="text-lg font-medium">Gap Analysis</p>
                  <p className="mt-1 text-sm">
                    Map findings to frameworks first, then run gap analysis to identify unaddressed controls.
                  </p>
                  <ol className="mt-4 mx-auto max-w-md space-y-2 text-left text-sm">
                    <li>1. Navigate to an assessment with findings</li>
                    <li>2. Map findings to framework controls</li>
                    <li>3. Run gap analysis per framework</li>
                    <li>4. Generate remediation report</li>
                  </ol>
                </div>
              </Card>
            </TabsContent>

            <TabsContent value="reports" className="space-y-4 pt-4">
              <Card>
                <div className="px-5 py-8 text-center text-text-muted">
                  <p className="text-lg font-medium">Compliance Reports</p>
                  <p className="mt-1 text-sm">
                    Generate executive, technical, or gap remediation compliance reports.
                  </p>
                  <div className="mt-4 mx-auto grid max-w-lg gap-3 sm:grid-cols-3">
                    {REPORT_TYPES.map((type) => (
                      <div key={type.id} className="rounded-lg border border-border p-3">
                        <p className="font-medium text-text-primary">{type.label}</p>
                        <p className="text-xs mt-1">{type.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      )}
    </PageContainer>
  )
}
