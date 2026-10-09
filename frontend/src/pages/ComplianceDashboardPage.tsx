import { useEffect, useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { Alert } from '@/components/ui/Alert'
import { Button } from '@/components/ui/Button'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/Tabs'
import {
  useAnalyzeComplianceGaps,
  useCalculateCoverage,
  useFrameworkControls,
  useFrameworks,
  useGenerateComplianceReport,
  useMapFindings,
} from '@/hooks/use-compliance'
import { useAssessment, useAssessments } from '@/hooks/use-assessments'
import { useFindings } from '@/hooks/use-findings'
import { useAuthStore } from '@/store/auth'
import { adminApi } from '@/api/admin'
import type {
  ExecutiveReport,
  FindingMapping,
  FrameworkCoverage,
  GapItem,
  GapRemediationReport,
  TechnicalReport,
} from '@/api/compliance'

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

const REPORT_TYPES = [
  { id: 'executive', label: 'Executive', description: 'High-level overview for stakeholders' },
  { id: 'technical', label: 'Technical', description: 'Detailed finding-to-control mappings' },
  { id: 'gap_remediation', label: 'Gap Remediation', description: 'Unaddressed controls with recommendations' },
] as const

type ReportType = (typeof REPORT_TYPES)[number]['id']
type ComplianceReport = ExecutiveReport | TechnicalReport | GapRemediationReport

function CoverageCharts({
  frameworks,
  coverage,
}: {
  frameworks: { id: string; name: string }[]
  coverage: FrameworkCoverage[]
}) {
  const byFramework = new Map(coverage.map((item) => [item.framework, item]))

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {frameworks.map((fw) => {
        const result = byFramework.get(fw.id)
        return (
          <Card key={fw.id}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <span className={`h-3 w-3 rounded-full ${frameworkColors[fw.id] || 'bg-gray-500'}`} />
                {fw.name}
              </CardTitle>
            </CardHeader>
            <div className="px-5 pb-5">
              <p className="text-2xl font-bold">{result ? `${result.coverage_percent.toFixed(1)}%` : '--%'}</p>
              {result ? (
                <p className="text-xs text-text-muted">
                  {result.passed} mapped · {result.failed} failed · {result.not_assessed} not assessed
                </p>
              ) : (
                <p className="text-xs text-text-muted">Select an assessment and map its findings to calculate coverage.</p>
              )}
            </div>
          </Card>
        )
      })}
    </div>
  )
}

function downloadJson(report: ComplianceReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `kingsec-compliance-${report.assessment_id}-${report.report_id}.json`
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

export function ComplianceDashboardPage() {
  const role = useAuthStore((state) => state.user?.role.toLowerCase())
  const canAnalyze = role === 'analyst' || role === 'admin'
  const [activeTab, setActiveTab] = useState('overview')
  const [selectedAssessmentId, setSelectedAssessmentId] = useState('')
  const [selectedFramework, setSelectedFramework] = useState('')
  const [reportType, setReportType] = useState<ReportType>('executive')
  const [mappings, setMappings] = useState<FindingMapping[]>([])
  const [coverage, setCoverage] = useState<FrameworkCoverage[]>([])
  const [gaps, setGaps] = useState<GapItem[] | null>(null)
  const [report, setReport] = useState<ComplianceReport | null>(null)
  const [isLoadingAllFindings, setIsLoadingAllFindings] = useState(false)
  const [localWorkflowError, setLocalWorkflowError] = useState<Error | null>(null)

  const {
    data: frameworks,
    isLoading: frameworksLoading,
    isError: frameworksError,
    error,
    refetch,
  } = useFrameworks()
  const {
    data: controls,
    isLoading: controlsLoading,
    isError: controlsError,
    error: controlsLoadError,
    refetch: refetchControls,
  } = useFrameworkControls(selectedFramework || null)
  const { data: assessmentList, isLoading: assessmentsLoading } = useAssessments({
    limit: 100,
    order_by: 'created_at',
    order_dir: 'desc',
  })
  const { data: assessment, isLoading: assessmentLoading } = useAssessment(selectedAssessmentId)
  const { data: findingsData, isLoading: findingsLoading } = useFindings({
    assessment_id: selectedAssessmentId || undefined,
    limit: 200,
  })
  const mapFindings = useMapFindings()
  const calculateCoverage = useCalculateCoverage()
  const analyzeGaps = useAnalyzeComplianceGaps()
  const generateReport = useGenerateComplianceReport()

  const completedAssessments = (assessmentList?.items ?? []).filter((item) =>
    item.status === 'completed' || item.status === 'completed_with_gaps',
  )

  useEffect(() => {
    if (!selectedAssessmentId && completedAssessments[0]) {
      setSelectedAssessmentId(completedAssessments[0].assessment_id)
    }
  }, [completedAssessments, selectedAssessmentId])

  useEffect(() => {
    if (!selectedFramework && frameworks?.[0]) {
      setSelectedFramework(frameworks[0].id)
    }
  }, [frameworks, selectedFramework])

  useEffect(() => {
    setMappings([])
    setCoverage([])
    setGaps(null)
    setReport(null)
  }, [selectedAssessmentId])

  const handleMapFindings = async () => {
    if (!assessment) return
    setIsLoadingAllFindings(true)
    setLocalWorkflowError(null)
    try {
      const firstPage = await adminApi.findings({
        assessment_id: assessment.assessment_id,
        limit: 200,
        offset: 0,
      })
      const allFindings = [...firstPage.items]
      while (allFindings.length < firstPage.total) {
        const page = await adminApi.findings({
          assessment_id: assessment.assessment_id,
          limit: 200,
          offset: allFindings.length,
        })
        if (page.items.length === 0) {
          throw new Error('Finding pagination ended before all assessment evidence was loaded.')
        }
        allFindings.push(...page.items)
      }
      if (allFindings.length === 0) return

      const mapped = await mapFindings.mutateAsync(
        allFindings.map((finding) => ({
          id: finding.finding_id,
          title: finding.title,
          description: finding.description,
          severity: finding.severity,
        })),
      )
      setMappings(mapped.mappings)
      const calculated = await calculateCoverage.mutateAsync({ mappings: mapped.mappings })
      setCoverage(calculated)
      setGaps(null)
      setReport(null)
    } catch (error) {
      setLocalWorkflowError(error instanceof Error ? error : new Error('Compliance workflow failed.'))
    } finally {
      setIsLoadingAllFindings(false)
    }
  }

  const handleAnalyzeGaps = async () => {
    if (!selectedFramework || mappings.length === 0) return
    const result = await analyzeGaps.mutateAsync({ framework: selectedFramework, mappings })
    setGaps(result.gaps)
  }

  const handleGenerateReport = async () => {
    if (!assessment || mappings.length === 0) return
    const generated = await generateReport.mutateAsync({
      assessment_id: assessment.assessment_id,
      target: assessment.target,
      mappings,
      frameworks: frameworks?.map((framework) => framework.id),
      type: reportType,
    })
    setReport(generated)
  }

  const workflowError = mapFindings.error
    ?? calculateCoverage.error
    ?? analyzeGaps.error
    ?? generateReport.error
    ?? localWorkflowError

  return (
    <PageContainer>
      <PageHeader
        title="Compliance Dashboard"
        description="Map assessment findings to security-framework controls — a decision aid, not a certified compliance assessment"
      />

      {frameworksError ? (
        <ErrorState
          title="Failed to load compliance frameworks"
          message={(error as Error)?.message}
          onRetry={() => refetch()}
        />
      ) : frameworksLoading ? (
        <div className="flex justify-center py-12"><Spinner size="lg" /></div>
      ) : (
        <div className="space-y-6">
          {canAnalyze ? (
            <Card className="p-5">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                <div className="min-w-0 flex-1">
                  <label htmlFor="compliance-assessment" className="mb-1 block text-sm font-medium text-text-primary">
                    Assessment evidence
                  </label>
                  {assessmentsLoading ? (
                    <div className="flex h-10 items-center"><Spinner size="sm" /></div>
                  ) : completedAssessments.length > 0 ? (
                    <select
                      id="compliance-assessment"
                      value={selectedAssessmentId}
                      onChange={(event) => setSelectedAssessmentId(event.target.value)}
                      className="flex h-10 w-full rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent"
                    >
                      {completedAssessments.map((item) => (
                        <option key={item.assessment_id} value={item.assessment_id}>
                          {item.target} · {item.findings_count} findings · {item.status.replace(/_/g, ' ')}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <p className="text-sm text-text-muted">Complete an assessment before calculating framework coverage.</p>
                  )}
                </div>
                <Button
                  onClick={handleMapFindings}
                  loading={isLoadingAllFindings || mapFindings.isPending || calculateCoverage.isPending || assessmentLoading || findingsLoading}
                  disabled={!assessment || (findingsData?.items.length ?? 0) === 0}
                >
                  Map Findings &amp; Calculate Coverage
                </Button>
              </div>
              {assessment && !findingsLoading && (findingsData?.items.length ?? 0) === 0 && (
                <p className="mt-3 text-sm text-text-muted">This assessment has no findings to map.</p>
              )}
              {mappings.length > 0 && (
                <p className="mt-3 text-sm text-emerald-400" role="status">
                  Mapped {mappings.length} findings. Coverage, gap analysis, and report generation are ready.
                </p>
              )}
            </Card>
          ) : (
            <Alert title="Read-only compliance catalog">
              Viewers can inspect supported frameworks and controls. An analyst or administrator must map assessment evidence or generate reports.
            </Alert>
          )}

          {workflowError && (
            <Alert variant="error" title="Compliance workflow failed">
              {(workflowError as Error).message}
            </Alert>
          )}

          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="frameworks">Frameworks</TabsTrigger>
              {canAnalyze && <TabsTrigger value="gaps">Gap Analysis</TabsTrigger>}
              {canAnalyze && <TabsTrigger value="reports">Reports</TabsTrigger>}
            </TabsList>

            <TabsContent value="overview" className="space-y-6 pt-4">
              <div className="grid gap-4 sm:grid-cols-3">
                <Card>
                  <CardHeader><CardTitle className="text-sm text-text-secondary">Frameworks</CardTitle></CardHeader>
                  <div className="px-5 pb-5">
                    <p className="text-2xl font-bold">{frameworks?.length ?? 0}</p>
                    <p className="text-xs text-text-muted">frameworks loaded</p>
                  </div>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-sm text-text-secondary">
                      Mapping <Badge variant="neutral" size="sm">Keyword based</Badge>
                    </CardTitle>
                  </CardHeader>
                  <div className="px-5 pb-5">
                    <p className="text-2xl font-bold">{mappings.length || '--'}</p>
                    <p className="text-xs text-text-muted">finding mappings in this workspace</p>
                  </div>
                </Card>
                <Card>
                  <CardHeader><CardTitle className="text-sm text-text-secondary">Report formats</CardTitle></CardHeader>
                  <div className="px-5 pb-5">
                    <p className="text-2xl font-bold">{REPORT_TYPES.length}</p>
                    <p className="text-xs text-text-muted">JSON exports available</p>
                  </div>
                </Card>
              </div>

              <div>
                <h2 className="mb-3 text-lg font-medium">Framework Coverage</h2>
                <CoverageCharts frameworks={frameworks ?? []} coverage={coverage} />
              </div>
            </TabsContent>

            <TabsContent value="frameworks" className="space-y-4 pt-4">
              <div className="flex flex-wrap items-center gap-2">
                <label htmlFor="framework-catalog" className="sr-only">Framework</label>
                <select
                  id="framework-catalog"
                  value={selectedFramework}
                  onChange={(event) => setSelectedFramework(event.target.value)}
                  className="flex h-10 w-full rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent sm:w-72"
                >
                  <option value="">Select a framework...</option>
                  {frameworks?.map((fw) => <option key={fw.id} value={fw.id}>{fw.name}</option>)}
                </select>
                {selectedFramework && (
                  <Badge variant="info">
                    {(frameworks ?? []).find((fw) => fw.id === selectedFramework)?.mapping_only
                      ? 'Mapping Only'
                      : 'Full Support'}
                  </Badge>
                )}
              </div>

              {controlsError ? (
                <ErrorState
                  title="Failed to load framework controls"
                  message={(controlsLoadError as Error)?.message}
                  onRetry={() => refetchControls()}
                />
              ) : controlsLoading ? (
                <div className="flex justify-center py-8"><Spinner /></div>
              ) : controls && controls.length > 0 ? (
                <div className="space-y-2">
                  {controls.map((control) => (
                    <Card key={control.control_id}>
                      <div className="flex flex-col gap-3 px-5 py-3 sm:flex-row sm:items-start">
                        <Badge variant="neutral" className="w-fit shrink-0 font-mono text-xs">{control.control_id}</Badge>
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium">{control.title}</p>
                          <p className="text-xs text-text-muted">{control.description}</p>
                        </div>
                        {control.category && <Badge variant="neutral" className="w-fit shrink-0 text-xs">{control.category}</Badge>}
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

            {canAnalyze && (
              <TabsContent value="gaps" className="space-y-4 pt-4">
                <Card className="p-5">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                    <div>
                      <label htmlFor="gap-framework" className="mb-1 block text-sm font-medium text-text-primary">Framework</label>
                      <select
                        id="gap-framework"
                        value={selectedFramework}
                        onChange={(event) => { setSelectedFramework(event.target.value); setGaps(null) }}
                        className="flex h-10 w-full rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm sm:w-72"
                      >
                        {frameworks?.map((fw) => <option key={fw.id} value={fw.id}>{fw.name}</option>)}
                      </select>
                    </div>
                    <Button onClick={handleAnalyzeGaps} loading={analyzeGaps.isPending} disabled={mappings.length === 0}>
                      Analyze Gaps
                    </Button>
                  </div>
                  {mappings.length === 0 && (
                    <p className="mt-3 text-sm text-text-muted">Map an assessment&apos;s findings before running gap analysis.</p>
                  )}
                </Card>

                {gaps !== null && (gaps.length > 0 ? (
                  <div className="space-y-2">
                    {gaps.map((gap) => (
                      <Card key={gap.control_id} className="p-4">
                        <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <Badge variant="warning" className="font-mono text-xs">{gap.control_id}</Badge>
                              <p className="font-medium text-text-primary">{gap.title}</p>
                            </div>
                            <p className="mt-2 text-sm text-text-secondary">{gap.recommendation}</p>
                          </div>
                          <Badge variant="neutral" className="w-fit shrink-0">{gap.status.replace(/_/g, ' ')}</Badge>
                        </div>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <Alert variant="success" title="No gaps identified">
                    The current keyword-based mapping did not identify an unaddressed control for this framework.
                  </Alert>
                ))}
              </TabsContent>
            )}

            {canAnalyze && (
              <TabsContent value="reports" className="space-y-4 pt-4">
                <div className="grid gap-3 md:grid-cols-3">
                  {REPORT_TYPES.map((type) => (
                    <button
                      key={type.id}
                      type="button"
                      onClick={() => setReportType(type.id)}
                      className={`rounded-lg border p-4 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                        reportType === type.id ? 'border-accent bg-accent/10' : 'border-border bg-surface-primary hover:border-border-light'
                      }`}
                      aria-pressed={reportType === type.id}
                    >
                      <p className="font-medium text-text-primary">{type.label}</p>
                      <p className="mt-1 text-xs text-text-muted">{type.description}</p>
                    </button>
                  ))}
                </div>
                <div className="flex flex-wrap gap-3">
                  <Button onClick={handleGenerateReport} loading={generateReport.isPending} disabled={mappings.length === 0}>
                    Generate Compliance Report
                  </Button>
                  {report && <Button variant="outline" onClick={() => downloadJson(report)}>Download JSON</Button>}
                </div>
                {mappings.length === 0 && (
                  <p className="text-sm text-text-muted">Map an assessment&apos;s findings before generating a report.</p>
                )}
                {report && (
                  <Card className="p-5">
                    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <p className="text-sm font-semibold text-text-primary">Report generated</p>
                        <p className="mt-1 break-all text-xs text-text-muted">ID: {report.report_id}</p>
                        <p className="text-xs text-text-muted">Target: {report.target}</p>
                      </div>
                      {'overall_coverage_percent' in report && (
                        <div className="text-left sm:text-right">
                          <p className="text-2xl font-bold text-text-primary">{report.overall_coverage_percent.toFixed(1)}%</p>
                          <p className="text-xs text-text-muted">overall mapped coverage</p>
                        </div>
                      )}
                      {'total_gaps' in report && (
                        <div className="text-left sm:text-right">
                          <p className="text-2xl font-bold text-text-primary">{report.total_gaps}</p>
                          <p className="text-xs text-text-muted">identified gaps</p>
                        </div>
                      )}
                    </div>
                  </Card>
                )}
              </TabsContent>
            )}
          </Tabs>
        </div>
      )}
    </PageContainer>
  )
}
