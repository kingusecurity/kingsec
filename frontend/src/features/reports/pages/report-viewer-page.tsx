import { useState, useCallback, useMemo } from "react"
import { useParams, useNavigate } from "react-router-dom"
import {
  ArrowLeft,
  Download,
  RefreshCw,
  Copy,
  Check,
  FileText,
  ExternalLink,
  Construction,
} from "lucide-react"
import { useAssessmentDetail } from "@/features/assessments/hooks/use-assessments"
import { useGenerateReport, useDownloadReport, reportKeys } from "../hooks/use-reports"
import { SeverityBadge } from "@/features/assessments/components/severity-badge"
import { PageHeader } from "@/shared/components/page-header"
import { PageSkeleton } from "@/shared/components/loading-skeleton"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/shared/ui/tabs"
import { Button } from "@/shared/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { getApiError } from "@/shared/api/error-handler"
import { formatDate } from "@/shared/lib/utils"
import type { ReportData } from "../types"

export function ReportViewerPage(): React.ReactElement {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [copied, setCopied] = useState(false)
  const [activeTab, setActiveTab] = useState("preview")

  const { data: assessment, isLoading, error, refetch } = useAssessmentDetail(id ?? "")
  const generateMutation = useGenerateReport()
  const downloadMutation = useDownloadReport()

  const handleCopyUrl = useCallback(() => {
    const url = window.location.href
    navigator.clipboard.writeText(url).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [])

  const handleDownload = useCallback(() => {
    if (!assessment) return
    downloadMutation.mutate({
      assessmentId: assessment.assessment_id,
      filename: `report-${assessment.assessment_id}.pdf`,
      mediaType: "application/pdf",
    })
  }, [assessment, downloadMutation])

  const handleGenerate = useCallback(() => {
    if (!assessment) return
    generateMutation.mutate(assessment.assessment_id)
  }, [assessment, generateMutation])

  if (isLoading) return <PageSkeleton />

  if (error || !assessment) {
    const apiErr = error ? getApiError(error) : { detail: "Assessment not found", status: 404 }
    return (
      <div className="p-6">
        <Button variant="ghost" size="sm" onClick={() => navigate("/reports")} className="mb-4">
          <ArrowLeft className="mr-2 size-4" />
          Back to Reports
        </Button>
        <div className="flex flex-col items-center gap-4 rounded-xl border border-[hsl(var(--border))] py-16" role="alert">
          <p className="text-sm text-[hsl(var(--destructive))]">{apiErr.detail}</p>
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="mr-2 size-4" />
            Retry
          </Button>
        </div>
      </div>
    )
  }

  const severityCounts = assessment.findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1
      return acc
    },
    {} as Record<string, number>,
  )

  return (
    <ErrorBoundary>
      <div className="p-6">
        <div className="mb-4 flex items-center justify-between">
          <Button variant="ghost" size="sm" onClick={() => navigate("/reports")}>
            <ArrowLeft className="mr-2 size-4" />
            Back
          </Button>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleCopyUrl}>
              {copied ? <Check className="mr-1 size-4" /> : <Copy className="mr-1 size-4" />}
              {copied ? "Copied" : "Copy URL"}
            </Button>
            <Button variant="outline" size="sm" onClick={handleDownload}>
              <Download className="mr-1 size-4" />
              Download
            </Button>
            <Button size="sm" onClick={handleGenerate} disabled={generateMutation.isPending}>
              {generateMutation.isPending ? <RefreshCw className="mr-1 size-4 animate-spin" /> : <RefreshCw className="mr-1 size-4" />}
              Regenerate
            </Button>
          </div>
        </div>

        <PageHeader
          title={`Report: ${assessment.target}`}
          description={`Assessment ${assessment.assessment_id}`}
        />

        <div className="mt-6">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList>
              <TabsTrigger value="preview">Preview</TabsTrigger>
              <TabsTrigger value="metadata">Metadata</TabsTrigger>
              <TabsTrigger value="history">History</TabsTrigger>
            </TabsList>

            <div className="mt-4">
              <TabsContent value="preview">
                <Card>
                  <CardContent className="flex flex-col items-center gap-4 py-16 text-center">
                    <div className="flex size-16 items-center justify-center rounded-lg bg-[hsl(var(--muted))]">
                      <FileText className="size-8 text-[hsl(var(--muted-fg))]" />
                    </div>
                    <div className="space-y-1">
                      <h3 className="text-lg font-semibold text-[hsl(var(--fg))]">PDF Preview</h3>
                      <p className="max-w-md text-sm text-[hsl(var(--fg-secondary))]">
                        Download the report to view the full PDF. In-browser preview will be available when the backend exposes a view endpoint.
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <Button variant="outline" onClick={handleDownload}>
                        <Download className="mr-2 size-4" />
                        Download PDF
                      </Button>
                      <Button onClick={handleGenerate} disabled={generateMutation.isPending}>
                        <RefreshCw className={`mr-2 size-4 ${generateMutation.isPending ? "animate-spin" : ""}`} />
                        Generate New
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="metadata">
                <Card>
                  <CardHeader>
                    <CardTitle>Report Information</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex justify-between border-b border-[hsl(var(--border))] pb-2">
                      <span className="text-sm text-[hsl(var(--muted-fg))]">Assessment ID</span>
                      <span className="font-mono text-sm text-[hsl(var(--fg))]">{assessment.assessment_id}</span>
                    </div>
                    <div className="flex justify-between border-b border-[hsl(var(--border))] pb-2">
                      <span className="text-sm text-[hsl(var(--muted-fg))]">Target</span>
                      <span className="text-sm font-medium text-[hsl(var(--fg))]">{assessment.target}</span>
                    </div>
                    <div className="flex justify-between border-b border-[hsl(var(--border))] pb-2">
                      <span className="text-sm text-[hsl(var(--muted-fg))]">Status</span>
                      <Badge variant={assessment.status === "COMPLETED" ? "success" : "secondary"}>
                        {assessment.status}
                      </Badge>
                    </div>
                    <div className="flex justify-between border-b border-[hsl(var(--border))] pb-2">
                      <span className="text-sm text-[hsl(var(--muted-fg))]">Findings</span>
                      <span className="text-sm text-[hsl(var(--fg))]">{assessment.findings.length}</span>
                    </div>
                    <div className="flex justify-between border-b border-[hsl(var(--border))] pb-2">
                      <span className="text-sm text-[hsl(var(--muted-fg))]">Created</span>
                      <span className="text-sm text-[hsl(var(--fg))]">{formatDate(assessment.created_at)}</span>
                    </div>
                    {Object.keys(severityCounts).length > 0 && (
                      <div className="pt-2">
                        <p className="mb-2 text-sm font-medium text-[hsl(var(--fg))]">Severity Breakdown</p>
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(severityCounts).map(([severity, count]) => (
                            <Badge key={severity} variant={severity === "CRITICAL" || severity === "HIGH" ? "destructive" : "secondary"}>
                              {severity}: {count}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="history">
                <Card>
                  <CardContent className="flex flex-col items-center gap-4 py-16 text-center">
                    <div className="flex size-12 items-center justify-center rounded-lg bg-[hsl(var(--muted))]">
                      <Construction className="size-6 text-[hsl(var(--muted-fg))]" />
                    </div>
                    <div className="space-y-1">
                      <h3 className="text-lg font-semibold text-[hsl(var(--fg))]">Report History</h3>
                      <p className="max-w-md text-sm text-[hsl(var(--fg-secondary))]">
                        Previous report versions and generation timeline will be available when the backend
                        exposes report history endpoints.
                      </p>
                    </div>
                    <Badge variant="secondary">Ready for backend integration</Badge>
                  </CardContent>
                </Card>
              </TabsContent>
            </div>
          </Tabs>
        </div>
      </div>
    </ErrorBoundary>
  )
}
