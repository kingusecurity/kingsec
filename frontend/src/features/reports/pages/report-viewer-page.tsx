import { useState, useCallback, useMemo } from "react"
import { useParams, useNavigate } from "react-router-dom"
import {
  ArrowLeft,
  Download,
  RefreshCw,
  Copy,
  Check,
  FileText,
  AlertTriangle,
  Shield,
  Construction,
} from "lucide-react"
import { useAssessmentDetail } from "@/features/assessments/hooks/use-assessments"
import { useGenerateReport, useDownloadReport } from "../hooks/use-reports"
import { getReportViewUrl } from "../api/reports"
import { PageHeader } from "@/shared/components/page-header"
import { PageSkeleton } from "@/shared/components/loading-skeleton"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/shared/ui/tabs"
import { Button } from "@/shared/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { getApiError } from "@/shared/api/error-handler"
import { formatDate, formatFileSize } from "@/shared/lib/utils"
import { useAuth } from "@/features/auth/hooks/use-auth"

export function ReportViewerPage(): React.ReactElement {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()
  const [copied, setCopied] = useState(false)
  const [activeTab, setActiveTab] = useState("preview")
  const [pdfLoadFailed, setPdfLoadFailed] = useState(false)

  const { data: assessment, isLoading, error, refetch } = useAssessmentDetail(id ?? "")
  const generateMutation = useGenerateReport()
  const downloadMutation = useDownloadReport()

  const reportUrl = useMemo(
    () => (id ? getReportViewUrl(id) : ""),
    [id],
  )

  const canGenerate = user?.role === "ADMIN" || user?.role === "ANALYST"

  const handleCopyUrl = useCallback(() => {
    const url = window.location.href
    navigator.clipboard.writeText(url).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [])

  const handleDownload = useCallback(() => {
    if (!assessment) return
    setPdfLoadFailed(false)
    downloadMutation.mutate({
      assessmentId: assessment.assessment_id,
      filename: `report-${assessment.assessment_id}.pdf`,
      mediaType: "application/pdf",
    })
  }, [assessment, downloadMutation])

  const handleGenerate = useCallback(() => {
    if (!assessment) return
    setPdfLoadFailed(false)
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

  const hasReport = assessment.status === "COMPLETED" && assessment.findings.length > 0

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
            {hasReport && (
              <Button variant="outline" size="sm" onClick={handleDownload} disabled={downloadMutation.isPending}>
                {downloadMutation.isPending ? (
                  <RefreshCw className="mr-1 size-4 animate-spin" />
                ) : (
                  <Download className="mr-1 size-4" />
                )}
                {downloadMutation.isPending
                  ? `Downloading... ${downloadMutation.progress?.percent ?? 0}%`
                  : "Download"}
              </Button>
            )}
            {canGenerate && (
              <Button size="sm" onClick={handleGenerate} disabled={generateMutation.isPending}>
                {generateMutation.isPending ? (
                  <RefreshCw className="mr-1 size-4 animate-spin" />
                ) : (
                  <RefreshCw className="mr-1 size-4" />
                )}
                {generateMutation.isPending ? "Generating..." : "Regenerate"}
              </Button>
            )}
          </div>
        </div>

        {downloadMutation.isPending && downloadMutation.progress && (
          <div className="mb-4">
            <div className="flex items-center justify-between text-xs text-[hsl(var(--muted-fg))] mb-1">
              <span>Downloading report...</span>
              <span>{downloadMutation.progress.percent}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-[hsl(var(--muted))]">
              <div
                className="h-full bg-[hsl(var(--primary))] transition-all duration-200"
                style={{ width: `${downloadMutation.progress.percent}%` }}
              />
            </div>
          </div>
        )}

        {downloadMutation.isError && (
          <div className="mb-4 flex items-center gap-3 rounded-lg border border-[hsl(var(--destructive))]/20 bg-[hsl(var(--destructive))]/5 p-3">
            <AlertTriangle className="size-4 shrink-0 text-[hsl(var(--destructive))]" />
            <span className="text-sm text-[hsl(var(--destructive))]">Download failed.</span>
            <Button variant="outline" size="sm" onClick={handleDownload}>
              Retry
            </Button>
          </div>
        )}

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
                  {hasReport && !pdfLoadFailed ? (
                    <div className="relative">
                      <div className="rounded-t-xl border-b border-[hsl(var(--border))] bg-[hsl(var(--muted))] p-2">
                        <div className="flex items-center gap-2">
                          <FileText className="size-4 text-[hsl(var(--muted-fg))]" />
                          <span className="text-xs text-[hsl(var(--muted-fg))]">PDF Preview</span>
                        </div>
                      </div>
                      <iframe
                        src={reportUrl}
                        className="h-[800px] w-full border-0"
                        title="Report PDF preview"
                        onError={() => setPdfLoadFailed(true)}
                      />
                    </div>
                  ) : (
                    <CardContent className="flex flex-col items-center gap-4 py-16 text-center">
                      <div className="flex size-16 items-center justify-center rounded-lg bg-[hsl(var(--muted))]">
                        <FileText className="size-8 text-[hsl(var(--muted-fg))]" />
                      </div>
                      <div className="space-y-1">
                        <h3 className="text-lg font-semibold text-[hsl(var(--fg))]">
                          {pdfLoadFailed ? "Preview unavailable" : "No report generated"}
                        </h3>
                        <p className="max-w-md text-sm text-[hsl(var(--fg-secondary))]">
                          {pdfLoadFailed
                            ? "Browser PDF preview is not supported. Download the file to view it."
                            : "Generate a report for this assessment to view it here."}
                        </p>
                      </div>
                      {hasReport && (
                        <Button variant="outline" onClick={handleDownload} disabled={downloadMutation.isPending}>
                          <Download className="mr-2 size-4" />
                          Download PDF
                        </Button>
                      )}
                    </CardContent>
                  )}
                </Card>
              </TabsContent>

              <TabsContent value="metadata">
                <Card>
                  <CardHeader>
                    <CardTitle>Report Information</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <MetadataRow label="Assessment ID" value={assessment.assessment_id} mono />
                    <MetadataRow label="Target" value={assessment.target} />
                    <MetadataRow
                      label="Status"
                      value={
                        <Badge variant={assessment.status === "COMPLETED" ? "success" : "secondary"}>
                          {assessment.status}
                        </Badge>
                      }
                    />
                    <MetadataRow label="Findings" value={String(assessment.findings.length)} />
                    <MetadataRow label="Created" value={formatDate(assessment.created_at)} />

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

function MetadataRow({
  label,
  value,
  mono,
}: {
  label: string
  value: React.ReactNode
  mono?: boolean
}): React.ReactElement {
  return (
    <div className="flex justify-between border-b border-[hsl(var(--border))] pb-2">
      <span className="text-sm text-[hsl(var(--muted-fg))]">{label}</span>
      <span className={`text-sm text-[hsl(var(--fg))] ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  )
}
