import { memo, useState, useMemo } from "react"
import { useNavigate } from "react-router-dom"
import { Search, FileText, ExternalLink, Download, RefreshCw, Plus } from "lucide-react"
import { useAssessments } from "@/features/assessments/hooks/use-assessments"
import { AssessmentStatusBadge } from "@/features/assessments/components/assessment-status-badge"
import { useGenerateReport, useDownloadReport } from "../hooks/use-reports"
import { PageHeader } from "@/shared/components/page-header"
import { EmptyState } from "@/shared/components/empty-state"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Select } from "@/shared/ui/select"
import { Badge } from "@/shared/ui/badge"
import { Card, CardContent } from "@/shared/ui/card"
import { formatRelative, formatDate } from "@/shared/lib/utils"
import { ROUTES } from "@/shared/lib/constants"
import { useDebounce } from "@/shared/hooks/use-debounce"
import { getApiError } from "@/shared/api/error-handler"
import type { AssessmentSummary } from "@/features/assessments/types"

const VERDICT_CONFIG: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "success" | "warning" | "muted" }> = {
  pass: { label: "Pass", variant: "success" },
  fail: { label: "Fail", variant: "destructive" },
  warning: { label: "Warning", variant: "warning" },
  info: { label: "Info", variant: "secondary" },
}

export function ReportsListPage(): React.ReactElement {
  const navigate = useNavigate()
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState("")
  const debouncedSearch = useDebounce(search, 300)

  const { data, isLoading, error, refetch, isFetching } = useAssessments({ limit: 200, offset: 0 })
  const generateMutation = useGenerateReport()
  const downloadMutation = useDownloadReport()

  const assessments = useMemo(() => {
    const items = data?.items ?? []
    let result = items.filter((a) => a.status === "COMPLETED" || a.findings_count > 0)

    if (statusFilter) {
      result = result.filter((a) => a.status === statusFilter)
    }

    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase()
      result = result.filter(
        (a) =>
          a.target.toLowerCase().includes(q) ||
          a.assessment_id.toLowerCase().includes(q),
      )
    }

    return result
  }, [data?.items, statusFilter, debouncedSearch])

  if (error) {
    const apiErr = getApiError(error)
    return (
      <div className="p-6">
        <PageHeader title="Reports" description="View and manage assessment reports." />
        <div className="mt-6 flex flex-col items-center gap-4 rounded-xl border border-[hsl(var(--border))] py-16" role="alert">
          <p className="text-sm text-[hsl(var(--destructive))]">{apiErr.detail}</p>
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="mr-2 size-4" />
            Retry
          </Button>
        </div>
      </div>
    )
  }

  return (
    <ErrorBoundary>
      <div className="p-6">
        <PageHeader
          title="Reports"
          description="View and manage assessment reports."
        />

        {/* Toolbar */}
        <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[hsl(var(--muted-fg))]" aria-hidden="true" />
            <Input
              placeholder="Search by target or ID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
              aria-label="Search reports"
            />
          </div>
          <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="w-40" aria-label="Filter by status">
            <option value="">All Statuses</option>
            <option value="COMPLETED">Completed</option>
          </Select>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`mr-2 size-4 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>

        {/* Reports List */}
        <div className="mt-4">
          {isLoading ? (
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="skeleton h-24 rounded-xl" />
              ))}
            </div>
          ) : assessments.length === 0 ? (
            <EmptyState
              icon={<FileText className="size-12" />}
              title="No reports found"
              description="Reports are generated from completed assessments. Complete an assessment to generate a report."
            />
          ) : (
            <div className="space-y-3">
              {assessments.map((assessment) => (
                <ReportCard
                  key={assessment.assessment_id}
                  assessment={assessment}
                  onGenerate={() => generateMutation.mutate(assessment.assessment_id)}
                  onDownload={() => {
                    // Report data comes from generate — use assessment info
                    downloadMutation.mutate({
                      assessmentId: assessment.assessment_id,
                      filename: `report-${assessment.assessment_id}.pdf`,
                      mediaType: "application/pdf",
                    })
                  }}
                  isGenerating={generateMutation.isPending}
                  isDownloading={downloadMutation.isPending}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </ErrorBoundary>
  )
}

interface ReportCardProps {
  assessment: AssessmentSummary
  onGenerate: () => void
  onDownload: () => void
  isGenerating: boolean
  isDownloading: boolean
}

const ReportCard = memo(function ReportCard({
  assessment,
  onGenerate,
  onDownload,
  isGenerating,
  isDownloading,
}: ReportCardProps): React.ReactElement {
  const navigate = useNavigate()
  const hasReport = assessment.findings_count > 0 && assessment.status === "COMPLETED"

  return (
    <Card className="transition-colors hover:bg-[hsl(var(--accent))]/30">
      <CardContent className="p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <h3 className="font-medium text-[hsl(var(--fg))]">{assessment.target}</h3>
              <AssessmentStatusBadge status={assessment.status} />
              {hasReport && (
                <Badge variant="success">
                  <FileText className="mr-1 size-3" />
                  Report
                </Badge>
              )}
            </div>
            <p className="text-xs text-[hsl(var(--muted-fg))]">
              {assessment.findings_count} findings · Created {formatRelative(assessment.created_at)}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate(`${ROUTES.ASSESSMENTS}/${assessment.assessment_id}`)}
            >
              <ExternalLink className="mr-1 size-4" />
              View
            </Button>
            {hasReport ? (
              <Button variant="outline" size="sm" onClick={onDownload} disabled={isDownloading}>
                <Download className="mr-1 size-4" />
                Download
              </Button>
            ) : (
              <Button variant="outline" size="sm" onClick={onGenerate} disabled={isGenerating || assessment.status !== "COMPLETED"}>
                <Plus className="mr-1 size-4" />
                Generate
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
})
