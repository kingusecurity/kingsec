import { FileText, Download, ExternalLink, RefreshCw } from "lucide-react"
import { Card, CardContent } from "@/shared/ui/card"
import { Button } from "@/shared/ui/button"
import { Badge } from "@/shared/ui/badge"
import { apiClient } from "@/shared/api/client"
import { toast } from "sonner"
import { getApiError } from "@/shared/api/error-handler"
import { useState } from "react"
import type { GenerateReportResponse } from "../types"

interface ReportsTabProps {
  assessmentId: string
  report: GenerateReportResponse | null
  onGenerateReport: () => void
  isGenerating: boolean
}

export function ReportsTab({ assessmentId, report, onGenerateReport, isGenerating }: ReportsTabProps): React.ReactElement {
  const [downloading, setDownloading] = useState(false)

  async function handleDownload(): Promise<void> {
    if (!report) return
    setDownloading(true)
    try {
      const response = await apiClient.get(`/assessments/${assessmentId}/report/download`, {
        responseType: "blob",
      })
      const blob = new Blob([response.data], { type: report.artifact_media_type })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = report.artifact_filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success("Report downloaded")
    } catch (err) {
      const e = getApiError(err)
      toast.error(e.detail)
    } finally {
      setDownloading(false)
    }
  }

  function handleView(): void {
    if (!report) return
    const baseUrl = apiClient.defaults.baseURL ?? ""
    window.open(`${baseUrl}/assessments/${assessmentId}/report/view`, "_blank")
  }

  if (!report) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-4 py-16 text-center">
          <div className="flex size-12 items-center justify-center rounded-lg bg-[hsl(var(--muted))]">
            <FileText className="size-6 text-[hsl(var(--muted-fg))]" />
          </div>
          <div className="space-y-1">
            <h3 className="text-lg font-semibold text-[hsl(var(--fg))]">No Report Generated</h3>
            <p className="max-w-md text-sm text-[hsl(var(--fg-secondary))]">
              Generate a PDF report for this assessment. Reports include findings, severity breakdown, and recommendations.
            </p>
          </div>
          <Button onClick={onGenerateReport} disabled={isGenerating}>
            {isGenerating ? <RefreshCw className="mr-2 size-4 animate-spin" /> : <FileText className="mr-2 size-4" />}
            Generate Report
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardContent className="space-y-4 p-6">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <h3 className="text-lg font-semibold text-[hsl(var(--fg))]">{report.artifact_filename}</h3>
            <div className="flex items-center gap-2">
              <Badge variant="success">Generated</Badge>
              <span className="text-xs text-[hsl(var(--muted-fg))]">
                Verdict: {report.verdict} · {report.total_findings} findings
              </span>
            </div>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleView}>
              <ExternalLink className="mr-2 size-4" />
              View
            </Button>
            <Button variant="outline" size="sm" onClick={handleDownload} disabled={downloading}>
              <Download className="mr-2 size-4" />
              Download
            </Button>
            <Button variant="outline" size="sm" onClick={onGenerateReport} disabled={isGenerating}>
              <RefreshCw className={`mr-2 size-4 ${isGenerating ? "animate-spin" : ""}`} />
              Regenerate
            </Button>
          </div>
        </div>
        {report.severity_counts.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {report.severity_counts.map((sc) => (
              <Badge key={sc.severity} variant={sc.severity === "CRITICAL" || sc.severity === "HIGH" ? "destructive" : "secondary"}>
                {sc.severity}: {sc.count}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
