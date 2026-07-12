import type { ExecutiveKPIs, TrendData, RiskAnalytics, AnalyticsExportData } from "../types"

function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function escapeCSV(value: string | number): string {
  const str = String(value)
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

export function exportToCSV(
  data: Record<string, string | number>[],
  filename: string,
): void {
  if (data.length === 0) return
  const headers = Object.keys(data[0])
  const rows = data.map((row) => headers.map((h) => escapeCSV(row[h])).join(","))
  const csv = [headers.join(","), ...rows].join("\n")
  downloadFile(csv, `${filename}.csv`, "text/csv;charset=utf-8")
}

export function exportToJSON(
  data: unknown,
  filename: string,
): void {
  const json = JSON.stringify(data, null, 2)
  downloadFile(json, `${filename}.json`, "application/json")
}

export function exportKPIsToCSV(kpis: ExecutiveKPIs, filename = "kingsec-kpis"): void {
  exportToCSV(
    [
      { Metric: "Total Assessments", Value: kpis.totalAssessments },
      { Metric: "Running", Value: kpis.running },
      { Metric: "Completed", Value: kpis.completed },
      { Metric: "Failed", Value: kpis.failed },
      { Metric: "Cancelled", Value: kpis.cancelled },
      { Metric: "Critical Findings", Value: kpis.criticalFindings },
      { Metric: "High Findings", Value: kpis.highFindings },
      { Metric: "Reports Generated", Value: kpis.reportsGenerated },
      { Metric: "Avg Scan Duration (s)", Value: kpis.averageScanDuration },
      { Metric: "Success Rate (%)", Value: kpis.successRate },
    ],
    filename,
  )
}

export function exportTrendsToCSV(trends: TrendData[], filename = "kingsec-trends"): void {
  exportToCSV(
    trends.map((t) => ({
      Date: t.date,
      Assessments: t.assessments,
      Findings: t.findings,
      Reports: t.reports,
      Failed: t.failed,
    })),
    filename,
  )
}

export function exportAnalyticsToJSON(
  kpis: ExecutiveKPIs,
  trends: TrendData[],
  risk: RiskAnalytics,
  filename = "kingsec-analytics",
): void {
  const exportData: AnalyticsExportData = {
    executiveKPIs: kpis,
    trendData: trends,
    riskAnalytics: risk,
    generatedAt: new Date().toISOString(),
  }
  exportToJSON(exportData, filename)
}
