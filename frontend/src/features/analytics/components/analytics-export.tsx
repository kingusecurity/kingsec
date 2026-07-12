import { memo, useCallback } from "react"
import { Download, FileJson } from "lucide-react"
import { Button } from "@/shared/ui/button"
import { exportKPIsToCSV, exportTrendsToCSV, exportAnalyticsToJSON } from "../lib/export"
import type { ExecutiveKPIs, TrendData, RiskAnalytics } from "../types"

interface AnalyticsExportProps {
  kpis: ExecutiveKPIs | null
  trends: TrendData[]
  risk: RiskAnalytics | null
}

export const AnalyticsExport = memo(function AnalyticsExport({
  kpis,
  trends,
  risk,
}: AnalyticsExportProps): React.ReactElement {
  const handleExportKPICSV = useCallback(() => {
    if (kpis) exportKPIsToCSV(kpis)
  }, [kpis])

  const handleExportTrendsCSV = useCallback(() => {
    if (trends.length > 0) exportTrendsToCSV(trends)
  }, [trends])

  const handleExportJSON = useCallback(() => {
    if (kpis && risk) exportAnalyticsToJSON(kpis, trends, risk)
  }, [kpis, trends, risk])

  return (
    <div className="flex items-center gap-2">
      <Button
        variant="outline"
        size="sm"
        onClick={handleExportKPICSV}
        disabled={!kpis}
        className="text-xs"
      >
        <Download className="mr-1 size-3" />
        KPIs CSV
      </Button>
      <Button
        variant="outline"
        size="sm"
        onClick={handleExportTrendsCSV}
        disabled={trends.length === 0}
        className="text-xs"
      >
        <Download className="mr-1 size-3" />
        Trends CSV
      </Button>
      <Button
        variant="outline"
        size="sm"
        onClick={handleExportJSON}
        disabled={!kpis || !risk}
        className="text-xs"
      >
        <FileJson className="mr-1 size-3" />
        Full JSON
      </Button>
    </div>
  )
})
