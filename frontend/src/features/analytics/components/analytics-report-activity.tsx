import { memo } from "react"
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts"
import { FileText, Download } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { EmptyState } from "@/shared/components/empty-state"
import type { ReportAnalytics } from "../types"

interface AnalyticsReportActivityProps {
  data: ReportAnalytics | null
  isLoading: boolean
}

const TOOLTIP_STYLE = {
  backgroundColor: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: "8px",
  fontSize: "12px",
}

export const AnalyticsReportActivity = memo(function AnalyticsReportActivity({
  data,
  isLoading,
}: AnalyticsReportActivityProps): React.ReactElement {
  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="skeleton h-48 rounded-lg" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Report Analytics</CardTitle>
      </CardHeader>
      <CardContent>
        {!data ? (
          <EmptyState title="No report data available" className="py-4" />
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="flex items-center gap-3 rounded-lg border border-[hsl(var(--border))] p-3">
                <FileText className="size-4 text-violet-500" />
                <div>
                  <p className="text-xs text-[hsl(var(--muted-fg))]">Total Generated</p>
                  <p className="text-lg font-bold text-[hsl(var(--fg))]">{data.totalGenerated}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 rounded-lg border border-[hsl(var(--border))] p-3">
                <Download className="size-4 text-blue-500" />
                <div>
                  <p className="text-xs text-[hsl(var(--muted-fg))]">Downloads</p>
                  <p className="text-lg font-bold text-[hsl(var(--fg))]">{data.downloadCount}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 rounded-lg border border-[hsl(var(--border))] p-3">
                <FileText className="size-4 text-[hsl(var(--primary))]" />
                <div>
                  <p className="text-xs text-[hsl(var(--muted-fg))]">Report Types</p>
                  <p className="text-lg font-bold text-[hsl(var(--fg))]">
                    {data.reportTypes.length}
                  </p>
                </div>
              </div>
            </div>

            {data.generationTrend.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-medium text-[hsl(var(--fg-secondary))]">
                  PDF Generation Trend
                </p>
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={data.generationTrend}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                    <XAxis
                      dataKey="date"
                      tickFormatter={(v: string) => v.slice(5)}
                      stroke="hsl(var(--muted-fg))"
                      fontSize={11}
                    />
                    <YAxis stroke="hsl(var(--muted-fg))" fontSize={11} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Line
                      type="monotone"
                      dataKey="count"
                      stroke="hsl(var(--primary))"
                      strokeWidth={2}
                      dot={{ fill: "hsl(var(--primary))", r: 3 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
})
