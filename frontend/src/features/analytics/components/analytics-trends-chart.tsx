import { memo, useState, useMemo } from "react"
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Button } from "@/shared/ui/button"
import { cn } from "@/shared/lib/utils"
import { EmptyState } from "@/shared/components/empty-state"
import type { TrendData, TimeRange } from "../types"

interface AnalyticsTrendsChartProps {
  data: TrendData[]
}

const TIME_RANGES: Array<{ label: string; value: TimeRange }> = [
  { label: "7D", value: "7d" },
  { label: "30D", value: "30d" },
  { label: "90D", value: "90d" },
  { label: "1Y", value: "1y" },
]

const TOOLTIP_STYLE = {
  backgroundColor: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: "8px",
  fontSize: "12px",
}

export const AnalyticsTrendsChart = memo(function AnalyticsTrendsChart({
  data,
}: AnalyticsTrendsChartProps): React.ReactElement {
  const [range, setRange] = useState<TimeRange>("30d")

  const filteredData = useMemo(() => {
    const now = new Date()
    const cutoff = new Date(now)
    switch (range) {
      case "7d": cutoff.setDate(now.getDate() - 7); break
      case "30d": cutoff.setDate(now.getDate() - 30); break
      case "90d": cutoff.setDate(now.getDate() - 90); break
      case "1y": cutoff.setFullYear(now.getFullYear() - 1); break
    }
    return data.filter((d) => new Date(d.date) >= cutoff)
  }, [data, range])

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium">Assessments Over Time</CardTitle>
        <div className="flex gap-1">
          {TIME_RANGES.map((tr) => (
            <Button
              key={tr.value}
              variant={range === tr.value ? "default" : "ghost"}
              size="sm"
              onClick={() => setRange(tr.value)}
              className="h-7 px-2 text-xs"
            >
              {tr.label}
            </Button>
          ))}
        </div>
      </CardHeader>
      <CardContent>
        {filteredData.length === 0 ? (
          <EmptyState title="No data available" className="py-8" />
        ) : (
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={filteredData}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis
                dataKey="date"
                tickFormatter={(v: string) => v.slice(5)}
                stroke="hsl(var(--muted-fg))"
                fontSize={11}
              />
              <YAxis stroke="hsl(var(--muted-fg))" fontSize={11} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Legend />
              <Line
                type="monotone"
                dataKey="assessments"
                name="Assessments"
                stroke="hsl(var(--primary))"
                strokeWidth={2}
                dot={{ fill: "hsl(var(--primary))", r: 3 }}
                activeDot={{ r: 5 }}
              />
              <Line
                type="monotone"
                dataKey="findings"
                name="Findings"
                stroke="hsl(var(--destructive))"
                strokeWidth={2}
                dot={{ fill: "hsl(var(--destructive))", r: 3 }}
              />
              <Line
                type="monotone"
                dataKey="failed"
                name="Failed"
                stroke="hsl(25, 95%, 53%)"
                strokeWidth={2}
                dot={{ fill: "hsl(25, 95%, 53%)", r: 3 }}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  )
})
