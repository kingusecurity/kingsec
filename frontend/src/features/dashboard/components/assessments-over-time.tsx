import { memo, useState } from "react"
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Button } from "@/shared/ui/button"
import type { AssessmentsOverTime } from "../types"

interface AssessmentsOverTimeChartProps {
  data: AssessmentsOverTime[]
}

const TIME_RANGES = [
  { label: "7D", days: 7 },
  { label: "30D", days: 30 },
  { label: "All", days: Infinity },
] as const

export const AssessmentsOverTimeChart = memo(function AssessmentsOverTimeChart({
  data,
}: AssessmentsOverTimeChartProps): React.ReactElement {
  const [range, setRange] = useState(30)

  const filtered = range === Infinity ? data : data.slice(-range)

  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Assessments Over Time</CardTitle>
        </CardHeader>
        <CardContent className="flex h-[250px] items-center justify-center">
          <p className="text-sm text-[hsl(var(--muted-fg))]">No data available</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">Assessments Over Time</CardTitle>
        <div className="flex gap-1">
          {TIME_RANGES.map((tr) => (
            <Button
              key={tr.label}
              variant={range === tr.days ? "default" : "ghost"}
              size="sm"
              className="h-7 px-2 text-xs"
              onClick={() => setRange(tr.days)}
            >
              {tr.label}
            </Button>
          ))}
        </div>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={filtered}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 11, fill: "hsl(var(--muted-fg))" }}
              tickFormatter={(v: string) => v.slice(5)}
            />
            <YAxis tick={{ fontSize: 12, fill: "hsl(var(--muted-fg))" }} allowDecimals={false} />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "8px",
                fontSize: "12px",
              }}
            />
            <Line
              type="monotone"
              dataKey="count"
              stroke="hsl(var(--primary))"
              strokeWidth={2}
              dot={{ fill: "hsl(var(--primary))", r: 3 }}
              activeDot={{ r: 5 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
})
