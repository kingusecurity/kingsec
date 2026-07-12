import { memo } from "react"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import type { SeverityDistribution } from "../types"

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "hsl(var(--destructive))",
  HIGH: "hsl(25, 95%, 53%)",
  MEDIUM: "hsl(var(--warning))",
  LOW: "hsl(var(--primary))",
  INFO: "hsl(var(--muted-fg))",
}

interface SeverityChartProps {
  data: SeverityDistribution[]
}

export const SeverityChart = memo(function SeverityChart({ data }: SeverityChartProps): React.ReactElement {
  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Severity Distribution</CardTitle>
        </CardHeader>
        <CardContent className="flex h-[250px] items-center justify-center">
          <p className="text-sm text-[hsl(var(--muted-fg))]">No data available</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Severity Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={data} layout="vertical" margin={{ left: 20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
            <XAxis type="number" tick={{ fontSize: 12, fill: "hsl(var(--muted-fg))" }} />
            <YAxis type="category" dataKey="name" tick={{ fontSize: 12, fill: "hsl(var(--muted-fg))" }} width={80} />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "8px",
                fontSize: "12px",
              }}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {data.map((entry, i) => (
                <Cell key={`cell-${i}`} fill={SEVERITY_COLORS[entry.name] ?? "hsl(var(--muted-fg))"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
})
