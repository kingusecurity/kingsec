import { memo } from "react"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { EmptyState } from "@/shared/components/empty-state"

interface AnalyticsSeverityChartProps {
  data: Array<{ name: string; count: number; fill: string }>
}

const TOOLTIP_STYLE = {
  backgroundColor: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: "8px",
  fontSize: "12px",
}

export const AnalyticsSeverityChart = memo(function AnalyticsSeverityChart({
  data,
}: AnalyticsSeverityChartProps): React.ReactElement {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Severity Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <EmptyState title="No data available" className="py-8" />
        ) : (
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={data} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis type="number" stroke="hsl(var(--muted-fg))" fontSize={11} />
              <YAxis
                type="category"
                dataKey="name"
                stroke="hsl(var(--muted-fg))"
                fontSize={11}
                width={80}
              />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  )
})
