import { memo } from "react"
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Legend,
  Tooltip,
} from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { EmptyState } from "@/shared/components/empty-state"

interface AnalyticsStatusChartProps {
  data: Array<{ name: string; value: number; color: string }>
}

const TOOLTIP_STYLE = {
  backgroundColor: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: "8px",
  fontSize: "12px",
}

function renderLegend(props: { payload?: Array<{ value: string; color: string }> }): React.ReactElement {
  const { payload } = props
  return (
    <div className="flex flex-wrap justify-center gap-3 pt-2">
      {payload?.map((entry, i) => (
        <div key={i} className="flex items-center gap-1.5 text-xs text-[hsl(var(--fg-secondary))]">
          <span className="size-2 rounded-full" style={{ backgroundColor: entry.color }} />
          {entry.value}
        </div>
      ))}
    </div>
  )
}

export const AnalyticsStatusChart = memo(function AnalyticsStatusChart({
  data,
}: AnalyticsStatusChartProps): React.ReactElement {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Status Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <EmptyState title="No data available" className="py-8" />
        ) : (
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={90}
                paddingAngle={2}
                dataKey="value"
                nameKey="name"
                data={data}
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Legend content={renderLegend} />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  )
})
