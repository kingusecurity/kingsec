import { memo } from "react"
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import type { StatusDistribution } from "../types"

interface RiskDistributionProps {
  data: StatusDistribution[]
}

export const RiskDistribution = memo(function RiskDistribution({ data }: RiskDistributionProps): React.ReactElement {
  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Assessment Status Distribution</CardTitle>
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
        <CardTitle className="text-base">Assessment Status Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={250}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={2}
              dataKey="value"
              nameKey="name"
            >
              {data.map((entry, i) => (
                <Cell key={`cell-${i}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "8px",
                fontSize: "12px",
              }}
            />
            <Legend
              formatter={(value) => <span className="text-xs text-[hsl(var(--fg))]">{value}</span>}
            />
          </PieChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
})
