import { memo } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { EmptyState } from "@/shared/components/empty-state"

interface AnalyticsTopTargetsProps {
  data: Array<{ target: string; findings: number; riskLevel: string }>
}

const RISK_BADGE: Record<string, "destructive" | "warning" | "secondary"> = {
  high: "destructive",
  medium: "warning",
  low: "secondary",
}

export const AnalyticsTopTargets = memo(function AnalyticsTopTargets({
  data,
}: AnalyticsTopTargetsProps): React.ReactElement {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Top Affected Targets</CardTitle>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <EmptyState title="No data available" className="py-8" />
        ) : (
          <div className="space-y-2">
            {data.map((item) => (
              <div
                key={item.target}
                className="flex items-center justify-between rounded-lg border border-[hsl(var(--border))] px-3 py-2"
              >
                <span className="truncate text-sm text-[hsl(var(--fg))]">{item.target}</span>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-[hsl(var(--fg-secondary))]">
                    {item.findings} findings
                  </span>
                  <Badge variant={RISK_BADGE[item.riskLevel] ?? "secondary"}>
                    {item.riskLevel}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
})
