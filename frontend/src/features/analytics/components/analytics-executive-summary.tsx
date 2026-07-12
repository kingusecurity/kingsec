import { memo } from "react"
import { TrendingUp, TrendingDown, AlertTriangle, User } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import type { ExecutiveSummary } from "../types"

interface AnalyticsExecutiveSummaryProps {
  summary: ExecutiveSummary
}

interface SummaryCardProps {
  icon: React.ReactNode
  label: string
  value: string | null
  color: string
}

function SummaryCard({ icon, label, value, color }: SummaryCardProps): React.ReactElement {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-[hsl(var(--border))] p-3">
      <div className={`mt-0.5 ${color}`}>{icon}</div>
      <div className="min-w-0 flex-1">
        <p className="text-xs text-[hsl(var(--muted-fg))]">{label}</p>
        <p className="mt-0.5 truncate text-sm font-medium text-[hsl(var(--fg))]">
          {value ?? "Ready for backend analytics"}
        </p>
      </div>
    </div>
  )
}

export const AnalyticsExecutiveSummary = memo(function AnalyticsExecutiveSummary({
  summary,
}: AnalyticsExecutiveSummaryProps): React.ReactElement {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Executive Summary</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 sm:grid-cols-2">
          <SummaryCard
            icon={<TrendingUp className="size-4" />}
            label="Biggest Improvement"
            value={summary.biggestImprovement}
            color="text-emerald-500"
          />
          <SummaryCard
            icon={<TrendingDown className="size-4" />}
            label="Biggest Regression"
            value={summary.biggestRegression}
            color="text-red-500"
          />
          <SummaryCard
            icon={<AlertTriangle className="size-4" />}
            label="Highest Risk Target"
            value={summary.highestRiskTarget}
            color="text-orange-500"
          />
          <SummaryCard
            icon={<User className="size-4" />}
            label="Most Active Analyst"
            value={summary.mostActiveAnalyst}
            color="text-violet-500"
          />
        </div>
      </CardContent>
    </Card>
  )
})
