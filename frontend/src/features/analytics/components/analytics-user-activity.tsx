import { memo } from "react"
import { Users, BarChart3 } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { EmptyState } from "@/shared/components/empty-state"
import type { UserAnalytics } from "../types"

interface AnalyticsUserActivityProps {
  data: UserAnalytics | null
  isLoading: boolean
}

export const AnalyticsUserActivity = memo(function AnalyticsUserActivity({
  data,
  isLoading,
}: AnalyticsUserActivityProps): React.ReactElement {
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
        <CardTitle className="text-sm font-medium">User Analytics</CardTitle>
      </CardHeader>
      <CardContent>
        {!data ? (
          <EmptyState title="No user data available" className="py-4" />
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-3 rounded-lg border border-[hsl(var(--border))] p-3">
              <Users className="size-4 text-[hsl(var(--primary))]" />
              <div>
                <p className="text-xs text-[hsl(var(--muted-fg))]">Active Analysts</p>
                <p className="text-lg font-bold text-[hsl(var(--fg))]">{data.activeUsers}</p>
              </div>
            </div>

            {data.mostActiveAnalysts.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-medium text-[hsl(var(--fg-secondary))]">
                  Most Active Analysts
                </p>
                <div className="space-y-1.5">
                  {data.mostActiveAnalysts.map((analyst) => (
                    <div
                      key={analyst.username}
                      className="flex items-center justify-between rounded border border-[hsl(var(--border))] px-3 py-1.5"
                    >
                      <span className="truncate text-sm text-[hsl(var(--fg))]">
                        {analyst.username}
                      </span>
                      <div className="flex gap-3 text-xs text-[hsl(var(--fg-secondary))]">
                        <span>{analyst.assessments} scans</span>
                        <span>{analyst.reports} reports</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
})
