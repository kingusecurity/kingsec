import { memo, useMemo } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { EmptyState } from "@/shared/components/empty-state"
import { cn } from "@/shared/lib/utils"

interface AnalyticsHeatmapProps {
  data: Array<{ date: string; count: number }>
  title?: string
}

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

function getIntensityClass(value: number, max: number): string {
  if (max === 0) return "bg-[hsl(var(--bg-secondary))]"
  const ratio = value / max
  if (ratio === 0) return "bg-[hsl(var(--bg-secondary))]"
  if (ratio < 0.25) return "bg-emerald-900/40"
  if (ratio < 0.5) return "bg-emerald-700/50"
  if (ratio < 0.75) return "bg-emerald-500/60"
  return "bg-emerald-400/80"
}

export const AnalyticsHeatmap = memo(function AnalyticsHeatmap({
  data,
  title = "Activity Heatmap",
}: AnalyticsHeatmapProps): React.ReactElement {
  const { grid, maxValue } = useMemo(() => {
    if (data.length === 0) return { grid: [], maxValue: 0 }

    const maxValue = Math.max(...data.map((d) => d.count), 1)
    const weeks = new Map<number, Map<number, number>>()

    for (const entry of data) {
      const date = new Date(entry.date)
      const day = date.getDay()
      const weekStart = new Date(date)
      weekStart.setDate(date.getDate() - day)
      const weekKey = Math.floor(weekStart.getTime() / (7 * 24 * 60 * 60 * 1000))

      if (!weeks.has(weekKey)) weeks.set(weekKey, new Map())
      weeks.get(weekKey)!.set(day, entry.count)
    }

    const sortedWeeks = Array.from(weeks.entries()).sort((a, b) => a[0] - b[0])
    const grid = sortedWeeks.map(([, days]) => {
      return WEEKDAYS.map((_, dayIndex) => days.get(dayIndex) ?? 0)
    })

    return { grid, maxValue }
  }, [data])

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {grid.length === 0 ? (
          <EmptyState title="No data available" className="py-8" />
        ) : (
          <div className="overflow-x-auto">
            <div className="inline-flex gap-1">
              <div className="flex flex-col gap-1">
                {WEEKDAYS.map((day) => (
                  <div
                    key={day}
                    className="flex h-5 w-8 items-center text-[10px] text-[hsl(var(--muted-fg))]"
                  >
                    {day}
                  </div>
                ))}
              </div>
              <div className="flex flex-col gap-1">
                {grid.map((week, weekIndex) => (
                  <div key={weekIndex} className="flex gap-1">
                    {week.map((value, dayIndex) => (
                      <div
                        key={dayIndex}
                        className={cn(
                          "size-5 rounded-sm transition-colors",
                          getIntensityClass(value, maxValue),
                        )}
                        title={`${WEEKDAYS[dayIndex]}: ${value} events`}
                      />
                    ))}
                  </div>
                ))}
              </div>
            </div>
            <div className="mt-2 flex items-center gap-2 text-[10px] text-[hsl(var(--muted-fg))]">
              <span>Less</span>
              <div className="flex gap-0.5">
                {[0, 0.25, 0.5, 0.75, 1].map((ratio) => (
                  <div
                    key={ratio}
                    className={cn(
                      "size-3 rounded-sm",
                      ratio === 0
                        ? "bg-[hsl(var(--bg-secondary))]"
                        : ratio < 0.25
                          ? "bg-emerald-900/40"
                          : ratio < 0.5
                            ? "bg-emerald-700/50"
                            : ratio < 0.75
                              ? "bg-emerald-500/60"
                              : "bg-emerald-400/80",
                    )}
                  />
                ))}
              </div>
              <span>More</span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
})
