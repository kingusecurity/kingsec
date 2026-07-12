import { memo } from "react"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts"
import { LogIn, KeyRound, UserPlus, ShieldAlert, Settings } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { EmptyState } from "@/shared/components/empty-state"
import type { AuditAnalytics } from "../types"

interface AnalyticsAuditActivityProps {
  data: AuditAnalytics | null
  isLoading: boolean
}

const TOOLTIP_STYLE = {
  backgroundColor: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: "8px",
  fontSize: "12px",
}

const STAT_CARDS = [
  { key: "loginActivity" as const, label: "Logins", icon: LogIn, color: "text-emerald-500" },
  { key: "failedLogins" as const, label: "Failed Logins", icon: ShieldAlert, color: "text-red-500" },
  { key: "passwordChanges" as const, label: "Password Changes", icon: KeyRound, color: "text-amber-500" },
  { key: "userCreations" as const, label: "User Creations", icon: UserPlus, color: "text-blue-500" },
  { key: "adminActions" as const, label: "Admin Actions", icon: Settings, color: "text-violet-500" },
]

export const AnalyticsAuditActivity = memo(function AnalyticsAuditActivity({
  data,
  isLoading,
}: AnalyticsAuditActivityProps): React.ReactElement {
  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="grid gap-4 sm:grid-cols-5">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="skeleton h-20 rounded-lg" />
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Audit Analytics</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-5">
          {STAT_CARDS.map(({ key, label, icon: Icon, color }) => (
            <div
              key={key}
              className="flex items-center gap-3 rounded-lg border border-[hsl(var(--border))] p-3"
            >
              <Icon className={`size-4 ${color}`} />
              <div>
                <p className="text-xs text-[hsl(var(--muted-fg))]">{label}</p>
                <p className="text-lg font-bold text-[hsl(var(--fg))]">
                  {data?.[key] ?? 0}
                </p>
              </div>
            </div>
          ))}
        </div>

        {data?.activityByAction && data.activityByAction.length > 0 && (
          <div>
            <p className="mb-2 text-xs font-medium text-[hsl(var(--fg-secondary))]">
              Activity by Action
            </p>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={data.activityByAction.slice(0, 8)}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis
                  dataKey="action"
                  stroke="hsl(var(--muted-fg))"
                  fontSize={10}
                  angle={-45}
                  textAnchor="end"
                  height={60}
                />
                <YAxis stroke="hsl(var(--muted-fg))" fontSize={11} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {(!data || data.activityByAction.length === 0) && (
          <EmptyState title="No audit data available" description="Audit analytics will appear once events are recorded" className="py-4" />
        )}
      </CardContent>
    </Card>
  )
})
