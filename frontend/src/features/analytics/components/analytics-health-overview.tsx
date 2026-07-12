import { memo } from "react"
import { Activity, Cpu, Database, Wifi, Server } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { EmptyState } from "@/shared/components/empty-state"
import { useHealthCheck } from "@/features/dashboard/hooks/use-dashboard"

const STATUS_CONFIG: Record<string, { color: string; label: string; badgeVariant: "success" | "warning" | "destructive" | "secondary" }> = {
  healthy: { color: "bg-emerald-500", label: "Healthy", badgeVariant: "success" },
  degraded: { color: "bg-amber-500", label: "Degraded", badgeVariant: "warning" },
  down: { color: "bg-red-500", label: "Down", badgeVariant: "destructive" },
}

interface ServiceRowProps {
  name: string
  status: string
  icon: React.ReactNode
}

function ServiceRow({ name, status, icon }: ServiceRowProps): React.ReactElement {
  const config = STATUS_CONFIG[status] ?? STATUS_CONFIG.healthy
  return (
    <div className="flex items-center justify-between rounded-lg border border-[hsl(var(--border))] px-3 py-2">
      <div className="flex items-center gap-2">
        {icon}
        <span className="text-sm text-[hsl(var(--fg))]">{name}</span>
      </div>
      <Badge variant={config.badgeVariant}>{config.label}</Badge>
    </div>
  )
}

export const AnalyticsHealthOverview = memo(function AnalyticsHealthOverview(): React.ReactElement {
  const { data: health, isLoading } = useHealthCheck()

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="skeleton h-10 rounded-lg" />
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  const status = (health as Record<string, string>)?.status ?? "healthy"

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">System Health</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          <ServiceRow name="API" status={status} icon={<Server className="size-3.5 text-[hsl(var(--muted-fg))]" />} />
          <ServiceRow name="Database" status={status} icon={<Database className="size-3.5 text-[hsl(var(--muted-fg))]" />} />
          <ServiceRow name="Authentication" status={status} icon={<Activity className="size-3.5 text-[hsl(var(--muted-fg))]" />} />
          <ServiceRow name="SSE" status={status} icon={<Wifi className="size-3.5 text-[hsl(var(--muted-fg))]" />} />
          <ServiceRow name="Workers" status={status} icon={<Cpu className="size-3.5 text-[hsl(var(--muted-fg))]" />} />
        </div>

        <div className="mt-4 rounded-lg border border-dashed border-[hsl(var(--border))] p-3 text-center">
          <p className="text-xs text-[hsl(var(--muted-fg))]">
            Worker utilization, queue depth, SSE connections, and avg response time are ready for backend analytics.
          </p>
        </div>
      </CardContent>
    </Card>
  )
})
