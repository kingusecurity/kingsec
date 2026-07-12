import { memo } from "react"
import { Shield, Wifi, WifiOff, RefreshCw } from "lucide-react"
import { Badge } from "@/shared/ui/badge"
import { formatDateTime } from "@/shared/lib/utils"
import type { SSEEvent } from "@/widgets/live-events/use-assessment-sse"

interface LiveEventsTabProps {
  events: SSEEvent[]
  isConnected: boolean
  error: string | null
}

const EVENT_LABELS: Record<string, string> = {
  "assessment.created": "Created",
  "assessment.started": "Started",
  "assessment.completed": "Completed",
  "assessment.failed": "Failed",
  "assessment.cancelled": "Cancelled",
  "assessment.deleted": "Deleted",
  "report.ready": "Report Ready",
}

const EVENT_VARIANTS: Record<string, "default" | "secondary" | "destructive" | "success" | "warning" | "muted"> = {
  "assessment.created": "secondary",
  "assessment.started": "default",
  "assessment.completed": "success",
  "assessment.failed": "destructive",
  "assessment.cancelled": "warning",
  "assessment.deleted": "muted",
  "report.ready": "success",
}

export const LiveEventsTab = memo(function LiveEventsTab({
  events,
  isConnected,
  error,
}: LiveEventsTabProps): React.ReactElement {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-[hsl(var(--fg))]">Live Events</h3>
        <div className="flex items-center gap-2">
          {isConnected ? (
            <Badge variant="success" className="gap-1">
              <Wifi className="size-3" />
              Connected
            </Badge>
          ) : (
            <Badge variant="destructive" className="gap-1">
              <WifiOff className="size-3" />
              Disconnected
            </Badge>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-[hsl(var(--warning))]/50 bg-[hsl(var(--warning))]/5 p-3 text-sm text-[hsl(var(--warning))]">
          <RefreshCw className="mr-2 inline size-3 animate-spin" />
          {error}
        </div>
      )}

      {events.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-12 text-center">
          <Shield className="size-8 text-[hsl(var(--muted-fg))]" />
          <p className="text-sm text-[hsl(var(--fg-secondary))]">Waiting for events...</p>
        </div>
      ) : (
        <div className="space-y-2">
          {events.map((event, i) => (
            <div
              key={`${event.timestamp}-${i}`}
              className="flex items-center gap-3 rounded-lg border border-[hsl(var(--border))] p-3 transition-colors hover:bg-[hsl(var(--accent))]/50"
            >
              <Badge variant={EVENT_VARIANTS[event.event_type] ?? "secondary"}>
                {EVENT_LABELS[event.event_type] ?? event.event_type}
              </Badge>
              <span className="flex-1 text-sm text-[hsl(var(--fg))]">{event.message}</span>
              <span className="text-xs text-[hsl(var(--muted-fg))]">{formatDateTime(event.timestamp)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
})
