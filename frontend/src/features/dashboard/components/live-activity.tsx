import { memo, useCallback, useState, useEffect, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { formatRelative } from "@/shared/lib/utils"
import { getApiBaseUrl } from "@/shared/lib/env"
import { getStoredToken } from "@/shared/api/client"
import { Wifi, WifiOff } from "lucide-react"

interface LiveEvent {
  event_type: string
  assessment_id: string
  state: string
  message: string
  timestamp: string
}

const EVENT_VARIANTS: Record<string, "default" | "secondary" | "destructive" | "success" | "warning" | "muted"> = {
  "assessment.started": "default",
  "assessment.completed": "success",
  "assessment.failed": "destructive",
  "assessment.cancelled": "warning",
  "report.ready": "success",
}

const EVENT_LABELS: Record<string, string> = {
  "assessment.created": "Created",
  "assessment.started": "Started",
  "assessment.completed": "Completed",
  "assessment.failed": "Failed",
  "assessment.cancelled": "Cancelled",
  "report.ready": "Report",
}

const MAX_EVENTS = 50

export const LiveActivityWidget = memo(function LiveActivityWidget(): React.ReactElement {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)
  const backoffRef = useRef(1000)

  const connect = useCallback(() => {
    const baseUrl = getApiBaseUrl()
    const token = getStoredToken()
    const params = new URLSearchParams()
    if (token) params.set("token", token)

    try {
      const es = new EventSource(`${baseUrl}/events?${params.toString()}`)
      esRef.current = es

      es.onopen = () => {
        setIsConnected(true)
        backoffRef.current = 1000
      }

      const handler = (e: MessageEvent) => {
        const data: LiveEvent = JSON.parse(e.data)
        setEvents((prev) => {
          const next = [data, ...prev]
          return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next
        })
      }

      es.addEventListener("assessment.started", handler as EventListener)
      es.addEventListener("assessment.completed", handler as EventListener)
      es.addEventListener("assessment.failed", handler as EventListener)
      es.addEventListener("assessment.cancelled", handler as EventListener)
      es.addEventListener("report.ready", handler as EventListener)

      es.onerror = () => {
        setIsConnected(false)
        es.close()
        const delay = backoffRef.current
        backoffRef.current = Math.min(delay * 2, 30_000)
        setTimeout(connect, delay)
      }
    } catch {
      setIsConnected(false)
    }
  }, [])

  useEffect(() => {
    connect()
    return () => { esRef.current?.close() }
  }, [connect])

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">Live Activity</CardTitle>
        <div className="flex items-center gap-2">
          {isConnected ? (
            <Badge variant="success" className="gap-1"><Wifi className="size-3" /> Live</Badge>
          ) : (
            <Badge variant="destructive" className="gap-1"><WifiOff className="size-3" /> Offline</Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {events.length === 0 ? (
          <p className="py-8 text-center text-sm text-[hsl(var(--muted-fg))]">Waiting for events...</p>
        ) : (
          <div className="max-h-[300px] space-y-2 overflow-y-auto">
            {events.map((event, i) => (
              <div key={`${event.timestamp}-${i}`} className="flex items-center gap-2 rounded-lg border border-[hsl(var(--border))] p-2 text-sm">
                <Badge variant={EVENT_VARIANTS[event.event_type] ?? "secondary"} className="shrink-0">
                  {EVENT_LABELS[event.event_type] ?? event.event_type}
                </Badge>
                <span className="flex-1 truncate text-[hsl(var(--fg))]">{event.message}</span>
                <span className="shrink-0 text-[10px] text-[hsl(var(--muted-fg))]">{formatRelative(event.timestamp)}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
})
