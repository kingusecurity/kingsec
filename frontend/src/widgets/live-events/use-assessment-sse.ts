import { useEffect, useRef, useCallback, useState } from "react"
import { getApiBaseUrl } from "@/shared/lib/env"
import { getStoredToken } from "@/shared/api/client"

export interface SSEEvent {
  event_type: string
  assessment_id: string
  state: string
  message: string
  severity_counts: Record<string, number> | null
  timestamp: string
}

interface UseAssessmentSSEOptions {
  assessmentId?: string
  enabled?: boolean
  onEvent?: (event: SSEEvent) => void
}

export function useAssessmentSSE({ assessmentId, enabled = true, onEvent }: UseAssessmentSSEOptions = {}) {
  const [events, setEvents] = useState<SSEEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const eventSourceRef = useRef<EventSource | null>(null)
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent

  const connect = useCallback(() => {
    if (!enabled) return

    const baseUrl = getApiBaseUrl()
    const token = getStoredToken()
    const params = new URLSearchParams()
    if (assessmentId) params.set("assessment_id", assessmentId)
    if (token) params.set("token", token)

    const url = `${baseUrl}/events?${params.toString()}`

    try {
      const es = new EventSource(url)
      eventSourceRef.current = es

      es.onopen = () => {
        setIsConnected(true)
        setError(null)
      }

      es.addEventListener("assessment.created", ((e: MessageEvent) => {
        const data: SSEEvent = JSON.parse(e.data)
        setEvents((prev) => [...prev, data])
        onEventRef.current?.(data)
      }) as EventListener)

      es.addEventListener("assessment.started", ((e: MessageEvent) => {
        const data: SSEEvent = JSON.parse(e.data)
        setEvents((prev) => [...prev, data])
        onEventRef.current?.(data)
      }) as EventListener)

      es.addEventListener("assessment.completed", ((e: MessageEvent) => {
        const data: SSEEvent = JSON.parse(e.data)
        setEvents((prev) => [...prev, data])
        onEventRef.current?.(data)
      }) as EventListener)

      es.addEventListener("assessment.failed", ((e: MessageEvent) => {
        const data: SSEEvent = JSON.parse(e.data)
        setEvents((prev) => [...prev, data])
        onEventRef.current?.(data)
      }) as EventListener)

      es.addEventListener("assessment.cancelled", ((e: MessageEvent) => {
        const data: SSEEvent = JSON.parse(e.data)
        setEvents((prev) => [...prev, data])
        onEventRef.current?.(data)
      }) as EventListener)

      es.addEventListener("assessment.deleted", ((e: MessageEvent) => {
        const data: SSEEvent = JSON.parse(e.data)
        setEvents((prev) => [...prev, data])
        onEventRef.current?.(data)
      }) as EventListener)

      es.addEventListener("report.ready", ((e: MessageEvent) => {
        const data: SSEEvent = JSON.parse(e.data)
        setEvents((prev) => [...prev, data])
        onEventRef.current?.(data)
      }) as EventListener)

      es.onerror = () => {
        setIsConnected(false)
        setError("Connection lost. Reconnecting...")
        es.close()
        if (enabled) {
          setTimeout(connect, 3000)
        }
      }
    } catch (err) {
      setError("Failed to connect to event stream")
      setIsConnected(false)
    }
  }, [assessmentId, enabled])

  useEffect(() => {
    connect()
    return () => {
      eventSourceRef.current?.close()
      eventSourceRef.current = null
    }
  }, [connect])

  const clearEvents = useCallback(() => setEvents([]), [])

  return { events, isConnected, error, clearEvents }
}
