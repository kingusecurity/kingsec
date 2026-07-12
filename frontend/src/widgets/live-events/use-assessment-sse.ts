import { useEffect, useRef, useCallback, useState } from "react"
import { getApiBaseUrl } from "@/shared/lib/env"
import { getStoredToken } from "@/shared/api/client"

const MAX_EVENTS = 100
const MAX_BACKOFF_MS = 30_000
const INITIAL_BACKOFF_MS = 1_000

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
  const backoffRef = useRef(INITIAL_BACKOFF_MS)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const enabledRef = useRef(enabled)
  const onEventRef = useRef(onEvent)
  enabledRef.current = enabled
  onEventRef.current = onEvent

  const connect = useCallback(() => {
    if (!enabledRef.current) return

    eventSourceRef.current?.close()

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
        backoffRef.current = INITIAL_BACKOFF_MS
      }

      const handleEvent = (e: MessageEvent) => {
        const data: SSEEvent = JSON.parse(e.data)
        setEvents((prev) => {
          const next = [...prev, data]
          return next.length > MAX_EVENTS ? next.slice(next.length - MAX_EVENTS) : next
        })
        onEventRef.current?.(data)
      }

      es.addEventListener("assessment.created", handleEvent as EventListener)
      es.addEventListener("assessment.started", handleEvent as EventListener)
      es.addEventListener("assessment.completed", handleEvent as EventListener)
      es.addEventListener("assessment.failed", handleEvent as EventListener)
      es.addEventListener("assessment.cancelled", handleEvent as EventListener)
      es.addEventListener("assessment.deleted", handleEvent as EventListener)
      es.addEventListener("report.ready", handleEvent as EventListener)

      es.onerror = () => {
        setIsConnected(false)
        es.close()

        if (!enabledRef.current) return

        const delay = backoffRef.current
        setError(`Connection lost. Reconnecting in ${Math.round(delay / 1000)}s...`)
        backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS)

        reconnectTimerRef.current = setTimeout(() => {
          connect()
        }, delay)
      }
    } catch {
      setError("Failed to connect to event stream")
      setIsConnected(false)

      if (enabledRef.current) {
        const delay = backoffRef.current
        backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS)
        reconnectTimerRef.current = setTimeout(() => connect(), delay)
      }
    }
  }, [assessmentId])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
      }
      eventSourceRef.current?.close()
      eventSourceRef.current = null
    }
  }, [connect])

  const clearEvents = useCallback(() => setEvents([]), [])

  return { events, isConnected, error, clearEvents }
}
