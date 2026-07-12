import { memo, useCallback, useState, useEffect, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { formatRelative } from "@/shared/lib/utils"
import { getApiBaseUrl } from "@/shared/lib/env"
import { getStoredToken } from "@/shared/api/client"
import { Play } from "lucide-react"

interface RunningJob {
  assessment_id: string
  target: string
  started_at: string
}

export const RunningJobsWidget = memo(function RunningJobsWidget(): React.ReactElement {
  const [jobs, setJobs] = useState<RunningJob[]>([])
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

      es.onopen = () => { backoffRef.current = 1000 }

      es.addEventListener("assessment.started", ((e: MessageEvent) => {
        const data = JSON.parse(e.data)
        setJobs((prev) => [
          ...prev.filter((j) => j.assessment_id !== data.assessment_id),
          { assessment_id: data.assessment_id, target: data.message, started_at: data.timestamp },
        ])
      }) as EventListener)

      const removeHandler = (e: MessageEvent) => {
        const data = JSON.parse(e.data)
        setJobs((prev) => prev.filter((j) => j.assessment_id !== data.assessment_id))
      }

      es.addEventListener("assessment.completed", removeHandler as EventListener)
      es.addEventListener("assessment.failed", removeHandler as EventListener)
      es.addEventListener("assessment.cancelled", removeHandler as EventListener)

      es.onerror = () => {
        es.close()
        const delay = backoffRef.current
        backoffRef.current = Math.min(delay * 2, 30_000)
        setTimeout(connect, delay)
      }
    } catch {
      // silent
    }
  }, [])

  useEffect(() => {
    connect()
    return () => { esRef.current?.close() }
  }, [connect])

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Play className="size-4 text-[hsl(var(--primary))]" />
          Running Jobs
          {jobs.length > 0 && <Badge variant="default">{jobs.length}</Badge>}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {jobs.length === 0 ? (
          <p className="py-4 text-center text-sm text-[hsl(var(--muted-fg))]">No running scans</p>
        ) : (
          <div className="space-y-2">
            {jobs.map((job) => (
              <div key={job.assessment_id} className="flex items-center justify-between rounded-lg border border-[hsl(var(--border))] p-3">
                <div className="space-y-1">
                  <p className="text-sm font-medium text-[hsl(var(--fg))]">{job.target}</p>
                  <p className="text-[10px] text-[hsl(var(--muted-fg))]">
                    Started {formatRelative(job.started_at)}
                  </p>
                </div>
                <Badge variant="default">
                  <Play className="mr-1 size-3" />
                  Running
                </Badge>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
})
