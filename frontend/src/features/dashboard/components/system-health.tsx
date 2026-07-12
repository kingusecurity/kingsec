import { memo, useState, useEffect, useCallback, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { getApiBaseUrl } from "@/shared/lib/env"
import { getStoredToken } from "@/shared/api/client"
import { Shield, Database, Key, Wifi, Settings } from "lucide-react"

type Status = "healthy" | "degraded" | "down"

const STATUS_CONFIG: Record<Status, { color: string; label: string }> = {
  healthy: { color: "bg-[hsl(var(--success))]", label: "Healthy" },
  degraded: { color: "bg-[hsl(var(--warning))]", label: "Degraded" },
  down: { color: "bg-[hsl(var(--destructive))]", label: "Down" },
}

interface ServiceStatus {
  name: string
  icon: React.ReactNode
  status: Status
}

export const SystemHealthWidget = memo(function SystemHealthWidget(): React.ReactElement {
  const [services, setServices] = useState<ServiceStatus[]>([
    { name: "API", icon: <Shield className="size-4" />, status: "healthy" },
    { name: "Database", icon: <Database className="size-4" />, status: "healthy" },
    { name: "Authentication", icon: <Key className="size-4" />, status: "healthy" },
    { name: "SSE", icon: <Wifi className="size-4" />, status: "healthy" },
    { name: "Workers", icon: <Settings className="size-4" />, status: "healthy" },
  ])
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const checkHealth = useCallback(async () => {
    try {
      const baseUrl = getApiBaseUrl()
      const response = await fetch(`${baseUrl.replace("/api/v1", "")}/health`, {
        headers: getStoredToken() ? { Authorization: `Bearer ${getStoredToken()}` } : {},
      })
      if (response.ok) {
        setServices((prev) => prev.map((s) => ({ ...s, status: "healthy" as Status })))
      } else {
        setServices((prev) => prev.map((s) => ({ ...s, status: "degraded" as Status })))
      }
    } catch {
      setServices((prev) => prev.map((s) => ({ ...s, status: "down" as Status })))
    }
  }, [])

  useEffect(() => {
    checkHealth()
    intervalRef.current = setInterval(checkHealth, 30_000)
    return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
  }, [checkHealth])

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">System Health</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {services.map((service) => (
            <div key={service.name} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {service.icon}
                <span className="text-sm text-[hsl(var(--fg))]">{service.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className={`size-2 rounded-full ${STATUS_CONFIG[service.status].color}`} />
                <span className="text-xs text-[hsl(var(--fg-secondary))]">{STATUS_CONFIG[service.status].label}</span>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
})
