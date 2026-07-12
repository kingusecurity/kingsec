import { useMemo } from "react"
import { useSystemInfo } from "../hooks/use-settings"
import { SettingsSection } from "../components/settings-section"
import { SettingsPlaceholder } from "../components/settings-placeholder"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Card, CardContent } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { getApiError } from "@/shared/api/error-handler"

export function AdvancedSettingsPage(): React.ReactElement {
  const { data: systemInfo, isLoading, error, refetch } = useSystemInfo()

  const browserInfo = useMemo(() => {
    if (typeof navigator === "undefined") return "N/A"
    return `${navigator.userAgent}`
  }, [])

  const environment = useMemo(() => {
    if (import.meta.env.PROD) return "production"
    if (import.meta.env.DEV) return "development"
    return "unknown"
  }, [])

  return (
    <ErrorBoundary>
      <SettingsSection
        title="Advanced"
        description="System information and advanced settings."
      >
        <Card>
          <CardContent className="p-6">
            {isLoading || error ? (
              <SettingsPlaceholder
                title="System Information"
                description="System information will be displayed here."
                isLoading={isLoading}
                error={error ? getApiError(error).detail : null}
                onRetry={refetch}
              />
            ) : (
              <div className="space-y-3">
                <InfoRow label="Frontend Version" value={systemInfo?.frontend_version ?? "0.1.0"} />
                <InfoRow label="Backend Version" value={systemInfo?.backend_version ?? "N/A"} />
                <InfoRow label="API Version" value={systemInfo?.api_version ?? "v1"} />
                <InfoRow label="Build Date" value={systemInfo?.build_date ?? new Date().toISOString().split("T")[0]} />
                <InfoRow
                  label="Environment"
                  value={
                    <Badge variant={environment === "production" ? "destructive" : "secondary"}>
                      {environment}
                    </Badge>
                  }
                />
                <InfoRow label="Browser" value={browserInfo} mono />
              </div>
            )}
          </CardContent>
        </Card>
      </SettingsSection>
    </ErrorBoundary>
  )
}

function InfoRow({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }): React.ReactElement {
  return (
    <div className="flex items-center justify-between border-b border-[hsl(var(--border))] pb-2">
      <span className="text-sm text-[hsl(var(--muted-fg))]">{label}</span>
      <span className={`text-sm text-[hsl(var(--fg))] ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  )
}
