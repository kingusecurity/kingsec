import { Loader2, RefreshCw } from "lucide-react"
import { Button } from "@/shared/ui/button"
import type { ReactNode } from "react"

interface SettingsSectionProps {
  title: string
  description: string
  children: ReactNode
  isLoading?: boolean
  error?: string | null
  onRetry?: () => void
  onSave?: () => void
  saveDisabled?: boolean
  saveLoading?: boolean
}

export function SettingsSection({
  title,
  description,
  children,
  isLoading,
  error,
  onRetry,
  onSave,
  saveDisabled,
  saveLoading,
}: SettingsSectionProps): React.ReactElement {
  if (isLoading) {
    return (
      <div className="space-y-4">
        <div>
          <h3 className="text-lg font-semibold text-[hsl(var(--fg))]">{title}</h3>
          <p className="text-sm text-[hsl(var(--muted-fg))]">{description}</p>
        </div>
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="skeleton h-10 rounded-lg" />
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-4">
        <div>
          <h3 className="text-lg font-semibold text-[hsl(var(--fg))]">{title}</h3>
          <p className="text-sm text-[hsl(var(--muted-fg))]">{description}</p>
        </div>
        <div className="flex flex-col items-center gap-3 rounded-lg border border-[hsl(var(--border))] py-8" role="alert">
          <p className="text-sm text-[hsl(var(--destructive))]">{error}</p>
          {onRetry && (
            <Button variant="outline" size="sm" onClick={onRetry}>
              <RefreshCw className="mr-2 size-4" />
              Retry
            </Button>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold text-[hsl(var(--fg))]">{title}</h3>
        <p className="text-sm text-[hsl(var(--muted-fg))]">{description}</p>
      </div>
      {children}
      {onSave && (
        <div className="flex justify-end">
          <Button onClick={onSave} disabled={saveDisabled || saveLoading}>
            {saveLoading && <Loader2 className="mr-2 size-4 animate-spin" />}
            Save Changes
          </Button>
        </div>
      )}
    </div>
  )
}
