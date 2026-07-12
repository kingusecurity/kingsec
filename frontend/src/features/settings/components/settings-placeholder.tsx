import { Loader2, RefreshCw, Construction } from "lucide-react"
import { Badge } from "@/shared/ui/badge"
import { Button } from "@/shared/ui/button"

interface SettingsPlaceholderProps {
  title: string
  description: string
  isLoading?: boolean
  error?: string | null
  onRetry?: () => void
}

export function SettingsPlaceholder({
  title,
  description,
  isLoading,
  error,
  onRetry,
}: SettingsPlaceholderProps): React.ReactElement {
  if (isLoading) {
    return (
      <div className="flex flex-col items-center gap-3 py-8">
        <Loader2 className="size-6 animate-spin text-[hsl(var(--muted-fg))]" />
        <p className="text-sm text-[hsl(var(--muted-fg))]">Loading...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center gap-3 py-8" role="alert">
        <p className="text-sm text-[hsl(var(--destructive))]">{error}</p>
        {onRetry && (
          <Button variant="outline" size="sm" onClick={onRetry}>
            <RefreshCw className="mr-2 size-4" />
            Retry
          </Button>
        )}
      </div>
    )
  }

  return (
    <div className="flex flex-col items-center gap-3 py-8 text-center">
      <div className="flex size-12 items-center justify-center rounded-lg bg-[hsl(var(--muted))]">
        <Construction className="size-6 text-[hsl(var(--muted-fg))]" />
      </div>
      <div className="space-y-1">
        <h4 className="font-medium text-[hsl(var(--fg))]">{title}</h4>
        <p className="max-w-md text-sm text-[hsl(var(--muted-fg))]">{description}</p>
      </div>
      <Badge variant="secondary">Ready for backend integration</Badge>
    </div>
  )
}
