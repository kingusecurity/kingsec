import { cn } from "@/shared/lib/utils"

interface EmptyStateProps {
  icon?: React.ReactNode
  title: string
  description?: string
  action?: React.ReactNode
  className?: string
}

export function EmptyState({ icon, title, description, action, className }: EmptyStateProps): React.ReactElement {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-4 py-16 text-center", className)}>
      {icon && <div className="text-[hsl(var(--muted-fg))]">{icon}</div>}
      <div className="space-y-1">
        <h3 className="text-lg font-medium text-[hsl(var(--fg))]">{title}</h3>
        {description && <p className="text-sm text-[hsl(var(--fg-secondary))]">{description}</p>}
      </div>
      {action}
    </div>
  )
}
