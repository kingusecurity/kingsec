import { cn } from "@/shared/lib/utils"
import type { ReactNode } from "react"

interface PageHeaderProps {
  title: string
  description?: string
  actions?: ReactNode
  className?: string
}

export function PageHeader({ title, description, actions, className }: PageHeaderProps): React.ReactElement {
  return (
    <div className={cn("flex items-start justify-between", className)}>
      <div className="space-y-1">
        <h1 className="text-2xl font-bold text-[hsl(var(--fg))]">{title}</h1>
        {description && (
          <p className="text-sm text-[hsl(var(--fg-secondary))]">{description}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}
