import type { ReactNode } from "react"
import { cn } from "@/shared/lib/utils"

interface PageTransitionProps {
  children: ReactNode
  className?: string
}

export function PageTransition({ children, className }: PageTransitionProps): React.ReactElement {
  return (
    <div className={cn("page-enter", className)}>
      {children}
    </div>
  )
}
