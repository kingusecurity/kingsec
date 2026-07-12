import * as React from "react"
import { cn } from "@/shared/lib/utils"

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "secondary" | "destructive" | "outline" | "success" | "warning" | "muted"
}

function Badge({ className, variant = "default", ...props }: BadgeProps): React.ReactElement {
  const variants: Record<string, string> = {
    default: "bg-[hsl(var(--primary))]/10 text-[hsl(var(--primary))] border-transparent",
    secondary: "bg-[hsl(var(--secondary))] text-[hsl(var(--fg))] border-transparent",
    destructive: "bg-[hsl(var(--destructive))]/10 text-[hsl(var(--destructive))] border-transparent",
    outline: "text-[hsl(var(--fg))]",
    success: "bg-[hsl(var(--success))]/10 text-[hsl(var(--success))] border-transparent",
    warning: "bg-[hsl(var(--warning))]/10 text-[hsl(var(--warning))] border-transparent",
    muted: "bg-[hsl(var(--muted))] text-[hsl(var(--muted-fg))] border-transparent",
  }

  return (
    <div
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors",
        variants[variant],
        className,
      )}
      {...props}
    />
  )
}

export { Badge }
