import { Badge } from "@/shared/ui/badge"

const SEVERITY_CONFIG: Record<string, { label: string; variant: "destructive" | "warning" | "secondary" | "muted" | "default" }> = {
  CRITICAL: { label: "Critical", variant: "destructive" },
  HIGH: { label: "High", variant: "destructive" },
  MEDIUM: { label: "Medium", variant: "warning" },
  LOW: { label: "Low", variant: "secondary" },
  INFO: { label: "Info", variant: "muted" },
}

interface SeverityBadgeProps {
  severity: string
}

export function SeverityBadge({ severity }: SeverityBadgeProps): React.ReactElement {
  const config = SEVERITY_CONFIG[severity] ?? { label: severity, variant: "secondary" as const }
  return <Badge variant={config.variant}>{config.label}</Badge>
}
