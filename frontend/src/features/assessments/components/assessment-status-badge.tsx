import { Badge } from "@/shared/ui/badge"
import type { AssessmentStatus } from "../types"

const STATUS_CONFIG: Record<AssessmentStatus, { label: string; variant: "default" | "secondary" | "destructive" | "success" | "warning" | "muted" }> = {
  CREATED: { label: "Created", variant: "secondary" },
  RUNNING: { label: "Running", variant: "default" },
  COMPLETED: { label: "Completed", variant: "success" },
  FAILED: { label: "Failed", variant: "destructive" },
  CANCELLED: { label: "Cancelled", variant: "muted" },
}

interface AssessmentStatusBadgeProps {
  status: AssessmentStatus
}

export function AssessmentStatusBadge({ status }: AssessmentStatusBadgeProps): React.ReactElement {
  const config = STATUS_CONFIG[status] ?? { label: status, variant: "secondary" as const }
  return <Badge variant={config.variant}>{config.label}</Badge>
}
