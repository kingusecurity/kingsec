import { Badge } from "@/shared/ui/badge"
import type { UserRole } from "../types"

const ROLE_CONFIG: Record<UserRole, { label: string; variant: "default" | "secondary" | "destructive" | "success" | "warning" | "muted" }> = {
  ADMIN: { label: "Admin", variant: "destructive" },
  ANALYST: { label: "Analyst", variant: "warning" },
  VIEWER: { label: "Viewer", variant: "secondary" },
}

export function UserRoleBadge({ role }: { role: UserRole }): React.ReactElement {
  const config = ROLE_CONFIG[role] ?? { label: role, variant: "secondary" as const }
  return <Badge variant={config.variant}>{config.label}</Badge>
}
