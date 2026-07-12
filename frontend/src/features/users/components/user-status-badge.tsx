import { Badge } from "@/shared/ui/badge"

export function UserStatusBadge({ isActive }: { isActive: boolean }): React.ReactElement {
  return (
    <Badge variant={isActive ? "success" : "muted"}>
      {isActive ? "Active" : "Disabled"}
    </Badge>
  )
}
