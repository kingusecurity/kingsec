import { memo } from "react"
import { useNavigate } from "react-router-dom"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Button } from "@/shared/ui/button"
import { ROUTES } from "@/shared/lib/constants"
import { Plus, RefreshCw, ScanSearch, ScrollText, User } from "lucide-react"

interface QuickActionsProps {
  onRefresh: () => void
  isRefreshing: boolean
}

export const QuickActions = memo(function QuickActions({ onRefresh, isRefreshing }: QuickActionsProps): React.ReactElement {
  const navigate = useNavigate()

  const actions = [
    { label: "New Assessment", icon: <Plus className="size-4" />, onClick: () => navigate(ROUTES.ASSESSMENTS), variant: "default" as const },
    { label: "Refresh", icon: <RefreshCw className={`size-4 ${isRefreshing ? "animate-spin" : ""}`} />, onClick: onRefresh, variant: "outline" as const },
    { label: "Assessments", icon: <ScanSearch className="size-4" />, onClick: () => navigate(ROUTES.ASSESSMENTS), variant: "outline" as const },
    { label: "Audit Logs", icon: <ScrollText className="size-4" />, onClick: () => navigate(ROUTES.AUDIT), variant: "outline" as const },
    { label: "Profile", icon: <User className="size-4" />, onClick: () => navigate(ROUTES.PROFILE), variant: "outline" as const },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Quick Actions</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          {actions.map((action) => (
            <Button key={action.label} variant={action.variant} size="sm" onClick={action.onClick}>
              {action.icon}
              <span className="ml-2">{action.label}</span>
            </Button>
          ))}
        </div>
      </CardContent>
    </Card>
  )
})
