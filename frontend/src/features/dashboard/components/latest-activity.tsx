import { memo } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { formatRelative } from "@/shared/lib/utils"
import type { AuditSummaryEntry } from "../types"
import { ScrollText } from "lucide-react"

const ACTION_LABELS: Record<string, string> = {
  LOGIN: "Login",
  FAILED_LOGIN: "Failed Login",
  ASSESSMENT_CREATED: "Created",
  ASSESSMENT_STARTED: "Started",
  ASSESSMENT_COMPLETED: "Completed",
  ASSESSMENT_FAILED: "Failed",
  ASSESSMENT_CANCELLED: "Cancelled",
  REPORT_GENERATED: "Report",
}

interface AuditSummaryWidgetProps {
  entries: AuditSummaryEntry[]
}

export const AuditSummaryWidget = memo(function AuditSummaryWidget({ entries }: AuditSummaryWidgetProps): React.ReactElement {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ScrollText className="size-4" />
          Recent Activity
        </CardTitle>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="py-4 text-center text-sm text-[hsl(var(--muted-fg))]">No audit events</p>
        ) : (
          <div className="max-h-[300px] space-y-2 overflow-y-auto">
            {entries.map((entry, i) => (
              <div key={`${entry.timestamp}-${i}`} className="flex items-center gap-2 rounded-lg border border-[hsl(var(--border))] p-2 text-sm">
                <Badge variant={entry.success ? "secondary" : "destructive"}>
                  {ACTION_LABELS[entry.action] ?? entry.action}
                </Badge>
                <span className="flex-1 truncate text-[hsl(var(--fg))]">
                  {entry.username ? `${entry.username} ` : ""}
                  {entry.resource_type}
                </span>
                <span className="shrink-0 text-[10px] text-[hsl(var(--muted-fg))]">{formatRelative(entry.timestamp)}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
})
