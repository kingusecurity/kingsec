import { Construction } from "lucide-react"
import { Card, CardContent } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"

export function TimelineTab(): React.ReactElement {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-4 py-16 text-center">
        <div className="flex size-12 items-center justify-center rounded-lg bg-[hsl(var(--muted))]">
          <Construction className="size-6 text-[hsl(var(--muted-fg))]" />
        </div>
        <div className="space-y-1">
          <h3 className="text-lg font-semibold text-[hsl(var(--fg))]">Assessment Timeline</h3>
          <p className="max-w-md text-sm text-[hsl(var(--fg-secondary))]">
            This feature will consume the existing audit event trail to display assessment state transitions.
            No new endpoint needed — it reuses the audit infrastructure.
          </p>
        </div>
        <Badge variant="secondary">Ready for backend integration</Badge>
      </CardContent>
    </Card>
  )
}
