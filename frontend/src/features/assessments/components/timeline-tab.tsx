import { Clock } from "lucide-react"
import { EmptyState } from "@/shared/components/empty-state"

export function TimelineTab(): React.ReactElement {
  return (
    <EmptyState
      icon={<Clock className="size-12" />}
      title="Timeline"
      description="Assessment state transition history will be available when the backend exposes the timeline endpoint."
    />
  )
}
