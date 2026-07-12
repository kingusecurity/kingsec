import { Lightbulb } from "lucide-react"
import { EmptyState } from "@/shared/components/empty-state"

export function RecommendationsTab(): React.ReactElement {
  return (
    <EmptyState
      icon={<Lightbulb className="size-12" />}
      title="Recommendations"
      description="Remediation recommendations will be available when the backend exposes the recommendations endpoint."
    />
  )
}
