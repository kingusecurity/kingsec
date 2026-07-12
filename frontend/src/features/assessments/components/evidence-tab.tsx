import { FileSearch } from "lucide-react"
import { EmptyState } from "@/shared/components/empty-state"

export function EvidenceTab(): React.ReactElement {
  return (
    <EmptyState
      icon={<FileSearch className="size-12" />}
      title="Evidence"
      description="Detailed evidence for each finding will be available when the backend exposes evidence endpoints."
    />
  )
}
