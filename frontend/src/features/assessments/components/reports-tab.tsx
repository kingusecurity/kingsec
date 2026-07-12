import { FileText } from "lucide-react"
import { EmptyState } from "@/shared/components/empty-state"
import { Button } from "@/shared/ui/button"

interface ReportsTabProps {
  onGenerateReport: () => void
  isGenerating: boolean
}

export function ReportsTab({ onGenerateReport, isGenerating }: ReportsTabProps): React.ReactElement {
  return (
    <div className="space-y-4">
      <EmptyState
        icon={<FileText className="size-12" />}
        title="Reports"
        description="Generate a PDF report for this assessment. Reports include findings, severity breakdown, and recommendations."
        action={
          <div className="flex gap-2">
            <Button onClick={onGenerateReport} disabled={isGenerating}>
              {isGenerating ? "Generating..." : "Generate Report"}
            </Button>
          </div>
        }
      />
    </div>
  )
}
