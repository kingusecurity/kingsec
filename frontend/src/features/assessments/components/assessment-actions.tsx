import { useState } from "react"
import { Play, XCircle, Trash2, FileText, Loader2 } from "lucide-react"
import { useStartAssessment, useCancelAssessment, useDeleteAssessment, useGenerateReport } from "../hooks/use-assessments"
import { ConfirmDialog } from "@/shared/components/confirm-dialog"
import { Button } from "@/shared/ui/button"
import type { AssessmentStatus } from "../types"

interface AssessmentActionsProps {
  assessmentId: string
  status: AssessmentStatus
  onDeleted: () => void
}

export function AssessmentActions({ assessmentId, status, onDeleted }: AssessmentActionsProps): React.ReactElement {
  const [deleteOpen, setDeleteOpen] = useState(false)
  const startMutation = useStartAssessment()
  const cancelMutation = useCancelAssessment()
  const deleteMutation = useDeleteAssessment()
  const reportMutation = useGenerateReport()

  const canStart = status === "CREATED"
  const canCancel = status === "RUNNING"
  const canDelete = status !== "RUNNING"
  const canReport = status === "COMPLETED"

  function handleDelete(): void {
    deleteMutation.mutate(assessmentId, {
      onSuccess: () => {
        setDeleteOpen(false)
        onDeleted()
      },
    })
  }

  return (
    <>
      <div className="flex flex-wrap gap-2">
        {canStart && (
          <Button
            size="sm"
            onClick={() => startMutation.mutate(assessmentId)}
            disabled={startMutation.isPending}
          >
            {startMutation.isPending ? <Loader2 className="mr-2 size-4 animate-spin" /> : <Play className="mr-2 size-4" />}
            Start Scan
          </Button>
        )}
        {canCancel && (
          <Button
            size="sm"
            variant="destructive"
            onClick={() => cancelMutation.mutate(assessmentId)}
            disabled={cancelMutation.isPending}
          >
            {cancelMutation.isPending ? <Loader2 className="mr-2 size-4 animate-spin" /> : <XCircle className="mr-2 size-4" />}
            Cancel
          </Button>
        )}
        {canReport && (
          <Button
            size="sm"
            variant="outline"
            onClick={() => reportMutation.mutate(assessmentId)}
            disabled={reportMutation.isPending}
          >
            {reportMutation.isPending ? <Loader2 className="mr-2 size-4 animate-spin" /> : <FileText className="mr-2 size-4" />}
            Generate Report
          </Button>
        )}
        {canDelete && (
          <Button
            size="sm"
            variant="destructive"
            onClick={() => setDeleteOpen(true)}
          >
            <Trash2 className="mr-2 size-4" />
            Delete
          </Button>
        )}
      </div>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete Assessment"
        description="This will permanently delete this assessment and all its findings. This action cannot be undone."
        confirmLabel="Delete"
        variant="destructive"
        onConfirm={handleDelete}
        loading={deleteMutation.isPending}
      />
    </>
  )
}
