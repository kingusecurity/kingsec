import { useState } from 'react'
import { Play, XCircle, Trash2, FileText } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'

interface AssessmentActionsProps {
  status: string
  onStart?: () => void
  onCancel?: () => void
  onDelete?: () => void
  onGenerateReport?: () => void
  startLoading?: boolean
  cancelLoading?: boolean
  deleteLoading?: boolean
  reportLoading?: boolean
}

export function AssessmentActions({
  status,
  onStart,
  onCancel,
  onDelete,
  onGenerateReport,
  startLoading,
  cancelLoading,
  deleteLoading,
  reportLoading,
}: AssessmentActionsProps) {
  const [confirmAction, setConfirmAction] = useState<'cancel' | 'delete' | null>(null)
  const s = status.toLowerCase()

  return (
    <div className="flex flex-wrap gap-2">
      {s === 'authorized' && onStart && (
        <Button size="sm" onClick={onStart} loading={startLoading} iconLeft={<Play className="h-4 w-4" />}>
          Start
        </Button>
      )}
      {(s === 'draft' || s === 'authorized' || s === 'running') && onCancel && (
        <Button size="sm" variant="outline" onClick={() => setConfirmAction('cancel')} iconLeft={<XCircle className="h-4 w-4" />}>
          Cancel
        </Button>
      )}
      {s === 'completed' && onGenerateReport && (
        <Button size="sm" variant="secondary" onClick={onGenerateReport} loading={reportLoading} iconLeft={<FileText className="h-4 w-4" />}>
          Generate Report
        </Button>
      )}
      {(s === 'draft' || s === 'failed' || s === 'cancelled') && onDelete && (
        <Button size="sm" variant="ghost" onClick={() => setConfirmAction('delete')} iconLeft={<Trash2 className="h-4 w-4" />}>
          Delete
        </Button>
      )}

      <ConfirmDialog
        open={confirmAction === 'cancel'}
        onClose={() => setConfirmAction(null)}
        onConfirm={() => { onCancel?.(); setConfirmAction(null) }}
        title="Cancel Assessment"
        message="Are you sure you want to cancel this assessment? This action cannot be undone."
        confirmLabel="Cancel Assessment"
        variant="warning"
        loading={cancelLoading}
      />
      <ConfirmDialog
        open={confirmAction === 'delete'}
        onClose={() => setConfirmAction(null)}
        onConfirm={() => { onDelete?.(); setConfirmAction(null) }}
        title="Delete Assessment"
        message="Are you sure you want to delete this assessment? All findings and reports will be permanently removed."
        confirmLabel="Delete"
        variant="danger"
        loading={deleteLoading}
      />
    </div>
  )
}
