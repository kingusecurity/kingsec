import { useParams, useNavigate } from 'react-router-dom'
import { useQueueEntry, useRetryJob, useCancelJob } from '@/hooks/use-distributed-queue'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'

export function JobDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: entry, isLoading } = useQueueEntry(id!)
  const retryJob = useRetryJob()
  const cancelJob = useCancelJob()
  const navigate = useNavigate()

  if (isLoading) return <div className="flex justify-center py-12"><Spinner size="lg" /></div>
  if (!entry) return <div className="text-center py-12 text-text-muted">Queue entry not found</div>

  const canCancel = ['queued', 'assigned', 'retrying'].includes(entry.state)
  const isFailed = entry.state === 'failed'
  const stateColor = (state: string) => {
    switch (state) {
      case 'queued': return 'neutral'
      case 'assigned': case 'running': return 'info'
      case 'completed': return 'success'
      case 'failed': case 'expired': return 'critical'
      case 'cancelled': case 'retrying': return 'warning'
      default: return 'neutral'
    }
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Job Detail</h1>
          <p className="text-sm text-text-muted font-mono">{entry.entry_id}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => navigate('/queue')}>Back</Button>
          {isFailed && <Button onClick={() => retryJob.mutate(entry.entry_id)}>Retry</Button>}
          {canCancel && <Button variant="danger" onClick={() => cancelJob.mutate(entry.entry_id)}>Cancel</Button>}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Card className="p-4 space-y-3">
          <h3 className="font-medium text-text-primary">Details</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-text-muted">State</span><Badge variant={stateColor(entry.state)}>{entry.state}</Badge></div>
            <div className="flex justify-between"><span className="text-text-muted">Job ID</span><span className="font-mono">{entry.job_id}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Target</span><span>{entry.target || '-'}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Worker</span><span>{entry.assigned_worker_id || 'unassigned'}</span></div>
          </div>
        </Card>

        <Card className="p-4 space-y-3">
          <h3 className="font-medium text-text-primary">Retry Info</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-text-muted">Retries</span><span>{entry.retry_count}/{entry.max_retries}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Created</span><span>{new Date(entry.created_at).toLocaleString()}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Started</span><span>{entry.started_at ? new Date(entry.started_at).toLocaleString() : '-'}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Completed</span><span>{entry.completed_at ? new Date(entry.completed_at).toLocaleString() : '-'}</span></div>
          </div>
        </Card>
      </div>

      {entry.error_message && (
        <Card className="p-4 space-y-2 border-red-500/30">
          <h3 className="font-medium text-red-400">Error</h3>
          <pre className="text-sm text-red-300 whitespace-pre-wrap">{entry.error_message}</pre>
        </Card>
      )}

      {entry.scanner_ids && entry.scanner_ids.length > 0 && (
        <Card className="p-4 space-y-2">
          <h3 className="font-medium text-text-primary">Scanner Requirements</h3>
          <div className="flex gap-2 flex-wrap">
            {entry.scanner_ids.map((s: string) => <Badge key={s} variant="info">{s}</Badge>)}
          </div>
        </Card>
      )}
    </div>
  )
}
