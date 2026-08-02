import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueue, useQueueMetrics, useRetryJob, useCancelJob, useDeadLetter, useRequeueDeadLetter } from '@/hooks/use-distributed-queue'
import { Button } from '@/components/ui/Button'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'

export function QueuePage() {
  const [tab, setTab] = useState<'queue' | 'dead-letter'>('queue')
  const [stateFilter, setStateFilter] = useState<string>('')
  const [cancelTarget, setCancelTarget] = useState<string | null>(null)
  const { data: queueData, isLoading: queueLoading } = useQueue(stateFilter || undefined)
  const { data: metrics } = useQueueMetrics()
  const retryJob = useRetryJob()
  const cancelJob = useCancelJob()
  const { data: deadLetterData, isLoading: dlLoading } = useDeadLetter()
  const requeue = useRequeueDeadLetter()
  const navigate = useNavigate()

  const stateColor = (state: string) => {
    switch (state) {
      case 'queued': return 'neutral'
      case 'assigned': return 'info'
      case 'running': return 'info'
      case 'completed': return 'success'
      case 'failed': return 'critical'
      case 'cancelled': return 'warning'
      case 'retrying': return 'warning'
      case 'expired': return 'critical'
      default: return 'neutral'
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Job Queue</h1>
        <p className="text-sm text-text-muted mt-1">Distributed scan job queue and dead letter queue</p>
      </div>

      {metrics && (
        <div className="grid grid-cols-4 gap-4">
          <Card className="p-3 text-center"><div className="text-2xl font-bold">{metrics.total_queued}</div><div className="text-xs text-text-muted">Queued</div></Card>
          <Card className="p-3 text-center"><div className="text-2xl font-bold">{metrics.total_running + metrics.total_assigned}</div><div className="text-xs text-text-muted">In Progress</div></Card>
          <Card className="p-3 text-center"><div className="text-2xl font-bold">{metrics.total_failed + metrics.total_expired}</div><div className="text-xs text-text-muted">Failed</div></Card>
          <Card className="p-3 text-center"><div className="text-2xl font-bold">{metrics.total_completed}</div><div className="text-xs text-text-muted">Completed</div></Card>
        </div>
      )}

      <div className="flex gap-2 border-b border-border pb-2">
        <Button variant={tab === 'queue' ? 'primary' : 'ghost'} size="sm" onClick={() => setTab('queue')}>Queue</Button>
        <Button variant={tab === 'dead-letter' ? 'primary' : 'ghost'} size="sm" onClick={() => setTab('dead-letter')}>
          Dead Letter {deadLetterData?.total ? `(${deadLetterData.total})` : ''}
        </Button>
      </div>

      {tab === 'queue' && (
        <div className="space-y-4">
          <div className="flex gap-2">
            {['', 'queued', 'assigned', 'running', 'completed', 'failed', 'retrying'].map(s => (
              <Button key={s} variant={stateFilter === s ? 'primary' : 'outline'} size="sm" onClick={() => setStateFilter(s)}>
                {s || 'All'}
              </Button>
            ))}
          </div>

          {queueLoading ? <div className="flex justify-center py-8"><Spinner /></div> : (
            <div className="space-y-2">
              {queueData?.entries.map(e => (
                <Card key={e.entry_id} className="p-3 flex items-center justify-between cursor-pointer hover:border-accent/50" onClick={() => navigate(`/queue/${e.entry_id}`)}>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm">{e.entry_id}</span>
                      <Badge variant={stateColor(e.state)}>{e.state}</Badge>
                    </div>
                    <div className="text-xs text-text-muted">
                      Target: {e.target} &middot; Retries: {e.retry_count}/{e.max_retries}
                      {e.assigned_worker_id && ` &middot; Worker: ${e.assigned_worker_id}`}
                    </div>
                    {e.error_message && <div className="text-xs text-red-400">{e.error_message}</div>}
                  </div>
                  <div className="flex gap-1">
                    {e.state === 'failed' && (
                      <Button size="sm" variant="outline" onClick={ev => { ev.stopPropagation(); retryJob.mutate(e.entry_id) }}>Retry</Button>
                    )}
                    {['queued', 'assigned', 'retrying'].includes(e.state) && (
                      <Button size="sm" variant="ghost" className="text-red-400" onClick={ev => { ev.stopPropagation(); setCancelTarget(e.entry_id) }}>Cancel</Button>
                    )}
                  </div>
                </Card>
              ))}
              {queueData?.entries.length === 0 && <p className="text-center text-text-muted py-8">No queue entries</p>}
            </div>
          )}
        </div>
      )}

      {tab === 'dead-letter' && (
        <div className="space-y-2">
          {dlLoading ? <div className="flex justify-center py-8"><Spinner /></div> : (
            deadLetterData?.entries.map(e => (
              <Card key={e.entry_id} className="p-3 flex items-center justify-between">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm">{e.original_job_id}</span>
                    <Badge variant="critical">dead</Badge>
                  </div>
                  <div className="text-xs text-text-muted">{e.reason}</div>
                  <div className="text-xs text-text-muted">Retried {e.retry_count}x &middot; Failed at: {new Date(e.failed_at).toLocaleString()}</div>
                </div>
                <Button size="sm" variant="outline" onClick={() => requeue.mutate(e.entry_id)}>Requeue</Button>
              </Card>
            ))
          )}
          {deadLetterData?.entries.length === 0 && <p className="text-center text-text-muted py-8">No dead letter entries</p>}
        </div>
      )}

      <ConfirmDialog
        open={cancelTarget !== null}
        onClose={() => setCancelTarget(null)}
        onConfirm={() => { if (cancelTarget) cancelJob.mutate(cancelTarget); setCancelTarget(null) }}
        title="Cancel Job"
        message="Are you sure you want to cancel this job? This action cannot be undone."
        confirmLabel="Cancel Job"
        variant="danger"
        loading={cancelJob.isPending}
      />
    </div>
  )
}
