import { useState } from 'react'
import {
  Loader2,
  CheckCircle2,
  XCircle,
  SkipForward,
  AlertTriangle,
  Clock,
  ChevronDown,
  ChevronRight,
  StopCircle,
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { Button } from '@/components/ui/Button'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { cn } from '@/lib/utils'
import { useExecutionStatus, useExecutionEvents, useCancelExecution } from '@/hooks/use-execution'
import type { ExecutionPhase } from '@/types/execution'

const phaseLabels: Record<ExecutionPhase, string> = {
  pending: 'Pending',
  preparing: 'Preparing',
  running_scanners: 'Running Scanners',
  correlating: 'Correlating Results',
  reporting: 'Generating Report',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
}

const phaseColors: Record<ExecutionPhase, string> = {
  pending: 'bg-gray-600',
  preparing: 'bg-blue-500',
  running_scanners: 'bg-blue-500',
  correlating: 'bg-purple-500',
  reporting: 'bg-yellow-500',
  completed: 'bg-emerald-500',
  failed: 'bg-red-500',
  cancelled: 'bg-gray-500',
}

function ProgressBar({ percent, phase }: { percent: number; phase: ExecutionPhase }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-xs">
        <span className="text-text-secondary">{phaseLabels[phase]}</span>
        <span className="text-text-muted tabular-nums">{Math.round(percent)}%</span>
      </div>
      <div className="h-2 rounded-full bg-surface-tertiary overflow-hidden">
        <div
          className={cn('h-full rounded-full transition-all duration-700 ease-out', phaseColors[phase])}
          style={{ width: `${Math.min(percent, 100)}%` }}
        />
      </div>
    </div>
  )
}

function ScannerStatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'running':
      return <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
    case 'completed':
      return <CheckCircle2 className="h-4 w-4 text-emerald-400" />
    case 'failed':
      return <XCircle className="h-4 w-4 text-red-400" />
    case 'skipped':
      return <SkipForward className="h-4 w-4 text-gray-500" />
    default:
      return <Clock className="h-4 w-4 text-gray-600" />
  }
}

function ScannerCard({
  scanner,
}: {
  scanner: { scanner_id: string; name: string; status: string; findings_count: number; duration_seconds: number | null; warnings: string[]; error: string | null; skipped_reason: string | null }
}) {
  const statusColors: Record<string, string> = {
    running: 'border-blue-800/50 bg-blue-950/20',
    completed: 'border-emerald-800/50 bg-emerald-950/20',
    failed: 'border-red-800/50 bg-red-950/20',
    skipped: 'border-gray-700 bg-gray-900/50',
    pending: 'border-gray-800 bg-transparent',
  }

  return (
    <div className={cn('flex items-center gap-3 rounded-lg border p-3 transition-colors', statusColors[scanner.status] || statusColors.pending)}>
      <ScannerStatusIcon status={scanner.status} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-text-primary truncate">{scanner.name}</span>
          {scanner.status === 'running' && <Badge variant="warning" size="sm">Running</Badge>}
        </div>
        <div className="mt-0.5 flex items-center gap-3 text-xs text-text-muted">
          {scanner.status === 'completed' && scanner.duration_seconds != null && (
            <span>{scanner.duration_seconds.toFixed(1)}s</span>
          )}
          {scanner.status === 'completed' && scanner.findings_count > 0 && (
            <span>{scanner.findings_count} findings</span>
          )}
          {scanner.status === 'completed' && scanner.findings_count === 0 && (
            <span>No findings</span>
          )}
          {scanner.error && (
            <span className="text-red-400 truncate" title={scanner.error}>{scanner.error}</span>
          )}
          {scanner.skipped_reason && (
            <span className="text-gray-500 truncate" title={scanner.skipped_reason}>{scanner.skipped_reason}</span>
          )}
        </div>
        {scanner.warnings.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-1">
            {scanner.warnings.map((w, i) => (
              <Badge key={i} variant="warning" size="sm">{w}</Badge>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

interface ExecutionProgressPanelProps {
  assessmentId: string
  className?: string
}

export function ExecutionProgressPanel({ assessmentId, className }: ExecutionProgressPanelProps) {
  const { data: status, isLoading, error, refetch } = useExecutionStatus(assessmentId)
  const { data: eventsData } = useExecutionEvents(assessmentId)
  const cancelMutation = useCancelExecution()
  const [showEvents, setShowEvents] = useState(false)
  const [confirmCancel, setConfirmCancel] = useState(false)

  if (error) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle>Execution Progress</CardTitle>
        </CardHeader>
        <ErrorState title="Failed to load execution status" message={(error as Error).message} onRetry={() => refetch()} />
      </Card>
    )
  }

  if (isLoading) {
    return (
      <Card className={className}>
        <CardHeader>
          <Skeleton className="h-5 w-32" />
          <Skeleton className="h-4 w-48" />
        </CardHeader>
        <div className="px-5 pb-5 space-y-3">
          <Skeleton className="h-2 w-full" />
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-14 w-full rounded-lg" />
          ))}
        </div>
      </Card>
    )
  }

  if (!status) {
    return null
  }

  const isTerminal = ['completed', 'failed', 'cancelled'].includes(status.phase)
  const isRunning = !isTerminal && status.phase !== 'pending'

  return (
    <Card className={className}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Execution Progress</CardTitle>
            <CardDescription>
              {isTerminal
                ? `Execution ${status.phase}`
                : isRunning
                  ? `Phase: ${phaseLabels[status.phase]}`
                  : 'Waiting to start'}
            </CardDescription>
          </div>
          {isRunning && (
            <Button
              variant="outline"
              size="xs"
              onClick={() => setConfirmCancel(true)}
              iconLeft={<StopCircle className="h-3.5 w-3.5" />}
            >
              Cancel
            </Button>
          )}
        </div>
      </CardHeader>

      <div className="px-5 pb-5 space-y-4">
        <ProgressBar percent={status.progress_percent} phase={status.phase} />

        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Scanners ({status.scanner_progress.length})
          </h4>
          {status.scanner_progress.length === 0 ? (
            <EmptyState
              icon={<Clock className="h-6 w-6" />}
              title="No scanners configured"
              description="This assessment has no scanners in its execution plan"
            />
          ) : (
            <div className="space-y-1.5">
              {status.scanner_progress.map((sp) => (
                <ScannerCard key={sp.scanner_id} scanner={sp} />
              ))}
            </div>
          )}
        </div>

        {status.error_message && (
          <div className="rounded-lg bg-red-900/20 p-3 text-xs text-red-300">
            <p className="font-medium mb-0.5">Error</p>
            <p>{status.error_message}</p>
          </div>
        )}

        {eventsData && eventsData.events.length > 0 && (
          <div>
            <button
              onClick={() => setShowEvents(!showEvents)}
              className="flex items-center gap-1.5 text-xs text-text-muted hover:text-text-primary transition-colors"
            >
              {showEvents ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
              Event Log ({eventsData.events.length})
            </button>
            {showEvents && (
              <div className="mt-2 space-y-1 max-h-48 overflow-y-auto">
                {eventsData.events.map((ev, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 rounded-md bg-surface-tertiary/50 px-2.5 py-1.5 text-xs"
                  >
                    <span className="text-text-muted shrink-0 font-mono tabular-nums">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="text-text-secondary">{ev.message}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmCancel}
        onClose={() => setConfirmCancel(false)}
        onConfirm={() => { cancelMutation.mutate(assessmentId); setConfirmCancel(false) }}
        title="Cancel Execution"
        message="Are you sure you want to cancel the running execution? In-progress scanners will be stopped."
        confirmLabel="Cancel Execution"
        variant="warning"
        loading={cancelMutation.isPending}
      />
    </Card>
  )
}
