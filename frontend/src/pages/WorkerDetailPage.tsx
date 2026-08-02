import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useWorker, useDeleteWorker } from '@/hooks/use-workers'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'

export function WorkerDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data, isLoading } = useWorker(id!)
  const deleteWorker = useDeleteWorker()
  const navigate = useNavigate()
  const [confirmDelete, setConfirmDelete] = useState(false)

  if (isLoading) return <div className="flex justify-center py-12"><Spinner size="lg" /></div>
  if (!data?.worker) return <div className="text-center py-12 text-text-muted">Worker not found</div>

  const w = data.worker

  const handleDelete = async () => {
    try {
      await deleteWorker.mutateAsync(w.worker_id)
      navigate('/workers')
    } catch {
      // Error is surfaced below via deleteWorker.error.
    } finally {
      setConfirmDelete(false)
    }
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">{w.hostname || w.worker_id}</h1>
          <p className="text-sm text-text-muted">Worker ID: {w.worker_id}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => navigate('/workers')}>Back</Button>
          <Button variant="danger" onClick={() => setConfirmDelete(true)}>Remove Worker</Button>
        </div>
      </div>

      {deleteWorker.isError && (
        <p className="text-sm text-red-500">
          {(deleteWorker.error as Error)?.message ?? 'Failed to remove worker'}
        </p>
      )}

      <div className="grid grid-cols-2 gap-4">
        <Card className="p-4 space-y-3">
          <h3 className="font-medium text-text-primary">Status</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-text-muted">Status</span><Badge variant={w.status === 'online' ? 'success' : w.status === 'offline' ? 'critical' : 'warning'}>{w.status}</Badge></div>
            <div className="flex justify-between"><span className="text-text-muted">Health</span><span>{w.health}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Last Heartbeat</span><span>{w.last_heartbeat ? new Date(w.last_heartbeat).toLocaleString() : 'never'}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Active Jobs</span><span>{w.current_jobs.length}</span></div>
          </div>
        </Card>

        <Card className="p-4 space-y-3">
          <h3 className="font-medium text-text-primary">System</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-text-muted">OS</span><span>{w.os || '-'}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">CPU</span><span>{w.cpu || '-'}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">RAM</span><span>{w.ram_mb ? `${w.ram_mb} MB` : '-'}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Registered</span><span>{new Date(w.created_at).toLocaleDateString()}</span></div>
          </div>
        </Card>
      </div>

      <Card className="p-4 space-y-3">
        <h3 className="font-medium text-text-primary">Scanner Capabilities ({w.capabilities.length})</h3>
        {w.capabilities.length === 0 ? (
          <p className="text-sm text-text-muted">No scanner capabilities reported</p>
        ) : (
          <div className="grid grid-cols-2 gap-2">
            {w.capabilities.map((c, i) => (
              <div key={i} className="text-sm p-2 bg-surface-tertiary rounded">
                <div className="font-medium">{c.scanner_name}</div>
                <div className="text-xs text-text-muted">{c.scanner_id} v{c.scanner_version}</div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <ConfirmDialog
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        onConfirm={handleDelete}
        title="Remove Worker"
        message="Are you sure you want to remove this worker? This action cannot be undone."
        confirmLabel="Remove Worker"
        variant="danger"
        loading={deleteWorker.isPending}
      />
    </div>
  )
}
