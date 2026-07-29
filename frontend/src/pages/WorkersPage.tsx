import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useWorkers, useRegisterWorker, useDeleteWorker } from '@/hooks/use-workers'
import { Button } from '@/components/ui/Button'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner } from '@/components/ui/Spinner'

export function WorkersPage() {
  const { data, isLoading } = useWorkers()
  const registerWorker = useRegisterWorker()
  const deleteWorker = useDeleteWorker()
  const navigate = useNavigate()
  const [showRegister, setShowRegister] = useState(false)
  const [form, setForm] = useState({ worker_id: '', hostname: '', os: '', cpu: '', ram_mb: 0 })

  const handleRegister = async () => {
    await registerWorker.mutateAsync(form)
    setShowRegister(false)
    setForm({ worker_id: '', hostname: '', os: '', cpu: '', ram_mb: 0 })
  }

  const statusColor = (status: string) => {
    switch (status) {
      case 'online': return 'success'
      case 'busy': return 'warning'
      case 'offline': return 'critical'
      case 'degraded': return 'warning'
      default: return 'neutral'
    }
  }

  if (isLoading) return <div className="flex justify-center py-12"><Spinner size="lg" /></div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Scan Workers</h1>
          <p className="text-sm text-text-muted mt-1">{data?.total ?? 0} registered workers</p>
        </div>
        <Button onClick={() => setShowRegister(!showRegister)}>
          {showRegister ? 'Cancel' : 'Register Worker'}
        </Button>
      </div>

      {showRegister && (
        <Card className="p-4 space-y-3">
          <h3 className="font-medium">Register New Worker</h3>
          <div className="grid grid-cols-2 gap-3">
            <input className="input" placeholder="Worker ID *" value={form.worker_id} onChange={e => setForm({ ...form, worker_id: e.target.value })} />
            <input className="input" placeholder="Hostname" value={form.hostname} onChange={e => setForm({ ...form, hostname: e.target.value })} />
            <input className="input" placeholder="OS" value={form.os} onChange={e => setForm({ ...form, os: e.target.value })} />
            <input className="input" placeholder="CPU" value={form.cpu} onChange={e => setForm({ ...form, cpu: e.target.value })} />
            <input className="input" placeholder="RAM (MB)" type="number" value={form.ram_mb} onChange={e => setForm({ ...form, ram_mb: parseInt(e.target.value) || 0 })} />
          </div>
          <Button onClick={handleRegister} disabled={!form.worker_id}>Register</Button>
        </Card>
      )}

      <div className="grid gap-4">
        {data?.workers.map((w) => (
          <Card key={w.worker_id} className="p-4 cursor-pointer hover:border-accent/50 transition-colors" onClick={() => navigate(`/workers/${w.worker_id}`)}>
            <div className="flex items-start justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-text-primary">{w.hostname || w.worker_id}</span>
                  <Badge variant={statusColor(w.status)}>{w.status}</Badge>
                  <Badge variant={w.health === 'healthy' ? 'success' : 'warning'}>{w.health}</Badge>
                </div>
                <div className="text-sm text-text-muted">
                  {w.os} &middot; {w.cpu} &middot; {w.ram_mb} MB RAM
                </div>
                <div className="text-xs text-text-muted">
                  {w.capabilities.length} scanners &middot; {w.current_jobs.length} active jobs
                </div>
              </div>
              <div className="text-right text-xs text-text-muted">
                <div>Last heartbeat: {w.last_heartbeat ? new Date(w.last_heartbeat).toLocaleString() : 'never'}</div>
                <Button variant="ghost" size="sm" className="mt-1 text-red-400" onClick={e => { e.stopPropagation(); deleteWorker.mutate(w.worker_id) }}>
                  Remove
                </Button>
              </div>
            </div>
          </Card>
        ))}
        {data?.workers.length === 0 && (
          <p className="text-center text-text-muted py-8">No workers registered. Register a worker to get started.</p>
        )}
      </div>
    </div>
  )
}
