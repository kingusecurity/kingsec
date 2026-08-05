import { useParams, useNavigate } from 'react-router-dom'
import {
  useBackup,
  useDeleteBackup,
  useRestoreWithScope,
  useVerifyBackupFull,
  useVerifications,
} from '@/hooks/use-backup'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { useState } from 'react'

export function BackupDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: backup, isLoading } = useBackup(id!)
  const deleteBackup = useDeleteBackup()
  const restoreScope = useRestoreWithScope()
  const verifyFull = useVerifyBackupFull()
  const { data: verifications } = useVerifications(id)
  const navigate = useNavigate()
  const [scope, setScope] = useState('complete')
  const [dryRun, setDryRun] = useState(false)

  if (isLoading) return <div className="flex justify-center py-12"><Spinner size="lg" /></div>
  if (!backup) return <div className="text-center py-12 text-text-muted">Backup not found</div>

  const statusColor = (s: string) => {
    switch (s) {
      case 'completed': return 'success'
      case 'running': return 'warning'
      case 'failed': return 'critical'
      case 'pending': return 'neutral'
      default: return 'neutral'
    }
  }

  const handleDelete = async () => {
    await deleteBackup.mutateAsync(backup.backup_id)
    navigate('/backup')
  }

  const handleRestore = async () => {
    await restoreScope.mutateAsync({ id: backup.backup_id, scope, dry_run: dryRun })
  }

  const handleVerify = async () => {
    await verifyFull.mutateAsync(backup.backup_id)
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">{backup.backup_id}</h1>
          <div className="flex items-center gap-2 mt-1">
            <Badge variant={statusColor(backup.status)}>{backup.status}</Badge>
            <Badge variant="info">{backup.backup_type}</Badge>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => navigate('/backup')}>Back</Button>
          <Button variant="danger" onClick={handleDelete}>Delete</Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Card className="p-4 space-y-3">
          <h3 className="font-medium text-text-primary">Backup Info</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-text-muted">Type</span><span>{backup.backup_type}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Status</span><span>{backup.status}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Size</span><span>{backup.size_bytes > 0 ? `${(backup.size_bytes / 1024).toFixed(1)} KB` : '-'}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Encrypted</span><span>{backup.encrypted ? 'Yes' : 'No'}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Compressed</span><span>{backup.compressed ? 'Yes' : 'No'}</span></div>
          </div>
        </Card>

        <Card className="p-4 space-y-3">
          <h3 className="font-medium text-text-primary">Timestamps</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-text-muted">Created</span><span>{new Date(backup.created_at).toLocaleString()}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Completed</span><span>{backup.completed_at ? new Date(backup.completed_at).toLocaleString() : '-'}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Owner</span><span>{backup.owner_user_id || '-'}</span></div>
          </div>
        </Card>
      </div>

      {backup.checksum && (
        <Card className="p-4 space-y-2">
          <h3 className="font-medium text-text-primary">Checksum</h3>
          <code className="text-xs text-text-muted break-all">{backup.checksum}</code>
        </Card>
      )}

      {backup.error_message && (
        <Card className="p-4 space-y-2 border-red-500/50">
          <h3 className="font-medium text-red-400">Error</h3>
          <p className="text-sm text-text-muted">{backup.error_message}</p>
        </Card>
      )}

      <Card className="p-4 space-y-3">
        <h3 className="font-medium text-text-primary">Restore</h3>
        <div className="grid grid-cols-3 gap-3 items-end">
          <div>
            <label className="text-xs text-text-muted">Scope</label>
            <select
              value={scope}
              onChange={e => setScope(e.target.value)}
              className="mt-1 flex h-10 rounded-lg border border-border bg-surface-primary px-3 py-2 text-sm"
            >
              <option value="complete">Complete</option>
              <option value="database">Database</option>
              <option value="configuration">Configuration</option>
              <option value="reports">Reports</option>
              <option value="assessments">Assessments</option>
              <option value="files">Files</option>
              <option value="licenses">Licenses</option>
              <option value="organizations">Organizations</option>
              <option value="users">Users</option>
              <option value="audit_logs">Audit Logs</option>
              <option value="settings">Settings</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <input type="checkbox" id="dry-run" checked={dryRun} onChange={e => setDryRun(e.target.checked)} className="rounded" />
            <label htmlFor="dry-run" className="text-sm">Dry Run</label>
          </div>
          <Button onClick={handleRestore} disabled={restoreScope.isPending}>
            {restoreScope.isPending ? 'Restoring...' : dryRun ? 'Test Restore' : 'Restore'}
          </Button>
        </div>
        {restoreScope.data && (
          <div className="text-sm text-text-muted">
            {restoreScope.data.message} (Scope: {restoreScope.data.scope}, Dry run: {restoreScope.data.dry_run ? 'Yes' : 'No'})
          </div>
        )}
      </Card>

      <Card className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-medium text-text-primary">Verification</h3>
          <Button variant="ghost" size="sm" onClick={handleVerify} disabled={verifyFull.isPending}>
            {verifyFull.isPending ? 'Verifying...' : 'Run Verification'}
          </Button>
        </div>
        {verifications?.verifications.length === 0 ? (
          <p className="text-sm text-text-muted">No verifications yet.</p>
        ) : (
          <div className="space-y-2">
            {verifications?.verifications.map(v => (
              <div key={v.verification_id} className="flex items-center justify-between text-sm p-2 bg-surface-tertiary rounded">
                <div className="flex items-center gap-2">
                  <Badge variant={v.checksum_valid ? 'success' : 'critical'}>{v.checksum_valid ? 'Valid' : 'Failed'}</Badge>
                  <span>{new Date(v.verified_at).toLocaleString()}</span>
                </div>
                <span className="text-text-muted">{v.duration_ms}ms</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
