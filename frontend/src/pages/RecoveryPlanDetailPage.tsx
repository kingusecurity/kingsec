import { useParams, useNavigate } from 'react-router-dom'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import {
  useRecoveryPlan,
  useRecoveryTests,
  useTestRecovery,
  useDeleteRecoveryPlan,
} from '@/hooks/use-backup'

const testStatusVariant: Record<string, 'success' | 'critical' | 'warning' | 'neutral'> = {
  completed: 'success',
  failed: 'critical',
  in_progress: 'warning',
  testing: 'warning',
  not_started: 'neutral',
}

export function RecoveryPlanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data, isLoading } = useRecoveryPlan(id!)
  const { data: testsData } = useRecoveryTests(id)
  const testRecovery = useTestRecovery()
  const deletePlan = useDeleteRecoveryPlan()

  if (isLoading) {
    return (
      <PageContainer>
        <div className="flex justify-center py-16"><Spinner /></div>
      </PageContainer>
    )
  }

  const plan = data?.plan
  if (!plan) {
    return (
      <PageContainer>
        <div className="py-16 text-center">
          <p className="text-lg font-medium">Recovery plan not found</p>
          <Button className="mt-4" onClick={() => navigate('/backup')}>Back to Backup Center</Button>
        </div>
      </PageContainer>
    )
  }

  const tests = testsData?.tests ?? []

  const handleTest = () => {
    testRecovery.mutate(plan.plan_id)
  }

  const handleDelete = async () => {
    await deletePlan.mutateAsync(plan.plan_id)
    navigate('/backup')
  }

  return (
    <PageContainer>
      <div className="mb-2">
        <button onClick={() => navigate('/backup')} className="text-sm text-accent hover:underline">&larr; Back to Backup Center</button>
      </div>

      <PageHeader
        title={plan.name}
        description={plan.description || 'No description'}
        actions={
          <div className="flex gap-2">
            <Button onClick={handleTest} disabled={testRecovery.isPending} variant="outline">
              {testRecovery.isPending ? 'Testing...' : 'Run Test'}
            </Button>
            <Button onClick={handleDelete} disabled={deletePlan.isPending} variant="danger">Delete</Button>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <div className="p-4">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Details</h3>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between"><dt className="text-text-muted">Status</dt><dd><Badge variant={plan.status === 'active' ? 'success' : 'neutral'}>{plan.status}</Badge></dd></div>
              <div className="flex justify-between"><dt className="text-text-muted">Estimated Downtime</dt><dd>{plan.estimated_downtime_minutes} min</dd></div>
              <div className="flex justify-between"><dt className="text-text-muted">Last Tested</dt><dd>{plan.last_tested_at ? new Date(plan.last_tested_at).toLocaleString() : 'Never'}</dd></div>
              <div className="flex justify-between"><dt className="text-text-muted">Created</dt><dd>{new Date(plan.created_at).toLocaleString()}</dd></div>
              <div className="flex justify-between"><dt className="text-text-muted">Created By</dt><dd className="break-all text-right">{plan.created_by || '-'}</dd></div>
            </dl>
          </div>
        </Card>

        <Card>
          <div className="p-4">
            <h3 className="mb-3 text-sm font-semibold text-text-primary">Checklist ({plan.checklist?.length ?? 0})</h3>
            <div className="space-y-2">
              {plan.checklist?.map((item) => (
                <div key={item.item_id} className="flex items-start justify-between gap-2 rounded bg-surface-tertiary p-2 text-sm">
                  <span>{item.description}</span>
                  <Badge variant={item.completed ? 'success' : 'neutral'} size="sm">{item.completed ? 'Done' : 'Pending'}</Badge>
                </div>
              ))}
              {(!plan.checklist || plan.checklist.length === 0) && <p className="text-xs text-text-muted">No checklist items</p>}
            </div>
          </div>
        </Card>
      </div>

      <Card className="mt-6">
        <div className="p-4">
          <h3 className="mb-3 text-sm font-semibold text-text-primary">Test History</h3>
          {tests.length === 0 ? (
            <p className="text-sm text-text-muted">No recovery tests run yet</p>
          ) : (
            <div className="space-y-2">
              {tests.map((t) => (
                <div key={t.test_id} className="flex items-center justify-between rounded bg-surface-tertiary p-3 text-sm">
                  <div>
                    <p className="font-medium">{new Date(t.started_at).toLocaleString()}</p>
                    <p className="text-xs text-text-muted">Executed by {t.executed_by || '-'}</p>
                  </div>
                  <Badge variant={testStatusVariant[t.status] ?? 'neutral'}>{t.status}</Badge>
                </div>
              ))}
            </div>
          )}
        </div>
      </Card>
    </PageContainer>
  )
}
