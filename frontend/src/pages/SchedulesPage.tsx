import { PageContainer, PageHeader, ContentSection } from '@/components/layout/PageContainer'
import { Card, CardHeader } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { useSchedules } from '@/hooks/use-schedules'
import { CalendarCheck, Clock, Power, PowerOff, PauseCircle } from 'lucide-react'

export function SchedulesPage() {
  const { data, isLoading, error, refetch } = useSchedules()

  if (error) {
    return (
      <PageContainer>
        <PageHeader title="Schedules" />
        <ErrorState title="Failed to load schedules" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <PageHeader title="Schedules" description="Scheduled security assessments" />

      {isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <CardHeader>
                <Skeleton className="h-5 w-32" />
                <Skeleton className="h-4 w-24" />
              </CardHeader>
            </Card>
          ))}
        </div>
      ) : data && (data as { items: unknown[] }).items.length > 0 ? (
        <ContentSection title="Active Schedules">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {(data as { items: unknown[] }).items.map((schedule: unknown) => {
              const s = schedule as { id: string; name?: string; target?: string; cron?: string; enabled?: boolean; status?: string }
              return (
                <Card key={s.id}>
                  <div className="p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <CalendarCheck className="h-5 w-5 text-accent" />
                        <h3 className="text-sm font-semibold text-text-primary">{s.name ?? 'Unnamed'}</h3>
                      </div>
                      {s.enabled ? (
                        <Power className="h-4 w-4 text-emerald-400" />
                      ) : (
                        <PowerOff className="h-4 w-4 text-text-muted" />
                      )}
                    </div>
                    <p className="text-sm text-text-secondary">{s.target ?? 'No target specified'}</p>
                    {s.cron && (
                      <div className="flex items-center gap-2 text-xs text-text-muted">
                        <Clock className="h-3 w-3" />
                        <code className="rounded bg-surface-tertiary px-1.5 py-0.5">{s.cron}</code>
                      </div>
                    )}
                    {s.status && (
                      <div className="flex items-center gap-2 text-xs">
                        <PauseCircle className="h-3 w-3 text-text-muted" />
                        <span className="text-text-secondary">{s.status}</span>
                      </div>
                    )}
                  </div>
                </Card>
              )
            })}
          </div>
        </ContentSection>
      ) : (
        <Card>
          <EmptyState
            icon={<CalendarCheck className="h-8 w-8" />}
            title="No schedules configured"
            description="Create recurring assessment schedules to automate security scanning."
          />
        </Card>
      )}
    </PageContainer>
  )
}
