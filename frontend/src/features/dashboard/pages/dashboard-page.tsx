import { Suspense, useCallback } from "react"
import { PageHeader } from "@/shared/components/page-header"
import { PageSkeleton } from "@/shared/components/loading-skeleton"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { useDashboardKPIs, useAuditSummary } from "../hooks/use-dashboard"
import { useAssessments } from "@/features/assessments/hooks/use-assessments"
import {
  LazyKPICards,
  LazyRiskDistribution,
  LazyAssessmentsOverTime,
  LazyLiveActivity,
  LazyRunningJobs,
  LazyRecentAssessments,
  LazyAuditSummary,
  LazySystemHealth,
  LazyQuickActions,
} from "../components/lazy-widgets"

function WidgetWrapper({ children, title }: { children: React.ReactNode; title: string }): React.ReactElement {
  return (
    <ErrorBoundary
      fallback={
        <div className="rounded-xl border border-[hsl(var(--border))] p-6 text-center">
          <p className="text-sm text-[hsl(var(--destructive))]">{title} failed to load</p>
        </div>
      }
    >
      <Suspense
        fallback={
          <div className="rounded-xl border border-[hsl(var(--border))] p-6">
            <div className="skeleton h-48 rounded-lg" />
          </div>
        }
      >
        {children}
      </Suspense>
    </ErrorBoundary>
  )
}

export function DashboardPage(): React.ReactElement {
  const { kpis, statusDistribution, assessmentsOverTime, isLoading, isFetching, refetch } = useDashboardKPIs()
  const { data: auditData } = useAuditSummary()
  const { data: recentData } = useAssessments({ limit: 5, offset: 0 })

  const handleRefresh = useCallback(() => {
    refetch()
  }, [refetch])

  if (isLoading) {
    return <PageSkeleton />
  }

  return (
    <div className="p-6">
      <PageHeader
        title="Dashboard"
        description="KingSec operational command center."
      />

      {/* Quick Actions */}
      <div className="mt-6">
        <WidgetWrapper title="Quick Actions">
          <LazyQuickActions onRefresh={handleRefresh} isRefreshing={isFetching} />
        </WidgetWrapper>
      </div>

      {/* KPI Cards */}
      <div className="mt-6">
        {kpis && (
          <WidgetWrapper title="KPI Cards">
            <LazyKPICards kpis={kpis} />
          </WidgetWrapper>
        )}
      </div>

      {/* Charts Row */}
      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <WidgetWrapper title="Status Distribution">
          <LazyRiskDistribution data={statusDistribution} />
        </WidgetWrapper>
        <WidgetWrapper title="Assessments Over Time">
          <LazyAssessmentsOverTime data={assessmentsOverTime} />
        </WidgetWrapper>
      </div>

      {/* Live + Jobs */}
      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <WidgetWrapper title="Live Activity">
          <LazyLiveActivity />
        </WidgetWrapper>
        <WidgetWrapper title="Running Jobs">
          <LazyRunningJobs />
        </WidgetWrapper>
      </div>

      {/* Recent + Audit */}
      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <WidgetWrapper title="Recent Assessments">
          <LazyRecentAssessments assessments={recentData?.items ?? []} />
        </WidgetWrapper>
        <WidgetWrapper title="Audit Summary">
          <LazyAuditSummary entries={auditData?.items ?? []} />
        </WidgetWrapper>
      </div>

      {/* Health */}
      <div className="mt-6">
        <WidgetWrapper title="System Health">
          <LazySystemHealth />
        </WidgetWrapper>
      </div>
    </div>
  )
}
