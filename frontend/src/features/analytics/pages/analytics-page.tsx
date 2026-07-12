import { lazy, Suspense, useState } from "react"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { PageHeader } from "@/shared/components/page-header"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/shared/ui/tabs"
import { Skeleton } from "@/shared/components/loading-skeleton"
import { useAnalyticsKPIs, useAnalyticsAuditDerived, useAnalyticsUserDerived, useAnalyticsReportDerived } from "../hooks/use-analytics"
import { AnalyticsExport } from "../components/analytics-export"
import type { TimeRange } from "../types"

const LazyKPICards = lazy(() => import("../components/analytics-kpi-cards").then((m) => ({ default: m.AnalyticsKPICards })))
const LazyTrendsChart = lazy(() => import("../components/analytics-trends-chart").then((m) => ({ default: m.AnalyticsTrendsChart })))
const LazySeverityChart = lazy(() => import("../components/analytics-severity-chart").then((m) => ({ default: m.AnalyticsSeverityChart })))
const LazyStatusChart = lazy(() => import("../components/analytics-status-chart").then((m) => ({ default: m.AnalyticsStatusChart })))
const LazyExecutiveSummary = lazy(() => import("../components/analytics-executive-summary").then((m) => ({ default: m.AnalyticsExecutiveSummary })))
const LazyTopTargets = lazy(() => import("../components/analytics-top-targets").then((m) => ({ default: m.AnalyticsTopTargets })))
const LazyHeatmap = lazy(() => import("../components/analytics-heatmap").then((m) => ({ default: m.AnalyticsHeatmap })))
const LazyAuditActivity = lazy(() => import("../components/analytics-audit-activity").then((m) => ({ default: m.AnalyticsAuditActivity })))
const LazyUserActivity = lazy(() => import("../components/analytics-user-activity").then((m) => ({ default: m.AnalyticsUserActivity })))
const LazyReportActivity = lazy(() => import("../components/analytics-report-activity").then((m) => ({ default: m.AnalyticsReportActivity })))
const LazyHealthOverview = lazy(() => import("../components/analytics-health-overview").then((m) => ({ default: m.AnalyticsHealthOverview })))

function WidgetWrapper({ children }: { children: React.ReactNode }): React.ReactElement {
  return (
    <ErrorBoundary fallback={<div className="rounded-lg border border-[hsl(var(--border))] p-4 text-sm text-[hsl(var(--destructive))]">Widget failed to load</div>}>
      <Suspense fallback={<Skeleton className="h-48 rounded-lg" />}>
        {children}
      </Suspense>
    </ErrorBoundary>
  )
}

export function AnalyticsPage(): React.ReactElement {
  const [timeRange, setTimeRange] = useState<TimeRange>("30d")
  const {
    kpis,
    trendData,
    statusDistribution,
    severityDistribution,
    topTargets,
    executiveSummary,
    isLoading,
  } = useAnalyticsKPIs(timeRange)

  const { auditAnalytics, isLoading: auditLoading } = useAnalyticsAuditDerived(timeRange)
  const { userAnalytics } = useAnalyticsUserDerived()
  const { reportAnalytics, isLoading: reportLoading } = useAnalyticsReportDerived(timeRange)

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-4 w-96" />
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
        <Skeleton className="h-64 rounded-xl" />
      </div>
    )
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-start justify-between">
        <PageHeader
          title="Analytics & Executive Dashboard"
          description="Trends, insights, and executive reporting for your security posture."
        />
        <AnalyticsExport kpis={kpis} trends={trendData} risk={null} />
      </div>

      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="trends">Trends</TabsTrigger>
          <TabsTrigger value="risk">Risk Analytics</TabsTrigger>
          <TabsTrigger value="audit">Audit</TabsTrigger>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
          <TabsTrigger value="health">Health</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {kpis && (
            <WidgetWrapper>
              <LazyKPICards kpis={kpis} />
            </WidgetWrapper>
          )}

          <div className="grid gap-6 lg:grid-cols-2">
            <WidgetWrapper>
              <LazyStatusChart data={statusDistribution} />
            </WidgetWrapper>
            <WidgetWrapper>
              <LazySeverityChart data={severityDistribution} />
            </WidgetWrapper>
          </div>

          <WidgetWrapper>
            <LazyExecutiveSummary summary={executiveSummary} />
          </WidgetWrapper>
        </TabsContent>

        <TabsContent value="trends" className="space-y-6">
          <WidgetWrapper>
            <LazyTrendsChart data={trendData} />
          </WidgetWrapper>

          <div className="grid gap-6 lg:grid-cols-2">
            <WidgetWrapper>
              <LazyHeatmap data={trendData.map((t) => ({ date: t.date, count: t.assessments }))} title="Findings by Weekday" />
            </WidgetWrapper>
            <WidgetWrapper>
              <LazyTopTargets data={topTargets} />
            </WidgetWrapper>
          </div>
        </TabsContent>

        <TabsContent value="risk" className="space-y-6">
          <div className="grid gap-6 lg:grid-cols-2">
            <WidgetWrapper>
              <LazySeverityChart data={severityDistribution} />
            </WidgetWrapper>
            <WidgetWrapper>
              <LazyStatusChart data={statusDistribution} />
            </WidgetWrapper>
          </div>

          <WidgetWrapper>
            <LazyTopTargets data={topTargets} />
          </WidgetWrapper>

          <WidgetWrapper>
            <LazyExecutiveSummary summary={executiveSummary} />
          </WidgetWrapper>
        </TabsContent>

        <TabsContent value="audit" className="space-y-6">
          <WidgetWrapper>
            <LazyAuditActivity data={auditAnalytics} isLoading={auditLoading} />
          </WidgetWrapper>

          {auditAnalytics?.activityOverTime && auditAnalytics.activityOverTime.length > 0 && (
            <WidgetWrapper>
              <LazyHeatmap data={auditAnalytics.activityOverTime} title="Audit Activity Over Time" />
            </WidgetWrapper>
          )}
        </TabsContent>

        <TabsContent value="users" className="space-y-6">
          <WidgetWrapper>
            <LazyUserActivity data={userAnalytics} isLoading={false} />
          </WidgetWrapper>
        </TabsContent>

        <TabsContent value="reports" className="space-y-6">
          <WidgetWrapper>
            <LazyReportActivity data={reportAnalytics} isLoading={reportLoading} />
          </WidgetWrapper>
        </TabsContent>

        <TabsContent value="health" className="space-y-6">
          <WidgetWrapper>
            <LazyHealthOverview />
          </WidgetWrapper>
        </TabsContent>
      </Tabs>
    </div>
  )
}
