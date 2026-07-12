import { lazy } from "react"

export const LazyKPICards = lazy(() =>
  import("../components/stats-cards").then((m) => ({ default: m.KPICards }))
)

export const LazyRiskDistribution = lazy(() =>
  import("../components/risk-distribution").then((m) => ({ default: m.RiskDistribution }))
)

export const LazySeverityChart = lazy(() =>
  import("../components/severity-chart").then((m) => ({ default: m.SeverityChart }))
)

export const LazyAssessmentsOverTime = lazy(() =>
  import("../components/assessments-over-time").then((m) => ({ default: m.AssessmentsOverTimeChart }))
)

export const LazyLiveActivity = lazy(() =>
  import("../components/live-activity").then((m) => ({ default: m.LiveActivityWidget }))
)

export const LazyRunningJobs = lazy(() =>
  import("../components/running-jobs").then((m) => ({ default: m.RunningJobsWidget }))
)

export const LazyRecentAssessments = lazy(() =>
  import("../components/recent-assessments").then((m) => ({ default: m.RecentAssessments }))
)

export const LazyAuditSummary = lazy(() =>
  import("../components/latest-activity").then((m) => ({ default: m.AuditSummaryWidget }))
)

export const LazySystemHealth = lazy(() =>
  import("../components/system-health").then((m) => ({ default: m.SystemHealthWidget }))
)

export const LazyQuickActions = lazy(() =>
  import("../components/quick-actions").then((m) => ({ default: m.QuickActions }))
)
