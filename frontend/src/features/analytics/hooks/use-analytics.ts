import { useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { useAssessments } from "@/features/assessments/hooks/use-assessments"
import { fetchAuditSummary } from "../api/analytics"
import type {
  ExecutiveKPIs,
  TrendData,
  RiskAnalytics,
  ExecutiveSummary,
  AuditAnalytics,
  UserAnalytics,
  ReportAnalytics,
  TimeRange,
} from "../types"
import type { AssessmentSummary } from "@/features/assessments/types"

export const analyticsKeys = {
  all: ["analytics"] as const,
  kpis: () => [...analyticsKeys.all, "kpis"] as const,
  trends: (range: TimeRange) => [...analyticsKeys.all, "trends", range] as const,
  risk: () => [...analyticsKeys.all, "risk"] as const,
  summary: () => [...analyticsKeys.all, "summary"] as const,
  audit: () => [...analyticsKeys.all, "audit"] as const,
  users: () => [...analyticsKeys.all, "users"] as const,
  reports: () => [...analyticsKeys.all, "reports"] as const,
}

function filterByTimeRange(items: AssessmentSummary[], range: TimeRange): AssessmentSummary[] {
  const now = new Date()
  const cutoff = new Date(now)
  switch (range) {
    case "7d":
      cutoff.setDate(now.getDate() - 7)
      break
    case "30d":
      cutoff.setDate(now.getDate() - 30)
      break
    case "90d":
      cutoff.setDate(now.getDate() - 90)
      break
    case "1y":
      cutoff.setFullYear(now.getFullYear() - 1)
      break
  }
  return items.filter((a) => new Date(a.created_at) >= cutoff)
}

function computeAverageScanDuration(items: AssessmentSummary[]): number {
  const completed = items.filter(
    (a) => a.status === "COMPLETED" || a.status === "FAILED",
  )
  if (completed.length === 0) return 0
  const durations = completed.map((a) => {
    const created = new Date(a.created_at).getTime()
    const now = Date.now()
    return (now - created) / 1000
  })
  return Math.round(durations.reduce((sum, d) => sum + d, 0) / durations.length)
}

function groupByDate(items: AssessmentSummary[]): TrendData[] {
  const grouped = new Map<string, TrendData>()
  for (const a of items) {
    const date = a.created_at.split("T")[0]
    if (!grouped.has(date)) {
      grouped.set(date, { date, assessments: 0, findings: 0, reports: 0, failed: 0 })
    }
    const entry = grouped.get(date)!
    entry.assessments += 1
    entry.findings += a.findings_count ?? 0
    if (a.status === "FAILED") entry.failed += 1
  }
  return Array.from(grouped.values()).sort((a, b) => a.date.localeCompare(b.date))
}

export function useAnalyticsKPIs(range: TimeRange = "30d") {
  const { data, isLoading, error, refetch, isFetching } = useAssessments({
    limit: 500,
    offset: 0,
  })

  const kpis = useMemo<ExecutiveKPIs | null>(() => {
    if (!data?.items) return null
    const items = filterByTimeRange(data.items, range)
    const total = items.length
    const running = items.filter((a) => a.status === "RUNNING").length
    const completed = items.filter((a) => a.status === "COMPLETED").length
    const failed = items.filter((a) => a.status === "FAILED").length
    const cancelled = items.filter((a) => a.status === "CANCELLED").length
    const successRate = total > 0 ? Math.round((completed / total) * 100) : 0

    return {
      totalAssessments: total,
      running,
      completed,
      failed,
      cancelled,
      criticalFindings: items.reduce((sum, a) => {
        const severityCounts = (a as Record<string, unknown>).severity_counts as
          | Record<string, number>
          | undefined
        return sum + (severityCounts?.critical ?? 0)
      }, 0),
      highFindings: items.reduce((sum, a) => {
        const severityCounts = (a as Record<string, unknown>).severity_counts as
          | Record<string, number>
          | undefined
        return sum + (severityCounts?.high ?? 0)
      }, 0),
      reportsGenerated: items.filter((a) => a.status === "COMPLETED").length,
      averageScanDuration: computeAverageScanDuration(items),
      successRate,
      lastUpdated: new Date().toISOString(),
    }
  }, [data, range])

  const trendData = useMemo(() => {
    if (!data?.items) return []
    return groupByDate(filterByTimeRange(data.items, range))
  }, [data, range])

  const statusDistribution = useMemo(() => {
    if (!data?.items) return []
    const items = filterByTimeRange(data.items, range)
    return [
      { name: "Completed", value: items.filter((a) => a.status === "COMPLETED").length, color: "hsl(142, 76%, 36%)" },
      { name: "Running", value: items.filter((a) => a.status === "RUNNING").length, color: "hsl(var(--primary))" },
      { name: "Failed", value: items.filter((a) => a.status === "FAILED").length, color: "hsl(var(--destructive))" },
      { name: "Created", value: items.filter((a) => a.status === "CREATED").length, color: "hsl(var(--muted-fg))" },
      { name: "Cancelled", value: items.filter((a) => a.status === "CANCELLED").length, color: "hsl(var(--warning))" },
    ].filter((d) => d.value > 0)
  }, [data, range])

  const severityDistribution = useMemo(() => {
    if (!data?.items) return []
    const items = filterByTimeRange(data.items, range)
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    for (const a of items) {
      const sc = (a as Record<string, unknown>).severity_counts as Record<string, number> | undefined
      if (sc) {
        counts.CRITICAL += sc.critical ?? 0
        counts.HIGH += sc.high ?? 0
        counts.MEDIUM += sc.medium ?? 0
        counts.LOW += sc.low ?? 0
        counts.INFO += sc.info ?? 0
      }
    }
    const SEVERITY_FILLS: Record<string, string> = {
      CRITICAL: "hsl(var(--destructive))",
      HIGH: "hsl(25, 95%, 53%)",
      MEDIUM: "hsl(var(--warning))",
      LOW: "hsl(var(--primary))",
      INFO: "hsl(var(--muted-fg))",
    }
    return Object.entries(counts)
      .filter(([, count]) => count > 0)
      .map(([name, count]) => ({ name, count, fill: SEVERITY_FILLS[name] }))
  }, [data, range])

  const topTargets = useMemo(() => {
    if (!data?.items) return []
    const items = filterByTimeRange(data.items, range)
    const targetMap = new Map<string, number>()
    for (const a of items) {
      const count = (a as Record<string, unknown>).findings_count as number ?? 0
      targetMap.set(a.target, (targetMap.get(a.target) ?? 0) + count)
    }
    return Array.from(targetMap.entries())
      .map(([target, findings]) => ({
        target,
        findings,
        riskLevel: findings > 10 ? "high" : findings > 5 ? "medium" : "low",
      }))
      .sort((a, b) => b.findings - a.findings)
      .slice(0, 10)
  }, [data, range])

  const executiveSummary = useMemo<ExecutiveSummary>(() => {
    if (!data?.items) {
      return {
        biggestImprovement: null,
        biggestRegression: null,
        highestRiskTarget: null,
        mostActiveAnalyst: null,
      }
    }
    const targets = topTargets
    return {
      biggestImprovement: null,
      biggestRegression: null,
      highestRiskTarget: targets.length > 0 ? targets[0].target : null,
      mostActiveAnalyst: null,
    }
  }, [data, topTargets])

  return {
    kpis,
    trendData,
    statusDistribution,
    severityDistribution,
    topTargets,
    executiveSummary,
    allAssessments: data?.items ?? [],
    isLoading,
    error,
    refetch,
    isFetching,
  }
}

export function useAnalyticsAudit() {
  return useQuery({
    queryKey: analyticsKeys.audit(),
    queryFn: () => fetchAuditSummary(200),
    refetchInterval: 60_000,
  })
}

export function useAnalyticsAuditDerived(range: TimeRange = "30d") {
  const { data, isLoading, error } = useAnalyticsAudit()

  const auditAnalytics = useMemo<AuditAnalytics | null>(() => {
    if (!data?.items) return null
    const items = data.items
    const now = new Date()
    const cutoff = new Date(now)
    switch (range) {
      case "7d": cutoff.setDate(now.getDate() - 7); break
      case "30d": cutoff.setDate(now.getDate() - 30); break
      case "90d": cutoff.setDate(now.getDate() - 90); break
      case "1y": cutoff.setFullYear(now.getFullYear() - 1); break
    }
    const filtered = items.filter((e) => new Date(e.timestamp) >= cutoff)

    const actionCounts = new Map<string, number>()
    const dateCounts = new Map<string, number>()
    for (const entry of filtered) {
      actionCounts.set(entry.action, (actionCounts.get(entry.action) ?? 0) + 1)
      const date = entry.timestamp.split("T")[0]
      dateCounts.set(date, (dateCounts.get(date) ?? 0) + 1)
    }

    return {
      loginActivity: filtered.filter((e) => e.action === "LOGIN").length,
      passwordChanges: filtered.filter((e) => e.action === "PASSWORD_CHANGED").length,
      userCreations: filtered.filter((e) => e.action === "USER_REGISTERED").length,
      failedLogins: filtered.filter((e) => e.action === "FAILED_LOGIN").length,
      adminActions: filtered.filter(
        (e) => !["LOGIN", "LOGOUT", "TOKEN_REFRESHED"].includes(e.action),
      ).length,
      activityByAction: Array.from(actionCounts.entries())
        .map(([action, count]) => ({ action, count }))
        .sort((a, b) => b.count - a.count),
      activityOverTime: Array.from(dateCounts.entries())
        .map(([date, count]) => ({ date, count }))
        .sort((a, b) => a.date.localeCompare(b.date)),
    }
  }, [data, range])

  return { auditAnalytics, isLoading, error }
}

export function useAnalyticsUserDerived() {
  const { data: assessmentsData } = useAssessments({ limit: 500, offset: 0 })
  const { data: auditData } = useAnalyticsAudit()

  const userAnalytics = useMemo<UserAnalytics | null>(() => {
    if (!assessmentsData?.items) return null

    const assessments = assessmentsData.items
    const analystMap = new Map<string, { assessments: number; reports: number }>()

    for (const a of assessments) {
      const owner = (a as Record<string, unknown>).created_by as string ?? "unknown"
      if (!analystMap.has(owner)) analystMap.set(owner, { assessments: 0, reports: 0 })
      analystMap.get(owner)!.assessments += 1
      if (a.status === "COMPLETED") analystMap.get(owner)!.reports += 1
    }

    const mostActiveAnalysts = Array.from(analystMap.entries())
      .map(([username, data]) => ({ username, ...data }))
      .sort((a, b) => b.assessments - a.assessments)
      .slice(0, 10)

    return {
      activeUsers: analystMap.size,
      mostActiveAnalysts,
      scanOwnership: mostActiveAnalysts.map((a) => ({
        username: a.username,
        count: a.assessments,
      })),
      reportOwnership: mostActiveAnalysts.map((a) => ({
        username: a.username,
        count: a.reports,
      })),
    }
  }, [assessmentsData, auditData])

  return { userAnalytics }
}

export function useAnalyticsReportDerived(range: TimeRange = "30d") {
  const { data: assessmentsData } = useAssessments({ limit: 500, offset: 0 })

  const reportAnalytics = useMemo<ReportAnalytics | null>(() => {
    if (!assessmentsData?.items) return null
    const items = filterByTimeRange(assessmentsData.items, range)
    const completed = items.filter((a) => a.status === "COMPLETED")

    const dateCounts = new Map<string, number>()
    for (const a of completed) {
      const date = a.created_at.split("T")[0]
      dateCounts.set(date, (dateCounts.get(date) ?? 0) + 1)
    }

    return {
      totalGenerated: completed.length,
      downloadCount: 0,
      reportTypes: [{ type: "PDF", count: completed.length }],
      generationTrend: Array.from(dateCounts.entries())
        .map(([date, count]) => ({ date, count }))
        .sort((a, b) => a.date.localeCompare(b.date)),
    }
  }, [assessmentsData, range])

  return { reportAnalytics }
}
