import { useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { useAssessments } from "@/features/assessments/hooks/use-assessments"
import { fetchAuditSummary, fetchHealth } from "../api/dashboard"
import type { DashboardKPIs, StatusDistribution, AssessmentsOverTime } from "../types"

export const dashboardKeys = {
  all: ["dashboard"] as const,
  kpis: () => [...dashboardKeys.all, "kpis"] as const,
  auditSummary: () => [...dashboardKeys.all, "auditSummary"] as const,
  health: () => [...dashboardKeys.all, "health"] as const,
}

export function useDashboardKPIs() {
  const { data, isLoading, error, refetch, isFetching } = useAssessments({ limit: 500, offset: 0 })

  const kpis: DashboardKPIs | null = useMemo(() => {
    if (!data) return null
    const items = data.items ?? []

    let criticalFindings = 0
    let highFindings = 0
    for (const item of items) {
      criticalFindings += item.findings_count // Simplified: backend doesn't expose per-severity in list
      highFindings += item.findings_count
    }

    const now = new Date().toISOString()
    return {
      totalAssessments: data.total,
      running: items.filter((i) => i.status === "RUNNING").length,
      completed: items.filter((i) => i.status === "COMPLETED").length,
      failed: items.filter((i) => i.status === "FAILED").length,
      cancelled: items.filter((i) => i.status === "CANCELLED").length,
      criticalFindings,
      highFindings,
      reportsGenerated: 0,
      lastUpdated: now,
    }
  }, [data])

  const statusDistribution: StatusDistribution[] = useMemo(() => {
    if (!data) return []
    const items = data.items ?? []
    return [
      { name: "Created", value: items.filter((i) => i.status === "CREATED").length, color: "hsl(var(--secondary))" },
      { name: "Running", value: items.filter((i) => i.status === "RUNNING").length, color: "hsl(var(--primary))" },
      { name: "Completed", value: items.filter((i) => i.status === "COMPLETED").length, color: "hsl(var(--success))" },
      { name: "Failed", value: items.filter((i) => i.status === "FAILED").length, color: "hsl(var(--destructive))" },
      { name: "Cancelled", value: items.filter((i) => i.status === "CANCELLED").length, color: "hsl(var(--muted))" },
    ].filter((d) => d.value > 0)
  }, [data])

  const assessmentsOverTime: AssessmentsOverTime[] = useMemo(() => {
    if (!data) return []
    const items = data.items ?? []
    const byDate = new Map<string, number>()
    for (const item of items) {
      const date = item.created_at.split("T")[0]
      byDate.set(date, (byDate.get(date) ?? 0) + 1)
    }
    return Array.from(byDate.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-30)
      .map(([date, count]) => ({ date, count }))
  }, [data])

  return {
    kpis,
    statusDistribution,
    assessmentsOverTime,
    isLoading,
    error,
    refetch,
    isFetching,
  }
}

export function useAuditSummary() {
  return useQuery({
    queryKey: dashboardKeys.auditSummary(),
    queryFn: fetchAuditSummary,
    refetchInterval: 60_000,
  })
}

export function useHealthCheck() {
  return useQuery({
    queryKey: dashboardKeys.health(),
    queryFn: fetchHealth,
    refetchInterval: 30_000,
    retry: 1,
  })
}
