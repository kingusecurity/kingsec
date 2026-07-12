export interface DashboardKPIs {
  totalAssessments: number
  running: number
  completed: number
  failed: number
  cancelled: number
  criticalFindings: number
  highFindings: number
  reportsGenerated: number
  lastUpdated: string
}

export interface StatusDistribution {
  name: string
  value: number
  color: string
}

export interface SeverityDistribution {
  name: string
  count: number
  fill: string
}

export interface AssessmentsOverTime {
  date: string
  count: number
}

export interface AuditSummaryEntry {
  action: string
  resource_type: string
  success: boolean
  timestamp: string
  username: string
}

export interface HealthStatus {
  api: "healthy" | "degraded" | "down"
  database: "healthy" | "degraded" | "down"
  authentication: "healthy" | "degraded" | "down"
  sse: "healthy" | "degraded" | "down"
  workers: "healthy" | "degraded" | "down"
}
