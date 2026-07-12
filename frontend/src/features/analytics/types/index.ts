export type TimeRange = "7d" | "30d" | "90d" | "1y"

export interface ExecutiveKPIs {
  totalAssessments: number
  running: number
  completed: number
  failed: number
  cancelled: number
  criticalFindings: number
  highFindings: number
  reportsGenerated: number
  averageScanDuration: number
  successRate: number
  lastUpdated: string
}

export interface TrendData {
  date: string
  assessments: number
  findings: number
  reports: number
  failed: number
}

export interface RiskAnalytics {
  severityDistribution: Array<{ name: string; count: number; fill: string }>
  riskScore: number
  vulnerabilityDensity: number
  topTargets: Array<{ target: string; findings: number; riskLevel: string }>
  topCategories: Array<{ category: string; count: number; severity: string }>
}

export interface ExecutiveSummary {
  biggestImprovement: string | null
  biggestRegression: string | null
  highestRiskTarget: string | null
  mostActiveAnalyst: string | null
}

export interface HeatmapCell {
  row: number
  col: number
  value: number
}

export interface AuditAnalytics {
  loginActivity: number
  passwordChanges: number
  userCreations: number
  failedLogins: number
  adminActions: number
  activityByAction: Array<{ action: string; count: number }>
  activityOverTime: Array<{ date: string; count: number }>
}

export interface UserAnalytics {
  activeUsers: number
  mostActiveAnalysts: Array<{ username: string; assessments: number; reports: number }>
  scanOwnership: Array<{ username: string; count: number }>
  reportOwnership: Array<{ username: string; count: number }>
}

export interface ReportAnalytics {
  totalGenerated: number
  downloadCount: number
  reportTypes: Array<{ type: string; count: number }>
  generationTrend: Array<{ date: string; count: number }>
}

export interface HealthOverview {
  api: string
  database: string
  authentication: string
  sse: string
  workers: string
  workerUtilization: number
  queueDepth: number
  sseConnectionCount: number
  avgResponseTime: number
}

export interface AnalyticsExportData {
  executiveKPIs: ExecutiveKPIs
  trendData: TrendData[]
  riskAnalytics: RiskAnalytics
  generatedAt: string
}
