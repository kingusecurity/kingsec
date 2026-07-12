import { memo } from "react"
import {
  ScanSearch,
  Play,
  CheckCircle,
  XCircle,
  Ban,
  AlertTriangle,
  Shield,
  FileText,
  Clock,
  TrendingUp,
} from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { formatRelative } from "@/shared/lib/utils"
import type { ExecutiveKPIs } from "../types"

interface AnalyticsKPICardsProps {
  kpis: ExecutiveKPIs
}

const CARDS = [
  { key: "totalAssessments" as const, label: "Total Assessments", icon: ScanSearch, color: "text-[hsl(var(--primary))]" },
  { key: "running" as const, label: "Running", icon: Play, color: "text-blue-500" },
  { key: "completed" as const, label: "Completed", icon: CheckCircle, color: "text-emerald-500" },
  { key: "failed" as const, label: "Failed", icon: XCircle, color: "text-red-500" },
  { key: "criticalFindings" as const, label: "Critical Findings", icon: AlertTriangle, color: "text-red-500" },
  { key: "highFindings" as const, label: "High Findings", icon: Shield, color: "text-orange-500" },
  { key: "reportsGenerated" as const, label: "Reports Generated", icon: FileText, color: "text-violet-500" },
  { key: "successRate" as const, label: "Success Rate", icon: TrendingUp, color: "text-emerald-500", suffix: "%" },
]

export const AnalyticsKPICards = memo(function AnalyticsKPICards({
  kpis,
}: AnalyticsKPICardsProps): React.ReactElement {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {CARDS.map(({ key, label, icon: Icon, color, suffix }) => (
        <Card key={key}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-[hsl(var(--fg-secondary))]">{label}</span>
              <Icon className={`size-4 ${color}`} />
            </div>
            <div className="mt-2">
              <span className="text-2xl font-bold text-[hsl(var(--fg))]">
                {kpis[key]}{suffix ?? ""}
              </span>
            </div>
          </CardContent>
        </Card>
      ))}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-[hsl(var(--fg-secondary))]">Avg Scan Duration</span>
            <Clock className="size-4 text-[hsl(var(--muted-fg))]" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold text-[hsl(var(--fg))]">
              {kpis.averageScanDuration > 0
                ? `${Math.round(kpis.averageScanDuration / 60)}m`
                : "--"}
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  )
})
