import { memo } from "react"
import { Card, CardContent } from "@/shared/ui/card"
import { formatRelative } from "@/shared/lib/utils"
import type { DashboardKPIs } from "../types"
import {
  ScanSearch,
  Play,
  CheckCircle,
  XCircle,
  Ban,
  AlertTriangle,
  Shield,
  FileText,
} from "lucide-react"

interface KPICardProps {
  title: string
  value: number
  icon: React.ReactNode
  color: string
  lastUpdated: string
}

const KPICard = memo(function KPICard({ title, value, icon, color, lastUpdated }: KPICardProps): React.ReactElement {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <p className="text-xs font-medium text-[hsl(var(--muted-fg))]">{title}</p>
            <p className="text-2xl font-bold text-[hsl(var(--fg))]">{value}</p>
          </div>
          <div className={`flex size-10 items-center justify-center rounded-lg ${color}`}>
            {icon}
          </div>
        </div>
        <p className="mt-2 text-[10px] text-[hsl(var(--muted-fg))]">
          Updated {formatRelative(lastUpdated)}
        </p>
      </CardContent>
    </Card>
  )
})

interface KPICardsProps {
  kpis: DashboardKPIs
}

export const KPICards = memo(function KPICards({ kpis }: KPICardsProps): React.ReactElement {
  const cards = [
    { title: "Total Assessments", value: kpis.totalAssessments, icon: <ScanSearch className="size-5 text-[hsl(var(--primary))]" />, color: "bg-[hsl(var(--primary))]/10" },
    { title: "Running", value: kpis.running, icon: <Play className="size-5 text-[hsl(var(--primary))]" />, color: "bg-[hsl(var(--primary))]/10" },
    { title: "Completed", value: kpis.completed, icon: <CheckCircle className="size-5 text-[hsl(var(--success))]" />, color: "bg-[hsl(var(--success))]/10" },
    { title: "Failed", value: kpis.failed, icon: <XCircle className="size-5 text-[hsl(var(--destructive))]" />, color: "bg-[hsl(var(--destructive))]/10" },
    { title: "Cancelled", value: kpis.cancelled, icon: <Ban className="size-5 text-[hsl(var(--muted-fg))]" />, color: "bg-[hsl(var(--muted))]" },
    { title: "Critical Findings", value: kpis.criticalFindings, icon: <AlertTriangle className="size-5 text-[hsl(var(--destructive))]" />, color: "bg-[hsl(var(--destructive))]/10" },
    { title: "High Findings", value: kpis.highFindings, icon: <Shield className="size-5 text-[hsl(var(--warning))]" />, color: "bg-[hsl(var(--warning))]/10" },
    { title: "Reports Generated", value: kpis.reportsGenerated, icon: <FileText className="size-5 text-[hsl(var(--success))]" />, color: "bg-[hsl(var(--success))]/10" },
  ]

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {cards.map((card) => (
        <KPICard key={card.title} {...card} lastUpdated={kpis.lastUpdated} />
      ))}
    </div>
  )
})
