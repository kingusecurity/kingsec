import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { AssessmentStatusBadge } from "../components/assessment-status-badge"
import { formatDate } from "@/shared/lib/utils"
import type { AssessmentDetail } from "../types"
import { Shield, Calendar, CheckCircle, AlertTriangle } from "lucide-react"

interface OverviewTabProps {
  assessment: AssessmentDetail
}

export function OverviewTab({ assessment }: OverviewTabProps): React.ReactElement {
  const severityCounts = assessment.findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1
      return acc
    },
    {} as Record<string, number>,
  )

  return (
    <div className="space-y-6">
      {/* Quick Stats */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex size-10 items-center justify-center rounded-lg bg-[hsl(var(--primary))]/10">
                <Shield className="size-5 text-[hsl(var(--primary))]" />
              </div>
              <div>
                <p className="text-xs text-[hsl(var(--muted-fg))]">Status</p>
                <AssessmentStatusBadge status={assessment.status} />
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex size-10 items-center justify-center rounded-lg bg-[hsl(var(--warning))]/10">
                <AlertTriangle className="size-5 text-[hsl(var(--warning))]" />
              </div>
              <div>
                <p className="text-xs text-[hsl(var(--muted-fg))]">Findings</p>
                <p className="text-lg font-semibold text-[hsl(var(--fg))]">{assessment.findings.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex size-10 items-center justify-center rounded-lg bg-[hsl(var(--success))]/10">
                <CheckCircle className="size-5 text-[hsl(var(--success))]" />
              </div>
              <div>
                <p className="text-xs text-[hsl(var(--muted-fg))]">Authorized</p>
                <p className="text-lg font-semibold text-[hsl(var(--fg))]">{assessment.is_authorized ? "Yes" : "No"}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex size-10 items-center justify-center rounded-lg bg-[hsl(var(--muted))]">
                <Calendar className="size-5 text-[hsl(var(--muted-fg))]" />
              </div>
              <div>
                <p className="text-xs text-[hsl(var(--muted-fg))]">Created</p>
                <p className="text-sm font-medium text-[hsl(var(--fg))]">{formatDate(assessment.created_at)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Assessment Info */}
      <Card>
        <CardHeader>
          <CardTitle>Assessment Details</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex justify-between border-b border-[hsl(var(--border))] pb-2">
            <span className="text-sm text-[hsl(var(--muted-fg))]">Assessment ID</span>
            <span className="font-mono text-sm text-[hsl(var(--fg))]">{assessment.assessment_id}</span>
          </div>
          <div className="flex justify-between border-b border-[hsl(var(--border))] pb-2">
            <span className="text-sm text-[hsl(var(--muted-fg))]">Target</span>
            <span className="text-sm font-medium text-[hsl(var(--fg))]">{assessment.target}</span>
          </div>
          <div className="flex justify-between border-b border-[hsl(var(--border))] pb-2">
            <span className="text-sm text-[hsl(var(--muted-fg))]">Status</span>
            <AssessmentStatusBadge status={assessment.status} />
          </div>
          <div className="flex justify-between">
            <span className="text-sm text-[hsl(var(--muted-fg))]">Created At</span>
            <span className="text-sm text-[hsl(var(--fg))]">{formatDate(assessment.created_at)}</span>
          </div>
        </CardContent>
      </Card>

      {/* Severity Distribution */}
      {Object.keys(severityCounts).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {Object.entries(severityCounts).map(([severity, count]) => (
                <Badge key={severity} variant={severity === "CRITICAL" || severity === "HIGH" ? "destructive" : severity === "MEDIUM" ? "warning" : "secondary"}>
                  {severity}: {count}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
