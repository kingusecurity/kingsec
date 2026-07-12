import { memo } from "react"
import { useNavigate } from "react-router-dom"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Button } from "@/shared/ui/button"
import { AssessmentStatusBadge } from "@/features/assessments/components/assessment-status-badge"
import { formatRelative } from "@/shared/lib/utils"
import { ROUTES } from "@/shared/lib/constants"
import type { AssessmentSummary } from "@/features/assessments/types"
import { ExternalLink } from "lucide-react"

interface RecentAssessmentsProps {
  assessments: AssessmentSummary[]
}

export const RecentAssessments = memo(function RecentAssessments({ assessments }: RecentAssessmentsProps): React.ReactElement {
  const navigate = useNavigate()

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">Recent Assessments</CardTitle>
        <Button variant="ghost" size="sm" onClick={() => navigate(ROUTES.ASSESSMENTS)}>
          View All
        </Button>
      </CardHeader>
      <CardContent>
        {assessments.length === 0 ? (
          <p className="py-4 text-center text-sm text-[hsl(var(--muted-fg))]">No assessments yet</p>
        ) : (
          <div className="space-y-2">
            {assessments.map((a) => (
              <div
                key={a.assessment_id}
                className="flex items-center justify-between rounded-lg border border-[hsl(var(--border))] p-3 transition-colors hover:bg-[hsl(var(--accent))]/50"
              >
                <div className="space-y-1">
                  <p className="text-sm font-medium text-[hsl(var(--fg))]">{a.target}</p>
                  <p className="text-[10px] text-[hsl(var(--muted-fg))]">
                    {a.findings_count} findings · {formatRelative(a.created_at)}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <AssessmentStatusBadge status={a.status} />
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-8"
                    onClick={() => navigate(`${ROUTES.ASSESSMENTS}/${a.assessment_id}`)}
                    aria-label={`Open assessment ${a.target}`}
                  >
                    <ExternalLink className="size-4" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
})
