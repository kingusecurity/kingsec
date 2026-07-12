import { memo } from "react"
import { SeverityBadge } from "./severity-badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import type { AssessmentFinding } from "../types"
import { AlertTriangle } from "lucide-react"

interface FindingsTabProps {
  findings: AssessmentFinding[]
}

const FindingsTable = memo(function FindingsTable({ findings }: { findings: AssessmentFinding[] }): React.ReactElement {
  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-center">
        <AlertTriangle className="size-8 text-[hsl(var(--muted-fg))]" />
        <p className="text-sm text-[hsl(var(--fg-secondary))]">No findings yet.</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-[hsl(var(--border))]">
      <table className="w-full text-sm" role="table" aria-label="Findings">
        <thead>
          <tr className="border-b border-[hsl(var(--border))] bg-[hsl(var(--muted))]/50">
            <th scope="col" className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]">Title</th>
            <th scope="col" className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]">Severity</th>
            <th scope="col" className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]">Status</th>
            <th scope="col" className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]">Evidence</th>
            <th scope="col" className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]">Recommendations</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr key={finding.finding_id} className="border-b border-[hsl(var(--border))] transition-colors hover:bg-[hsl(var(--accent))]/50">
              <td className="px-4 py-3 font-medium text-[hsl(var(--fg))]">{finding.title}</td>
              <td className="px-4 py-3"><SeverityBadge severity={finding.severity} /></td>
              <td className="px-4 py-3 text-[hsl(var(--fg-secondary))]">{finding.status}</td>
              <td className="px-4 py-3 text-[hsl(var(--fg-secondary))]">{finding.evidence_count}</td>
              <td className="px-4 py-3 text-[hsl(var(--fg-secondary))]">{finding.recommendation_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
})

export function FindingsTab({ findings }: FindingsTabProps): React.ReactElement {
  const grouped = findings.reduce(
    (acc, f) => {
      const key = f.severity ?? "UNKNOWN"
      if (!acc[key]) acc[key] = []
      acc[key].push(f)
      return acc
    },
    {} as Record<string, AssessmentFinding[]>,
  )

  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
  const sorted = severityOrder.filter((s) => grouped[s]).map((s) => ({ severity: s, findings: grouped[s] }))

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-center">
        <AlertTriangle className="size-8 text-[hsl(var(--muted-fg))]" />
        <p className="text-sm text-[hsl(var(--fg-secondary))]">No findings yet.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <FindingsTable findings={findings} />
      {sorted.map(({ severity, findings: group }) => (
        <Card key={severity}>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">{severity} ({group.length})</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {group.map((f) => (
              <div key={f.finding_id} className="rounded-lg border border-[hsl(var(--border))] p-3">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="font-medium text-[hsl(var(--fg))]">{f.title}</p>
                    <p className="mt-1 text-xs text-[hsl(var(--fg-secondary))]">
                      {f.evidence_count} evidence · {f.recommendation_count} recommendations
                    </p>
                  </div>
                  <SeverityBadge severity={f.severity} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
