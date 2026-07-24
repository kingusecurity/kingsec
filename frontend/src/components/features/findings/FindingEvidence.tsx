import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { FileText } from 'lucide-react'
import type { FindingResponse } from '@/types/api'

interface FindingEvidenceProps {
  finding: FindingResponse
  loading?: boolean
}

export function FindingEvidence({ finding, loading }: FindingEvidenceProps) {
  if (loading) {
    return (
      <Card>
        <CardHeader>
          <div className="h-5 w-24 animate-pulse rounded bg-surface-tertiary" />
          <div className="h-4 w-full animate-pulse rounded bg-surface-tertiary" />
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Evidence</CardTitle>
        <CardDescription>{finding.evidence_count} evidence items</CardDescription>
      </CardHeader>
      <div className="px-5 pb-5">
        {finding.evidence_count > 0 ? (
          <p className="text-sm text-text-secondary">
            Evidence details are available from the API.
          </p>
        ) : (
          <div className="flex flex-col items-center gap-2 py-4 text-center">
            <FileText className="h-6 w-6 text-text-muted" />
            <p className="text-sm text-text-muted">No evidence recorded for this finding.</p>
          </div>
        )}
      </div>
    </Card>
  )
}
