import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Lightbulb } from 'lucide-react'
import type { FindingResponse } from '@/types/api'

interface FindingRecommendationsProps {
  finding: FindingResponse
  loading?: boolean
}

export function FindingRecommendations({ finding, loading }: FindingRecommendationsProps) {
  if (loading) {
    return (
      <Card>
        <CardHeader>
          <div className="h-5 w-32 animate-pulse rounded bg-surface-tertiary" />
          <div className="h-4 w-full animate-pulse rounded bg-surface-tertiary" />
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recommendations</CardTitle>
        <CardDescription>{finding.recommendation_count} recommendations</CardDescription>
      </CardHeader>
      <div className="px-5 pb-5">
        {finding.recommendation_count > 0 ? (
          <p className="text-sm text-text-secondary">
            Recommendation details are available from the API.
          </p>
        ) : (
          <div className="flex flex-col items-center gap-2 py-4 text-center">
            <Lightbulb className="h-6 w-6 text-text-muted" />
            <p className="text-sm text-text-muted">No recommendations for this finding.</p>
          </div>
        )}
      </div>
    </Card>
  )
}
